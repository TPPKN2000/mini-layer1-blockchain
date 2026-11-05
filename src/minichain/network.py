"""Deterministic discrete-event network simulator (virtual time in integer ms).

Models: random delay, reordering (via independent delays), duplication, loss
(before GST), outbound rate limit per node, inbound anti-flood blocking of
overactive peers. Every network event is logged (send/drop/delay/dup/block/unblock).
"""
import heapq
import itertools
import math
import random


def _components(adj, removed):
    alive = [i for i in range(len(adj)) if i not in removed]
    seen, comps = set(), []
    for s0 in alive:
        if s0 in seen:
            continue
        comp, st = [s0], [s0]
        seen.add(s0)
        while st:
            x = st.pop()
            for y in adj[x]:
                if y not in removed and y not in seen:
                    seen.add(y)
                    comp.append(y)
                    st.append(y)
        comps.append(comp)
    return comps


def _violation(adj, f, max_subsets=200000):
    """Return a witness that <= f faulty nodes can break the correct nodes' connectivity."""
    n = len(adj)
    if f == 0:
        return None
    for i in range(n):
        if len(adj[i]) < f + 1:
            return ("deg", i)
    if math.comb(n, f) > max_subsets:       # too many subsets: min-degree check only
        return None
    for sub in itertools.combinations(range(n), f):
        comps = _components(adj, set(sub))
        if len(comps) > 1:
            return ("cut", comps)
    return None


def build_topology(n, topo, degree, seed, f=0):
    """Undirected neighbour lists. 'full' = complete graph; 'random' = ring + chords, then
    hardened so that removing ANY f nodes leaves the remaining (correct) nodes connected
    (vertex connectivity >= f+1). Without this, gossip itself could be partitioned by the
    faulty nodes and no protocol could make progress."""
    adj = [set() for _ in range(n)]
    if topo == "full":
        for i in range(n):
            adj[i] = set(range(n)) - {i}
        return [sorted(a) for a in adj]
    rng = random.Random(seed ^ 0xA5A5)
    for i in range(n):                       # ring guarantees connectivity
        adj[i].add((i + 1) % n)
        adj[(i + 1) % n].add(i)
    guard = 0
    while sum(len(a) for a in adj) < n * degree and guard < 10000:
        guard += 1
        a, b = rng.randrange(n), rng.randrange(n)
        if a != b:
            adj[a].add(b)
            adj[b].add(a)
    for _ in range(10000):                   # harden against f-node cuts
        v = _violation(adj, f)
        if v is None:
            break
        if v[0] == "deg":
            i = v[1]
            cand = sorted(set(range(n)) - adj[i] - {i})
            j = cand[rng.randrange(len(cand))]
        else:
            i, j = rng.choice(v[1][0]), rng.choice(v[1][1])
        adj[i].add(j)
        adj[j].add(i)
    return [sorted(a) for a in adj]


class Network:
    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg["network"]
        self.rng = random.Random(ctx.cfg["seed"])
        self.heap = []
        self.seq = 0
        self.now = 0
        self.nodes = []
        self.next_free = [0] * ctx.n
        self.gap = max(1, -(-1000 // self.cfg["out_rate"]))     # ms between sends
        self.inwin = {}          # (dst, src) -> [window_start, count]
        self.blocked = {}        # (dst, src) -> until
        ctx.net = self

    def log(self, node, ev, h=None, **kw):
        if self.cfg["log_net"]:
            self.ctx.log(self.now, node, ev, h, **kw)

    def at(self, t, fn, *args):
        self.seq += 1
        heapq.heappush(self.heap, (t, self.seq, fn, args))

    def run(self, stop_fn, max_time):
        while self.heap:
            t, _, fn, args = heapq.heappop(self.heap)
            if t > max_time:
                self.now = max_time
                return False
            self.now = t
            fn(*args)
            if stop_fn():
                return True
        return stop_fn()

    def send(self, src, dst, wire, mtype, h):
        c = self.cfg
        t0 = max(self.now, self.next_free[src])
        self.next_free[src] = t0 + self.gap
        self.log(src, "send", h, to=dst, type=mtype, size=len(wire))
        if t0 > self.now:
            self.log(src, "delay", h, to=dst, type=mtype, why="throttle", d=t0 - self.now)
        stable = self.now >= c["gst_ms"]
        if not stable and self.rng.random() < c["pre_drop"]:
            self.log(src, "drop", h, to=dst, type=mtype, why="loss")
            return
        dmax = c["delay_max"] if stable else c["pre_delay_max"]
        d = self.rng.randint(c["delay_min"], dmax)
        if d > c["delay_max"]:
            self.log(src, "delay", h, to=dst, type=mtype, why="slow_link", d=d)
        self.at(t0 + d, self._deliver, src, dst, wire, mtype, h)
        if self.rng.random() < (c["dup"] if stable else c["pre_dup"]):
            d2 = self.rng.randint(c["delay_min"], dmax)
            self.log(src, "dup", h, to=dst, type=mtype, d=d2)
            self.at(t0 + d2, self._deliver, src, dst, wire, mtype, h)

    def _deliver(self, src, dst, wire, mtype, h):
        node = self.nodes[dst]
        if node.crashed:
            self.log(dst, "drop", h, frm=src, type=mtype, why="crashed")
            return
        c = self.cfg
        key = (dst, src)
        until = self.blocked.get(key)
        if until is not None:
            if self.now < until:
                self.log(dst, "drop", h, frm=src, type=mtype, why="blocked")
                return
            del self.blocked[key]
        w = self.inwin.get(key)
        if w is None or self.now - w[0] >= c["in_window_ms"]:
            w = self.inwin[key] = [self.now, 0]
        w[1] += 1
        if w[1] > c["in_limit"]:
            self.blocked[key] = self.now + c["block_ms"]
            self.inwin.pop(key, None)
            self.log(dst, "block", h, peer=src, until=self.now + c["block_ms"])
            self.at(self.now + c["block_ms"], self._unblock, dst, src)
            self.log(dst, "drop", h, frm=src, type=mtype, why="blocked")
            return
        node.on_message(src, wire)

    def _unblock(self, dst, src):
        self.log(dst, "unblock", None, peer=src)
