"""Validator node: gossip, block validation, Tendermint-style two-phase BFT, sync.

Layers inside one node (cf. lecture "Internal Architecture Overview"):
  network I/O (on_message / gossip) -> message guards -> consensus rules (check)
  -> execution (validate) -> commit (finalize) -> ledger / mempool.
"""
from collections import Counter
from .encoding import enc, dec
from .crypto import H
from .state import State, apply_tx, check_tx
from .types import (Tx, Proposal, Vote, NIL, PREVOTE, PRECOMMIT, PHASE_NAME,
                    block_hash, tx_root_of)

S_PROPOSE, S_PREVOTE, S_PRECOMMIT = 0, 1, 2
DEFER = "defer"            # handler result: message NOT consumed -> must stay re-deliverable
MAX_VOTES_PER_VOTER = 256  # distinct (round, phase) entries stored per validator per height
FUTURE_WINDOW = 3          # only buffer messages up to this many heights ahead
FUTURE_PER_SENDER = 256    # buffered future messages per (height, signer)
FUTURE_CAP = 4096          # buffered future messages per height


class HState:
    """Consensus state for one height."""
    def __init__(self, h):
        self.h = h
        self.round = 0
        self.step = S_PROPOSE
        self.started = False
        self.locked_round = -1
        self.locked_hash = None
        self.valid_round = -1
        self.valid_hash = None
        self.proposals = {}      # round -> Proposal (first accepted wins)
        self.votes = {}          # (round, phase) -> {voter: Vote}  (one counted vote per voter)
        self.sent = {}           # (round, phase) -> block_hash    (own-vote guard)
        self.own_wires = {}      # (round, phase) -> wire, for re-gossip
        self.flags = set()       # one-shot rule firings
        self.vcount = {}         # voter -> stored vote entries (quota)
        self.polkas = set()      # (round, block_hash) proven by a verified POL certificate
        self.pol_wires = {}      # round -> POL wire we proposed with (for re-gossip)
        self.certified = {}      # block_hash -> (round, [precommit Votes]) from a verified COMMIT cert


class Node:
    honest = True

    def __init__(self, idx, ctx, net, neighbors):
        self.id = idx
        self.ctx = ctx
        self.net = net
        self.neighbors = neighbors
        self.cp = ctx.cfg["consensus"]
        self.key = ctx.val_keys[idx]
        self.crashed = False
        self.done = False
        self.state = State()
        self.last_hash = ctx.genesis_hash
        self.height = 1
        self.ledger = []                 # (height, block_hash, state_hash)
        self.applied = []                # tx ids in execution order
        self.hs = HState(1)
        self.headers = {}                # block_hash -> Proposal
        self.bodies = {}                 # block_hash -> [Tx]
        self.validated = {}              # block_hash -> (ok, reason, State)
        self.mempool = {}                # (sender, nonce) -> Tx
        self.seen = set()
        self.recent = []                 # recently accepted wires (for Byzantine replay)
        self.future = {}                 # height -> [(src, msg)]
        self.fcount = {}                 # (height, signer) -> buffered count
        self.commits = {}                # height -> COMMIT wire
        self.req_time = {}
        self.req_n = {}
        self.hint = {}
        self.waiting = {}                # block_hash -> set(peers awaiting the body)
        self.last_serve = {}
        self.dups = 0
        self.stale = 0
        self.status_seq = 0
        self.max_tally = 0               # max counted votes seen in any set (test instrumentation)

    # ------------------------------------------------------------------ utils
    def log(self, ev, **kw):
        self.ctx.log(self.net.now, self.id, ev, self.height, **kw)

    def send(self, dst, wire, mtype):
        self.net.send(self.id, dst, wire, mtype, self.height)

    def gossip(self, wire, mtype, exclude=None):
        for nb in self.neighbors:
            if nb != exclude:
                self.send(nb, wire, mtype)

    def timer(self, delay, kind, h, r):
        self.net.at(self.net.now + delay, self.on_timer, kind, h, r)

    def reject(self, mtype, reason, **kw):
        self.log("reject", type=mtype, reason=reason, **kw)

    def have_valid(self, bh):
        v = self.validated.get(bh)
        return v is not None and v[0]

    # -------------------------------------------------------------- lifecycle
    def start(self):
        self.net.at(self.net.now, self.begin_height, 1)
        self.net.at(self.net.now + self.cp["resend_ms"], self.on_resend)

    def crash(self):
        self.crashed = True
        self.ctx.log(self.net.now, self.id, "crash", self.height)

    def begin_height(self, h):
        if self.crashed or self.done or self.height != h or self.hs.started:
            return
        hs = self.hs
        hs.started = True
        self.log("height_start")
        self.start_round(0)
        self.check()

    def start_round(self, r):
        hs = self.hs
        hs.round, hs.step = r, S_PROPOSE
        self.log("round", r=r, proposer=self.ctx.proposer(hs.h, r))
        if self.ctx.proposer(hs.h, r) == self.id:
            self.propose()
        self.timer(self.cp["timeout_propose"] + r * self.cp["timeout_delta"], "propose", hs.h, r)

    # ------------------------------------------------------------ block build
    def build_block(self):
        st = self.state.copy()
        txs = []
        for k in sorted(self.mempool):
            tx = self.mempool[k]
            if apply_tx(st, tx, self.ctx)[0]:
                txs.append(tx)
                if len(txs) >= self.cp["max_txs"]:
                    break
        return txs, st

    def sign_proposal(self, h, r, pol, bh, parent, sh, txr, key=None):
        p = Proposal(h, r, pol, bh, parent, sh, txr, self.id, b"")
        p.sig = (key or self.key).sign("HEADER", self.ctx.chain_id, p.payload())
        return p

    def make_block_proposal(self, txs, st, r, pol=-1):
        h = self.hs.h
        sh, txr = st.root(), tx_root_of(txs)
        bh = block_hash(h, self.last_hash, sh, txr)
        return self.sign_proposal(h, r, pol, bh, self.last_hash, sh, txr)

    def register_own(self, p, txs):
        hs = self.hs
        self.headers.setdefault(p.block_hash, p)
        self.bodies[p.block_hash] = txs
        self.run_validation(p.block_hash)
        hs.proposals.setdefault(p.round, p)

    def propose(self):
        hs = self.hs
        r = hs.round
        if hs.valid_hash is not None and self.have_valid(hs.valid_hash):
            hd = self.headers[hs.valid_hash]
            p = self.sign_proposal(hs.h, r, hs.valid_round, hd.block_hash, hd.parent,
                                   hd.state_hash, hd.tx_root)
            txs = self.bodies[hd.block_hash]
        else:
            txs, st = self.build_block()
            p = self.make_block_proposal(txs, st, r)
        self.register_own(p, txs)
        self.log("propose", r=r, block=p.block_hash, pol=p.pol_round, ntx=len(txs))
        wire = enc(p.to_list())
        self.seen.add(H(wire))
        self.gossip(wire, "HDR")
        if p.pol_round >= 0:       # prove the polka so peers need not have seen it themselves
            pv = sorted((v for v in hs.votes.get((p.pol_round, PREVOTE), {}).values()
                         if v.block_hash == p.block_hash), key=lambda z: z.voter)[:self.ctx.q]
            if len(pv) >= self.ctx.q:
                pw = enc(["POL", hs.h, p.pol_round, p.block_hash, [v.to_list() for v in pv]])
                hs.pol_wires[r] = pw
                self.seen.add(H(pw))
                self.gossip(pw, "POL")

    # --------------------------------------------------------------- validate
    def run_validation(self, bh):
        """Execute block on top of current finalized state; cache the verdict."""
        hd, txs = self.headers[bh], self.bodies[bh]
        ok, reason, st = True, None, None
        if hd.height != self.height or hd.parent != self.last_hash:
            ok, reason = False, "bad_parent"
        elif tx_root_of(txs) != hd.tx_root:
            ok, reason = False, "bad_tx_root"
        elif len(txs) > self.cp["max_txs"]:
            ok, reason = False, "too_many_txs"
        else:
            st = self.state.copy()
            for tx in txs:
                good, why = apply_tx(st, tx, self.ctx)
                if not good:
                    ok, reason = False, "tx_" + why
                    break
            if ok and st.root() != hd.state_hash:
                ok, reason = False, "bad_state_hash"
        self.validated[bh] = (ok, reason, st)
        self.log("validate", block=bh, ok=ok, reason=reason)

    # ---------------------------------------------------------------- inbound
    def on_message(self, src, wire):
        if self.crashed:
            return
        mid = H(wire)
        if mid in self.seen:
            self.dups += 1
            return
        self.seen.add(mid)
        try:
            msg = dec(wire)
            kind = msg[0]
        except Exception:
            self.reject("?", "malformed", frm=src)
            return
        if self.dispatch(src, msg, True) == DEFER:
            self.seen.discard(mid)      # not consumed: a later retransmission must be processed
            return
        self.recent.append(wire)
        if len(self.recent) > 300:
            self.recent.pop(0)

    def on_client_tx(self, wire):
        if self.crashed:
            return
        self.log("submit", size=len(wire))
        try:
            self.handle_tx(-1, dec(wire), False)
        except Exception:
            self.reject("TX", "malformed", frm=-1)

    def dispatch(self, src, msg, relay):
        kind = msg[0] if msg and isinstance(msg[0], str) else None
        h = {"TX": self.handle_tx, "HDR": self.handle_hdr, "VOTE": self.handle_vote,
             "POL": self.handle_pol}.get(kind)
        try:
            if h is not None:
                return h(src, msg, relay)
            if kind == "COMMIT":
                return self.handle_commit(src, msg)
            if kind == "BODY":
                return self.handle_body(src, msg)
            if kind == "BODYREQ":
                return self.handle_bodyreq(src, msg)
            if kind == "HDRREQ":
                return self.handle_hdrreq(src, msg)
            if kind == "STATUS":
                return self.handle_status(src, msg)
            self.reject(str(kind), "unknown_type", frm=src)
        except (ValueError, TypeError, IndexError, KeyError):
            self.reject(str(kind), "malformed", frm=src)
        return None

    def buffer_future(self, h, src, msg, who):
        """Buffer a message for a later height. Returns False (-> DEFER) when the height is
        too far ahead or the per-signer / per-height quota is exhausted."""
        if h > self.height + FUTURE_WINDOW:
            return False
        lst = self.future.setdefault(h, [])
        cnt = self.fcount.setdefault((h, who), 0)
        if len(lst) >= FUTURE_CAP or cnt >= FUTURE_PER_SENDER:
            return False
        self.fcount[(h, who)] = cnt + 1
        lst.append((src, msg))
        return True

    def serve_commit(self, src, h):
        w = self.commits.get(h)
        if w is None or src < 0:
            return
        k = (src, h)
        last = self.last_serve.get(k)
        if last is not None and self.net.now - last < self.cp["resend_ms"] // 2:
            return
        self.last_serve[k] = self.net.now
        self.send(src, w, "COMMIT")

    # TX ---------------------------------------------------------------------
    def handle_tx(self, src, l, relay):
        tx = Tx.from_list(l)
        why = check_tx(tx, self.ctx)
        if why:
            self.reject("TX", why, frm=src, sender=tx.sender, nonce=tx.nonce)
            return
        if tx.nonce <= self.state.nonce(tx.sender):
            self.reject("TX", "stale_nonce", frm=src, sender=tx.sender, nonce=tx.nonce)
            return
        k = (tx.sender, tx.nonce)
        if k in self.mempool:
            self.log("ignore", type="TX", reason="duplicate_nonce", sender=tx.sender, nonce=tx.nonce)
            return
        self.mempool[k] = tx
        self.log("tx_accept", sender=tx.sender, nonce=tx.nonce)
        if relay:
            self.gossip(enc(l), "TX", exclude=src)

    # HDR --------------------------------------------------------------------
    def header_static_check(self, p):
        if not (0 <= p.proposer < self.ctx.n) or p.height < 1 or p.round > 1000:
            return "bad_fields"
        if p.proposer != self.ctx.proposer(p.height, p.round):
            return "wrong_proposer"
        if p.block_hash != p.computed_block_hash():
            return "bad_block_hash"
        if not self.ctx.verify(self.ctx.val_pks[p.proposer], "HEADER", p.payload(), p.sig):
            return "bad_signature"
        return None

    def handle_hdr(self, src, l, relay):
        p = Proposal.from_list(l)
        why = self.header_static_check(p)
        if why:
            self.reject("HDR", why, frm=src, r=p.round)
            return
        if p.height < self.height:
            self.stale += 1
            self.serve_commit(src, p.height)
            return
        if p.height > self.height:
            if not self.buffer_future(p.height, src, l, p.proposer):
                return DEFER
            if relay:
                self.gossip(enc(l), "HDR", exclude=src)
            return
        if p.parent != self.last_hash:
            self.reject("HDR", "bad_parent", frm=src, r=p.round)
            return
        if not (-1 <= p.pol_round < p.round):
            self.reject("HDR", "bad_pol_round", frm=src, r=p.round)
            return
        hs = self.hs
        old = hs.proposals.get(p.round)
        if old is not None:
            if old.block_hash != p.block_hash:
                self.log("equivocation", what="proposal", proposer=p.proposer, r=p.round,
                         a=old.block_hash, b=p.block_hash)
                # Keep the (validly signed) header: a quorum may have formed on THIS block and
                # we must be able to fetch/validate its body, else we would wait forever.
                self.headers.setdefault(p.block_hash, p)
                self.hint.setdefault(p.block_hash, src)
                if relay:
                    self.gossip(enc(l), "HDR", exclude=src)
            return
        hs.proposals[p.round] = p
        self.headers.setdefault(p.block_hash, p)
        self.hint[p.block_hash] = src
        self.log("hdr_accept", r=p.round, block=p.block_hash, pol=p.pol_round, frm=src)
        if relay:
            self.gossip(enc(l), "HDR", exclude=src)
        self.want(p.block_hash)
        self.check()

    # BODY / requests ---------------------------------------------------------
    def want(self, bh):
        """Fetch a missing header (HDRREQ) or body (BODYREQ). Bodies are only
        requested after the matching header has been accepted."""
        if bh in self.headers:
            if bh in self.bodies:
                return
            kind = "BODYREQ"
        else:
            kind = "HDRREQ"
        key = (kind, bh)
        last = self.req_time.get(key)
        if last is not None and self.net.now - last < self.cp["req_retry_ms"]:
            return
        self.req_time[key] = self.net.now
        n = self.req_n[key] = self.req_n.get(key, 0) + 1
        wire = enc([kind, bh, n, self.id])   # origin id: unsigned msgs must be unique per sender
        for nb in self.neighbors:
            self.send(nb, wire, kind)

    def handle_bodyreq(self, src, l):
        bh = l[1]
        if src < 0 or bh not in self.headers:
            return
        if bh in self.bodies:
            self.send(src, enc(["BODY", bh, [t.to_list() for t in self.bodies[bh]]]), "BODY")
        else:                              # remember requester, reply once body arrives
            self.waiting.setdefault(bh, set()).add(src)

    def handle_hdrreq(self, src, l):
        bh = l[1]
        if bh in self.headers and src >= 0:
            self.send(src, enc(self.headers[bh].to_list()), "HDR")

    def handle_body(self, src, l):
        bh, raw = l[1], l[2]
        if not isinstance(bh, bytes) or not isinstance(raw, list):
            raise ValueError("bad body")
        hd = self.headers.get(bh)
        if hd is None:
            self.reject("BODY", "body_without_header", frm=src, block=bh)
            return
        if bh in self.bodies:
            return
        txs = [Tx.from_list(x) for x in raw]
        if tx_root_of(txs) != hd.tx_root:
            self.reject("BODY", "bad_tx_root", frm=src, block=bh)
            return
        self.bodies[bh] = txs
        for peer in sorted(self.waiting.pop(bh, ())):
            self.send(peer, enc(["BODY", bh, [t.to_list() for t in txs]]), "BODY")
        if hd.height == self.height:
            self.run_validation(bh)
        self.check()

    # STATUS (anti-entropy) -----------------------------------------------------
    def handle_status(self, src, l):
        if not isinstance(l[1], int):
            raise ValueError("bad status")
        if l[1] < self.height:
            self.serve_commit(src, l[1])

    def broadcast_status(self):
        self.status_seq += 1
        self.gossip(enc(["STATUS", self.height, self.status_seq, self.id]), "STATUS")

    # VOTE -------------------------------------------------------------------
    def handle_vote(self, src, l, relay):
        v = Vote.from_list(l)
        if not (0 <= v.voter < self.ctx.n):
            self.reject("VOTE", "bad_voter", frm=src)
            return
        if not self.ctx.verify(self.ctx.val_pks[v.voter], "VOTE", v.payload(), v.sig):
            self.reject("VOTE", "bad_signature", frm=src, voter=v.voter, vh=v.height, r=v.round)
            return
        if v.height < self.height:
            self.stale += 1
            self.serve_commit(src, v.height)
            return
        if v.height > self.height:
            if not self.buffer_future(v.height, src, l, v.voter):
                return DEFER
            if relay:
                self.gossip(enc(l), "VOTE", exclude=src)
            return
        status = self.add_vote(v)
        if status == "quota":
            return DEFER
        if status == "new":
            if relay:
                self.gossip(enc(l), "VOTE", exclude=src)
            self.check()
        elif status == "conflict":
            if relay:
                self.gossip(enc(l), "VOTE", exclude=src)

    def add_vote(self, v):
        """Counts at most one vote per (voter, height, round, phase)."""
        hs = self.hs
        vs = hs.votes.setdefault((v.round, v.phase), {})
        old = vs.get(v.voter)
        if old is not None:
            if old.block_hash == v.block_hash:
                return "dup"
            self.log("equivocation", what="vote", voter=v.voter, r=v.round,
                     phase=PHASE_NAME[v.phase], a=old.block_hash, b=v.block_hash)
            return "conflict"
        if v.voter != self.id and hs.vcount.get(v.voter, 0) >= MAX_VOTES_PER_VOTER:
            if not vs:
                del hs.votes[(v.round, v.phase)]
            return "quota"                    # bounded memory: excess entries are not stored
        hs.vcount[v.voter] = hs.vcount.get(v.voter, 0) + 1
        vs[v.voter] = v
        self.max_tally = max(self.max_tally, len(vs))
        self.log("vote_in", voter=v.voter, r=v.round, phase=PHASE_NAME[v.phase], block=v.block_hash)
        return "new"

    # POL (polka certificate) ---------------------------------------------------
    def handle_pol(self, src, l, relay):
        if len(l) != 5 or not all(isinstance(x, int) for x in l[1:3]) or not isinstance(l[3], bytes) \
                or not isinstance(l[4], list):
            raise ValueError("bad pol")
        h, pr, bh = l[1], l[2], l[3]
        if h < self.height:
            self.stale += 1
            return
        if h > self.height:
            if not self.buffer_future(h, src, l, src):
                return DEFER
            if relay:
                self.gossip(enc(l), "POL", exclude=src)
            return
        voters = set()
        for x in l[4]:
            v = Vote.from_list(x)
            if (v.height, v.round, v.phase, v.block_hash) != (h, pr, PREVOTE, bh):
                self.reject("POL", "vote_mismatch", frm=src)
                return
            if not (0 <= v.voter < self.ctx.n) or not self.ctx.verify(
                    self.ctx.val_pks[v.voter], "VOTE", v.payload(), v.sig):
                self.reject("POL", "bad_signature", frm=src)
                return
            voters.add(v.voter)
        if len(voters) < self.ctx.q:
            self.reject("POL", "no_quorum", frm=src)
            return
        self.hs.polkas.add((pr, bh))
        self.log("pol_in", frm=src, pol=pr, block=bh)
        if relay:
            self.gossip(enc(l), "POL", exclude=src)
        self.check()

    # COMMIT -----------------------------------------------------------------
    def handle_commit(self, src, l):
        if len(l) != 6 or not all(isinstance(x, int) for x in l[1:3]) or not isinstance(l[3], bytes):
            raise ValueError("bad commit")
        h, r, bh = l[1], l[2], l[3]
        if h < self.height:
            self.stale += 1
            return
        if h > self.height:
            if not self.buffer_future(h, src, l, src):
                return DEFER
            return
        p = Proposal.from_list(l[5])
        why = self.header_static_check(p)
        if why or p.block_hash != bh or p.height != h:
            self.reject("COMMIT", why or "header_mismatch", frm=src)
            return
        if p.parent != self.last_hash:
            self.reject("COMMIT", "bad_parent", frm=src)
            return
        voters = {}
        for x in l[4]:
            v = Vote.from_list(x)
            if (v.height, v.round, v.phase, v.block_hash) != (h, r, PRECOMMIT, bh):
                self.reject("COMMIT", "vote_mismatch", frm=src)
                return
            if not (0 <= v.voter < self.ctx.n) or not self.ctx.verify(
                    self.ctx.val_pks[v.voter], "VOTE", v.payload(), v.sig):
                self.reject("COMMIT", "bad_signature", frm=src)
                return
            voters[v.voter] = v
        if len(voters) < self.ctx.q:
            self.reject("COMMIT", "no_quorum", frm=src)
            return
        self.headers.setdefault(bh, p)
        self.hint[bh] = src
        for v in sorted(voters.values(), key=lambda z: z.voter):
            self.add_vote(v)
        # A certificate proves a quorum regardless of which (possibly equivocating) votes this
        # node saw first, so it is kept separately and used to finalize.
        self.hs.certified[bh] = (r, sorted(voters.values(), key=lambda z: z.voter)[:self.ctx.q])
        self.log("commit_cert_in", frm=src, r=r, block=bh)
        self.want(bh)
        self.check()

    # --------------------------------------------------------------- outbound
    def make_vote(self, phase, bh, key=None, voter=None, h=None, r=None, domain="VOTE"):
        hs = self.hs
        v = Vote(hs.h if h is None else h, hs.round if r is None else r, phase, bh,
                 self.id if voter is None else voter, b"")
        v.sig = (key or self.key).sign(domain, self.ctx.chain_id, v.payload())
        return v

    def cast_vote(self, phase, bh):
        hs = self.hs
        r = hs.round
        key = (r, phase)
        if key in hs.sent:      # guard: at most one PREVOTE / PRECOMMIT per (height, round)
            self.log("guard", what="double_vote_blocked", r=r, phase=PHASE_NAME[phase])
            return
        hs.sent[key] = bh
        v = self.make_vote(phase, bh)
        wire = enc(v.to_list())
        self.seen.add(H(wire))
        hs.own_wires[key] = wire
        self.add_vote(v)
        self.log(PHASE_NAME[phase].lower(), r=r, block=bh)
        self.gossip(wire, "VOTE")

    # ------------------------------------------------------------------ timers
    def on_timer(self, kind, h, r):
        if self.crashed or self.done or self.hs.h != h or not self.hs.started:
            return
        hs = self.hs
        if kind == "propose" and hs.round == r and hs.step == S_PROPOSE:
            self.log("timeout", what="propose", r=r)
            self.cast_vote(PREVOTE, NIL)
            hs.step = S_PREVOTE
        elif kind == "prevote" and hs.round == r and hs.step == S_PREVOTE:
            self.log("timeout", what="prevote", r=r)
            self.cast_vote(PRECOMMIT, NIL)
            hs.step = S_PRECOMMIT
        elif kind == "precommit" and hs.round == r:
            self.log("timeout", what="precommit", r=r)
            self.start_round(r + 1)
        self.check()

    def on_resend(self):
        if self.crashed or self.done:
            return
        self.net.at(self.net.now + self.cp["resend_ms"], self.on_resend)
        hs = self.hs
        if hs.started:
            for k in sorted(hs.own_wires):
                self.gossip(hs.own_wires[k], "VOTE")
            p = hs.proposals.get(hs.round)
            if p is not None and p.proposer == self.id:
                self.gossip(enc(p.to_list()), "HDR")
                if hs.round in hs.pol_wires:
                    self.gossip(hs.pol_wires[hs.round], "POL")
            for (r, ph), vs in sorted(hs.votes.items()):
                if r == hs.round:
                    for voter in sorted(vs):
                        if voter != self.id:
                            self.gossip(enc(vs[voter].to_list()), "VOTE")
        self.broadcast_status()
        self.check()

    # --------------------------------------------------------------- consensus
    def tally(self, r, phase):
        c = Counter()
        for v in self.hs.votes.get((r, phase), {}).values():
            c[v.block_hash] += 1
        return c

    def check(self):
        """Evaluate Tendermint rules to a fixed point."""
        hs = self.hs
        if self.crashed or self.done or not hs.started:
            return
        Q, F = self.ctx.q, self.ctx.f
        progress = True
        while progress and hs is self.hs and not self.done:
            progress = False
            r = hs.round
            # R1: finalize on a quorum of PRECOMMITs (any round) or a verified commit
            #     certificate; fetch missing data.
            for bh, (rr, cvotes) in sorted(hs.certified.items()):
                if self.have_valid(bh):
                    self.finalize(rr, bh, cvotes)
                    return
                self.want(bh)
            for (rr, ph) in sorted(hs.votes):
                for bh, c in sorted(self.tally(rr, ph).items()):
                    if bh == NIL or c < Q:
                        continue
                    if ph == PRECOMMIT and self.have_valid(bh):
                        self.finalize(rr, bh)
                        return
                    self.want(bh)
            # R2: round skip on f+1 distinct validators active in a higher round.
            best = None
            for rr in sorted({k[0] for k in hs.votes if k[0] > r}):
                vs = set()
                for (r2, _), d in hs.votes.items():
                    if r2 >= rr:
                        vs.update(d)
                if len(vs) >= F + 1:
                    best = rr
            if best is not None:
                self.log("round_skip", to=best)
                self.start_round(best)
                progress = True
                continue
            # R3: PROPOSE step -> cast PREVOTE (locking rules 3, 5).
            if hs.step == S_PROPOSE:
                p = hs.proposals.get(r)
                if p is not None and p.block_hash in self.validated:
                    bh = p.block_hash
                    ok = self.have_valid(bh)
                    vote, wait = NIL, False
                    if ok:
                        if p.pol_round == -1:
                            if hs.locked_round == -1 or hs.locked_hash == bh:
                                vote = bh
                        elif p.pol_round < r:
                            if (p.pol_round, bh) in hs.polkas or \
                                    self.tally(p.pol_round, PREVOTE).get(bh, 0) >= Q:
                                if hs.locked_round <= p.pol_round or hs.locked_hash == bh:
                                    vote = bh
                            else:
                                wait = True       # PoL not seen yet; timeout -> nil
                    if not wait:
                        self.cast_vote(PREVOTE, vote)
                        hs.step = S_PREVOTE
                        progress = True
                        continue
            # R4: any quorum of PREVOTEs -> start prevote timeout.
            if hs.step == S_PREVOTE and ("pvto", r) not in hs.flags:
                if len(hs.votes.get((r, PREVOTE), {})) >= Q:
                    hs.flags.add(("pvto", r))
                    self.timer(self.cp["timeout_prevote"] + r * self.cp["timeout_delta"],
                               "prevote", hs.h, r)
            # R5: quorum of PREVOTEs for a valid non-nil block -> lock + PRECOMMIT (rule 4).
            p = hs.proposals.get(r)
            if p is not None and hs.step >= S_PREVOTE and ("lock", r) not in hs.flags \
                    and self.have_valid(p.block_hash) \
                    and self.tally(r, PREVOTE).get(p.block_hash, 0) >= Q:
                hs.flags.add(("lock", r))
                hs.valid_hash, hs.valid_round = p.block_hash, r
                if hs.step == S_PREVOTE:
                    hs.locked_hash, hs.locked_round = p.block_hash, r
                    self.log("lock", r=r, block=p.block_hash)
                    self.cast_vote(PRECOMMIT, p.block_hash)
                    hs.step = S_PRECOMMIT
                progress = True
                continue
            # R6: quorum of nil PREVOTEs -> PRECOMMIT nil.
            if hs.step == S_PREVOTE and self.tally(r, PREVOTE).get(NIL, 0) >= Q:
                self.cast_vote(PRECOMMIT, NIL)
                hs.step = S_PRECOMMIT
                progress = True
                continue
            # R7: any quorum of PRECOMMITs -> start precommit timeout.
            if ("pcto", r) not in hs.flags and len(hs.votes.get((r, PRECOMMIT), {})) >= Q:
                hs.flags.add(("pcto", r))
                self.timer(self.cp["timeout_precommit"] + r * self.cp["timeout_delta"],
                           "precommit", hs.h, r)

    def finalize(self, rr, bh, cert_votes=None):
        hs = self.hs
        h = hs.h
        _, _, st = self.validated[bh]
        hd, txs = self.headers[bh], self.bodies[bh]
        self.state = st
        self.last_hash = bh
        self.ledger.append((h, bh, hd.state_hash))
        self.applied.extend(t.id() for t in txs)
        if cert_votes is not None:
            precs = cert_votes
        else:
            precs = sorted((v for v in hs.votes[(rr, PRECOMMIT)].values() if v.block_hash == bh),
                           key=lambda z: z.voter)[:self.ctx.q]
        self.commits[h] = enc(["COMMIT", h, rr, bh, [v.to_list() for v in precs], hd.to_list()])
        for k in [k for k in self.mempool if k[1] <= st.nonce(k[0])]:
            del self.mempool[k]
        self.log("finalize", r=rr, block=bh, state=hd.state_hash, ntx=len(txs),
                 dups=self.dups, stale=self.stale)
        if self.honest:
            self.ctx.auditor.record(self.id, h, bh)
            self.ctx.fin_times.append(self.net.now)
        self.height += 1
        self.hs = HState(self.height)
        self.gossip(self.commits[h], "COMMIT")
        if h >= self.ctx.cfg["target_height"]:
            self.done = True
            return
        self.broadcast_status()
        self.net.at(self.net.now + self.cp["commit_wait"], self.begin_height, self.height)
        for src, msg in self.future.pop(self.height, []):
            self.dispatch(src, msg, False)


# =============================================================== Byzantine ====
class ByzNode(Node):
    """Faulty validator. Behaviours: silent, equivocate, invalid_proposal, bad_sig, replay."""
    honest = False

    def __init__(self, idx, ctx, net, neighbors, behaviours):
        super().__init__(idx, ctx, net, neighbors)
        self.beh = set(behaviours)
        self.tick = 0

    def start(self):
        if "silent" in self.beh:
            return
        super().start()
        if "replay" in self.beh:
            self.net.at(self.net.now + 100, self.replay_tick)
        if "bad_sig" in self.beh:
            self.net.at(self.net.now + 150, self.noise_tick)

    def on_message(self, src, wire):
        if "silent" in self.beh:
            return
        super().on_message(src, wire)

    # replayed / duplicated traffic (flooding)
    def replay_tick(self):
        self.net.at(self.net.now + 100, self.replay_tick)
        self.tick += 1
        for w in self.recent[-60:]:
            for nb in self.neighbors:
                self.send(nb, w, "REPLAY")

    # forged signatures / wrong domain / impersonation
    def noise_tick(self):
        self.net.at(self.net.now + 150, self.noise_tick)
        self.tick += 1
        h = self.height
        junk = H(enc(["junk", self.id, self.tick]))
        other = (self.id + 1) % self.ctx.n
        forged = [
            self.make_vote(PREVOTE, junk, h=h, r=0, domain="HEADER"),            # wrong domain
            self.make_vote(PRECOMMIT, junk, h=h, r=0, voter=other),              # impersonation
        ]
        for v in forged:
            self.gossip(enc(v.to_list()), "VOTE")
        tx = Tx("Alice", "Alice/evil", "x%d" % self.tick, 999, b"\x00" * 64)    # bad signature
        self.gossip(enc(tx.to_list()), "TX")

    def build_block(self):
        txs, st = super().build_block()
        if "invalid_proposal" in self.beh:
            st = st.copy()
            st.kv["bogus"] = "1"          # state hash will not match execution
        return txs, st

    def propose(self):
        if "equivocate" not in self.beh:
            return super().propose()
        hs = self.hs
        r, h = hs.round, hs.h
        txsA, stA = self.build_block()
        txsB = txsA[:-1]
        if len(txsB) == len(txsA):        # nothing to drop -> use Mallory's own account
            mk = self.ctx.part_keys["Mallory"]
            tx = Tx("Mallory", "Mallory/m", "r%d" % r, self.state.nonce("Mallory") + 1, b"")
            tx.sig = mk.sign("TX", self.ctx.chain_id, tx.payload())
            txsB = [tx]
        stB = self.state.copy()
        for t in txsB:
            apply_tx(stB, t, self.ctx)
        pA = self.make_block_proposal(txsA, stA, r)
        pB = self.make_block_proposal(txsB, stB, r)
        self.register_own(pA, txsA)
        self.headers.setdefault(pB.block_hash, pB)
        self.bodies[pB.block_hash] = txsB
        self.run_validation(pB.block_hash)
        self.log("propose_equivocating", r=r, a=pA.block_hash, b=pB.block_hash)
        wA, wB = enc(pA.to_list()), enc(pB.to_list())
        self.seen.update([H(wA), H(wB)])
        for i, nb in enumerate(self.neighbors):          # split the neighbourhood
            self.send(nb, wA if i % 2 == 0 else wB, "HDR")

    def cast_vote(self, phase, bh):
        if "equivocate" not in self.beh:
            return super().cast_vote(phase, bh)
        hs = self.hs
        key = (hs.round, phase)
        if key in hs.sent:
            return
        hs.sent[key] = bh
        alt = NIL
        if bh == NIL:
            others = [x for x in sorted(self.headers) if self.headers[x].height == hs.h]
            alt = others[0] if others else H(b"alt")
        vA, vB = self.make_vote(phase, bh), self.make_vote(phase, alt)
        wA, wB = enc(vA.to_list()), enc(vB.to_list())
        self.seen.update([H(wA), H(wB)])
        self.add_vote(vA)
        self.log("equivocating_" + PHASE_NAME[phase].lower(), r=hs.round, a=bh, b=alt)
        for i, nb in enumerate(self.neighbors):
            self.send(nb, wA if i % 2 == 0 else wB, "VOTE")
