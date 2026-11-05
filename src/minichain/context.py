"""Shared run context: configuration, key material, deterministic log, safety auditor."""
import json
import copy
from .encoding import enc
from .crypto import H, KeyPair, verify

DEFAULTS = {
    "name": "run", "seed": 1, "chain_id": "minichain-1", "n": 10,
    "participants": ["Alice", "Bob", "Carol"],
    "target_height": 8, "max_time_ms": 120000,
    "network": {
        "topology": "random", "degree": 5,
        "delay_min": 10, "delay_max": 100,           # post-GST bound (Delta = delay_max)
        "gst_ms": 0, "pre_delay_max": 600, "pre_drop": 0.25, "pre_dup": 0.10,
        "dup": 0.02,
        "out_rate": 1000,                            # max outbound msgs/s per node
        "in_limit": 400, "in_window_ms": 1000, "block_ms": 2000,
        "log_net": True,
    },
    "consensus": {
        "timeout_propose": 1000, "timeout_prevote": 500, "timeout_precommit": 500,
        "timeout_delta": 500, "commit_wait": 50, "resend_ms": 500,
        "req_retry_ms": 400, "max_txs": 50,
    },
    "workload": {"count": 12, "start_ms": 0, "interval_ms": 150, "faults": []},
    "byzantine": {},   # {"3": ["equivocate", "replay"]}
    "crash": {},       # {"2": 500}  node -> crash time (ms)
}


def merge(base, over):
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict) and k not in ("byzantine", "crash"):
            out[k] = merge(out[k], v)
        else:
            out[k] = v
    return out


class Auditor:
    """Global (omniscient) safety monitor, never visible to nodes."""
    def __init__(self, ctx):
        self.ctx = ctx
        self.final = {}          # height -> {block_hash: [nodes]}
        self.violations = []

    def record(self, node, h, bh):
        d = self.final.setdefault(h, {})
        d.setdefault(bh, []).append(node)
        if len(d) > 1:
            self.violations.append((h, sorted(x.hex()[:8] for x in d)))
            self.ctx.log(0, node, "SAFETY_VIOLATION", h, blocks=sorted(x.hex()[:8] for x in d))


class Context:
    def __init__(self, cfg):
        self.cfg = cfg = merge(DEFAULTS, cfg)
        self.chain_id = cfg["chain_id"]
        self.n = cfg["n"]
        self.f = (self.n - 1) // 3
        self.q = (self.n + self.f) // 2 + 1       # = 2f+1 when n = 3f+1
        seed = cfg["seed"]
        self.val_keys = [KeyPair.derive(seed, "validator/%d" % i) for i in range(self.n)]
        self.val_pks = [k.pk for k in self.val_keys]
        names = list(cfg["participants"])
        if "Mallory" not in names:
            names.append("Mallory")       # account controlled by Byzantine validators
        self.part_keys = {nm: KeyPair.derive(seed, "participant/" + nm) for nm in names}
        self.participants = {nm: k.pk for nm, k in self.part_keys.items()}
        self.genesis_hash = H(enc(["genesis", self.chain_id]))
        self.net = None                   # set by simulator
        self.lines = []
        self.auditor = Auditor(self)
        self.fin_times = []              # time of every honest finalization (stall watchdog)
        self._vcache = {}

    # signature verification is a pure function -> safe to memoise across nodes
    def verify(self, pk, domain, payload, sig):
        k = (pk, domain, payload, sig)
        r = self._vcache.get(k)
        if r is None:
            r = verify(pk, domain, self.chain_id, payload, sig)
            self._vcache[k] = r
        return r

    def proposer(self, h, r):
        return (h + r) % self.n

    def log(self, t, node, ev, h=None, **kw):
        d = {"t": t, "n": node, "ev": ev}
        if h is not None:
            d["h"] = h
        for k, v in kw.items():
            d[k] = v.hex()[:8] if isinstance(v, (bytes, bytearray)) else v
        self.lines.append(json.dumps(d, sort_keys=True, separators=(",", ":")))
