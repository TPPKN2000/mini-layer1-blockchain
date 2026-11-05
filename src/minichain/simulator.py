"""Scenario builder / runner. A scenario is a JSON config (see config/)."""
import json
import os
from .encoding import enc
from .crypto import H
from .context import Context
from .network import Network, build_topology
from .node import Node, ByzNode
from .types import Tx


class Simulation:
    def __init__(self, cfg):
        self.ctx = Context(cfg)
        self.cfg = self.ctx.cfg
        ctx = self.ctx
        self.net = Network(ctx)
        net_cfg = self.cfg["network"]
        adj = build_topology(ctx.n, net_cfg["topology"], net_cfg["degree"], self.cfg["seed"], ctx.f)
        byz = {int(k): v for k, v in self.cfg["byzantine"].items()}
        self.crash_at = {int(k): v for k, v in self.cfg["crash"].items()}
        self.nodes = []
        for i in range(ctx.n):
            if i in byz:
                nd = ByzNode(i, ctx, self.net, adj[i], byz[i])
            else:
                nd = Node(i, ctx, self.net, adj[i])
            self.nodes.append(nd)
        self.net.nodes = self.nodes
        self.topology = adj
        self.faulty = set(byz) | set(self.crash_at)
        self.submitted = []              # (t, Tx) workload transactions
        self._schedule_workload()

    # ---------------------------------------------------------------- workload
    def mk_tx(self, name, key, value, nonce, domain="TX", corrupt=False):
        tx = Tx(name, key, value, nonce, b"")
        tx.sig = self.ctx.part_keys[name].sign(domain, self.ctx.chain_id, tx.payload())
        if corrupt:
            tx.sig = bytes([tx.sig[0] ^ 1]) + tx.sig[1:]
        return tx

    def submit(self, tx):
        wire = enc(tx.to_list())
        for nd in self.nodes:            # clients submit to every validator
            nd.on_client_tx(wire)

    def _schedule_workload(self):
        w = self.cfg["workload"]
        names = [p for p in self.cfg["participants"]]
        nonces = {nm: 0 for nm in names}
        for i in range(w["count"]):
            nm = names[i % len(names)]
            nonces[nm] += 1
            tx = self.mk_tx(nm, "%s/msg%d" % (nm, i % 3), "v%d" % i, nonces[nm])
            t = w["start_ms"] + i * w["interval_ms"]
            self.submitted.append((t, tx))
            self.net.at(t, self.submit, tx)
        for f in w["faults"]:
            t = f["t"]
            if f["type"] == "bad_sig":
                tx = self.mk_tx("Alice", "Alice/forged", "x", 1, corrupt=True)
            elif f["type"] == "wrong_domain":
                tx = self.mk_tx("Alice", "Alice/wrongdom", "x", 1, domain="VOTE")
            elif f["type"] == "not_owner":
                tx = self.mk_tx("Alice", "Bob/steal", "x", 1)
            elif f["type"] == "replay_tx":
                tx = self.submitted[f["index"]][1]
            else:
                raise ValueError(f["type"])
            self.net.at(t, self.submit, tx)

    # --------------------------------------------------------------------- run
    def run(self):
        for nd in self.nodes:
            nd.start()
        for i, t in self.crash_at.items():
            self.net.at(t, self.nodes[i].crash)
        honest = [nd for nd in self.nodes if nd.id not in self.faulty]

        def stop():
            return all(nd.done for nd in honest)
        finished = self.net.run(stop, self.cfg["max_time_ms"])
        return self.result(finished)

    def result(self, finished):
        honest = [nd for nd in self.nodes if nd.id not in self.faulty]
        per = []
        for nd in self.nodes:
            per.append({
                "node": nd.id, "honest": nd.id not in self.faulty,
                "height": len(nd.ledger),
                "head": nd.ledger[-1][1].hex()[:16] if nd.ledger else None,
                "state_hash": nd.ledger[-1][2].hex() if nd.ledger else None,
            })
        chains = [[(h, b) for h, b, _ in nd.ledger] for nd in honest]
        prefix_ok = True
        for a in chains:
            for b in chains:
                k = min(len(a), len(b))
                if a[:k] != b[:k]:
                    prefix_ok = False
        full = [nd for nd in honest if nd.done]
        final_state = full[0].ledger[-1][2].hex() if full else None
        ts = sorted(self.ctx.fin_times)
        pts = [0] + ts + ([] if finished else [self.net.now])
        max_stall = max((b - a for a, b in zip(pts, pts[1:])), default=0)
        summary = {
            "max_stall_ms": max_stall,
            "name": self.cfg["name"], "finished": finished, "time_ms": self.net.now,
            "n": self.ctx.n, "f": self.ctx.f, "quorum": self.ctx.q,
            "safety_violations": self.ctx.auditor.violations,
            "honest_prefix_consistent": prefix_ok,
            "final_state_hash": final_state,
            "all_final_state_equal": len({nd.ledger[-1][2] for nd in full}) <= 1,
            "nodes": per,
        }
        return {"summary": summary, "ctx": self.ctx, "sim": self}

    def log_text(self, summary):
        return "\n".join(self.ctx.lines) + "\n" + json.dumps(summary, sort_keys=True,
                                                            separators=(",", ":")) + "\n"


def load_config(path):
    with open(path) as f:
        return json.load(f)


def run_config(cfg, outdir=None):
    sim = Simulation(cfg)
    res = sim.run()
    text = sim.log_text(res["summary"])
    res["log"] = text
    if outdir:
        os.makedirs(outdir, exist_ok=True)
        with open(os.path.join(outdir, sim.cfg["name"] + ".log"), "w") as f:
            f.write(text)
    return res
