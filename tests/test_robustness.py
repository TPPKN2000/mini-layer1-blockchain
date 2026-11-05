"""Deadlock / starvation audit tests: every state in which a node waits must have an exit."""
import itertools, unittest
from common import Simulation, cfg, run_config
from minichain.encoding import enc
from minichain.crypto import H
from minichain.types import Vote, PREVOTE, PRECOMMIT, block_hash, tx_root_of
from minichain.state import apply_tx


def small_sim(n=4, **extra):
    c = {"name": "rb", "n": n, "target_height": 3, "network": {"topology": "full"},
         "workload": {"count": 0}}
    c.update(extra)
    return Simulation(c)


def vote(sim, voter, phase, bh, h, r):
    v = Vote(h, r, phase, bh, voter, b"")
    v.sig = sim.ctx.val_keys[voter].sign("VOTE", sim.ctx.chain_id, v.payload())
    return v


def connected(adj, removed):
    alive = [i for i in range(len(adj)) if i not in removed]
    seen, st = {alive[0]}, [alive[0]]
    while st:
        x = st.pop()
        for y in adj[x]:
            if y not in removed and y not in seen:
                seen.add(y); st.append(y)
    return len(seen) == len(alive)


class TestNoLostMessages(unittest.TestCase):
    def test_D1_dropped_future_message_is_not_marked_seen(self):
        """A message that could not be buffered must stay deliverable later (retransmission)."""
        sim = small_sim()
        node = sim.nodes[0]
        for r in range(1200):                         # Byzantine voter 3 floods valid future votes
            node.on_message(3, enc(vote(sim, 3, PREVOTE, H(b"x%d" % r), 2, r).to_list()))
        legit = vote(sim, 1, PREVOTE, H(b"legit"), 2, 0)
        node.on_message(1, enc(legit.to_list()))
        buffered_voters = {m[3 - 0] if False else m[5] for _, m in node.future.get(2, []) if m[0] == "VOTE"}
        self.assertIn(1, buffered_voters, "honest voter's message starved by flooder")

    def test_D1b_deferred_message_can_be_redelivered(self):
        sim = small_sim()
        node = sim.nodes[0]
        for r in range(300):                           # exceeds the 256-entry per-validator quota
            node.on_message(3, enc(vote(sim, 3, PREVOTE, H(b"y%d" % r), 1, r).to_list()))
        late = enc(vote(sim, 3, PREVOTE, H(b"late"), 1, 9999).to_list())
        node.on_message(3, late)                      # over quota -> deferred, not consumed
        self.assertNotIn(H(late), node.seen)

    def test_D4_stored_votes_per_validator_are_bounded(self):
        sim = small_sim()
        node = sim.nodes[0]
        for r in range(500):
            node.on_message(3, enc(vote(sim, 3, PREVOTE, H(b"z%d" % r), 1, r).to_list()))
        mine = sum(1 for vs in node.hs.votes.values() if 3 in vs)
        self.assertLessEqual(mine, 256)

    def test_D2_header_fetched_for_equivocated_round_is_kept(self):
        """Quorum may form on block B while we only saw A for the same round: B's header
        (returned by HDRREQ) must still be stored, else the node waits forever."""
        sim = small_sim()
        node, prop = sim.nodes[0], sim.nodes[1]       # proposer(1,0) = 1
        txB = [sim.mk_tx("Alice", "Alice/m", "v", 1)]

        def mk(txs):
            st = node.state.copy()
            for t in txs:
                apply_tx(st, t, sim.ctx)
            sh, tr = st.root(), tx_root_of(txs)
            return prop.sign_proposal(1, 0, -1, block_hash(1, node.last_hash, sh, tr),
                                      node.last_hash, sh, tr)
        A, B = mk([]), mk(txB)
        node.on_message(1, enc(A.to_list()))
        node.on_message(2, enc(B.to_list()))          # e.g. reply to our HDRREQ
        self.assertIn(B.block_hash, node.headers)


class TestTopology(unittest.TestCase):
    def test_D3_f_faulty_nodes_cannot_partition_correct_nodes(self):
        for n, deg, seeds in [(10, 5, range(1, 11)), (10, 4, range(1, 6)), (16, 5, range(1, 4))]:
            for seed in seeds:
                sim = small_sim(n, seed=seed)
                sim.cfg["network"]["topology"] = "random"
                from minichain.network import build_topology
                adj = build_topology(n, "random", deg, seed, sim.ctx.f)
                for sub in itertools.combinations(range(n), sim.ctx.f):
                    self.assertTrue(connected(adj, set(sub)), (n, deg, seed, sub))


class TestWatchdog(unittest.TestCase):
    """No scenario may sit idle (no finalization anywhere) for long once running."""
    def test_progress_watchdog(self):
        for name, bound in [("T1_normal", 3000), ("T3_bad_signature", 3000), ("T6_silent_proposer", 12000),
                            ("T7_byzantine_f", 20000)]:
            s = run_config(cfg(name))["summary"]
            self.assertTrue(s["finished"], name)
            self.assertLess(s["max_stall_ms"], bound, (name, s["max_stall_ms"]))

    def test_random_fuzz_never_stalls(self):
        import random
        rng = random.Random(2024)
        beh = [["equivocate"], ["invalid_proposal"], ["silent"], ["bad_sig"], ["replay"], ["equivocate", "invalid_proposal"]]
        for i in range(12):
            n = rng.choice([7, 10, 13]); f = (n - 1) // 3
            ids = rng.sample(range(n), rng.randint(0, f))
            c = cfg("T5_drop_delay_pre_gst")
            c.update({"name": "fuzz%d" % i, "seed": rng.randrange(1000), "n": n, "target_height": 5,
                      "byzantine": {str(k): rng.choice(beh) for k in ids}, "max_time_ms": 200000})
            c["network"].update({"gst_ms": rng.choice([0, 1500, 4000]), "pre_drop": rng.choice([0.0, 0.2, 0.4]),
                                 "log_net": False})
            s = run_config(c)["summary"]
            self.assertTrue(s["finished"], c)
            self.assertEqual(s["safety_violations"], [], c)


if __name__ == "__main__":
    unittest.main()
