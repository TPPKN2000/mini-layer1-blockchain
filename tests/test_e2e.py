"""End-to-end tests T1..T8 (see Lab01.pdf section 9). Each runs a full simulation."""
import json, os, unittest
from common import run, cfg, honest_nodes, events, run_config
import check_determinism


def assert_safe(tc, res):
    s = res["summary"]
    tc.assertEqual(s["safety_violations"], [], "two different blocks finalized at one height")
    tc.assertTrue(s["honest_prefix_consistent"], "honest ledgers diverge")
    tc.assertTrue(s["all_final_state_equal"])


def assert_live(tc, res):
    s = res["summary"]
    tc.assertTrue(s["finished"], "honest nodes did not reach target height")
    tc.assertTrue(all(n.done for n in honest_nodes(res)))


def all_applied(res):
    ids = []
    for n in honest_nodes(res):
        ids.extend((n.id, t) for t in n.applied)
    return ids


class E2E(unittest.TestCase):
    def test_T1_normal_run(self):
        res = run("T1_normal")
        assert_safe(self, res); assert_live(self, res)
        nodes = honest_nodes(res)
        self.assertEqual(len(nodes), 10)
        self.assertEqual(len({tuple(n.ledger) for n in nodes}), 1)         # same chain + state hashes
        self.assertEqual(len(nodes[0].ledger), cfg("T1_normal")["target_height"])
        self.assertEqual(len(events(res, "timeout")), 0)                    # no faults -> round 0 only
        st = nodes[0].state.kv                                              # workload really executed
        self.assertEqual(st["nonce/Alice"], "4")
        self.assertEqual(len(nodes[0].applied), 12)

    def test_T2_duplicate_reordered(self):
        res = run("T2_dup_reorder")
        assert_safe(self, res); assert_live(self, res)
        n = res["ctx"].n
        for nd in res["sim"].nodes:
            self.assertLessEqual(nd.max_tally, n)                          # never more than one vote/validator
        self.assertGreater(sum(nd.dups for nd in honest_nodes(res)), 100)   # duplicates really arrived & ignored
        self.assertGreater(len(events(res, "dup")), 100)
        self.assertGreater(len(events(res, "block")), 0)                    # flooding peer got blocked
        ub = len(events(res, "unblock"))                                    # run may end before last expiry
        self.assertTrue(0 < ub <= len(events(res, "block")))
        self.assertEqual(len(events(res, "SAFETY_VIOLATION")), 0)

    def test_T3_invalid_signature_wrong_domain(self):
        res = run("T3_bad_signature")
        assert_safe(self, res); assert_live(self, res)
        rej = events(res, "reject")
        reasons = {r["reason"] for r in rej}
        self.assertIn("bad_signature", reasons)
        self.assertIn("not_owner", reasons)
        self.assertTrue(any(r["type"] == "TX" and r["reason"] == "bad_signature" for r in rej))
        self.assertTrue(any(r["type"] == "VOTE" and r["reason"] == "bad_signature" for r in rej))
        for nd in honest_nodes(res):                                        # none of the forged txs executed
            for k in nd.state.kv:
                self.assertNotIn(k, ("Alice/forged", "Alice/wrongdom", "Bob/steal", "Alice/evil"))

    def test_T4_replayed_transaction_applied_once(self):
        res = run("T4_replay_tx")
        assert_safe(self, res); assert_live(self, res)
        ids = all_applied(res)
        self.assertEqual(len(ids), len(set(ids)))                           # no tx twice on any node
        for nd in honest_nodes(res):
            self.assertEqual(len(nd.applied), len(set(nd.applied)))
            self.assertEqual(len(nd.applied), 9)
        reasons = {r["reason"] for r in events(res, "reject")}
        self.assertIn("stale_nonce", reasons)                               # replay after finalisation
        self.assertTrue(events(res, "ignore", reason="duplicate_nonce"))    # replay before finalisation

    def test_T5_drop_delay_before_synchrony(self):
        res = run("T5_drop_delay_pre_gst")
        assert_safe(self, res)
        self.assertGreater(len(events(res, "drop", why="loss")), 500)
        self.assertGreater(len(events(res, "delay", why="slow_link")), 100)
        self.assertEqual(len(events(res, "SAFETY_VIOLATION")), 0)
        assert_live(self, res)                                              # liveness after GST
        self.assertGreaterEqual(res["summary"]["time_ms"], 0)

    def test_T6_silent_or_crashed_proposer(self):
        res = run("T6_silent_proposer")
        assert_safe(self, res); assert_live(self, res)
        to = events(res, "timeout", what="propose")
        self.assertGreater(len(to), 0)                                      # round timeout fired
        self.assertTrue(any(e["r"] >= 1 for e in events(res, "round")))     # moved to next proposer
        self.assertEqual(len(events(res, "crash")), 1)
        self.assertEqual(len(honest_nodes(res)[0].ledger), cfg("T6_silent_proposer")["target_height"])

    def test_T7_f_byzantine_equivocate(self):
        res = run("T7_byzantine_f")
        c = res["ctx"]
        self.assertEqual(len(res["sim"].faulty), c.f)                       # exactly f = 3 faulty
        assert_safe(self, res); assert_live(self, res)
        self.assertGreater(len(events(res, "propose_equivocating")), 0)
        self.assertGreater(len(events(res, "equivocation")), 0)             # honest nodes saw the evidence
        self.assertTrue(any(e["reason"] == "bad_state_hash" for e in events(res, "validate", ok=False)))
        # no height has two finalized hashes across honest nodes
        for h, d in c.auditor.final.items():
            self.assertEqual(len(d), 1)

    def test_T8_same_seed_rerun_identical(self):
        r = check_determinism.check("T8_determinism")
        self.assertTrue(r["logs_identical"], r)
        self.assertTrue(r["state_hash_identical"], r)
        a = run_config(cfg("T8_determinism"))            # in-process re-run as well
        b = run_config(cfg("T8_determinism"))
        self.assertEqual(a["log"].encode(), b["log"].encode())
        c = cfg("T8_determinism"); c["seed"] = 99          # sanity: a different seed changes the run
        self.assertNotEqual(run_config(c)["log"], a["log"])


if __name__ == "__main__":
    unittest.main()
