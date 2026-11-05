"""Unit tests: crypto/context checks, state rules, vote counting, block validation."""
import unittest
from common import Simulation
from minichain.encoding import enc, dec
from minichain.crypto import KeyPair, verify, merkle_root, H
from minichain.state import State, apply_tx
from minichain.types import Tx, Vote, Proposal, NIL, PREVOTE, PRECOMMIT
import json


def small_sim(n=4):
    return Simulation({"name": "unit", "n": n, "target_height": 1,
                       "network": {"topology": "full"}, "workload": {"count": 0}})


def signed_vote(sim, voter, phase, bh, h=1, r=0, domain="VOTE"):
    v = Vote(h, r, phase, bh, voter, b"")
    v.sig = sim.ctx.val_keys[voter].sign(domain, sim.ctx.chain_id, v.payload())
    return v


def feed(node, v):
    node.on_message(99 if False else 1, enc(v.to_list()))


def reasons(sim):
    return [json.loads(l).get("reason") for l in sim.ctx.lines if '"ev":"reject"' in l]


class TestEncodingCrypto(unittest.TestCase):
    def test_encoding_roundtrip_and_determinism(self):
        x = ["a", 7, b"\x00\x01", ["z", 0]]
        self.assertEqual(dec(enc(x)), x)
        self.assertEqual(enc(x), enc(list(x)))
        with self.assertRaises(ValueError):
            dec(enc(x) + b"\x00")                 # trailing bytes rejected

    def test_encoding_unambiguous(self):
        self.assertNotEqual(enc(["ab", "c"]), enc(["a", "bc"]))
        self.assertNotEqual(enc(["1"]), enc([1]))

    def test_signature_context_checks(self):
        k = KeyPair.derive(1, "x")
        p = enc(["m"])
        s = k.sign("TX", "chainA", p)
        self.assertTrue(verify(k.pk, "TX", "chainA", p, s))
        self.assertFalse(verify(k.pk, "VOTE", "chainA", p, s))     # wrong domain
        self.assertFalse(verify(k.pk, "TX", "chainB", p, s))       # wrong chain
        self.assertFalse(verify(k.pk, "TX", "chainA", enc(["n"]), s))  # tampered payload
        self.assertFalse(verify(KeyPair.derive(1, "y").pk, "TX", "chainA", p, s))  # wrong key
        self.assertFalse(verify(k.pk, "TX", "chainA", p, s[:-1] + bytes([s[-1] ^ 1])))

    def test_vote_signature_binds_height_and_phase(self):
        sim = small_sim()
        v = signed_vote(sim, 1, PREVOTE, H(b"b"))
        pk = sim.ctx.val_pks[1]
        self.assertTrue(sim.ctx.verify(pk, "VOTE", v.payload(), v.sig))
        v2 = Vote(2, v.round, v.phase, v.block_hash, 1, v.sig)      # replay at another height
        self.assertFalse(sim.ctx.verify(pk, "VOTE", v2.payload(), v2.sig))
        v3 = Vote(v.height, v.round, PRECOMMIT, v.block_hash, 1, v.sig)   # other phase
        self.assertFalse(sim.ctx.verify(pk, "VOTE", v3.payload(), v3.sig))

    def test_merkle_canonical(self):
        a, b = State({"x": "1", "y": "2"}), State({"y": "2", "x": "1"})
        self.assertEqual(a.root(), b.root())
        self.assertNotEqual(a.root(), State({"x": "1", "y": "3"}).root())
        self.assertEqual(merkle_root([]), H(b"EMPTY"))


class TestState(unittest.TestCase):
    def setUp(self):
        self.sim = small_sim()
        self.ctx = self.sim.ctx

    def test_apply_and_ownership(self):
        st = State()
        ok, _ = apply_tx(st, self.sim.mk_tx("Alice", "Alice/message", "hello", 1), self.ctx)
        self.assertTrue(ok)
        self.assertEqual(st.kv["Alice/message"], "hello")
        ok, why = apply_tx(st, self.sim.mk_tx("Alice", "Bob/message", "x", 2), self.ctx)
        self.assertEqual((ok, why), (False, "not_owner"))
        self.assertNotIn("Bob/message", st.kv)

    def test_nonce_replay_rejected(self):
        st = State()
        tx = self.sim.mk_tx("Alice", "Alice/a", "1", 1)
        self.assertTrue(apply_tx(st, tx, self.ctx)[0])
        self.assertEqual(apply_tx(st, tx, self.ctx), (False, "bad_nonce"))      # replay
        self.assertEqual(apply_tx(st, self.sim.mk_tx("Alice", "Alice/a", "1", 3), self.ctx),
                         (False, "bad_nonce"))                                  # gap

    def test_bad_signature_and_domain(self):
        st = State()
        self.assertEqual(apply_tx(st, self.sim.mk_tx("Alice", "Alice/a", "1", 1, corrupt=True),
                                  self.ctx), (False, "bad_signature"))
        self.assertEqual(apply_tx(st, self.sim.mk_tx("Alice", "Alice/a", "1", 1, domain="VOTE"),
                                  self.ctx), (False, "bad_signature"))
        self.assertEqual(apply_tx(st, Tx("Eve", "Eve/a", "1", 1, b"\0" * 64), self.ctx),
                         (False, "unknown_sender"))

    def test_same_ordered_txs_same_root(self):
        txs = [self.sim.mk_tx("Alice", "Alice/message", "hello", 1),
               self.sim.mk_tx("Bob", "Bob/message", "hi", 1)]
        roots = []
        for _ in range(2):
            st = State()
            for t in txs:
                apply_tx(st, t, self.ctx)
            roots.append(st.root())
        self.assertEqual(roots[0], roots[1])
        self.assertEqual(len(State({k: v for k, v in st.kv.items() if "/message" in k}).kv), 2)


class TestVoteCounting(unittest.TestCase):
    def setUp(self):
        self.sim = small_sim(4)           # n=4, f=1, quorum=3
        self.node = self.sim.nodes[0]
        self.bh = H(b"block")

    def tally(self, phase=PREVOTE):
        return self.node.tally(0, phase)

    def test_quorum_size(self):
        self.assertEqual((self.sim.ctx.f, self.sim.ctx.q), (1, 3))

    def test_duplicate_vote_counted_once(self):
        v = signed_vote(self.sim, 1, PREVOTE, self.bh)
        feed(self.node, v)
        feed(self.node, v)                                   # byte-identical duplicate
        self.assertEqual(self.tally()[self.bh], 1)
        self.assertEqual(self.node.dups, 1)

    def test_conflicting_vote_not_double_counted(self):
        feed(self.node, signed_vote(self.sim, 1, PREVOTE, self.bh))
        feed(self.node, signed_vote(self.sim, 1, PREVOTE, NIL))   # equivocation
        t = self.tally()
        self.assertEqual(t[self.bh], 1)
        self.assertEqual(t.get(NIL, 0), 0)
        self.assertEqual(sum(t.values()), 1)
        self.assertTrue(any('"ev":"equivocation"' in l for l in self.sim.ctx.lines))

    def test_invalid_votes_rejected(self):
        feed(self.node, signed_vote(self.sim, 1, PREVOTE, self.bh, domain="HEADER"))
        bad = signed_vote(self.sim, 1, PREVOTE, H(b"o"))
        bad.voter = 2                                         # impersonation
        feed(self.node, bad)
        self.assertEqual(sum(self.tally().values()), 0)
        self.assertEqual(reasons(self.sim).count("bad_signature"), 2)

    def test_phases_and_rounds_are_separate(self):
        feed(self.node, signed_vote(self.sim, 1, PREVOTE, self.bh))
        feed(self.node, signed_vote(self.sim, 1, PRECOMMIT, self.bh))
        feed(self.node, signed_vote(self.sim, 1, PREVOTE, self.bh, r=1))
        self.assertEqual(self.tally(PREVOTE)[self.bh], 1)
        self.assertEqual(self.tally(PRECOMMIT)[self.bh], 1)
        self.assertEqual(self.node.tally(1, PREVOTE)[self.bh], 1)

    def test_quorum_reached_with_distinct_voters(self):
        for i in (1, 2, 3):
            feed(self.node, signed_vote(self.sim, i, PREVOTE, self.bh))
        self.assertGreaterEqual(self.tally()[self.bh], self.sim.ctx.q)

    def test_own_double_vote_guard(self):
        n = self.node
        n.hs.started = True
        n.cast_vote(PREVOTE, self.bh)
        n.cast_vote(PREVOTE, NIL)                              # must be blocked
        self.assertEqual(n.hs.sent[(0, PREVOTE)], self.bh)
        self.assertEqual(sum(n.tally(0, PREVOTE).values()), 1)


class TestBlockValidation(unittest.TestCase):
    def setUp(self):
        self.sim = small_sim(4)
        self.node = self.sim.nodes[0]
        self.txs = [self.sim.mk_tx("Alice", "Alice/message", "hello", 1),
                    self.sim.mk_tx("Bob", "Bob/message", "hi", 1)]

    def proposal(self, txs, st_mut=None, parent=None, txr=None):
        n = self.node
        st = n.state.copy()
        for t in txs:
            apply_tx(st, t, self.sim.ctx)
        if st_mut:
            st.kv.update(st_mut)
        from minichain.types import block_hash, tx_root_of
        sh = st.root()
        tr = txr or tx_root_of(txs)
        par = parent or n.last_hash
        bh = block_hash(1, par, sh, tr)
        return self.sim.nodes[1].sign_proposal(1, 0, -1, bh, par, sh, tr)   # proposer(1,0) = 1

    def verdict(self, p, txs):
        n = self.node
        n.headers[p.block_hash] = p
        n.bodies[p.block_hash] = txs
        n.run_validation(p.block_hash)
        return n.validated[p.block_hash][:2]

    def test_valid_block(self):
        self.assertEqual(self.verdict(self.proposal(self.txs), self.txs), (True, None))

    def test_wrong_parent(self):
        p = self.proposal(self.txs, parent=H(b"other"))
        self.assertEqual(self.verdict(p, self.txs), (False, "bad_parent"))

    def test_wrong_state_hash(self):
        p = self.proposal(self.txs, st_mut={"evil": "1"})
        self.assertEqual(self.verdict(p, self.txs), (False, "bad_state_hash"))

    def test_tx_root_mismatch(self):
        p = self.proposal(self.txs)
        self.assertEqual(self.verdict(p, self.txs[:1]), (False, "bad_tx_root"))

    def test_invalid_tx_inside_block(self):
        bad = self.sim.mk_tx("Alice", "Alice/x", "1", 1, corrupt=True)
        from minichain.types import block_hash, tx_root_of
        tr, sh = tx_root_of([bad]), State().root()
        p = self.node.sign_proposal(1, 0, -1, block_hash(1, self.node.last_hash, sh, tr),
                                    self.node.last_hash, sh, tr)
        self.assertEqual(self.verdict(p, [bad]), (False, "tx_bad_signature"))

    def test_replayed_tx_inside_block(self):
        dup = [self.txs[0], self.txs[0]]
        p = self.proposal(self.txs[:1])
        from minichain.types import block_hash, tx_root_of
        tr = tx_root_of(dup)
        p = self.node.sign_proposal(1, 0, -1, block_hash(1, self.node.last_hash, p.state_hash, tr),
                                    self.node.last_hash, p.state_hash, tr)
        self.assertEqual(self.verdict(p, dup), (False, "tx_bad_nonce"))

    def test_header_checks(self):
        n = self.node
        good = self.proposal(self.txs)
        self.assertIsNone(n.header_static_check(good))
        wrong = n.sign_proposal(1, 0, -1, good.block_hash, good.parent, good.state_hash,
                                good.tx_root)                       # signed by node 0, not proposer 1
        self.assertEqual(n.header_static_check(wrong), "wrong_proposer")
        forged = Proposal(good.height, good.round, good.pol_round, good.block_hash, good.parent,
                          good.state_hash, good.tx_root, good.proposer, b"\0" * 64)
        self.assertEqual(n.header_static_check(forged), "bad_signature")


if __name__ == "__main__":
    unittest.main()
