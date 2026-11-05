# Lab 01 – MiniChain: a minimal BFT Layer 1 on a simulated unreliable network

Blockchain course 2026 – Knowledge Engineering Dept. (HCMUS).
A deterministic discrete-event simulator of `n` validators that reach **finality** with a
Tendermint-style two-phase protocol (PREVOTE / PRECOMMIT, locking, round timeouts) over a network
that delays, reorders, duplicates and drops messages before GST.

## Requirements
* Python >= 3.9 (tested on 3.12)
* `pip install cryptography`   (only for Ed25519; everything else is the standard library)

No build step is needed.

## Layout
```
src/run.py              CLI: run one scenario and write logs/<name>.log
src/minichain/
  encoding.py           canonical byte encoding (hashes/signatures are computed over it)
  crypto.py             Ed25519 + domain separation (TX/HEADER/VOTE:chain_id), SHA-256, Merkle
  types.py              Tx, Proposal (signed header), Vote, block hash
  state.py              key-value state, ownership + nonce rules, Merkle state commitment
  network.py            event queue, delay/dup/drop, outbound throttle, inbound peer blocking, topology
  node.py               honest Node (gossip, guards, consensus, sync) + ByzNode (faulty behaviours)
  context.py            config defaults, keys, log writer, global safety auditor
  simulator.py          scenario builder, workload, result summary
config/T1..T8_*.json    one scenario per required test
tests/                  unit tests, end-to-end tests T1..T8, determinism checker, single entry point
logs/                   logs produced by the scenarios
```

## Run a scenario
```
python3 src/run.py config/T1_normal.json              # writes logs/T1_normal.log
python3 src/run.py config/T7_byzantine_f.json --seed 42
```
The last line of every log is a JSON summary (finished?, safety violations, final state hash,
per-node head). Exit code is 0 iff all correct nodes reached `target_height` with no safety violation.

## Run all tests (single entry point)
```
python3 tests/run_all.py            # unit + end-to-end (T1..T8) + robustness
python3 tests/run_all.py unit       # only unit tests
python3 tests/run_all.py e2e        # only T1..T8
python3 tests/run_all.py robust     # deadlock / starvation audit tests
```
Determinism (T8) by hand – runs the scenario twice in separate processes with different
`PYTHONHASHSEED`, then compares log bytes and final state hash:
```
python3 tests/check_determinism.py T8_determinism
```

| Test | Config | What is checked |
|------|--------|-----------------|
| T1 | T1_normal | all 10 nodes finalize the same chain and state hash, no timeouts |
| T2 | T2_dup_reorder | 30 % duplicates, wide delays, a flooding replayer: no double-counted vote, flooder is blocked |
| T3 | T3_bad_signature | corrupted signature, wrong domain, impersonated votes, non-owner key: rejected, reason logged |
| T4 | T4_replay_tx | a transaction replayed before and after finalization is applied at most once |
| T5 | T5_drop_delay_pre_gst | 35 % loss, long delays before GST: no conflicting finalization, liveness after GST |
| T6 | T6_silent_proposer | silent proposer + crashed node: timeout, next round, chain continues |
| T7 | T7_byzantine_f | f = 3 faulty (equivocating proposer/votes, invalid state hash, forged signatures) |
| T8 | T8_determinism | same seed twice: byte-identical logs, same final state hash |

## Configuration (JSON, merged over defaults in `context.py`)
`n` validators (`f=(n-1)//3`, quorum `(n+f)//2+1`, which is `2f+1` when `n=3f+1`; the default `n=10, f=3`),
`seed`, `target_height`, `network` (topology, delays, `gst_ms`, loss/dup before GST, rate limits),
`consensus` (timeouts), `workload` (transactions + injected faults), `byzantine`
(`{"3": ["equivocate","replay"]}`; behaviours: `silent`, `equivocate`, `invalid_proposal`,
`bad_sig`, `replay`) and `crash` (`{"2": 800}` = node 2 crashes at 800 ms).

## Determinism
Time is virtual (integer ms). All randomness comes from one `random.Random(seed)` consumed in a
fixed event order; keys are derived from the seed; Ed25519 signing is deterministic; no iteration
over unordered containers influences output. Re-running yields byte-identical logs.
