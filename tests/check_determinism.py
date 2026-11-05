#!/usr/bin/env python3
"""Run the same scenario twice (separate processes, different PYTHONHASHSEED) and
verify byte-identical logs and identical final state hash.
usage: python3 tests/check_determinism.py [config_name]"""
import hashlib, json, os, subprocess, sys, tempfile
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def run_once(name, hashseed):
    out = tempfile.mkdtemp(prefix="det_")
    env = dict(os.environ, PYTHONHASHSEED=str(hashseed))
    cfg = os.path.join(ROOT, "config", name + ".json")
    subprocess.run([sys.executable, os.path.join(ROOT, "src", "run.py"), cfg, "--out", out],
                   env=env, stdout=subprocess.DEVNULL, check=False)
    with open(os.path.join(out, name + ".log"), "rb") as f:
        data = f.read()
    summary = json.loads(data.strip().split(b"\n")[-1])
    return data, summary["final_state_hash"]


def check(name="T8_determinism"):
    d1, s1 = run_once(name, 1)
    d2, s2 = run_once(name, 12345)
    res = {"scenario": name, "log_bytes": len(d1),
           "sha256_run1": hashlib.sha256(d1).hexdigest(), "sha256_run2": hashlib.sha256(d2).hexdigest(),
           "logs_identical": d1 == d2, "final_state_hash": s1, "state_hash_identical": s1 == s2 and s1 is not None}
    return res


if __name__ == "__main__":
    r = check(sys.argv[1] if len(sys.argv) > 1 else "T8_determinism")
    print(json.dumps(r, indent=1))
    sys.exit(0 if r["logs_identical"] and r["state_hash_identical"] else 1)
