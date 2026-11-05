#!/usr/bin/env python3
"""CLI: python3 src/run.py config/T1_normal.json [--out logs] """
import argparse, os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from minichain.simulator import load_config, run_config


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("config")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs"))
    ap.add_argument("--seed", type=int, default=None)
    a = ap.parse_args()
    cfg = load_config(a.config)
    if a.seed is not None:
        cfg["seed"] = a.seed
    res = run_config(cfg, a.out)
    s = res["summary"]
    print(json.dumps({k: v for k, v in s.items() if k != "nodes"}, indent=1))
    for nd in s["nodes"]:
        print(nd)
    sys.exit(0 if s["finished"] and not s["safety_violations"] else 1)


if __name__ == "__main__":
    main()
