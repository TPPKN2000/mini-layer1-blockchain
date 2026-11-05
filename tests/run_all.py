#!/usr/bin/env python3
"""Single entry point: unit tests + end-to-end tests T1..T8.
usage: python3 tests/run_all.py          (everything)
       python3 tests/run_all.py unit|e2e"""
import os, sys, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    pats = {"unit": ["test_unit.py"], "e2e": ["test_e2e.py"], "robust": ["test_robustness.py"], "all": ["test_unit.py", "test_e2e.py", "test_robustness.py"]}[which]
    suite = unittest.TestSuite()
    for p in pats:
        suite.addTests(unittest.defaultTestLoader.discover(HERE, pattern=p))
    r = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if r.wasSuccessful() else 1)
