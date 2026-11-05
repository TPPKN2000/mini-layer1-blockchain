import os, sys, json
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))
from minichain.simulator import Simulation, run_config, load_config   # noqa

CONFIG_DIR = os.path.join(ROOT, "config")
LOG_DIR = os.path.join(ROOT, "logs")


def cfg(name):
    return load_config(os.path.join(CONFIG_DIR, name + ".json"))


def run(name, write_logs=True):
    return run_config(cfg(name), LOG_DIR if write_logs else None)


def honest_nodes(res):
    sim = res["sim"]
    return [n for n in sim.nodes if n.id not in sim.faulty]


def events(res, ev, **match):
    out = []
    for line in res["ctx"].lines:
        d = json.loads(line)
        if d["ev"] == ev and all(d.get(k) == v for k, v in match.items()):
            out.append(d)
    return out
