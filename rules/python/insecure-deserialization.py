# Shieldgate rule test fixture -- intentionally vulnerable code, never run.
import json
import pickle
import yaml

def bad(blob, text):
    # ruleid: shieldgate.python.pickle-deserialization
    obj = pickle.loads(blob)
    # ruleid: shieldgate.python.unsafe-yaml-load
    cfg = yaml.load(text)
    # ruleid: shieldgate.python.unsafe-yaml-load
    cfg2 = yaml.load(text, Loader=yaml.Loader)
    return obj, cfg, cfg2

def good(blob, text):
    # ok: shieldgate.python.pickle-deserialization
    obj = json.loads(blob)
    # ok: shieldgate.python.unsafe-yaml-load
    cfg = yaml.safe_load(text)
    # ok: shieldgate.python.unsafe-yaml-load
    cfg2 = yaml.load(text, Loader=yaml.SafeLoader)
    return obj, cfg, cfg2
