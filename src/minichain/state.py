"""Deterministic execution layer: key-value state, ownership, per-sender nonce."""
from .crypto import merkle_root, kv_leaf


class State:
    def __init__(self, kv=None):
        self.kv = dict(kv or {})

    def copy(self):
        return State(self.kv)

    def nonce(self, sender):
        return int(self.kv.get("nonce/" + sender, "0"))

    def root(self):
        """Merkle root over leaves sorted by key (canonical order)."""
        return merkle_root([kv_leaf(k, self.kv[k]) for k in sorted(self.kv)])


def check_tx(tx, ctx):
    """Stateless checks: known sender, signature in TX domain, key ownership.
    Returns a reject reason or None."""
    pk = ctx.participants.get(tx.sender)
    if pk is None:
        return "unknown_sender"
    if not ctx.verify(pk, "TX", tx.payload(), tx.sig):
        return "bad_signature"
    if not tx.key.startswith(tx.sender + "/") or len(tx.key) == len(tx.sender) + 1:
        return "not_owner"
    return None


def apply_tx(state, tx, ctx):
    """Apply to `state` in place if valid. Returns (ok, reason)."""
    r = check_tx(tx, ctx)
    if r:
        return False, r
    if tx.nonce != state.nonce(tx.sender) + 1:
        return False, "bad_nonce"
    state.kv[tx.key] = tx.value
    state.kv["nonce/" + tx.sender] = str(tx.nonce)
    return True, None
