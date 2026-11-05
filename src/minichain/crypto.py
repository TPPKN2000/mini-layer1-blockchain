"""Cryptography layer: Ed25519 signatures with domain separation, SHA-256, Merkle."""
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from .encoding import enc

DOMAINS = ("TX", "HEADER", "VOTE")


def H(b):
    return hashlib.sha256(b).digest()


def sig_message(domain, chain_id, payload):
    """Bytes that are actually signed: enc(["<DOMAIN>:<chain_id>", payload])."""
    return enc([domain + ":" + chain_id, payload])


class KeyPair:
    def __init__(self, seed32):
        self.sk = ed25519.Ed25519PrivateKey.from_private_bytes(seed32)
        self.pk = self.sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    @staticmethod
    def derive(master_seed, label):
        # Simulator-only deterministic key derivation (reproducible runs).
        return KeyPair(H(enc(["key", master_seed, label])))

    def sign(self, domain, chain_id, payload):
        return self.sk.sign(sig_message(domain, chain_id, payload))


_pk_cache = {}


def verify(pk, domain, chain_id, payload, sig):
    try:
        k = _pk_cache.get(pk)
        if k is None:
            k = ed25519.Ed25519PublicKey.from_public_bytes(pk)
            _pk_cache[pk] = k
        k.verify(sig, sig_message(domain, chain_id, payload))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def merkle_root(leaves):
    """Leaves are 32-byte hashes in canonical order. Odd node is promoted as-is."""
    if not leaves:
        return H(b"EMPTY")
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(H(b"\x01" + level[i] + level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
    return level[0]


def kv_leaf(k, v):
    return H(b"\x00" + enc([k, v]))
