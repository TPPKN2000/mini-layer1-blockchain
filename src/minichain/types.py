"""Protocol objects. Every object <-> canonical list <-> wire bytes."""
from dataclasses import dataclass
from .encoding import enc
from .crypto import H, merkle_root

NIL = bytes(32)
PREVOTE, PRECOMMIT = 0, 1
PHASE_NAME = {0: "PREVOTE", 1: "PRECOMMIT"}


def _chk(l, spec):
    if not isinstance(l, list) or len(l) != len(spec):
        raise ValueError("bad shape")
    for x, c in zip(l, spec):
        ok = {"S": isinstance(x, str), "I": isinstance(x, int) and not isinstance(x, bool),
              "B": isinstance(x, bytes), "L": isinstance(x, list)}[c]
        if not ok:
            raise ValueError("bad field type")


def _h32(*xs):
    for x in xs:
        if len(x) != 32:
            raise ValueError("bad hash length")


@dataclass
class Tx:
    sender: str
    key: str
    value: str
    nonce: int
    sig: bytes

    def payload(self):
        return enc(["tx", self.sender, self.key, self.value, self.nonce])

    def to_list(self):
        return ["TX", self.sender, self.key, self.value, self.nonce, self.sig]

    @staticmethod
    def from_list(l):
        _chk(l, "SSSSIB")
        if l[0] != "TX":
            raise ValueError("not TX")
        return Tx(l[1], l[2], l[3], l[4], l[5])

    def id(self):
        return H(enc(self.to_list()))


@dataclass
class Proposal:
    """Signed header message (HEADER domain). Block identity is block_hash and
    does NOT depend on round, so the same block can be re-proposed (pol_round)."""
    height: int
    round: int
    pol_round: int      # -1 = none
    block_hash: bytes
    parent: bytes
    state_hash: bytes
    tx_root: bytes
    proposer: int
    sig: bytes

    def payload(self):
        return enc(["hdr", self.height, self.round, self.pol_round + 1, self.block_hash,
                    self.parent, self.state_hash, self.tx_root, self.proposer])

    def to_list(self):
        return ["HDR", self.height, self.round, self.pol_round + 1, self.block_hash,
                self.parent, self.state_hash, self.tx_root, self.proposer, self.sig]

    @staticmethod
    def from_list(l):
        _chk(l, "SIIIBBBBIB")
        if l[0] != "HDR":
            raise ValueError("not HDR")
        _h32(l[4], l[5], l[6], l[7])
        return Proposal(l[1], l[2], l[3] - 1, l[4], l[5], l[6], l[7], l[8], l[9])

    def computed_block_hash(self):
        return block_hash(self.height, self.parent, self.state_hash, self.tx_root)


@dataclass
class Vote:
    height: int
    round: int
    phase: int
    block_hash: bytes   # NIL for nil vote
    voter: int
    sig: bytes

    def payload(self):
        return enc(["vote", self.height, self.round, self.phase, self.block_hash])

    def to_list(self):
        return ["VOTE", self.height, self.round, self.phase, self.block_hash, self.voter, self.sig]

    @staticmethod
    def from_list(l):
        _chk(l, "SIIIBIB")
        if l[0] != "VOTE" or l[3] not in (0, 1):
            raise ValueError("bad vote")
        _h32(l[4])
        return Vote(l[1], l[2], l[3], l[4], l[5], l[6])


def block_hash(height, parent, state_hash, tx_root):
    return H(enc(["block", height, parent, state_hash, tx_root]))


def tx_root_of(txs):
    return merkle_root([t.id() for t in txs])
