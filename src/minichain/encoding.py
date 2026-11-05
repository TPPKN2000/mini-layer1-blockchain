"""Deterministic canonical encoding (one byte string per logical value).

Grammar (all integers big-endian):
  int   -> 'I' + u64                (non-negative only)
  bytes -> 'B' + u32 len + data
  str   -> 'S' + u32 len + utf-8
  list  -> 'L' + u32 count + items
Every hash / signature in the system is computed over enc(...) output, so two
nodes always derive identical bytes from identical logical content.
"""
import struct


def enc(x):
    if isinstance(x, bool):
        raise TypeError("bool not encodable")
    if isinstance(x, int):
        if x < 0 or x >= 1 << 64:
            raise ValueError("int out of range")
        return b"I" + struct.pack(">Q", x)
    if isinstance(x, (bytes, bytearray)):
        return b"B" + struct.pack(">I", len(x)) + bytes(x)
    if isinstance(x, str):
        b = x.encode("utf-8")
        return b"S" + struct.pack(">I", len(b)) + b
    if isinstance(x, (list, tuple)):
        return b"L" + struct.pack(">I", len(x)) + b"".join(enc(i) for i in x)
    raise TypeError("cannot encode %r" % type(x))


def _dec(b, o):
    if o >= len(b):
        raise ValueError("unexpected end")
    t = b[o:o + 1]
    o += 1
    if t == b"I":
        if o + 8 > len(b):
            raise ValueError("short int")
        return struct.unpack(">Q", b[o:o + 8])[0], o + 8
    if t in (b"B", b"S"):
        if o + 4 > len(b):
            raise ValueError("short len")
        n = struct.unpack(">I", b[o:o + 4])[0]
        o += 4
        if o + n > len(b):
            raise ValueError("short data")
        data = b[o:o + n]
        return (data if t == b"B" else data.decode("utf-8")), o + n
    if t == b"L":
        if o + 4 > len(b):
            raise ValueError("short count")
        n = struct.unpack(">I", b[o:o + 4])[0]
        o += 4
        if n > len(b):
            raise ValueError("bad count")
        out = []
        for _ in range(n):
            v, o = _dec(b, o)
            out.append(v)
        return out, o
    raise ValueError("bad tag")


def dec(b):
    v, o = _dec(b, 0)
    if o != len(b):
        raise ValueError("trailing bytes")
    return v
