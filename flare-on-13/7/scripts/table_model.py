#!/usr/bin/env python3
"""FlareCalc - recompute the decrypted table and the global real-position list
from the binary alone, without any cached pickle.

The position list is the DP result from decrypt_table_final.py: the padding of
every entry is filled with one global 128-byte pattern C, so positions whose
byte differs from C are real; the DP enforces the observed gap distribution
(2..4) and repairs code bytes that are 0x00 after XOR.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ks_model import load                                  # noqa: E402
from decrypt_table_final import C, raw_code, true_positions  # noqa: E402


def load_positions():
    """-> (model dict, {id: raw cycled-keystream buffer}, pos list)."""
    d = load()
    entries, ids = d['entries'], d['ids']
    bufs = {i: raw_code(i, entries[i]) for i in ids}
    pos, _ = true_positions(bufs, ids)
    return d, bufs, pos


def code_from(bufs, pos, entry_id):
    """The entry's payload at the real positions (padding removed)."""
    v = bufs[entry_id]
    return bytes(0 if v[p] == C[p % 128] else v[p]
                 for p in pos if p < len(v))


if __name__ == '__main__':
    d, bufs, pos = load_positions()
    print('entries %d, real positions %d, gaps %s'
          % (len(d['ids']), len(pos),
             sorted({pos[i + 1] - pos[i] for i in range(len(pos) - 1)})))
    print('id 52090 code %d bytes: %s'
          % (len(code_from(bufs, pos, 52090)),
             code_from(bufs, pos, 52090)[:16].hex(' ')))
