#!/usr/bin/env python3
"""FlareCalc - verify ks continues past byte 128 (no 128-cycle).

Uses the known-plain of 52090 (mask-fixed) and the recomputed real-position
list 'pos' (global schedule, first entries = real positions of every blob).
Check:  ct[pos[j]] ^ ks_stream[pos[j]]  ==  plain[j]  ?
Variants:  cycled (pos%128), continuous per-position (low8 / hi16),
           continuous-per-real (low8 / hi16).
"""
import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from find_mask2 import unmask   # noqa: E402
from table_model import load_positions, code_from   # noqa: E402

PASSWORD = b'8675309-88224646-31428571'
A, Cadd = 1103515245, 12345


def seed_of(node_id, pwd=PASSWORD):
    lcg = 0
    for b in hashlib.md5(pwd + struct.pack('<I', node_id)).digest():
        lcg = (lcg * 31 + b) & 0xffffffff
    return lcg


def main():
    d, bufs, pos = load_positions()
    E = d['entries']
    plain = unmask(code_from(bufs, pos, 52090), [(44, 84), (129, 152)])
    ppt = pos[:len(plain)]

    ct = E[52090]
    seed = seed_of(52090)
    s = seed
    ks_low8, ks_hi16 = [], []
    for _ in range(len(ct)):
        s = (s * A + Cadd) & 0xffffffff
        ks_low8.append(s & 0xFF)
        ks_hi16.append((s >> 16) & 0xFF)

    cur = seed
    stepped = 0
    rs_low8, rs_hi16 = [], []
    for _ in range(len(plain)):
        cur = (cur * A + Cadd) & 0xffffffff
        stepped += 1
        rs_low8.append(cur & 0xFF)
        rs_hi16.append((cur >> 16) & 0xFF)

    variants = {
        'cycled low8  (old)': [ks_low8[p % 128] for p in ppt],
        'cont per-pos low8': [ks_low8[p] for p in ppt],
        'cont per-pos hi16': [ks_hi16[p] for p in ppt],
        'cont per-real low8': rs_low8,
        'cont per-real hi16': rs_hi16,
    }
    for name, stream in variants.items():
        got = bytes(c ^ k for c, k in zip([ct[p] for p in ppt], stream))
        n_bad = sum(1 for a, b in zip(got, plain) if a != b)
        print('%-20s mismatches %3d/%d' % (name, n_bad, len(plain)),
              '' if n_bad == 0 else '  first-bad@%d: got %02x want %02x'
              % (next(i for i, (a, b) in enumerate(zip(got, plain)) if a != b),
                 *next((a, b) for a, b in zip(got, plain) if a != b)))
    # detail of mismatches for cycled variant
    got = bytes(ct[p] ^ ks_low8[p % 128] for p in ppt)
    bad = [(j, ppt[j], '%02x' % got[j], '%02x' % plain[j]) for j in range(len(plain)) if got[j] != plain[j]]
    print('cycled bad positions (plain-idx, blob-pos, got, want):')
    print('  ', bad[:12], '... total', len(bad))


if __name__ == '__main__':
    main()
