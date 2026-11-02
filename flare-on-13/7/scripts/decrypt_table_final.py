#!/usr/bin/env python3
"""FlareCalc - decrypt the whole table (FINAL, verified model).

    KS(id)  = keystream of the node:
                  md5(password || u32le(id))  ->  seed = fold(digest, *31)
                  state = (state*1103515245 + 12345) & 0xffffffff
                  ks[i] = state & 0xFF
    blob[p] = code[p] ^ KS(id)[p & 127]        at the real positions
    blob[p] = C[p & 127] ^ KS(id)[p & 127]     at the padding positions

C is one global 128-byte constant: the author filled the padding with a fixed
pattern instead of zeros so that the padding does not stand out.

Because the padding is not zero, the "real" positions are found by comparing
with C, and a code byte of 0x00 is still invisible - those are repaired with a
DP that enforces gaps of 2..4 bytes.
"""
import collections
import hashlib
import os
import pickle
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ks_model import load   # noqa: E402

PERIOD = 128
PASSWORD = b'8675309-88224646-31428571'
C = bytes.fromhex(
    'ef fc 85 da 0b e8 01 a6 e7 94 3d 32 83 00 39 7e df 2c f5 8a fb 18 71 '
    '56 d7 c4 ad e2 73 30 a9 2e cf 5c 65 3a eb 48 e1 06 c7 f4 1d 92 63 60 '
    '19 de bf 8c d5 ea db 78 51 b6 b7 24 8d 42 53 90 89 8e af bc 45 9a cb '
    'a8 c1 66 a7 54 fd f2 43 c0 f9 3e 9f ec b5 4a bb d8 31 16 97 84 6d a2 '
    '33 f0 69 ee 8f 1c 25 fa ab 08 a1 c6 87 b4 dd 52 23 20 d9 9e 7f 4c 95 '
    'aa 9b 38 11 76 77 e4 4d 02 13 50 49 4e'.replace(' ', ''))


def keystream(node_id, n=PERIOD, pwd=PASSWORD):
    dg = hashlib.md5(pwd + struct.pack('<I', node_id)).digest()
    s = 0
    for b in dg:
        s = (s * 31 + b) & 0xffffffff
    out = bytearray()
    for _ in range(n):
        s = (s * 1103515245 + 12345) & 0xffffffff
        out.append(s & 0xFF)
    return bytes(out)


def raw_code(entry_id, blob):
    """blob ^ KS  -> the code at the real positions, C at the padding."""
    ks = keystream(entry_id)
    return bytes(x ^ ks[p % PERIOD] for p, x in enumerate(blob))


def true_positions(bufs, ids):
    maxlen = max(len(bufs[i]) for i in ids)
    nz = [False] * maxlen
    for i in ids:
        v = bufs[i]
        for p in range(len(v)):
            if v[p] != C[p % PERIOD]:        # != the padding pattern
                nz[p] = True
    nz = nz + [False] * 8
    nxt = [maxlen] * (maxlen + 8)
    for p in range(maxlen - 1, -1, -1):
        nxt[p] = (p + 1) if nz[p + 1] else nxt[p + 1]
    INF = float('inf')
    dp = [INF] * (maxlen + 8)
    back = [-1] * (maxlen + 8)
    dp[0] = 0
    for p in range(maxlen + 8):
        if dp[p] == INF:
            continue
        limit = nxt[p]
        for g in (2, 3, 4):
            q = p + g
            if q > limit or q >= maxlen:
                break
            cost = dp[p] + (0 if nz[q] else 1)
            if cost < dp[q]:
                dp[q] = cost
                back[q] = p
    end = -1
    for q in range(maxlen - 1, -1, -1):
        if dp[q] != INF:
            end = q
            break
    pos = []
    p = end
    while p >= 0:
        pos.append(p)
        p = back[p]
    pos.reverse()
    return pos, nz


def main():
    d = load()
    E = d['entries']
    ids = d['ids']
    bufs = {i: raw_code(i, E[i]) for i in ids}
    pos, nz = true_positions(bufs, ids)
    print('true positions: %d  gaps %s'
          % (len(pos), collections.Counter(pos[i + 1] - pos[i]
                                          for i in range(len(pos) - 1)).most_common()))
    code = {}
    for i in ids:
        v = bufs[i]
        out = bytearray()
        for p in pos:
            if p >= len(v):
                break
            out.append(0 if v[p] == C[p % PERIOD] else v[p])
        code[i] = bytes(out)
    pickle.dump({'code': code, 'pos': pos, 'C': C},
                open('/tmp/opencode/code.pkl', 'wb'))

    import capstone
    MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    MD.detail = False
    tot = cov = 0
    bad = []
    for i in ids:
        c = code[i]
        ins = list(MD.disasm(c, 0x1000))
        cv = sum(x.size for x in ins)
        tot += len(c)
        cov += cv
        if cv < len(c):
            bad.append((i, cv, len(c)))
    print('overall capstone coverage: %d / %d (%.1f%%), %d entries incomplete'
          % (cov, tot, 100.0 * cov / tot, len(bad)))
    for eid in (52090, 4485, 9990, 49, 3829, 3833):
        c = code[eid]
        ins = list(MD.disasm(c, 0x1000))
        cv = sum(x.size for x in ins)
        print('\nid %-6d code %d bytes  capstone %d/%d (%.0f%%)'
              % (eid, len(c), cv, len(c), 100.0 * cv / len(c)))
        print('  ', c[:80].hex(' '))
        for x in ins[:20]:
            print('     %04x  %s %s' % (x.address, x.mnemonic, x.op_str))


if __name__ == '__main__':
    main()
