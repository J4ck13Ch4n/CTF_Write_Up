#!/usr/bin/env python3
"""FlareCalc - FINAL table decryption (verified keystream, no masks).

    ct[p] = code_byte_or_noise[p] ^ ks[p]        (p = position in the raw ct)
    ks[p]: per-entry LCG seeded by fold(md5(pwd || u32le(id)), *31),
           advanced s = (s*1103515245 + 12345) & 0xffffffff ONCE PER ct BYTE
           (junk positions consume states too), keystream byte = s & 0xFF.
    Noise positions follow a global schedule 'pos' (gaps 2..4, identical for
    every entry because the skip LCG is seeded from the password only).
"""
import hashlib
import os
import pickle
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from table_model import load_positions   # noqa: E402

PERIOD = 128
PASSWORD = b'8675309-88224646-31428571'
A, Cadd = 1103515245, 12345


def keystream(node_id, n, pwd=PASSWORD):
    lcg = 0
    for b in hashlib.md5(pwd + struct.pack('<I', node_id)).digest():
        lcg = (lcg * 31 + b) & 0xffffffff
    out = bytearray()
    for _ in range(n):
        lcg = (lcg * A + Cadd) & 0xffffffff
        out.append(lcg & 0xFF)
    return out


def main():
    d, _bufs, pos = load_positions()
    E, ids = d['entries'], d['ids']

    code = {}
    for i in ids:
        ct = E[i]
        ks = keystream(i, len(ct))
        buf = bytes(c ^ k for c, k in zip(ct, ks))
        blob = bytes(buf[p] for p in pos if p < len(ct))
        code[i] = blob
    os.makedirs('/tmp/opencode', exist_ok=True)
    pickle.dump({'code': code, 'pos': pos}, open('/tmp/opencode/code_cont.pkl', 'wb'))

    import capstone
    MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    tot = cov = 0
    bad = []
    for i in ids:
        c = code[i]
        cv = sum(x.size for x in MD.disasm(c, 0x1000))
        tot += len(c)
        cov += cv
        if cv != len(c):
            bad.append((i, cv, len(c)))
    print('capstone coverage %d/%d (%.2f%%), incomplete: %d'
          % (cov, tot, 100.0 * cov / tot, len(bad)))
    for b in bad[:12]:
        print('   bad id %d cov %d len %d' % b)

    for eid in (52090, 54272, 44269, 4485, 9990, 3833):
        c = code[eid]
        print('\n== id %-6d %d bytes' % (eid, len(c)))
        print('   ', c[:64].hex(' '))
        for x in list(MD.disasm(c, 0x1000))[-12:] if eid in (52090, 54272, 44269) or c[:4] == b'\x0f\xaf' else []:
            off = x.address - 0x1000
            print('   %04x  %-22s %s %s' % (off, c[off:off + x.size].hex(' '),
                                            x.mnemonic, x.op_str))


if __name__ == '__main__':
    main()
