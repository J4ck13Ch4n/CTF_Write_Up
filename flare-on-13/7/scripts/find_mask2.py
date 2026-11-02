#!/usr/bin/env python3
"""FlareCalc - recover the 0x80 mask of every node stub, then walk the DFA.

Mask
----
The author XORed two byte ranges of every stub with 0x80 so that the
tell-tale "44 24" pattern of `mov dword ptr [rsp+0x10],0` (the start of the
anti-analysis delay loop) does not show up in the ASN.1 table.

  range 1 (fixed code offsets 44..84)  -> the delay loop
  range 2 (near the end of the stub)   -> the tail that computes the next id

The only oracle that cannot lie is the program itself: a stub must return the
id of a node that exists in the table, and for a given state exactly ONE
printable character may do so (the walk has branching factor 1).  A cheap
pre-filter (the unmasked stub must decode 100% and end with `ret`) removes
almost all candidates before the emulation runs.
"""
import os
import pickle
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capstone                                   # noqa: E402
from flarecalc_table import load_entries           # noqa: E402
from node_emu import make_emulator                # noqa: E402

IDS = set(i for i, _ in load_entries())
PRINTABLE = range(0x20, 0x7f)
MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
MD.detail = False
R1 = (44, 84)
CACHE = '/tmp/opencode/masks2.pkl'


def load_code():
    p = '/tmp/opencode/code.pkl'
    if not os.path.exists(p):
        raise SystemExit('run decrypt_table_final.py first')
    return pickle.load(open(p, 'rb'))['code']


def unmask(code, regions):
    b = bytearray(code)
    for s, e in regions:
        for i in range(s, e):
            b[i] ^= 0x80
    return bytes(b)


def valid_hits(emu, code, state):
    out = []
    for ch in PRINTABLE:
        try:
            eax, st = emu.run(code, ch, state)
        except Exception:
            continue          # broken stub under a wrong masking: not a candidate
        if eax in IDS:
            out.append((chr(ch), eax, st))
    return out


def find_mask(code, emu, r1=R1, verbose=False):
    """-> (regions, hits)"""
    n = len(code)
    cands = []
    for s2 in range(r1[1] - 6, n - 3):
        # every observed stub masks through the very end of the blob, so the
        # plausible suffix end lies in the last 24 bytes
        for e2 in range(max(s2 + 1, n - 24), n + 1):
            t = unmask(code, [r1, (s2, e2)])
            ins = list(MD.disasm(t, 0x1000))
            if sum(i.size for i in ins) != n:
                continue
            mns = [i.mnemonic for i in ins]
            if 'ret' not in mns:
                continue
            cands.append((s2, e2))
    if verbose:
        print('    pre-filter left %d candidates' % len(cands))
    for s2, e2 in cands:
        t = unmask(code, [r1, (s2, e2)])
        hits = valid_hits(emu, t, b'\x00' * 32)
        if len(hits) == 1:
            return [r1, (s2, e2)], hits
    return None, []


def main():
    code = load_code()
    emu = make_emulator()
    cache = pickle.load(open(CACHE, 'rb')) if os.path.exists(CACHE) else {}
    for eid in [int(x) for x in sys.argv[1:]] or [52090]:
        if eid in cache:
            print('id %-6d cached %s' % (eid, cache[eid][0]))
            continue
        if eid not in code:
            print('id %-6d not a stub' % eid)
            continue
        regs, hits = find_mask(code[eid], emu, verbose=True)
        print('id %-6d regions=%s hits=%s' % (eid, regs, [(h[0], h[1]) for h in hits]))
        if regs:
            cache[eid] = (regs, hits)
            pickle.dump(cache, open(CACHE, 'wb'))


if __name__ == '__main__':
    main()
