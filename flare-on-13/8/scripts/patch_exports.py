#!/usr/bin/env python3
"""Create a patched copy of main.wasm that exports additional internal
functions, so they can be called directly from JS.

Usage: python3 scripts/patch_exports.py <funcidx> [<funcidx> ...]
Output: work/main_patched.wasm
"""
import struct, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from wasm_parse import Wasm, WASM

OUT = os.path.join(HERE, '..', 'work', 'main_patched.wasm')


def uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def read_uleb(data, p):
    r = 0
    s = 0
    while True:
        b = data[p]; p += 1
        r |= (b & 0x7f) << s
        if not (b & 0x80):
            return r, p
        s += 7


def sleb(n):
    out = bytearray()
    more = True
    while more:
        b = n & 0x7f
        n >>= 7
        if (n == 0 and not (b & 0x40)) or (n == -1 and (b & 0x40)):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)


def build(extra_funcs, out_path=OUT, export_globals=((0, 'g0'), (2, 'g2'))):
    w = Wasm(WASM)
    data = w.data
    secs = w.sections
    # export section
    exp = [s for s in secs if s['id'] == 7][0]
    body = data[exp['start']:exp['end']]
    n, p = 0, 0

    def rd():
        nonlocal p
        r = 0
        s = 0
        while True:
            b = body[p]
            p += 1
            r |= (b & 0x7f) << s
            if not (b & 0x80):
                return r
            s += 7

    n = rd()
    entries = []
    for _ in range(n):
        ln = rd()
        nm = body[p:p + ln].decode()
        p += ln
        kind = body[p]; p += 1
        idx = rd()
        entries.append((nm, kind, idx))
    print('# existing exports:', entries)

    for f in extra_funcs:
        entries.append(('f%d' % f, 0, f))
    for gi, nm in export_globals:
        entries.append((nm, 3, gi))

    newbody = bytearray(uleb(len(entries)))
    for nm, kind, idx in entries:
        b = nm.encode()
        newbody += uleb(len(b)) + b + bytes([kind]) + uleb(idx)
    newsec = bytes([7]) + uleb(len(newbody)) + bytes(newbody)

    # reassemble the file
    out = bytearray(b'\x00asm\x01\x00\x00\x00')
    for s in secs:
        if s['id'] == 7:
            out += newsec
        else:
            # section header: id byte + size uleb + payload
            payload = data[s['start']:s['end']]
            if s['id'] == 0:
                # custom section: payload starts with the name
                out += bytes([0]) + uleb(len(payload)) + payload
            else:
                out += bytes([s['id']]) + uleb(len(payload)) + payload
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    open(out_path, 'wb').write(bytes(out))
    print('# wrote', os.path.normpath(out_path), len(out), 'bytes; exports:', [e[0] for e in entries])


if __name__ == '__main__':
    args = [int(a) for a in sys.argv[1:]]
    build(args)
