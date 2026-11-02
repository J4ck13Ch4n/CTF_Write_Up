#!/usr/bin/env python3
"""Minimal WASM section parser for main.wasm (Flare-On 13 - crux).

Provides:
  * parse sections
  * list data segments (file offset -> memory offset)
  * locate the Go pclntab inside the data section
"""
import struct, sys, os

WASM = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ext', 'main.wasm')

SECTION_NAMES = {
    0: 'custom', 1: 'type', 2: 'import', 3: 'function', 4: 'table', 5: 'memory',
    6: 'global', 7: 'export', 8: 'start', 9: 'elem', 10: 'code', 11: 'data',
    12: 'datacount',
}


class Wasm:
    def __init__(self, path):
        self.data = open(path, 'rb').read()
        self.sections = []
        self.parse()

    def u32(self, off):
        r = 0; s = 0
        while True:
            b = self.data[off]; off += 1
            r |= (b & 0x7f) << s
            if not (b & 0x80): break
            s += 7
        return r, off

    def parse(self):
        assert self.data[:4] == b'\x00asm'
        off = 8
        while off < len(self.data):
            sid = self.data[off]; off += 1
            size, off = self.u32(off)
            body = off
            name = SECTION_NAMES.get(sid, 'id%d' % sid)
            extra = ''
            if sid == 0:
                nlen, o2 = self.u32(body)
                extra = self.data[o2:o2 + nlen].decode('utf8', 'replace')
            self.sections.append(dict(id=sid, name=name, start=body, end=body + size,
                                      size=size, extra=extra))
            off = body + size

    def section(self, sid):
        for s in self.sections:
            if s['id'] == sid:
                return s
        return None


def parse_data_segments(w):
    """Return list of dicts: mem_off, size, file_off."""
    sec = w.section(11)
    assert sec, 'no data section'
    off = sec['start']
    count, off = w.u32(off)
    segs = []
    for _ in range(count):
        flags, off = w.u32(off)
        assert flags == 0, 'unexpected data segment flags %d' % flags
        # i32.const offset expr, then end
        assert w.data[off] == 0x41, hex(w.data[off])
        # read sleb
        o = off + 1
        r = 0; s = 0
        while True:
            b = w.data[o]; o += 1
            r |= (b & 0x7f) << s
            s += 7
            if not (b & 0x80):
                if b & 0x40: r -= (1 << s)
                break
        mem_off = r
        assert w.data[o] == 0x0b, 'expected end of expr'
        o += 1
        size, o = w.u32(o)
        segs.append(dict(mem_off=mem_off, size=size, file_off=o))
        off = o + size
    return segs


def code_section_body(w):
    sec = w.section(10)
    off = sec['start']
    count, off = w.u32(off)
    bodies = []
    for i in range(count):
        sz, off = w.u32(off)
        bodies.append((off, off + sz))
        off += sz
    return bodies


if __name__ == '__main__':
    w = Wasm(WASM)
    for s in w.sections:
        print('section %-10s id=%-3d start=0x%08x end=0x%08x size=%d %s' %
              (s['name'], s['id'], s['start'], s['end'], s['size'], s['extra']))
    segs = parse_data_segments(w)
    print('\ndata segments: %d' % len(segs))
    # merge/print a summary of ranges
    segs_sorted = sorted(segs, key=lambda d: d['mem_off'])
    print('first 5:', [(hex(s['mem_off']), s['size'], hex(s['file_off'])) for s in segs_sorted[:5]])
    print('last 5:', [(hex(s['mem_off']), s['size'], hex(s['file_off'])) for s in segs_sorted[-5:]])
    # locate pclntab magic
    magic = b'\xf0\xff\xff\xff'
    for m in [i for i in range(len(w.data)) if w.data[i:i + 4] == magic]:
        # find enclosing segment
        for s in segs:
            if s['file_off'] <= m < s['file_off'] + s['size']:
                mem = s['mem_off'] + (m - s['file_off'])
                print('pclntab magic at file 0x%x -> mem 0x%x (seg mem 0x%x size %d)' %
                      (m, mem, s['mem_off'], s['size']))
                break
