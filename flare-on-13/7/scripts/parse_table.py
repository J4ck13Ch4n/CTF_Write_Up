#!/usr/bin/env python3
"""FlareCalc (FLARE-On 13 / challenge 07) - step 1: carve the ASN.1 table.

The Authenticode overlay of FlareCalc.exe is a PKCS#7 SignedData that carries a
self-signed X.509 certificate.  One custom extension (OID 1.3.6.1.4.1.13839.1)
holds the real payload: a DER SEQUENCE of 1035 records, each record being
SEQUENCE { INTEGER <node id>, OCTET STRING <blob> }.

    python3 parse_table.py            # summary
    python3 parse_table.py --dump     # also write work/table.tsv
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PE = os.path.join(ROOT, 'FlareCalc.exe')
OVERLAY_OFF = 0xEEC00
FLARE_OID = bytes.fromhex('06082b060104018a3901')   # 1.3.6.1.4.1.13839.1


def read_tlv(buf, o):
    """Return (tag, length, content_start) for the TLV at buf[o:]."""
    t = buf[o]
    o += 1
    l = buf[o]
    o += 1
    if l & 0x80:
        n = l & 0x7f
        l = int.from_bytes(buf[o:o + n], 'big')
        o += n
    return t, l, o


def children(buf):
    """List of (tag, tag_offset, content_start, length) for the TLVs in buf."""
    out = []
    o = 0
    while o < len(buf):
        start = o
        t, l, cs = read_tlv(buf, o)
        if cs + l > len(buf):
            raise ValueError('DER overflow at 0x%X' % o)
        out.append((t, start, cs, l))
        o = cs + l
    return out


def content(buf, k):
    """Content of the TLV described by k = (tag, tag_off, cs, len)."""
    return buf[k[2]:k[2] + k[3]]


def find_extension_table(raw):
    """Return (file offset, payload bytes) of the custom extension's OCTET STRING."""
    blob = raw[OVERLAY_OFF + 8:]
    pos = blob.find(FLARE_OID)
    if pos < 0:
        raise SystemExit('flare OID not found in the overlay')
    t, l, cs = read_tlv(blob, pos + len(FLARE_OID))
    assert t == 0x04, 'expected OCTET STRING'
    return OVERLAY_OFF + 8 + cs, blob[cs:cs + l]


def parse_entries(table):
    """table = content of the extension OCTET STRING."""
    t, l, cs = read_tlv(table, 0)
    assert t == 0x30, 'outer element must be a SEQUENCE'
    body = table[cs:cs + l]
    entries = []
    for et, eoff, ecs, el in children(body):
        assert et == 0x30
        ent = body[ecs:ecs + el]
        sub = children(ent)
        assert len(sub) == 2 and sub[0][0] == 0x02 and sub[1][0] == 0x04
        eid = int.from_bytes(content(ent, sub[0]), 'big')
        data = content(ent, sub[1])
        entries.append((eid, data))
    return entries


def main():
    raw = open(PE, 'rb').read()
    dwlen, wrev, wtype = struct.unpack('<IHH', raw[OVERLAY_OFF:OVERLAY_OFF + 8])
    print('WIN_CERTIFICATE @0x%X  dwLength=%d  wRevision=0x%X  wCertificateType=%d (2=PKCS_SIGNED_DATA)'
          % (OVERLAY_OFF, dwlen, wrev, wtype))
    off, table = find_extension_table(raw)
    print('custom extension payload @ file 0x%X  (%d bytes)' % (off, len(table)))
    entries = parse_entries(table)
    ids = [e[0] for e in entries]
    print('records: %d   id range %d..%d   unique ids %d' %
          (len(entries), min(ids), max(ids), len(set(ids))))
    lens = sorted(len(d) for _, d in entries)
    print('blob length: min %d  max %d  median %d' % (lens[0], lens[-1], lens[len(lens) // 2]))
    top = sorted(entries, key=lambda x: -len(x[1]))[:3]
    print('largest records: %s' % ', '.join('id %d/%dB' % (i, len(b)) for i, b in top))
    for wanted in (3821, 3822, 3829, 3833, 4485, 52090, 9990):
        for eid, d in entries:
            if eid == wanted:
                print('  id %-6d blob %d bytes  head %s' % (wanted, len(d), d[:16].hex()))
    if '--dump' in sys.argv:
        out = os.path.join(ROOT, 'work')
        os.makedirs(out, exist_ok=True)
        with open(os.path.join(out, 'table.tsv'), 'w') as f:
            for eid, d in entries:
                f.write('%d\t%s\n' % (eid, d.hex()))
        print('wrote', os.path.join(out, 'table.tsv'))


if __name__ == '__main__':
    main()
