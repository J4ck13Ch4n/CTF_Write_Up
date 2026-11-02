#!/usr/bin/env python3
"""Derive the crux target prime N from ext/main.wasm -- statically.

Background
----------
After the Pratt certificate passes the structural verifier, the closure that
implements check() (wasm function 3270) compares the certificate's root value A
against an embedded 256-bit prime N.  N is not stored in the clear anywhere in
the module: function 3270 rebuilds it on the stack from two 32-byte rodata
blobs plus three constant words, using a small byte-permutation loop.

The relevant code (wasm2c output of function 3270, block B454) is:

    B := mem[0x469F7 : 0x469F7+32]          ; via memory.copy dst=sP+240, src=289271
    A := mem[0x4EFA0 : 0x4EFA0+32]          ; via memory.copy dst=sP+672, src=323488

    g3 := u64[0x20ABA0]                     ; 0x3bdfe0e3eb80a09e
    g4 := u8 [0x20ABA8]                     ; 0x45
    p  := u64[0x20ABB0]                     ; 0x20A6A0
    p  := u64[p+112]                        ; 0x209B80
    g5 := u8 [p+39]                         ; 0xE3

    ; pre-adjust five bytes of B with constants derived from g3/g4/g5
    B[28] ^= 0x8a
    B[ 6] ^= g5
    B[26] -= g3 >> 56
    old7   = B[7]
    B[ 7]  = old7 + 15
    B[14] -= g4
    B[ 4] += 15
    B[ 5] ^= (g3 >> 24) & 0xff
    B[ 7]  = old7 + g4 + 15

    ; 16 pairwise exchanges, i = 0, 2, ..., 30
    for i in range(0, 32, 2):
        a0, a1 = A[i], A[i+1]
        k      = i + (a0 ^ a1)
        x      = B[a0] - k
        y      = B[a1] - k
        B[a0]  = y - 85
        B[a1]  = x - 85

The resulting 32 bytes are N in little-endian order; function 3270 converts
them to a big.Int and compares that with the certified root A.

This script parses the data section of the wasm file, maps linear addresses to
file bytes, and replays the loop.  It needs no memory dump and no Node.
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_WASM = os.path.join(HERE, '..', 'ext', 'main.wasm')

# linear addresses used by function 3270
B_ADDR = 0x469F7      # 32-byte blob, becomes N (little-endian)
A_ADDR = 0x4EFA0      # 32-byte permutation table
G3_ADDR = 0x20ABA0    # u64  = 0x3bdfe0e3eb80a09e
G4_ADDR = 0x20ABA8    # u8   = 0x45
G5_PTR_ADDR = 0x20ABB0  # u64 pointer -> +112 -> +39 -> 0xE3


def _leb(data, pos):
    value = shift = 0
    while True:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return value, pos
        shift += 7


def load_data_segments(path):
    """Return [(linear_address, file_offset, length), ...] for the wasm data section."""
    data = open(path, 'rb').read()
    pos = 8  # skip magic + version
    data_section = None
    while pos < len(data):
        section_id = data[pos]
        pos += 1
        size, pos = _leb(data, pos)
        if section_id == 11:
            data_section = (pos, pos + size)
        pos += size
    if data_section is None:
        raise ValueError('no data section in %s' % path)

    pos, end = data_section
    count, pos = _leb(data, pos)
    segments = []
    for _ in range(count):
        flags, pos = _leb(data, pos)
        if flags == 0:
            if data[pos] != 0x41:  # i32.const
                raise ValueError('bad offset expression at 0x%x' % pos)
            pos += 1
            address, pos = _leb(data, pos)
            if data[pos] != 0x0B:  # end
                raise ValueError('bad offset expression at 0x%x' % pos)
            pos += 1
            length, pos = _leb(data, pos)
            segments.append((address, pos, length))
            pos += length
        elif flags == 1:  # passive segment, no linear address
            length, pos = _leb(data, pos)
            pos += length
        elif flags == 2:  # active segment with explicit memory index
            _memory_index, pos = _leb(data, pos)
            if data[pos] != 0x41:
                raise ValueError('bad offset expression at 0x%x' % pos)
            pos += 1
            address, pos = _leb(data, pos)
            if data[pos] != 0x0B:
                raise ValueError('bad offset expression at 0x%x' % pos)
            pos += 1
            length, pos = _leb(data, pos)
            segments.append((address, pos, length))
            pos += length
        else:
            raise ValueError('unknown data segment flags %d' % flags)
    if pos != end:
        raise ValueError('data section parse mismatch: 0x%x != 0x%x' % (pos, end))
    return data, segments


class LinearMemory:
    """Read-only view of the wasm's initial linear memory built from data segments."""

    def __init__(self, wasm_path=DEFAULT_WASM):
        self.path = wasm_path
        self.file, self.segments = load_data_segments(wasm_path)

    def read(self, address, size):
        out = bytearray()
        while size:
            for seg_addr, file_off, seg_len in self.segments:
                if seg_addr <= address < seg_addr + seg_len:
                    take = min(size, seg_addr + seg_len - address)
                    start = file_off + (address - seg_addr)
                    out += self.file[start:start + take]
                    address += take
                    size -= take
                    break
            else:
                raise ValueError('address 0x%x is not backed by an active data segment' % address)
        return bytes(out)

    def u8(self, address):
        return self.read(address, 1)[0]

    def u64(self, address):
        return struct.unpack('<Q', self.read(address, 8))[0]


def derive_n(wasm_path=DEFAULT_WASM):
    """Replay function 3270's constructor; return (N, details)."""
    mem = LinearMemory(wasm_path)
    blob = bytearray(mem.read(B_ADDR, 32))
    table = mem.read(A_ADDR, 32)

    g3 = mem.u64(G3_ADDR)
    g4 = mem.u8(G4_ADDR)
    first = mem.u64(G5_PTR_ADDR)
    second = mem.u64(first + 112)
    g5 = mem.u8(second + 39)

    details = {
        'blob_initial': bytes(blob).hex(),
        'table': table.hex(),
        'g3': g3,
        'g4': g4,
        'g5': g5,
        'g3_hi': (g3 >> 56) & 0xFF,
        'g3_mid': (g3 >> 24) & 0xFF,
        'pointer_chain': (first, second),
    }

    # pre-adjust five bytes
    blob[28] ^= 0x8A
    blob[6] ^= g5
    blob[26] = (blob[26] - ((g3 >> 56) & 0xFF)) & 0xFF
    old7 = blob[7]
    blob[7] = (blob[7] + 15) & 0xFF
    blob[14] = (blob[14] - g4) & 0xFF
    blob[4] = (blob[4] + 15) & 0xFF
    blob[5] ^= (g3 >> 24) & 0xFF
    blob[7] = (old7 + g4 + 15) & 0xFF

    # 16 pairwise exchanges
    for i in range(0, 32, 2):
        a0, a1 = table[i], table[i + 1]
        k = i + (a0 ^ a1)
        x = (blob[a0] - k) & 0xFF
        y = (blob[a1] - k) & 0xFF
        blob[a0] = (y - 85) & 0xFF
        blob[a1] = (x - 85) & 0xFF

    details['n_bytes_le'] = bytes(blob).hex()
    return int.from_bytes(blob, 'little'), details


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_WASM
    n, details = derive_n(path)
    print('wasm                :', os.path.relpath(path))
    print('B blob @0x%05X     : %s' % (B_ADDR, details['blob_initial']))
    print('A table @0x%05X    : %s' % (A_ADDR, details['table']))
    print('g3=0x%016x  g4=0x%02x  g5=0x%02x' % (details['g3'], details['g4'], details['g5']))
    print('g5 pointer chain    : 0x%x -> 0x%x' % details['pointer_chain'])
    print('N bytes (LE)        :', details['n_bytes_le'])
    print('N                   :', hex(n))
    print('N (decimal)         :', n)
    print('N bit length        :', n.bit_length())


if __name__ == '__main__':
    main()
