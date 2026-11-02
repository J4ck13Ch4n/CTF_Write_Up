#!/usr/bin/env python3
"""
FLARE-On 13 / challenge 9 - "NeonOutRun"
Step A (static): unpack the 4 layers that hide `backend.js` inside the ELF.

  layer 1  XOR with the 2 byte key  d3 5a
  layer 2  custom LZSS (4096 byte window, 12 bit offset, 4 bit length)
  layer 3  Zstandard frame  (magic 28 b5 2f fd)
  layer 4  raw DEFLATE (RFC1951, no zlib header / no adler32)

The packed blob lives in .rodata right behind the V8 snapshot string
"FromUtf8Errorbyteserrorcapacity overflow," at file offset 0x21db73.

usage:  python3 scripts/unpack_backend.py [elf] [out.js]
"""
import os
import re
import shutil
import struct
import subprocess
import sys
import zlib

try:
    import pyzstd
except ImportError:
    pyzstd = None

try:                              # Python 3.14+ ships zstd in the stdlib
    from compression import zstd as stdlib_zstd
except ImportError:
    stdlib_zstd = None


def zstd_decompress(data):
    if pyzstd is not None:
        return pyzstd.decompress(data)
    if stdlib_zstd is not None:
        return stdlib_zstd.decompress(data)
    raise RuntimeError("no zstd backend: install pyzstd or use Python 3.14+")

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ELF = os.path.join(os.path.dirname(HERE), "neon_outrun")
DEFAULT_OUT = os.path.join(os.path.dirname(HERE), "work", "backend.js")

XOR_KEY = (0xD3, 0x5A)
ZSTD_MAGIC = bytes.fromhex("28b52ffd")


# --------------------------------------------------------------------- layer 1
def xor_layer(data: bytes, key=(0xD3, 0x5A)) -> bytes:
    """blob[i] ^= key[i % 2]"""
    k = bytes(key)
    return bytes(b ^ k[i & 1] for i, b in enumerate(data))


# --------------------------------------------------------------------- layer 2
def lzss_decode(data: bytes, length_base: int = 3, literal_bit: int = 1) -> bytes:
    """Custom LZSS used by the challenge.

    * a control byte holds 8 flags, LSB first
    * flag == literal_bit (1) -> one literal byte follows
    * flag != literal_bit (0) -> a 2 byte match token follows:
          offset = ((tok[1] & 0xF0) << 4) | tok[0]     (12 bit)
          length = (tok[1] & 0x0F) + length_base
    """
    out = bytearray()
    pos = 0
    flags = 0
    nbits = 0
    n = len(data)
    while pos < n:
        if nbits == 0:
            flags = data[pos]
            pos += 1
            nbits = 8
        bit = flags & 1
        flags >>= 1
        nbits -= 1
        if bit == literal_bit:
            out.append(data[pos])
            pos += 1
        else:
            if pos + 1 >= n:
                break
            a, b = data[pos], data[pos + 1]
            pos += 2
            offset = ((b & 0xF0) << 4) | a
            length = (b & 0x0F) + length_base
            if offset == 0 or offset > len(out):
                break                      # end of the useful stream
            for _ in range(length):
                out.append(out[len(out) - offset])
    return bytes(out)


# --------------------------------------------------------------------- layer 4
def raw_inflate(data: bytes) -> bytes:
    """RFC 1951 raw deflate (no zlib header, no adler32)."""
    d = zlib.decompressobj(-15)
    return d.decompress(data) + d.flush()


# ------------------------------------------------------------------------ main
def find_blob(data: bytes):
    """Locate the packed blob.

    The blob is XORed with the 2 byte key d3/5a, therefore the zstd frame
    magic 28 b5 2f fd can only be found XORed as well.  There is exactly one
    such place in the whole 21 MB file.
    """
    pat_even = bytes(ZSTD_MAGIC[i] ^ XOR_KEY[i & 1] for i in range(4))
    pat_odd = bytes(ZSTD_MAGIC[i] ^ XOR_KEY[(i + 1) & 1] for i in range(4))
    hits = []
    for pat, phase in ((pat_even, 0), (pat_odd, 1)):
        for m in re.finditer(re.escape(pat), data):
            hits.append((m.start(), phase))
    if len(hits) != 1:
        raise SystemExit("expected exactly one XORed zstd magic, got %r" % hits)
    off, phase = hits[0]

    # The LZSS stream starts a few bytes before the magic (the first token is
    # a control byte, the magic itself is stored as a literal), so try every
    # plausible start and keep the one whose LZSS decode starts with the magic.
    for start in range(off, max(0, off - 64) - 1, -1):
        blob = xor_layer(data[start:start + 0x4000])
        if lzss_decode(blob)[:4] == ZSTD_MAGIC:
            return start, phase
    raise SystemExit("could not locate the start of the packed blob")


def unpack(elf_path=DEFAULT_ELF, verbose=True):
    data = open(elf_path, "rb").read()
    start, phase = find_blob(data)
    if verbose:
        print("[*] ELF            : %s (%d bytes)" % (elf_path, len(data)))
        print("[*] packed blob    : file offset 0x%x (xor phase %d)" % (start, phase))
        print("[*]   raw first 16 : %s" % data[start:start + 16].hex())

    # ---- layer 1 : XOR -----------------------------------------------------
    blob = xor_layer(data[start:start + 0x4000])
    if verbose:
        print("[L1] XOR d3/5a      : %s ..." % blob[:16].hex())

    # ---- layer 2 : custom LZSS --------------------------------------------
    lz = lzss_decode(blob)
    if verbose:
        print("[L2] LZSS           : %d bytes, starts with %s" % (len(lz), lz[:8].hex()))
    if lz[:4] != ZSTD_MAGIC:
        raise SystemExit("LZSS output does not start with the zstd magic")

    # ---- layer 3 : zstd ----------------------------------------------------
    frame = lz
    raw = None
    for length in range(len(lz), max(0, len(lz) - 4096), -1):
        try:
            raw = zstd_decompress(lz[:length])
        except Exception:
            continue
        frame = lz[:length]
        break
    if raw is None:
        raise SystemExit("zstd decompression failed (no valid frame prefix)")
    if verbose:
        print("[L3] zstd           : frame %d bytes -> %d bytes of raw deflate"
              % (len(frame), len(raw)))
        print("     zstd frame hdr : %s" % frame[:10].hex())
        print("     (no 78 01/78 9c zlib header, no adler32 -> raw RFC1951)")

    # ---- layer 4 : raw deflate -------------------------------------------
    js = raw_inflate(raw)
    if verbose:
        print("[L4] raw inflate    : %d bytes of JavaScript" % len(js))
        print("     head: %s" % js[:96].decode("utf8", "replace"))
    return js


def main():
    elf = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ELF
    out = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUT
    js = unpack(elf)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    open(out, "wb").write(js)
    print("[+] written %s (%d bytes)" % (out, len(js)))
    node = shutil.which('node')
    if node:
        r = subprocess.run([node, "--check", out], capture_output=True)
        print("[+] node --check    : %s" % ("OK" if r.returncode == 0 else r.stderr.decode()))
    else:
        print("[+] node not found, skipping syntax check")


if __name__ == "__main__":
    main()
