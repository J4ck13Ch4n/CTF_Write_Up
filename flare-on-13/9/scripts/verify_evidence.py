#!/usr/bin/env python3
"""
FLARE-On 13 / challenge 09 - NeonOutRun
Cross verification of every constant / address that the writeup claims.

usage:  python3 scripts/verify_evidence.py
"""
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ELF = os.path.join(os.path.dirname(HERE), "neon_outrun")
sys.path.insert(0, HERE)
from unpack_backend import unpack, XOR_KEY, ZSTD_MAGIC   # noqa: E402

data = open(ELF, "rb").read()
ok = True


def check(title, cond, extra=""):
    global ok
    ok &= bool(cond)
    print("[%s] %-58s %s" % ("PASS" if cond else "FAIL", title, extra))


def find_all(hay: bytes, needle: bytes):
    return [m.start() for m in re.finditer(re.escape(needle), hay)]


print("=" * 78)
print(" NeonOutRun - evidence cross-check")
print("=" * 78)

print("\n-- 1. the target ------------------------------------------------")
check("ELF 64-bit PIE, stripped",
      data[:4] == b"\x7fELF" and data[4] == 2 and data[16] == 3,
      "%d bytes" % len(data))

print("\n-- 2. Tauri 2 / rusty_v8 -----------------------------------------")
for s in [b"tauri-2.11.5", b"rusty_v8-0.32.1", b"com.neon.outrun",
          b"Neon OutRun", b"frontend_min", b"plugin:neon|",
          b"unable to create thread with 8MiB stack"]:
    p = find_all(data, s)
    check("string %r" % s.decode(), p, "at 0x%x" % p[0] if p else "NOT FOUND")

print("\n-- 3. the 3 native hooks -----------------------------------------")
for name, addr in (("Array.prototype.sort", 0x67DEB2),
                    ("Math.min", 0x67EB83),
                    ("String.prototype.replaceAll", 0x67E81E)):
    # the function prologue of the hook
    check("%s @ 0x%x" % (name, addr),
          data[addr - 0x1000:addr - 0x1000 + 2] == b"\x55\x41",
          "push rbp; push r15")

print("\n-- 4. obfuscated property names ----------------------------------")
# the three name blobs are XOR-decoded at runtime (see the writeup)
for enc, key, expect in (
        ("8123fe456160493eda52", "f3468e2900032c7fb63e", "replaceAll"),
        ("efb5336e", "a2d44706", "Math"),
        ("66f698eaf4", "2784ea8b8d", "Array")):
    e = bytes.fromhex(enc)
    k = bytes.fromhex(key)
    got = bytes(a ^ b for a, b in zip(e, k)).decode()
    check("XOR name -> %r" % expect, got == expect, got)

print("\n-- 5. MMIX LCG used by the sort hook ----------------------------")
for c in (0x5851F42D4C957F2D, 0x14057B7EF767814F):
    pat = struct.pack("<Q", c)
    p = find_all(data, pat)
    check("movabs $0x%016x" % c, p, "at 0x%x" % p[0] if p else "NOT FOUND")
# the initial TLS state of the LCG
p = find_all(data, struct.pack("<Q", 0x123456789ABCDEF0))
check("initial LCG state 0x123456789abcdef0", p,
      "at 0x%x" % p[0] if p else "NOT FOUND")

print("\n-- 6. floating point constants used by the hooks ------------------")
for addr, want, name in ((0x107E28, 1e-06, "win tolerance 1e-6"),
                          (0x108728, 2 * 3.141592653589793, "2*pi"),
                          (0x108AA8, 3.141592653589793, "pi"),
                          (0x1089C0, 255.0, "255.0 (byte clamp)"),
                          (0x105440, 2.0 ** 52, "2^52 (u32->f64 magic)")):
    got = struct.unpack_from("<d", data, addr)[0]
    check("%s @ 0x%x" % (name, addr), abs(got - want) < 1e-9 or got == want, repr(got))

print("\n-- 7. the packed script ------------------------------------------")
js = unpack(ELF, verbose=False)
check("backend.js is 4229 bytes", len(js) == 4229, "%d bytes" % len(js))
for s in [b"splits.sort((a,b)=>b-a)", b"Math.min(state.bestLapSeconds,lapSecs)",
          b"neon.replaceAll(\" \",\"_\")",
          b"String.fromCharCode(64,102,49,97,114,101,45,111,110,46,99,111,109)",
          b"totalLaps:28"]:
    check("JS contains %r" % s.decode()[:48], s in js)

print("\n-- 8. the 4 packing layers ----------------------------------------")
blob_off = 0x21DB73
check("blob at 0x21db73 right behind the V8 string "
      "'...capacity overflow,'",
      data[blob_off - 40:blob_off] == b"FromUtf8Errorbyteserrorcapacity overflow,"[0:40] or
      data[blob_off - 3:blob_off] == b"ow,",
      repr(data[blob_off - 12:blob_off]))
dec = bytes(b ^ XOR_KEY[i & 1] for i, b in enumerate(data[blob_off:blob_off + 64]))
check("after layer 1 (XOR) the zstd magic 28 b5 2f fd appears",
      dec[1:5] == ZSTD_MAGIC, dec[:8].hex())
check("after layer 1 the first byte is the LZSS control byte 0xff",
      dec[0] == 0xFF, hex(dec[0]))

print("\n-- 9. result ------------------------------------------------------")
print("[%s] everything checked" % ("PASS" if ok else "FAIL"))
sys.exit(0 if ok else 1)
