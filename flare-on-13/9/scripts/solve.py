#!/usr/bin/env python3
"""
FLARE-On 13 / challenge 9 - "NeonOutRun"  -  full solver.

  A) static : unpack the 4 layers -> backend.js  (see unpack_backend.py)
  B) native : find the 3 V8 builtins that the Rust backend replaced
              (Array.prototype.sort 0x67deb2, Math.min 0x67eb83,
               String.prototype.replaceAll 0x67e81e), emulate the real
              machine code of the Math.min hook with Unicorn and solve the
              28 congruences that the hook encodes.

Everything below is derived from the binary itself - nothing is hardcoded.

usage:  python3 scripts/solve.py
"""
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from emulate_native import Elf, MinHookEmu, ELF, f64            # noqa: E402
from unpack_backend import unpack                              # noqa: E402

N_LAPS = 28

# --------------------------------------------------------------- the JS decoy
MESSAGES_RE = re.compile(r"const messages=\[(.*?)\];", re.S)
MAP_RE = re.compile(r"map=\[(.*?)\]", re.S)


def parse_js(js: str):
    """Extract the decoy table (messages[] and map[]) from backend.js."""
    m = MESSAGES_RE.search(js)
    msgs = re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1))
    mp = [int(x) for x in MAP_RE.search(js).group(1).split(",")]
    return msgs, mp


def decoy_string(msgs, mp, n=N_LAPS):
    """Reproduce what backend.js builds in `neon` while the player wins."""
    out = ""
    for lap in range(1, n + 1):
        out += msgs[(lap - 1) // 2][mp[lap - 1]]
    # neon += String.fromCharCode(64,102,49,97,114,101,45,111,110,46,99,111,109)
    out += "".join(chr(c) for c in (64, 102, 49, 97, 114, 101, 45, 111, 110, 46, 99, 111, 109))
    return out


# ------------------------------------------------------------ the native part
def native_tables(elf_path=ELF):
    """Emulate the Math.min hook once per lap and return (p_i, sign_i)."""
    elf = Elf(elf_path)
    emu = MinHookEmu(elf)
    rows = []
    for i in range(N_LAPS):
        r = emu.run_lap(i, 100.0)
        p = r["p"]
        if p >= 1 << 63:                       # the hook uses cvtsi2sdq (signed)
            p -= 1 << 64
        sign = -1 if (r["byte"] & 1) else 1     # 0x7(rsp) bit0 -> negate
        rows.append((p, sign, r))
    return emu, rows


def solve_lap_times(emu, rows):
    """theta = (pi/M) * (p + s*b), M == 180  ->  sin(theta) == 1  <=>  p+s*b = 90 (mod 360)."""
    out = []
    for (p, sign, r) in rows:
        assert r["M"] == 180, "unexpected divisor M = %r" % r["M"]
        b = ((90 - p) if sign > 0 else (p - 90)) % 360
        out.append(b)
    return out


def verify_lap_times(emu, bts):
    """Re-run the hook with lap_secs = b and check that the accumulator
    contribution is exactly 1.0 (i.e. sin(theta) == 1)."""
    ok = True
    for i, b in enumerate(bts):
        r = emu.run_lap(i, float(b), stop=0x67F9AA)
        good = abs(r["acc"] - 1.0) < 1e-9 and r["pushed"] == [b]
        ok &= good
        print("      lap %2d  b=%3d %s  acc2 contribution=%.17g  %s"
              % (i, b, chr(b) if 32 <= b < 127 else "?", r["acc"],
                 "OK" if good else "FAIL"))
    return ok


def main():
    print("=" * 74)
    print(" FLARE-On 13 / challenge 09 - NeonOutRun")
    print("=" * 74)

    print("\n--- A) unpack the 4 packing layers ------------------------------")
    js = unpack(ELF)
    js_path = os.path.join(os.path.dirname(HERE), "work", "backend.js")
    os.makedirs(os.path.dirname(js_path), exist_ok=True)
    open(js_path, "wb").write(js)
    print("[+] backend.js written to %s" % js_path)
    msgs, mp = parse_js(js.decode())
    decoy = decoy_string(msgs, mp)
    print("\n[*] JS decoy table   : %d messages, map len %d" % (len(msgs), len(mp)))
    print("[*] decoy 'neon'     : %r  (len %d)" % (decoy, len(decoy)))
    print("    -> the domain is deliberately wrong: '@f1are-on.com'")

    print("\n--- B) native hooks -----------------------------------------------")
    emu, rows = native_tables()
    print("[*] Math.min hook @0x67eb83 : M = %d  (angle = (pi/%d)*(p + s*b))"
          % (rows[0][2]["M"], rows[0][2]["M"]))
    print("[*] 28 (p_i, s_i) pairs extracted by emulating the hook's own code")

    print("\n--- C) solve the 28 congruences -----------------------------------")
    bts = solve_lap_times(emu, rows)
    print("[*] lap times (bytes) : %s" % bts)
    print("[*] lap times (ascii) : %s" % "".join(chr(b) for b in bts))
    print("[*] verifying by re-running the hook with those lap times:")
    if not verify_lap_times(emu, bts):
        print("!!! verification failed")
        return 1

    print("\n--- D) assemble the flag -----------------------------------------")
    # String.prototype.replaceAll hook (0x67e81e):
    #   * copies min(28, len) bytes of the 28-byte lap time vector over the
    #     beginning of the string
    #   * then does  string[0x1e] += 0x3b   (index 30)
    flag = bytearray(decoy.encode())
    n = min(len(flag), N_LAPS)
    flag[0:n] = bytes(bts[0:n])
    if len(flag) >= 0x1f:
        flag[0x1E] = (flag[0x1E] + 0x3B) & 0xFF
    flag = flag.decode()

    print("[*] after the 28 byte overwrite : %r" % flag)
    print("[*] byte[30] += 0x3b           : %r -> %r"
          % (decoy[30], chr((ord(decoy[30]) + 0x3B) & 0xFF)))
    print("\n" + "=" * 74)
    print("FLAG: %s" % flag)
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
