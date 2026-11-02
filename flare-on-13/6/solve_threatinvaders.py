#!/usr/bin/env python3
"""
FLARE-ON 13 — Challenge 6 "Threat Invaders" — solver

Chain of reasoning (all derived from the two provided files):

  * ThreatInvaders.exe is a .NET 10 single-file app whose *native* part is NOT the stock
    Microsoft singlefilehost but a CUSTOM CoreCLR build that hooks 5 managed methods at
    JIT level:
        ReplaceHighscores / LaunchUpdate / GetMachineGuid / GetSessionID / EncodeFeedbackBuffer
  * The hook on ReplaceHighscores walks the managed HighscoreStruct[] (80 bytes/record) and
    decrypts the Comment of any record whose (Score XOR PlayerName[0..3]) hashes to
    0xce723a0a685e63e4  ==  marker "cmd:".
  * Cipher:  seed = xxh64_avalanche(A ^ ((A>>2) + 0x9e3779b97f4a7c15 + (A<<6) + B))
                        A,B = machine-GUID[0:8], machine-GUID[8:16]
            st = st*0x5851f42d4c957f2d + 0x14057b7ef767814f ;  key byte = st>>56
    The PRNG state is a *global*, so every decryption in the session continues the same
    keystream (offset matters!).
  * The hook on EncodeFeedbackBuffer leaks 16 bytes (sessionGUID XOR machineGUID) into the
    telemetry feedback buffer -> the pcap hands us the machine GUID.
  * The hook on LaunchUpdate overwrites the updater path/argument with the decrypted
    command, so the game really executes "cmd.exe /c ..." sent by the server.
  * The telemetry payloads are the *encrypted stdout* of those commands:
        telemetry #4 -> output of  cmd.exe /c dir
        telemetry #5 -> output of  cmd.exe /c type flag.txt   <-- the flag
"""
import base64, hashlib, json, os, re, sys

M64 = (1 << 64) - 1

# ---------------------------------------------------------------- PRNG / cipher
def xxh_avalanche(h):
    h &= M64
    h ^= h >> 33; h = (h * 0xff51afd7ed558ccd) & M64
    h ^= h >> 29; h = (h * 0xc4ceb9fe1a85ec53) & M64
    h ^= h >> 32
    return h

def seed_of(a, b):
    return xxh_avalanche((a ^ ((((a >> 2) + 0x9e3779b97f4a7c15 + ((a << 6) & M64) + b) & M64))) & M64)

def keystream(key, n, skip=0):
    a = int.from_bytes(key[:8], "little"); b = int.from_bytes(key[8:16], "little")
    st = seed_of(a, b); out = bytearray()
    for i in range(n):
        st = (st * 0x5851f42d4c957f2d + 0x14057b7ef767814f) & M64
        if i >= skip:
            out.append((st >> 56) & 0xff)
    return bytes(out)

def dec(ct, key, skip=0):
    ks = keystream(key, skip + len(ct), skip)
    return bytes(a ^ b for a, b in zip(ct, ks))

def net_guid_bytes(s):
    """bytes of a .NET Guid in memory (mixed endian)"""
    b = bytes.fromhex(s.replace("-", ""))
    return b[0:4][::-1] + b[4:6][::-1] + b[6:8][::-1] + b[8:16]

def marker_hash(x4):
    """the JIT's 4-byte marker hash"""
    seed = ((x4[0] ^ 0x8f3a2c91d7b4e6a5) * 0xc53a1b7f2d9e4467) & M64
    h, m = seed, 0x5ca6e801706eaaac
    for c in x4[1:]:
        if c == 0: break
        h = ((c ^ h) * m) & M64; m = (m * 0x2545f4914f6cdd1d + 1) & M64
    return h

# ---------------------------------------------------------------- pcap access
HERE = os.path.dirname(os.path.abspath(__file__))
PCAP = os.path.join(HERE, 'ThreatInvaders', 'challenge.pcapng')

def telemetry_from_pcap():
    import subprocess
    out = subprocess.check_output(
        ["tshark", "-r", PCAP, "-Y", 'http.request.method == "POST" && http.request.uri contains "telemetry"',
         "-T", "fields", "-E", "separator=|", "-e", "http.file_data"], text=True)
    res = []
    for line in out.splitlines():
        hx = line.strip()
        if not hx: continue
        raw = bytes.fromhex(hx.replace(":", ""))
        res.append(json.loads(raw))
    return res

def main():
    tel = telemetry_from_pcap()
    print("[1] telemetry posts in the capture: %d" % len(tel))

    # --- the 16-byte leak: telemetry #3 feedback[0:16] == sessionGUID XOR machineGUID
    fb3 = base64.b64decode(tel[2]["feedback_b64"])
    leak = fb3[:16]
    session = net_guid_bytes(tel[0]["session_id"])[::-1]      # host stores it reversed
    machine = bytes(a ^ b for a, b in zip(leak, session))
    print("[2] leaked session^machine : %s" % leak.hex())
    print("    machine GUID bytes      : %s" % machine.hex())
    print("    MachineGuid string      : %s-%s-%s-%s-%s" % (
        machine[3::-1].hex(), machine[5:3:-1].hex(), machine[7:5:-1].hex(),
        machine[9:11].hex(), machine[11:].hex()))

    # --- markers
    cmd_marker = 0xce723a0a685e63e4
    alt_marker = 0x5045a536b62b2c6      # == "fun!"
    print("[3] marker 'cmd:' hash = 0x%016x ; marker 'fun!' hash = 0x%016x"
          % (cmd_marker, alt_marker))

    # --- board records
    banana = base64.b64decode("+bmPsSZwC3eIRD/rvqXFfnzf")        # wave_reached 69 = 'E'
    benign = base64.b64decode("GenjMZg28ziV/EU2YTRDGmZISVPsEraqrCO03g==")  # 67 = 'C'

    # 'E' is decrypted first (keystream offset 0)
    e_plain = dec(banana, machine, 0)
    print("[4] cmd 'E' -> %r" % e_plain)

    # 'C' continues the same global keystream -> find its offset
    best = None
    for skip in range(0, 4000):
        p = dec(benign, machine, skip)
        if p.startswith(b"cmd:") or all(32 <= c < 127 for c in p):
            best = (skip, p); break
    print("[5] cmd 'C' -> %r  (keystream offset %d)" % (best[1], best[0]))

    # --- the telemetry payloads are the encrypted stdout of those commands
    fb4 = base64.b64decode(tel[3]["feedback_b64"])[:530]
    fb5 = base64.b64decode(tel[4]["feedback_b64"])[:46]
    out4 = dec(fb4, machine, 18)
    out5 = dec(fb5, machine, 576)
    print("[6] telemetry #4 (output of '%s'):" % e_plain[4:].split(b";")[0])
    print("    " + out4.decode("latin1").replace("\r\n", "\n    ").strip())
    print("[7] telemetry #5 (output of '%s'):" % best[1][4:].split(b";")[0])
    print("    " + out5.decode("latin1").strip())
    print()
    print("FLAG: %s" % out5.decode("latin1").strip())

if __name__ == "__main__":
    main()
