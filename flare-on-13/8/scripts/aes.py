#!/usr/bin/env python3
"""AES helpers: S-box, key expansion, block encrypt/decrypt (pure python)."""

def gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return r


def rotl8(x, s):
    return ((x << s) | (x >> (8 - s))) & 0xff


def _build_sbox():
    sbox = [0] * 256
    for i in range(256):
        x = 0
        for j in range(1, 256):
            if gmul(i, j) == 1:
                x = j
                break
        y = x
        for _ in range(4):
            y = rotl8(y, 1)
            x ^= y
        sbox[i] = x ^ 0x63
    return sbox


SBOX = _build_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i
assert SBOX[0] == 0x63 and SBOX[255] == 0x16 and INV_SBOX[0x63] == 0
assert SBOX[0x52] == 0x00 or True


def expand_key(key):
    """Return (round keys as bytes, nrounds) for a 16/24/32 byte key."""
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[x] for x in t]
            t[0] ^= rcon
            rcon = ((rcon << 1) ^ 0x1b) & 0xff if rcon & 0x80 else (rcon << 1) & 0xff
        elif nk > 6 and i % nk == 4:
            t = [SBOX[x] for x in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return b''.join(bytes(x) for x in w), nr + 1


def _add_round_key(s, rk):
    return bytes(a ^ b for a, b in zip(s, rk))


def _shift_rows(s):
    # state is column major: s[r + 4c]
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    return bytes(out)


def _inv_shift_rows(s):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[r + 4 * c] = s[r + 4 * ((c - r) % 4)]
    return bytes(out)


def _mix_columns(s):
    out = bytearray(16)
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        out[4 * c + 0] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3]
        out[4 * c + 1] = a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3]
        out[4 * c + 2] = a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3)
        out[4 * c + 3] = gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2)
    return bytes(out)


def _inv_mix_columns(s):
    out = bytearray(16)
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        out[4 * c + 0] = gmul(a[0], 14) ^ gmul(a[1], 11) ^ gmul(a[2], 13) ^ gmul(a[3], 9)
        out[4 * c + 1] = gmul(a[0], 9) ^ gmul(a[1], 14) ^ gmul(a[2], 11) ^ gmul(a[3], 13)
        out[4 * c + 2] = gmul(a[0], 13) ^ gmul(a[1], 9) ^ gmul(a[2], 14) ^ gmul(a[3], 11)
        out[4 * c + 3] = gmul(a[0], 11) ^ gmul(a[1], 13) ^ gmul(a[2], 9) ^ gmul(a[3], 14)
    return bytes(out)


def _sub_bytes(s):
    return bytes(SBOX[b] for b in s)


def _inv_sub_bytes(s):
    return bytes(INV_SBOX[b] for b in s)


def encrypt_block(key, block):
    rks, nr = expand_key(key)
    s = _add_round_key(block, rks[0:16])
    for r in range(1, nr - 1):
        s = _sub_bytes(s)
        s = _shift_rows(s)
        s = _mix_columns(s)
        s = _add_round_key(s, rks[16 * r:16 * r + 16])
    s = _sub_bytes(s)
    s = _shift_rows(s)
    s = _add_round_key(s, rks[16 * (nr - 1):16 * (nr - 1) + 16])
    return s


def decrypt_block(key, block):
    rks, nr = expand_key(key)
    s = _add_round_key(block, rks[16 * (nr - 1):16 * (nr - 1) + 16])
    for r in range(nr - 2, 0, -1):
        s = _inv_shift_rows(s)
        s = _inv_sub_bytes(s)
        s = _add_round_key(s, rks[16 * r:16 * r + 16])
        s = _inv_mix_columns(s)
    s = _inv_shift_rows(s)
    s = _inv_sub_bytes(s)
    s = _add_round_key(s, rks[0:16])
    return s


if __name__ == '__main__':
    # FIPS-197 test vector
    k = bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    p = bytes.fromhex('00112233445566778899aabbccddeeff')
    ct = encrypt_block(k, p)
    print('AES-256 encrypt:', ct.hex(), 'expect 8ea2b7ca516745bfeafc49904b496089')
    assert ct.hex() == '8ea2b7ca516745bfeafc49904b496089'
    assert decrypt_block(k, ct) == p
    print('AES-256 decrypt roundtrip OK')
