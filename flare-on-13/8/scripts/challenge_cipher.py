#!/usr/bin/env python3
"""The challenge's outer cipher (LdUZ4Cb) - exact model.

Fitting against the patched-wasm oracle gives:

  Decrypt(C) = ARK(rk[14])
               for r = 13 .. 1:  InvShiftRows, InvSubBytes, ARK(rk[r]), InvMixColumns
               InvShiftRows, InvSubBytes, ARK(rk[0])

i.e. the "equivalent inverse cipher" layout of AES, but using the *encryption*
round keys (the challenge does not pre-compute the InvMixColumns'ed dec keys),
so the cipher is asymmetric: its Encrypt is NOT the standard AES-256 encryption.

The encryption we need is simply the inverse of the above.
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from aes import (expand_key, _add_round_key, _inv_shift_rows, _inv_mix_columns,
                 _inv_sub_bytes, _mix_columns, _shift_rows, _sub_bytes)

KEY = bytes.fromhex('cabeba7ad156801d1c82381c7cb8a3c406ae2c3cd168a96cd8373684cdbf8723')
IV = bytes.fromhex('5ff26040c4c20b9f2ffdefa7ecf65d91')
RKS, NR = expand_key(KEY)


def _ark(s, r):
    return _add_round_key(s, RKS[16 * r:16 * r + 16])


def decrypt_block(block):
    """The challenge cipher's block decryption (verified against the oracle)."""
    s = _ark(block, NR - 1)                       # ARK(rk[14])
    for r in range(NR - 2, 0, -1):                # r = 13 .. 1
        s = _inv_shift_rows(s)
        s = _inv_sub_bytes(s)
        s = _ark(s, r)
        s = _inv_mix_columns(s)
    s = _inv_shift_rows(s)                        # peeled last round
    s = _inv_sub_bytes(s)
    s = _ark(s, 0)
    return s


def encrypt_block(block):
    """Inverse of decrypt_block (what we need to build a valid input)."""
    s = _ark(block, 0)                            # undo ARK(rk[0])
    s = _sub_bytes(s)                             # undo InvSubBytes
    s = _shift_rows(s)                            # undo InvShiftRows
    for r in range(1, NR - 1):                    # r = 1 .. 13
        s = _mix_columns(s)                       # undo InvMixColumns
        s = _ark(s, r)                            # undo ARK(rk[r])
        s = _sub_bytes(s)                         # undo InvSubBytes
        s = _shift_rows(s)                        # undo InvShiftRows
    s = _ark(s, NR - 1)                           # undo ARK(rk[14])
    return s


def cbc_decrypt(ct, iv=IV):
    out, prev = b'', iv
    for i in range(0, len(ct), 16):
        blk = ct[i:i + 16]
        out += bytes(a ^ b for a, b in zip(decrypt_block(blk), prev))
        prev = blk
    return out


def cbc_encrypt(pt, iv=IV):
    out, prev = b'', iv
    for i in range(0, len(pt), 16):
        blk = bytes(a ^ b for a, b in zip(pt[i:i + 16], prev))
        c = encrypt_block(blk)
        out += c
        prev = c
    return out


def pkcs7_pad(data):
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


if __name__ == '__main__':
    # self test: encrypt then decrypt must round-trip
    import os
    for t in (b'', b'hello', bytes(range(64)), b'A' * 100):
        pt = pkcs7_pad(t)
        ct = cbc_encrypt(pt)
        assert cbc_decrypt(ct) == pt, 'round trip failed'
    print('cipher model self-test OK (encrypt/decrypt round trip)')
