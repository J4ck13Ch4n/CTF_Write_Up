#!/usr/bin/env python3
"""Check the challenge cipher's round keys against the standard AES-256 schedule.

The cipher struct (LdUZ4Cb.(*wSlIsLQux)) holds two slices of 60 uint32 (the
15 round keys of AES-256).  The keys are stored as big-endian uint32 words, so
in memory the bytes of every 4-byte word appear in reverse order.
"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from aes import SBOX, expand_key

KEY = bytes.fromhex('cabeba7ad156801d1c82381c7cb8a3c406ae2c3cd168a96cd8373684cdbf8723')


def main():
    d = json.load(open(os.path.join(HERE, '..', 'work', 'roundkeys.json')))
    raw = bytes.fromhex(d['s1'])
    # undo the little-endian word storage: each 4-byte group is a big-endian word
    rks = b''.join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
    std, nr = expand_key(KEY)
    print('rounds field      :', d['rounds'])
    print('slice1 == slice2  :', d['s1'] == d['s2'])
    print('round keys (as stored, word-swapped):')
    for i in range(0, len(rks), 16):
        print('   rk%-2d %s' % (i // 16, rks[i:i + 16].hex()))
    print('\nstandard AES-256 key schedule:')
    for i in range(0, len(std), 16):
        print('   rk%-2d %s' % (i // 16, std[i:i + 16].hex()))
    print('\nMATCH with standard AES-256 key expansion:', rks == std)


if __name__ == '__main__':
    main()
