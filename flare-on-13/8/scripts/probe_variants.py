#!/usr/bin/env python3
"""Regenerate every negative/format probe used in crux.md, then run each through
the real wasm check().

Names produced (also written as work/probe/<name>.b64):

  canonical     the accepted Pratt certificate for N
  leaf_val      same tree but leaves encoded as 00 | u32(1) | 02
  desc          children reversed at every level
  rootB2        root witness B = 2
  rootB4        root witness B = 4
  rootAplus2    root A = N + 2
  childAplus2   one composite child A += 2
  dropchild     one child of the root removed
  extra_leaf    one extra leaf appended to the root
  other_5 / other_65537 / other_1000003
                structurally valid certificates for other primes

Run:  python3 scripts/probe_variants.py
"""
import copy
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import challenge_cipher as cc
from solve_crux import (build_node, self_check, serialize, derive_n, le, u32,
                        run_real_check)

OUTDIR = os.path.join(ROOT, 'work', 'probe')


def to_dict(node):
    a, b, children = node
    return {'a': a, 'b': b, 'children': [to_dict(c) for c in children]}


def serialize_mut(node, order='asc', leaf=b'\x00'):
    a, b, children = node['a'], node['b'], node['children']
    if a == 2:
        return leaf
    kids = children if order == 'asc' else list(reversed(children))
    body = bytearray(b'\x01' + u32(len(kids)))
    for child in kids:
        blob = serialize_mut(child, order, leaf)
        body += u32(len(blob)) + blob
    a_le, b_le = le(a), le(b)
    body += u32(len(a_le)) + a_le + u32(len(b_le)) + b_le
    return bytes(body)


def first_child_composite(node):
    for child in node['children']:
        if child['a'] != 2 and child['children']:
            return child
    return None


def make_variants(n):
    root = to_dict(build_node(n))
    variants = {}

    variants['canonical'] = serialize_mut(root)
    variants['leaf_val'] = serialize_mut(root, leaf=b'\x00' + u32(1) + b'\x02')
    variants['desc'] = serialize_mut(root, order='desc')

    t = copy.deepcopy(root); t['b'] = 2
    variants['rootB2'] = serialize_mut(t)
    t = copy.deepcopy(root); t['b'] = 4
    variants['rootB4'] = serialize_mut(t)
    t = copy.deepcopy(root); t['a'] = n + 2
    variants['rootAplus2'] = serialize_mut(t)

    t = copy.deepcopy(root)
    child = first_child_composite(t)
    if child is not None:
        child['a'] += 2
        variants['childAplus2'] = serialize_mut(t)

    t = copy.deepcopy(root); t['children'].pop()
    variants['dropchild'] = serialize_mut(t)

    t = copy.deepcopy(root)
    t['children'].append({'a': 2, 'b': None, 'children': []})
    variants['extra_leaf'] = serialize_mut(t)

    for p in (5, 65537, 1000003):
        variants['other_%d' % p] = serialize(build_node(p))

    return variants


def main():
    os.makedirs(OUTDIR, exist_ok=True)
    print('[*] deriving N and building the canonical tree (this takes a few seconds) ...')
    n, _ = derive_n()
    root = build_node(n)
    assert self_check(root) == n
    print('    N = 0x%064x, canonical certificate %d bytes' % (n, len(serialize(root))))

    variants = make_variants(n)
    print('[*] encrypting and running the real check() on %d probes ...\n' % len(variants))
    print('%-14s %-8s %s' % ('variant', 'bytes', 'check() result'))
    print('-' * 72)
    for name, plaintext in variants.items():
        path = os.path.join(OUTDIR, name + '.b64')
        ciphertext = cc.cbc_encrypt(cc.pkcs7_pad(plaintext))
        with open(path, 'w') as fh:
            fh.write(__import__('base64').b64encode(ciphertext).decode())
        t0 = time.time()
        try:
            result = run_real_check(ciphertext)
        except Exception as exc:                       # noqa: BLE001 - report and continue
            result = 'ERROR: %s' % exc
        elapsed = (time.time() - t0) * 1000
        print('%-14s %-8d %s  (%d ms)' % (name, len(plaintext), result, elapsed))
        sys.stdout.flush()

    print('\n[*] b64 inputs written to %s' % os.path.relpath(OUTDIR, ROOT))


if __name__ == '__main__':
    main()
