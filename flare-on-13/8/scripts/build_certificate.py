#!/usr/bin/env python3
"""Build the Pratt (Lucas) certificate tree for the challenge target N and
serialise it in the challenge's format, then encrypt it with the challenge
cipher and feed it to check().

Pratt certificate (Lucas primality criterion):  a prime A is certified by
  * the prime factorisation A-1 = q1*q2*...*qk  (q1 <= q2 <= ... <= qk)
  * a witness B with  B^(A-1) = 1 (mod A)  and  B^((A-1)/qi) != 1 (mod A)
The tree therefore has one node per prime in the recursive factorisation of N-1.
"""
import os, sys, subprocess
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from challenge_cipher import cbc_encrypt, pkcs7_pad

N = 95681613235744740119807961018865688051340183696570761153419351987106658443873


# ---------------------------------------------------------------- big ints
def factorize(n):
    """Pollard rho + Miller-Rabin (only for the numbers we need)."""
    if n == 1:
        return []
    if is_prime(n):
        return [n]
    d = pollard_rho(n)
    return factorize(d) + factorize(n // d)


def is_prime(n):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def pollard_rho(n, seed=2):
    if n % 2 == 0:
        return 2
    for c in (1, 2, 3, 5, 7, 11, 13):
        x = y = seed
        d = 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = gcd(abs(x - y), n)
        if d != n:
            return d
    raise RuntimeError('rho failed')


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


# ---------------------------------------------------------------- the tree
_cache = {}


def build(a):
    """Return the list of children (prime factors of a-1, ascending)."""
    if a in _cache:
        return _cache[a]
    if a == 2:
        return []
    f = factorize(a - 1)
    f.sort()
    _cache[a] = f
    return f


def node_count(a):
    if a == 2:
        return 1
    return 1 + sum(node_count(c) for c in build(a))


# ---------------------------------------------------------------- encoding
def le_bytes(n):
    """minimal little-endian byte representation"""
    if n == 0:
        return b'\x00'
    out = bytearray()
    while n:
        out.append(n & 0xff)
        n >>= 8
    return bytes(out)


def serialize(a, leaf_has_value=True, order='asc'):
    out = bytearray()
    if a == 2:
        out.append(0x00)
        if leaf_has_value:
            v = le_bytes(2)
            out += len(v).to_bytes(4, 'little') + v
        return bytes(out)
    out.append(0x01)
    v = le_bytes(a)
    out += len(v).to_bytes(4, 'little') + v
    kids = build(a)
    if order == 'asc':
        kids = sorted(kids)
    for c in kids:
        out += serialize(c, leaf_has_value, order)
    return bytes(out)


def main():
    print('N-1 factorisation:', factorize(N - 1))
    print('number of nodes in the tree:', node_count(N))
    variants = []
    for leaf_has_value in (True, False):
        for order in ('asc', 'desc'):
            variants.append((leaf_has_value, order))
    import base64
    for leaf_has_value, order in variants:
        pt = serialize(N, leaf_has_value, order)
        ct = cbc_encrypt(pkcs7_pad(pt))
        b64 = base64.b64encode(ct).decode()
        p = subprocess.run(['node', os.path.join(HERE, 'run_wasm.cjs'), b64],
                           capture_output=True, text=True, cwd=os.path.join(HERE, '..'))
        res = p.stdout.strip().split('\n')[-1]
        print('leafvalue=%-5s order=%-4s plaintext=%d bytes -> check() = %s' %
              (leaf_has_value, order, len(pt), res))
        if res not in ('Bad input',) and 'Bad input' not in res:
            print('  *** POSSIBLE FLAG:', res)


if __name__ == '__main__':
    main()
