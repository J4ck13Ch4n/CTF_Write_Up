#!/usr/bin/env python3
"""crux -- Flare-On 13 challenge 8 -- end-to-end solver.

Pipeline
--------
1. Derive the target prime N from ext/main.wasm itself (two rodata blobs plus a
   byte-permutation loop inside the check() closure; see derive_n.py).
2. Factor N-1 recursively with Miller-Rabin + Pollard rho and build the Pratt
   (Lucas) certificate tree: every composite node A has children q1..qk with
   q1*...*qk = A-1 (ascending, with multiplicity) and a witness B that is the
   *least* primitive root modulo A.
3. Serialise the tree in the challenge's canonical format.
4. Re-check every property the wasm verifier enforces, encrypt the blob with
   the challenge's custom AES-derived cipher and feed it to the real wasm
   check() through Node.
5. Independently decrypt the embedded 64-byte payload with
   AES-256(key = SHA-256(canonical serialisation), IV = challenge IV) and
   confirm both paths produce the same flag.

Run:  python3 scripts/solve_crux.py
"""
import base64
import functools
import hashlib
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import challenge_cipher as cc
from derive_n import derive_n

# 64 ciphertext bytes at linear address 0x36C000 in the post-check memory dump.
# They are a garble-encrypted literal (absent from the raw module) and only
# materialise when check() runs the successful path.  See crux.md section 6.
PAYLOAD = bytes.fromhex(
    '78b95d284fb5a232df1ccc908e10fe1a'
    '2d7faa97cc43c2797087f03ad311c512'
    '997cd0e4fb72ca3072c3e2ad0de6232f'
    'f619632797e3708ad29b2cdd4491a3c2'
)


# --------------------------------------------------------------------------
# number theory: deterministic-enough Miller-Rabin + Pollard rho
# --------------------------------------------------------------------------
def is_prime(n):
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in small:
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in small:
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


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def pollard_rho(n):
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3
    c = 1
    while True:
        x = y = 2
        d = 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = _gcd(abs(x - y), n)
        if d != n:
            return d
        c += 1


@functools.lru_cache(maxsize=None)
def factor(n):
    """Prime factors of n with multiplicity, ascending."""
    if n == 1:
        return ()
    if is_prime(n):
        return (n,)
    d = pollard_rho(n)
    return tuple(sorted(factor(d) + factor(n // d)))


def least_primitive_root(p, prime_factors):
    """Smallest g with g^(p-1)=1 and g^((p-1)/q)!=1 for every q | p-1."""
    for g in range(2, p):
        if pow(g, p - 1, p) == 1 and all(
                pow(g, (p - 1) // q, p) != 1 for q in prime_factors):
            return g
    raise RuntimeError('no primitive root for %d' % p)


# --------------------------------------------------------------------------
# building and serialising the Pratt certificate
# --------------------------------------------------------------------------
@functools.lru_cache(maxsize=None)
def build_node(a):
    """Return (A, B, children) with children sorted by A (multiplicity kept)."""
    if a == 2:
        return (2, None, ())
    fac = factor(a - 1)
    children = sorted((build_node(q) for q in fac), key=lambda node: node[0])
    witness = least_primitive_root(a, set(fac))
    return (a, witness, tuple(children))


def le(n):
    """Minimal little-endian encoding (0 -> b'\\x00')."""
    if n == 0:
        return b'\x00'
    out = bytearray()
    while n:
        out.append(n & 0xFF)
        n >>= 8
    return bytes(out)


def u32(n):
    return n.to_bytes(4, 'little')


def serialize(node):
    """Canonical certificate encoding accepted by the wasm parser.

    leaf (prime 2) : 00
    composite     : 01 | u32 nchildren | (u32 len(ci) | ci)*n
                    | u32 len(A_le) | A_le | u32 len(B_le) | B_le
    """
    a, b, children = node
    if a == 2:
        return b'\x00'
    body = bytearray(b'\x01' + u32(len(children)))
    for child in children:
        blob = serialize(child)
        body += u32(len(blob)) + blob
    a_le, b_le = le(a), le(b)
    body += u32(len(a_le)) + a_le + u32(len(b_le)) + b_le
    return bytes(body)


def is_witness(p, k, children):
    """Verifier semantics: Fermat plus non-1 for every child value (A-1)/q."""
    if pow(k, p - 1, p) != 1:
        return False
    for child in children:
        q = child[0]
        if pow(k, (p - 1) // q, p) == 1:
            return False
    return True


def self_check(node):
    """Assert exactly the constraints the wasm verifier enforces."""
    a, b, children = node
    if a == 2:
        assert not children
        return 2
    values = [child[0] for child in children]
    assert values == sorted(values), 'children not ascending'
    product = 1
    for child in children:
        product *= self_check(child)
    assert product == a - 1, 'A-1 != product(children) for %d' % a
    assert is_witness(a, b, children), 'B is not a witness for %d' % a
    for k in range(2, b):                       # B must be the LEAST witness
        assert not is_witness(a, k, children), '%d is a smaller witness' % k
    return a


def count_nodes(node):
    return 1 + sum(count_nodes(child) for child in node[2])


def distinct_primes(node):
    primes = {node[0]}
    for child in node[2]:
        primes |= distinct_primes(child)
    return primes


# --------------------------------------------------------------------------
# real wasm oracle + payload decryption
# --------------------------------------------------------------------------
def run_real_check(ciphertext):
    b64 = base64.b64encode(ciphertext).decode('ascii')
    proc = subprocess.run(
        ['node', os.path.join(HERE, 'run_wasm.cjs'), b64],
        cwd=ROOT, capture_output=True, text=True, timeout=600)
    lines = [line for line in proc.stdout.splitlines() if line.startswith('check(')]
    if not lines:
        raise RuntimeError('wasm oracle failed:\n%s\n%s' % (proc.stdout, proc.stderr))
    line = lines[-1]
    marker = ') => '
    if marker not in line:
        raise RuntimeError('cannot parse oracle output: %r' % line)
    result = line.split(marker, 1)[1].rsplit(' (typeof', 1)[0]
    return result


def decrypt_payload(canonical_plaintext):
    key = hashlib.sha256(canonical_plaintext).digest()
    saved = (cc.RKS, cc.NR)
    cc.RKS, cc.NR = cc.expand_key(key)
    try:
        raw = cc.cbc_decrypt(PAYLOAD)
    finally:
        cc.RKS, cc.NR = saved
    pad = raw[-1]
    if not (1 <= pad <= 16 and raw.endswith(bytes([pad]) * pad)):
        raise RuntimeError('payload has invalid PKCS#7 padding')
    return key, raw[:-pad]


def main():
    t0 = time.time()
    print('[*] deriving N from ext/main.wasm ...')
    n, details = derive_n()
    print('    N = 0x%064x  (%d bits)' % (n, n.bit_length()))
    assert n.bit_length() == 256 and is_prime(n)

    print('[*] factoring N-1 and building the Pratt certificate ...')
    root = build_node(n)
    plaintext = serialize(root)
    assert self_check(root) == n
    primes = distinct_primes(root)
    print('    certificate: %d bytes, %d nodes, %d distinct primes (incl. 2), root B=%d'
          % (len(plaintext), count_nodes(root), len(primes), root[1]))

    print('[*] encrypting with the challenge cipher ...')
    ciphertext = cc.cbc_encrypt(cc.pkcs7_pad(plaintext))
    print('    plaintext %d bytes -> ciphertext %d bytes' % (len(plaintext), len(ciphertext)))

    print('[*] calling the real wasm check() (fresh Node process) ...')
    oracle = run_real_check(ciphertext)
    if oracle == 'Bad input' or oracle.startswith('Bad input'):
        raise SystemExit('verifier rejected the certificate: %s' % oracle)
    print('    check() = %s' % oracle)

    print('[*] local payload cross-check (SHA-256 of serialisation + challenge IV) ...')
    key, local = decrypt_payload(plaintext)
    print('    key      = %s' % key.hex())
    local_flag = local.decode('ascii')
    print('    plaintext= %r' % local_flag)

    if local_flag != oracle:
        raise SystemExit('mismatch: oracle=%r local=%r' % (oracle, local_flag))

    print()
    print('FLAG: %s' % local_flag)
    print('[*] done in %.1fs' % (time.time() - t0))


if __name__ == '__main__':
    main()
