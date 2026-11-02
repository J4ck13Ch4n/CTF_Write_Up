#!/usr/bin/env python3
"""FlareCalc (FLARE-On 13 / challenge 07) - one-command end-to-end solver.

    .venv/bin/python scripts/solve_flarecalc.py

Stages (each stage is also runnable standalone):

  1. scripts/decrypt_cont.py    carve the ASN.1 table out of the Authenticode
                                overlay and decrypt every record with the
                                continuous keystream
                                (verified 0/152 mismatches on known-plaintext
                                node 52090)  -> /tmp/opencode/code_cont.pkl
  2. scripts/walk_final.py      DFS the 1034-node labyrinth: exactly one
                                printable char per step lands in the entry-id
                                space, 32 steps must end on node 4485
                                -> /tmp/opencode/walk_solutions.pkl
  3. scripts/xtea_final.py      emulate the 384-byte modified-XTEA decryptor
                                (node 4485) with unicorn: rcx=out, rdx=cipher
                                (entry 9990, 40 bytes), r8=key (the 32-byte
                                six-step state buffer) -> the flag

Everything is derived from the binary; the repo scripts never read answers.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PY = os.path.join(HERE, '..', '..', '.venv', 'bin', 'python')


def run(script):
    print('\n=== %s ===' % script, flush=True)
    r = subprocess.run([PY, os.path.join(HERE, script)], cwd=HERE)
    if r.returncode != 0:
        print('STAGE %s FAILED (exit %d)' % (script, r.returncode))
        return False
    return True


def main():
    for script in ('decrypt_cont.py', 'walk_final.py', 'xtea_final.py'):
        if not run(script):
            return 1
    print('\n*** ALL STAGES PASSED ***')
    return 0


if __name__ == '__main__':
    sys.exit(main())
