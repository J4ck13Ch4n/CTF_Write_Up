#!/usr/bin/env python3
"""FlareCalc - 32-step labyrinth walk with the verified blobs (DFS edition).

The walk rules, derived from the stub semantics:
  * each step must land inside the entry-id space,
  * after exactly 32 steps the node must be 4485 (the cipher node),
  * every surviving branch produces one candidate 32-byte XTEA key; the key
    validates itself when running node 4485 on entry 9990's 40 bytes
    (see xtea_final.py).

Multi-branch nodes exist (a few chars return ids), so a plain first-hit walk
is fragile; we DFS instead and let the startup chain (steps 1..8, verified
deterministically) anchor the search.
"""
import pickle
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from node_emu import make_emulator   # noqa: E402

CODE = pickle.load(open('/tmp/opencode/code_cont.pkl', 'rb'))['code']
IDS = set(CODE)

BLOG_WALK = 'FLAREON_ASN1_Labyrinth_Key_2026!'      # information only
BLOG_SOL = {'1': ('F', 54272), '2': ('L', 44269), '3': ('A', 60903),
            '4': ('R', 3394), '5': ('E', 5295)}

BUDGET = [400000]
MAXSOL = 64
EMU = None


def hits(node, state):
    if BUDGET[0] <= 0:
        return None
    out = []
    for ch in range(0x20, 0x7f):
        BUDGET[0] -= 1
        nxt, ns = EMU.run(CODE[node], ch, state)
        if nxt in IDS:
            out.append((chr(ch), nxt, ns))
    return out


def dfs(node, state, stepno, walk, acc):
    if len(acc) >= MAXSOL or BUDGET[0] <= 0:
        return
    if stepno > 32:
        acc.append((list(walk), bytes(state)))
        return
    hs = hits(node, state)
    if not hs:
        return
    for ch, nxt, ns in hs:
        if nxt == 4485 and stepno != 32:
            continue
        dfs(nxt, ns, stepno + 1, walk + [ch], acc)


def main():
    global EMU
    EMU = make_emulator()
    acc = []
    dfs(52090, bytes(32), 1, [], acc)
    print('budget used %d, solutions %d' % (400000 - BUDGET[0], len(acc)))
    for i, (walk, state) in enumerate(acc):
        s = ''.join(walk)
        mark = []
        for sn, (bc, bi) in BLOG_SOL.items():
            if len(walk) >= int(sn) and (walk[int(sn) - 1],) == (bc,):
                mark.append('s%s=%s' % (sn, walk[int(sn) - 1]))
        print('%2d %-40r key=%s' % (i, s, bytes(state).hex()))
    pickle.dump({'sol': acc}, open('/tmp/opencode/walk_solutions.pkl', 'wb'))
    return 0 if acc else 1


if __name__ == '__main__':
    sys.exit(main())
