#!/usr/bin/env python3
"""FlareCalc - debug linear walk: follow first-hit, print everything."""
import pickle
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from node_emu import make_emulator
from unicorn import UcError

CODE = pickle.load(open('/tmp/opencode/code_cont.pkl', 'rb'))['code']
IDS = set(CODE)
EMU = make_emulator()


def main():
    state = bytes(32)
    node = 52090
    for stepno in range(1, 40):
        hs = []
        for ch in range(0x20, 0x7f):
            try:
                nxt, ns = EMU.run(CODE[node], ch, state)
            except UcError as e:
                print('   [emu error node %d char %r: %s]' % (node, chr(ch), e))
                continue
            if nxt in IDS:
                hs.append((chr(ch), nxt, ns))
        print('step %-2d node %-6d len(code)=%-5d hits: %s'
              % (stepno, node, len(CODE[node]),
                 [(h[0], h[1]) for h in hs]))
        if not hs:
            print('   DEAD')
            return 1
        ch, nxt, ns = hs[0]
        d = [(i, state[i], ns[i]) for i in range(32) if state[i] != ns[i]]
        print('   take %r -> %d   state diffs %s'
              % (ch, nxt, ' '.join('[%d]%02x->%02x' % x for x in d)))
        state, node = ns, nxt


if __name__ == '__main__':
    sys.exit(main())
