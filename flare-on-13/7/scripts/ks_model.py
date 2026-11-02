#!/usr/bin/env python3
"""FlareCalc - core model helpers: noise constant, real-position set, keystream tests.

Model (verified empirically, see FlareCalc.md):
  * every entry blob interleaves "real" ciphertext bytes with 1..3 noise bytes
  * noise bytes have their low 3 bits frozen to a per-entry constant c_entry
  * real bytes: ct[p] = pt[j] ^ ks[j]   (j = index among real bytes)
  * a real byte is undetectable when low3(pt[j]) == 0
"""
import collections
import os
import pickle
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flarecalc_table import load_entries   # noqa: E402

CACHE = '/tmp/opencode/ks_model.pkl'
DECOY = 3821          # the entry that is *not* encrypted (real x86-64 code)


def entries():
    return dict(load_entries())


def noise_const(blob):
    """Per-entry frozen low-3-bit constant of the noise bytes (modal low3)."""
    return collections.Counter(x & 7 for x in blob).most_common(1)[0][0]


def real_mask(blob):
    """List[bool]: True where the byte is *detectable* real data."""
    c = noise_const(blob)
    return [((x & 7) != c) for x in blob]


def build():
    E = entries()
    ids = [i for i in sorted(E) if i != DECOY]
    consts = {i: noise_const(E[i]) for i in ids}
    masks = {i: real_mask(E[i]) for i in ids}
    maxlen = max(len(E[i]) for i in ids)
    # length-aware vote: among entries that actually have byte p, how many show
    # it as real data?
    have = [0] * maxlen
    real = [0] * maxlen
    for i in ids:
        m = masks[i]
        for p, v in enumerate(m):
            have[p] += 1
            if v:
                real[p] += 1
    frac = [real[p] / have[p] if have[p] else 0.0 for p in range(maxlen)]
    R = [p for p in range(maxlen) if frac[p] > 0.5]
    gaps = [R[i + 1] - R[i] for i in range(len(R) - 1)]
    data = dict(entries=E, ids=ids, consts=consts, masks=masks,
                frac=frac, R=R, gaps=gaps, maxlen=maxlen, have=have)
    return data


def load():
    if os.path.exists(CACHE):
        with open(CACHE, 'rb') as f:
            return pickle.load(f)
    d = build()
    with open(CACHE, 'wb') as f:
        pickle.dump(d, f)
    return d


if __name__ == '__main__':
    d = load()
    print('entries %d  maxlen %d' % (len(d['ids']), d['maxlen']))
    print('noise const histogram:', collections.Counter(d['consts'].values()).most_common())
    print('R size %d' % len(d['R']))
    print('R[:80]:', d['R'][:80])
    print('gap histogram:', collections.Counter(d['gaps']).most_common())
    for i in (4485, 52090, 9990, 3833, 49, 122, 3829):
        if i not in d['entries']:
            continue
        b = d['entries'][i]
        det = sum(d['masks'][i])
        nreal = sum(1 for p in d['R'] if p < len(b))
        print('id %-6d len %-5d c=%d detected=%d  R<len=%d' %
              (i, len(b), d['consts'][i], det, nreal))
