#!/usr/bin/env python3
"""Shared helper: load the FlareCalc ASN.1 table straight from the executable."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parse_table import PE, find_extension_table, parse_entries   # noqa: E402

_CACHE = None


def load_entries():
    """-> list of (node id, blob bytes) in table order."""
    global _CACHE
    if _CACHE is None:
        raw = open(PE, 'rb').read()
        off, table = find_extension_table(raw)
        _CACHE = parse_entries(table)
    return _CACHE


def load_dict():
    return dict(load_entries())


if __name__ == '__main__':
    e = load_entries()
    print('records: %d' % len(e))
    print('id range %d..%d' % (min(x[0] for x in e), max(x[0] for x in e)))
