#!/usr/bin/env python3
"""R3 Ip3 verify window-schedule model, m=45. Registered 2026-08-16.

Standalone check of the four settled numbers: caprows_45, the refill law,
the host split, and msgwin_45. No repo imports (own_utils is off limits
while a KAT run has it loaded) - cap_rows is copied verbatim.

Usage: python3 window_model.py
"""
import argparse
import sys

O = 45
N = 66
CAP_ENTRIES = 8 * N


def cap_rows(o, cap_entries):
    """caps[s] = max c <= o-s with c*(2*o - 2*s - c + 1)//2 <= cap_entries.

    R2 admission convention (entries, not bytes). The sum is strictly
    increasing in c over the valid range, so first miss ends the scan.
    """
    caps = []
    for s in range(o):
        best = 0
        for c in range(1, o - s + 1):
            val = c * (2 * o - 2 * s - c + 1) // 2
            if val > cap_entries:
                break
            best = c
        caps.append(best)
    return caps


def refills(e):
    """Fired-refill law: 4 entries land in the UPDATE prologue prefetch,
    a trailing refill fires when the last entry completes an 8-group."""
    return (e + 4) // 8


def align32(x):
    return (x + 31) // 32 * 32


def entries(rs, rc, o=O):
    """E(rs,rc): row count admitted by window [rs, rs+rc)."""
    return sum(o - i for i in range(rs, rs + rc))


def greedy_split(caps):
    windows = []
    s = 0
    while s < len(caps):
        rc = caps[s]
        if rc == 0:
            raise ValueError("stuck at row %d, cap 0" % s)
        windows.append((s, rc))
        s += rc
    return windows


def main():
    caprows_45 = cap_rows(O, CAP_ENTRIES)
    print("caprows_45 = " + ", ".join(str(c) for c in caprows_45))

    assert caprows_45[0] == 13
    assert caprows_45[13] == 32
    assert caprows_45[12] == 25

    windows = greedy_split(caprows_45)
    assert windows == [(0, 13), (13, 32)]
    assert sum(rc for _, rc in windows) == O

    e_1332 = entries(13, 32)
    assert e_1332 == 528
    assert refills(e_1332) == N
    assert align32(196 + 360 * N) == 23968

    binding = []
    for rs in range(O):
        rc = caprows_45[rs]
        e = entries(rs, rc)
        if refills(e) == N:
            read_end = 196 + 360 * refills(e)
            binding.append((rs, rc, e, read_end))

    print("binding-touch cells (refills == %d):" % N)
    for rs, rc, e, read_end in binding:
        print("  (rs=%d, rc=%d, E=%d) read_end=%d" % (rs, rc, e, read_end))
    assert len(binding) == 6

    print("OK")


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__,
                            formatter_class=argparse.RawDescriptionHelpFormatter).parse_args()
    try:
        main()
    except AssertionError:
        print("FAIL", file=sys.stderr)
        sys.exit(1)
