#!/usr/bin/env python3
"""Emit the host-side test vector for the chip-level streamed verify test, UOV-Is.

Is differs from Ip in every host-visible dimension: DMEM layout, a 32 B packed
entry (GF16 nibbles, so pub_m_byte not o), and at least three windows - 2,080
entries at 32 B is 66,560 B, which no two windows can carry.

The oil vector is nibble-aligned per window, so the shifts are done here and the
driver just writes bytes.

Usage (from repo root):
  python3 sw/device/tests/acc_uov/gen_verify_is_testvec.py --case 11 \\
      > sw/device/tests/acc_uov/verify_stream_is_testvec.h        # streamed (deployed)
  python3 sw/device/tests/acc_uov/gen_verify_is_testvec.py --case 11 \\
      --elf bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k/verify_stream_uniform/ov-Is-pkc/ov-Is-verify_stream_uniform_bngfaes.elf \\
      > sw/device/tests/acc_uov/verify_stream_uniform_is_testvec.h     # stream_uniform-bounded
"""
import argparse
import subprocess
import contextlib
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(_HERE, '..', '..', '..', '..'))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, 'sw/acc/crypto/handwritten/own_utils'))

from ov_params import OV_IS
from ov_pk_utils import parse_pkc_test_data_file
from gf_arithmetic import gfv_get_ele_gf16

MSG = 0x100              # window base, per the Is kernel's host contract
BUS_WINDOW = 31744
DEFAULT_WINDOW_BYTES = 30 * 1024   # kernels that export no winend/msgwin pair


def window_cap(elf):
    """Bytes a P3 window may occupy, from the ELF: winend - msgwin.

    The stream_uniform arms link the backend's .data straight after winend, so a
    schedule sized for the deployed kernel (which has none) silently corrupts
    it - the kernel then rejects a valid signature and the driver reads that as
    a crypto failure. The deployed kernels export neither symbol; they keep the
    default.
    """
    if not elf:
        return DEFAULT_WINDOW_BYTES
    out = subprocess.run(
        [sys.executable, os.path.join(REPO, 'hw/ip/acc/util/acc_objdump.py'), '-t', elf],
        capture_output=True, text=True, check=True).stdout
    sym = {}
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 5 and f[-1] in ('msgwin', 'winend'):
            sym[f[-1]] = int(f[0], 16)
    if 'msgwin' in sym and 'winend' in sym:
        return sym['winend'] - sym['msgwin']
    return DEFAULT_WINDOW_BYTES
MASK256 = (1 << 256) - 1


def entry_offset(oil_count, row):
    return sum(oil_count - r for r in range(row))


def maxfill_schedule(oil_count, m_bytes, max_window_bytes):
    """Greedy row-aligned windows, each <= max_window_bytes of entries."""
    max_entries = max_window_bytes // m_bytes
    schedule, row = [], 0
    while row < oil_count:
        entries = rows = 0
        probe = row
        while probe < oil_count and entries + (oil_count - probe) <= max_entries:
            entries += oil_count - probe
            rows += 1
            probe += 1
        schedule.append((row, rows or 1))
        row += rows or 1
    return schedule


def pack_oil(sig_x, p):
    """Oil part of the signature, one GF16 nibble per element."""
    val = 0
    for k in range(p.o):
        val |= (gfv_get_ele_gf16(sig_x, p.v + k) & 0xF) << (4 * k)
    return val


def carr(name, data, per_line=12):
    out = [f'static const uint8_t {name}[{len(data)}] = {{']
    for i in range(0, len(data), per_line):
        out.append('    ' + ' '.join(f'0x{b:02x},' for b in data[i:i + per_line]))
    out.append('};')
    return '\n'.join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--case', type=int, default=0, help='KAT case index')
    ap.add_argument('--elf', default=None,
                    help='target ELF; its winend-msgwin bounds the windows')
    a = ap.parse_args()

    p = OV_IS
    src = os.path.join(REPO, 'sw/acc/crypto/handwritten/test_data',
                       'testvectors-Is-pkc-skc')
    with contextlib.redirect_stdout(sys.stderr):
        cases = parse_pkc_test_data_file(src, p)
    cpk, _sk, msg, sig = cases[a.case]

    m_bytes = p.pub_m_byte
    seed = bytes(cpk[:p.pkc_seed_size])
    p3 = bytes(cpk[p.pkc_seed_size:])
    oil_vec = pack_oil(bytes(sig[:p.pub_n_byte]), p)
    sched = maxfill_schedule(p.o, m_bytes, window_cap(a.elf))

    windows, oils = [], []
    for row_start, row_count in sched:
        start = entry_offset(p.o, row_start)
        n = sum(p.o - r for r in range(row_start, row_start + row_count))
        # No 16 B prefix here: unlike Ip, the Is kernel reads entries at MSG+0.
        w = p3[start * m_bytes:(start + n) * m_bytes]
        if MSG + len(w) > BUS_WINDOW:
            raise SystemExit(f'window at row {row_start} ends past the bus window')
        windows.append(w)
        oils.append(((oil_vec >> (4 * row_start)) & MASK256).to_bytes(32, 'little'))

    print('// Generated test data for the chip-level streamed verify test, UOV-Is.')
    print(f'// case {a.case}, msglen {len(msg)}. Do not hand-edit.')
    print('#pragma once')
    print('#include <stdint.h>')
    print()
    print(f'enum {{ kIsMsgLen = {len(msg)}, kIsOilCount = {p.o},')
    print(f'       kIsEntry = {m_bytes}, kIsWindows = {len(sched)} }};')
    print()
    print('// {row_start, row_count} per window, and each window\'s byte length.')
    print('static const uint32_t kIsSched[%d][3] = {' % len(sched))
    for (rs, rc), w in zip(sched, windows):
        print(f'    {{{rs}, {rc}, {len(w)}}},')
    print('};')
    print()
    print(carr('kIsSig', bytes(sig[:96])))
    print()
    print(carr('kIsSeed32', seed + bytes(16)))
    print()
    for i, o in enumerate(oils):
        print(carr(f'kIsOil{i}', o))
        print()
    for i, w in enumerate(windows):
        print(carr(f'kIsWindow{i}', w))
        print()
    # Always emitted: the driver guards with a runtime if, which still
    # needs the symbol. One dummy byte when the message is empty.
    print(carr('kIsMsgData', bytes(msg) if msg else b'\0'))


if __name__ == '__main__':
    main()
