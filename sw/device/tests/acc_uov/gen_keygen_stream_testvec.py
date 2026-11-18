#!/usr/bin/env python3
"""Emit the host-side test vector for the chip-level streamed keygen test.

Streamed keygen hands the public map back one column window at a time; the host
folds the transpose and packs cpk. Both the input seed and the expected cpk come
from the KAT, so the chip result is checked against the spec rather than against
the simulator.

Ip and Ip3 (GF256) keep each column entry in a 64 B slot. Is (GF16) packs its 32 B
entries exactly, with no slot padding, and needs an even column count in a short
last window.

Usage (from repo root):
  python3 sw/device/tests/acc_uov/gen_keygen_stream_testvec.py --param Ip --case 0 \\
      --elf bazel-bin/.../ov_Ip_keygen_stream_bngfaes.elf > sw/device/tests/acc_uov/keygen_stream_ip_bngfaes_testvec.h
"""
import argparse
import contextlib
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(_HERE, '..', '..', '..', '..'))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, 'sw/acc/crypto/handwritten/own_utils'))

from ov_params import OV_IP, OV_IP3, OV_IS
from ov_pk_utils import parse_pkc_test_data_file

PARAMS = {'Ip': OV_IP, 'Ip3': OV_IP3, 'Is': OV_IS}


# Slice geometry is derived from the ELF, never hardcoded: the tiers differ
# (sw shrinks the window to make room for the T-table) and a stale constant here
# would silently mis-stride every read the driver makes.
def slice_geometry(elf, oil_dim):
    out = subprocess.run(
        [sys.executable, os.path.join(REPO, 'hw/ip/acc/util/acc_objdump.py'), '-t', elf],
        capture_output=True, text=True, check=True).stdout
    sym = {}
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 5 and f[-1] in ('slice', 'slice_end'):
            sym[f[-1]] = int(f[0], 16)
    return sym['slice'], (sym['slice_end'] - sym['slice']) // oil_dim


def carr(name, data, per_line=12):
    out = [f'static const uint8_t {name}[{len(data)}] = {{']
    for i in range(0, len(data), per_line):
        out.append('    ' + ' '.join(f'0x{b:02x},' for b in data[i:i + per_line]))
    out.append('};')
    return '\n'.join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--case', type=int, default=0, help='KAT case index')
    ap.add_argument('--param', choices=sorted(PARAMS), default='Ip')
    ap.add_argument('--elf', required=True, help='the ELF whose geometry to emit')
    a = ap.parse_args()

    p = PARAMS[a.param]
    slot = 32 if a.param == 'Is' else 64
    src = os.path.join(REPO, 'sw/acc/crypto/handwritten/test_data',
                       f'testvectors-{a.param}-pkc-skc')
    # The parser narrates to stdout, which would land in the header.
    with contextlib.redirect_stdout(sys.stderr):
        cases = parse_pkc_test_data_file(src, p)
    cpk, sk_seed, _msg, _sig = cases[a.case]

    cpk = bytes(cpk)
    o = p.o
    slots = o * (o + 1) // 2
    if len(cpk) != 16 + slots * p.pub_m_byte:
        raise SystemExit(f'cpk is {len(cpk)} B, expected {16 + slots * p.pub_m_byte}')

    slice_addr, kstride = slice_geometry(a.elf, o)
    wj = kstride // slot
    if a.param == 'Is' and o % wj and (o % wj) % 2:
        raise SystemExit(f'short window {o % wj} is odd; kernel needs even col_count')

    print('// Generated test data for the chip-level streamed keygen test.')
    print(f'// UOV-{a.param}, case {a.case}. Do not hand-edit.')
    print('#pragma once')
    print('#include <stdint.h>')
    print()
    print(f'enum {{ kOilDim = {o}, kEntry = {p.pub_m_byte}, kSlots = {slots},')
    print(f'       kSliceAddr = 0x{slice_addr:x}, kStride = {kstride}, kWj = {wj} }};')
    print()
    print(carr('kSkSeed', bytes(sk_seed)))
    print()
    print(carr('kPkSeed16', cpk[:16]))
    print()
    print('// Folded upper-triangular P3, exactly as the host must assemble it.')
    print(carr('kP3Expected', cpk[16:]))


if __name__ == '__main__':
    main()
