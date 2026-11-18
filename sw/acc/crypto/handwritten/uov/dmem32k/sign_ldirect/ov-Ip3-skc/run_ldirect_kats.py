#!/usr/bin/env python3
"""Runs the gf256_ldirect_74_45 KAT sweep (cases in gen_ldirect_test_inputs.py).

Per case: regen inputs -> bazel build -> ISS -> compare ld_L_out against the
python reference in ldirect_expected.bin (45 columns x 64 B, low 45 valid).
The inputs carry O in the padded-96 layout with NONZERO slack, so a consumer
that reads past a column's 74 valid bytes fails here instead of silently
multiplying zero.

The sweep rewrites ldirect_test_inputs.s case by case and puts the file back
as it found it. Run from the repo root:
  python3 sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip3-skc/run_ldirect_kats.py --cases 0-9 --tier sw
"""
import argparse, subprocess, sys, os
from elftools.elf.elffile import ELFFile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), *['..'] * 8))
DIR = 'sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip3-skc'
sys.path[:0] = [ROOT, f'{ROOT}/sw/acc/crypto/handwritten/own_utils',
                f'{ROOT}/hw/ip/acc/dv/accsim']
EXPECTED = f'{ROOT}/{DIR}/ldirect_expected.bin'
EXPECTED_Y = f'{ROOT}/{DIR}/ldirect_expected_y.bin'
O_COLS, M = 45, 45

TIERS = {'bngfaes': 'ldirect_kat_test_bngfaes',
         'bngfonly': 'ldirect_kat_test_bngfonly',
         'sw': 'ldirect_kat_test_sw'}


def sh(cmd):
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if r.returncode:
        print(r.stdout[-3000:], r.stderr[-3000:])
        raise SystemExit(f'FAILED: {" ".join(cmd)}')
    return r.stdout


def sym_addr(elf_path, name):
    with open(elf_path, 'rb') as f:
        s = ELFFile(f).get_section_by_name('.symtab').get_symbol_by_name(name)
        return s[0]['st_value']


def read_symbol(dmem, elf, name, size):
    """size bytes at a symbol of the DMEM dump; a read past its end fails (the shared helper would pad with zeros)."""
    addr = sym_addr(elf, name)
    assert 0 <= addr and addr + size <= len(dmem), \
        f'{name} at {addr:#x} + {size} B is outside the {len(dmem)} B DMEM dump'
    from dmem_utils import extract_bytes_from_dmem
    return extract_bytes_from_dmem(dmem, addr, size)


def run_case(c, target):
    sh([sys.executable, f'{DIR}/gen_ldirect_test_inputs.py', '--case', str(c)])
    sh(['./bazelisk.sh', 'build', f'//{DIR}:{target}'])
    elf = f'{ROOT}/bazel-bin/{DIR}/{target}.elf'
    from acc_sim_utils import run_acc_test
    ok, dmem, stats = run_acc_test(elf)
    assert ok, f'case {c}: sim did not complete cleanly'
    got = read_symbol(dmem, elf, 'ld_L_out', 64 * O_COLS)
    want = open(EXPECTED, 'rb').read()
    bad = [i for i in range(64 * O_COLS) if got[i] != want[i]]
    tag = f'case {c} [{target}]'
    if bad:
        i = bad[0]
        print(f'{tag}: FAIL - {len(bad)} L bytes differ, first at col {i//64} '
              f'byte {i%64}: got {got[i]:#04x} want {want[i]:#04x}')
        return False
    # y = vin^T P1 vin, fused into the same P1 pass and checked nowhere else
    gy = read_symbol(dmem, elf, 'ld_y_out', 64)
    wy = open(EXPECTED_Y, 'rb').read()
    if gy[:M] != wy[:M]:
        i = next(k for k in range(M) if gy[k] != wy[k])
        print(f'{tag}: FAIL - y differs at byte {i}: '
              f'got {gy[i]:#04x} want {wy[i]:#04x}')
        return False
    # y's pad is NOT cosmetic: the sign orchestrator ORs the oil slot into the
    # signature, so a dirty byte at oil[45..53] lands on the salt. Gate it.
    if gy[M:] != bytes(64 - M):
        print(f'{tag}: FAIL - y pad {M}..63 NONZERO ({gy[M:].hex()}); the sign '
              f'assembly ORs oil[{M}..53] into the salt word')
        return False
    print(f'{tag}: PASS - {O_COLS} L columns + y match, y pad {M}..63 zero')
    return True


def main():
    from acc_sim_utils import parse_cases
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--cases', type=parse_cases, default=[0], metavar='LIST',
                    help='KAT cases: 0, 0,3 or 0-9 (default 0)')
    ap.add_argument('--tier', choices=sorted(TIERS), default='bngfaes', help='kernel tier (default bngfaes)')
    a = ap.parse_args()
    inputs = f'{ROOT}/{DIR}/ldirect_test_inputs.s'
    with open(inputs, 'rb') as fh:
        before = fh.read()
    try:
        ok = all([run_case(c, TIERS[a.tier]) for c in a.cases])
    finally:
        with open(inputs, 'wb') as fh:
            fh.write(before)
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
