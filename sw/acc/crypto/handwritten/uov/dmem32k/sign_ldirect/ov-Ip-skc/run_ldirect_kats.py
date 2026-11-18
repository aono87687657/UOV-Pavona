#!/usr/bin/env python3
"""Runs the gf256_ldirect_68_44 edge-case KAT sweep (cases in gen_ldirect_test_inputs.py).

Per case: regen inputs -> bazel build -> ISS -> compare ld_L_out against the
python reference in ldirect_expected.bin (44 columns x 64 B; the kernel zeroes
the whole 4096-B region).

The sweep rewrites ldirect_test_inputs.s case by case and puts the file back
as it found it. Run from the repo root:
  python3 sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip-skc/run_ldirect_kats.py --cases 0-9
"""
import argparse, subprocess, sys, os
from elftools.elf.elffile import ELFFile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), *['..'] * 8))
DIR = 'sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip-skc'
sys.path[:0] = [ROOT, f'{ROOT}/sw/acc/crypto/handwritten/own_utils',
                f'{ROOT}/hw/ip/acc/dv/accsim']
ELF = f'{ROOT}/bazel-bin/{DIR}/ldirect_kat_test_bngfaes.elf'
EXPECTED = f'{ROOT}/{DIR}/ldirect_expected.bin'
L_BUF = 4096


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


def run_case(c):
    sh([sys.executable, f'{DIR}/gen_ldirect_test_inputs.py', '--case', str(c)])
    sh(['./bazelisk.sh', 'build', f'//{DIR}:ldirect_kat_test_bngfaes'])
    from acc_sim_utils import run_acc_test
    ok, dmem, _ = run_acc_test(ELF)
    assert ok, f'case {c}: sim did not complete cleanly'
    got = read_symbol(dmem, ELF, 'ld_L_out', L_BUF)
    want = open(EXPECTED, 'rb').read()
    assert len(want) == 2816
    want += bytes(L_BUF - len(want))
    bad = [i for i in range(L_BUF) if got[i] != want[i]]
    if bad:
        i = bad[0]
        print(f'case {c}: FAIL - {len(bad)} L bytes differ, first at {i}: '
              f'got {got[i]:#04x} want {want[i]:#04x}')
        return False
    print(f'case {c}: PASS')
    return True


def main():
    from acc_sim_utils import parse_cases
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--cases', type=parse_cases, default=parse_cases('0-9'), metavar='LIST',
                    help='KAT cases: 0, 0,3 or 0-9 (default 0-9)')
    a = ap.parse_args()
    inputs = f'{ROOT}/{DIR}/ldirect_test_inputs.s'
    with open(inputs, 'rb') as fh:
        before = fh.read()
    try:
        results = [run_case(c) for c in a.cases]
    finally:
        with open(inputs, 'wb') as fh:
            fh.write(before)
    print(f'{sum(results)}/{len(results)} PASS')
    sys.exit(0 if all(results) else 1)


if __name__ == '__main__':
    main()
