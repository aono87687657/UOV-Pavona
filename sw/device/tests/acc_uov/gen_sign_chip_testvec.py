#!/usr/bin/env python3
"""Emit the expected signature for the chip-level sign test.

The signature depends only on the parameter set, not the tier: all three tiers
compute the same value by different means, which is the point of the ablation.
So one header per param serves its three cells.

Usage (from repo root):
  python3 sw/device/tests/gen_sign_chip_testvec.py --param Ip \\
      > sw/device/tests/acc_uov/sign_ip_testvec.h
"""
import argparse
import contextlib
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(_HERE, '..', '..', '..', '..'))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, 'sw/acc/crypto/handwritten/own_utils'))

from ov_params import OV_IP, OV_IP3, OV_IS
from ov_pk_utils import parse_pkc_test_data_file


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--param', choices=['Ip', 'Is', 'Ip3'], required=True)
    ap.add_argument('--case', type=int, default=0, help='KAT case index')
    a = ap.parse_args()

    p = {'Ip': OV_IP, 'Is': OV_IS, 'Ip3': OV_IP3}[a.param]
    src = os.path.join(REPO, 'sw/acc/crypto/handwritten/test_data',
                       f'testvectors-{a.param}-pkc-skc')
    with contextlib.redirect_stdout(sys.stderr):
        cases = parse_pkc_test_data_file(src, p)
    _cpk, sk, msg, sig = cases[a.case]

    sig = bytes(sig)
    sk = bytes(sk)
    if len(sig) != p.signature_bytes:
        raise SystemExit(f'sig is {len(sig)} B, expected {p.signature_bytes}')
    if len(msg) != 0:
        raise SystemExit(f'case {a.case} has msglen {len(msg)}, expected 0')
    if len(sk) != 32:
        raise SystemExit(f'sk_seed is {len(sk)} B, expected 32 (skc format)')

    # The kernel's sig slot is the signature rounded up to 32 B (Ip 128, Is 96,
    # Ip3 135 -> 160); the driver writes and reads whole slots, compares kSigBytes.
    slot = -(-len(sig) // 32) * 32

    def emit(name, b):
        print(f'static const uint8_t {name}[{len(b)}] = {{')
        for i in range(0, len(b), 12):
            print('    ' + ' '.join(f'0x{x:02x},' for x in b[i:i + 12]))
        print('};')

    print('// Generated test data for the chip-level sign test.')
    print(f'// UOV-{a.param}, case {a.case} (msglen 0). Do not hand-edit.')
    print('#pragma once')
    print('#include <stdint.h>')
    print()
    print(f'enum {{ kSigBytes = {len(sig)}, kSigSlot = {slot} }};   // x + 16 B salt; slot = 32 B multiple')
    print(f'enum {{ kMsgLen = {len(msg)} }};')
    print()
    emit('kSigExpected', sig.ljust(slot, b'\0'))
    print()
    print('// Host-injected inputs: the driver writes these over TL-UL after the')
    print('// app load, mirroring the keygen/verify input path. The salt input is')
    print('// the last 16 B of the signature the driver writes into the sig slot.')
    emit('kSkSeed', sk)


if __name__ == '__main__':
    main()
