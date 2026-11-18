#!/usr/bin/env python3
"""Emit the host-side test vector for the chip-level streamed verify test.

The streamed verify feeds cpk to ACC in row-aligned windows because cpk (43,576 B
for Ip) never fits the 31,744 B bus window. The host therefore has to hold it,
so it is emitted here as Ibex rodata rather than linked into the ACC app.

Ip only. Is needs a different DMEM layout, a 32 B entry stride and at least three
windows, none of which this emitter handles.

Usage (from repo root):
  python3 sw/device/tests/gen_verify_ip_testvec.py --case 0 \\
      --elf bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k/verify_stream_uniform/ov-Ip-pkc/ \\
            ov-Ip-verify_stream_uniform_bngfaes.elf \\
      > sw/device/tests/acc_uov/verify_ip_testvec.h
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

from ov_params import OV_IP, OV_IP3
from ov_pk_utils import parse_pkc_test_data_file

SPLIT = 13          # 2-window split: rows 0..12 | 13..o-1 (Ip and Ip3 alike)
# Host map per param. Ip3's 135-B signature takes a 160-B slot, so seed and the
# window sit 32 B above the Ip addresses; its windows must be written as exactly
# msgwin bytes (no slack: the bngfonly caprows/AES constants sit right after).
LAYOUT = {'Ip': dict(sig=0xE0, seed=0x160, msg=0x180, sigslot=128, slack=512),
          'Ip3': dict(sig=0xE0, seed=0x180, msg=0x1A0, sigslot=160, slack=None)}
BUS_WINDOW = 31744
BLOCK = 32          # kernel loads windows in 32B blocks


def window_cap(elf):
    """Bytes a P3 window may occupy, from the ELF: winend - msgwin.

    The stream_uniform arms link the backend's .data straight after winend, so a
    window sized past it silently corrupts the capacity table and the kernel
    rejects a valid signature - which reads as a crypto failure, not a bounds
    bug. Ip's schedule is an exact fit at 22,368 B, so any layout change here
    is a silent overrun; pass --elf to catch it.
    """
    if not elf:
        return None
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
    raise SystemExit('--elf exports no msgwin/winend (deployed streamed kernels '
                     'have none) - point it at a stream_uniform ELF, whose window '
                     'reservation is what bounds this schedule')


def entry_offset(oil_count, row):
    """Packed P3 entries before `row` (the map is triangular)."""
    return sum(oil_count - r for r in range(row))


def pad_window(data, slack, cap):
    """Ip: round up to a block and add read-ahead slack, as the ISS harness does.
    Ip3: exactly the kernel's msgwin (the R3 ISS driver does the same)."""
    if slack is None:
        return bytes(data) + bytes(cap - len(data))
    return bytes(data) + bytes(-len(data) % BLOCK + slack)


def carr(name, data, per_line=12):
    out = [f'static const uint8_t {name}[{len(data)}] = {{']
    for i in range(0, len(data), per_line):
        out.append('    ' + ' '.join(f'0x{b:02x},' for b in data[i:i + per_line]))
    out.append('};')
    return '\n'.join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--case', type=int, default=0, help='msglen case index')
    ap.add_argument('--param', choices=['Ip', 'Ip3'], default='Ip')
    ap.add_argument('--elf', required=True,
                    help='target ELF; its winend-msgwin bounds the windows')
    a = ap.parse_args()

    p = OV_IP3 if a.param == 'Ip3' else OV_IP
    L = LAYOUT[a.param]
    # 12 cases, 3 lines each: cpk / sk_seed / sm (message || signature).
    src = os.path.join(REPO, 'sw/acc/crypto/handwritten/test_data',
                       f'testvectors-{a.param}-pkc-skc')

    # The parser narrates to stdout, which would land in the header.
    with contextlib.redirect_stdout(sys.stderr):
        cases = parse_pkc_test_data_file(src, p)
    cpk, _sk, msg, sig = cases[a.case]

    oil_count, vinegar = p.o, p.v
    oil_vec = bytes(sig[:p.pub_n_byte])[vinegar:vinegar + oil_count]
    split_entry = entry_offset(oil_count, SPLIT)

    # Entry stride is pub_m_byte, NOT o: they coincide for Ip (GF256, 44) but Is
    # packs GF16 nibbles, so o=64 while the stride is 32.
    stride = p.pub_m_byte
    cap = window_cap(a.elf)
    if L['slack'] is None and cap is None:
        raise SystemExit('Ip3 windows are sized to the kernel msgwin: pass an --elf that exports it')
    w1 = pad_window(cpk[0:16 + split_entry * stride], L['slack'], cap)
    w2 = pad_window(bytes(16) + bytes(cpk[16 + split_entry * stride:]), L['slack'], cap)
    for tag, w in (('window 1', w1), ('window 2', w2)):
        if L['msg'] + len(w) > BUS_WINDOW:
            raise SystemExit(f"{tag} ends at {L['msg'] + len(w)}, over the {BUS_WINDOW} B window")
        if cap is not None and len(w) > cap:
            raise SystemExit(f'{tag} is {len(w)} B, over the kernel cap of {cap} B')

    print('// Generated test data for the chip-level streamed verify test.')
    print(f'// UOV-{a.param}, case {a.case}, msglen {len(msg)}. Do not hand-edit.')
    print('#pragma once')
    print('#include <stdint.h>')
    print()
    print(f'enum {{ kMsgLen = {len(msg)}, kSplitEntry = {split_entry},')
    print(f'       kOilCount = {oil_count}, kSplit = {SPLIT},')
    print(f'       kWindow1Bytes = {len(w1)}, kWindow2Bytes = {len(w2)},')
    print(f"       kSigAddr = 0x{L['sig']:X}, kSeedAddr = 0x{L['seed']:X}, kMsgAddr = 0x{L['msg']:X},")
    print(f"       kSigBytes = {len(sig)}, kSigSlot = {L['sigslot']} }};")
    print()
    print(carr('kSigData', bytes(sig).ljust(L['sigslot'], b'\0')))
    print()
    print(carr('kSeed16', bytes(cpk[:16])))
    print()
    print(carr('kOilVec1', oil_vec.ljust(64, b'\0')))
    print()
    print(carr('kOilVec2', oil_vec[SPLIT:].ljust(64, b'\0')))
    print()
    print(carr('kWindow1', w1))
    print()
    print(carr('kWindow2', w2))
    print()
    # Always emitted: the driver guards with a runtime if, which still
    # needs the symbol. One dummy byte when the message is empty.
    print(carr('kMsgData', bytes(msg) if msg else b'\0'))


if __name__ == '__main__':
    main()
