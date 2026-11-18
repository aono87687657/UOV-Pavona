"""The host driver of the streamed UOV-PKC verify (Ip, Is, Ip3): the KAT check with per-phase cycles, and a
functional check.

The streamed verify is one ACC binary, loaded once, then executed per phase:
INIT -> UPDATE x K -> FINAL. The {acc, oil, target} context lives in DMEM and
survives between phases (acc_execute does not wipe DMEM), so each phase reloads
what the previous one spilled. This script drives that sequence in the ACC ISS.

--mode measure (default) reports per-phase and summed instruction/cycle counts per KAT case.
Cycles are ACC ISS cycles (instruction + stall); host dispatch / DMA latency is
not modelled. Each case must end with ctrl.status == 0 (accept) or the run
FAILs; INIT and UPDATE write only an error (-2, -3), which FINAL would overwrite, so the status is cleared before
INIT and a nonzero one after INIT or an UPDATE ends the case with it. Exit code is nonzero on any failure. --dump-stats writes the summed count in
the KAT-sweep stats format plus per-phase comment lines. Ip3 also takes --phases (per-phase
lines), --negative (one signature byte flipped per case; every case must reject with status -1)
and --vectors.
--reject: flipped signature bits, another key and a corrupted key must reject.
--mode functional (Ip, Is) reads the accumulator back: it must equal the Python public map P(s)
bit for bit over the KAT cases (all 12 by default), and a corrupted signature must be rejected
(status -1).

Runs only on the 32 KiB DMEM profile. Build //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/... first.
Is windows are as large as the ELF allows: winend - msgwin when it exports them,
else the 30 KiB host contract of the deployed bngfaes arm (nothing linked in DMEM).
Ip3 vectors are `test_data/testvectors-Ip3-pkc-skc` (msglen 0..1024), recorded with a pre-release Round-3
reference implementation and confirmed by the Round-3 reference implementation; `.nistkat` is byte-exact
against the Round-3 known-answer tests of the submission package (test_data/README.md).

  python3 sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/tests/measure_cycles.py \\
    --param Is --cases 0,11 \\
    --elf bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/ov-Is-pkc/ov-Is-verify_stream_bngfaes.elf
  python3 sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/tests/measure_cycles.py --param Ip3 --negative
  python3 sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/tests/measure_cycles.py --mode functional --param Ip \\
    --elf bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/ov-Ip-pkc/ov-Ip-verify_stream_bngfaes.elf
"""

import argparse
import os
import re
import sys
import traceback

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), *['..'] * 8))
OWN = os.path.join(REPO, 'sw/acc/crypto/handwritten/own_utils')
sys.path.insert(0, OWN)
from ov_params import OV_IS, OV_IP, OV_IP3
from ov_pk_utils import parse_pkc_test_data_file, expand_compressed_pk
from gf_arithmetic import gfv_get_ele_gf16, ov_publicmap_reference
from ov_keygen_test_utils import _kg_objdump_syms

sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, 'hw/ip/acc/util'))
from acc_sim_utils import elf_tier, parse_cases, require_dmem_profile, setup_default_keys
from dmem_utils import bytes_to_dmem_words, inject_words_to_dmem, extract_bytes_from_dmem
from hw.ip.acc.dv.accsim.sim.standalonesim import StandaloneSim
from hw.ip.acc.dv.accsim.sim.load_elf import load_elf
from hw.ip.acc.dv.accsim.sim.stats import ExecutionStatAnalyzer
from shared.mem_layout import get_memory_layout

# Phase index, written to ctrl[0].
INIT, UPDATE, FINAL = 0, 1, 2

# DMEM byte offsets per parameter set (match the verify kernels' layout).
LAYOUT_IS = dict(CTRL=0x00, OIL=0x40, SIG=0x80, SEED=0xE0, MSG=0x100)
LAYOUT_IP = dict(CTRL=0x00, OIL=0x60, SIG=0xE0, SEED=0x160, MSG=0x180)
# Ip3: the 135-B sig takes a 160-B slot, so SEED and the P3 window sit 32 B above their Ip addresses.
LAYOUT_IP3 = dict(CTRL=0x00, OIL=0x60, SIG=0xE0, SEED=0x180, MSG=0x1A0)
SPLIT = 13                                    # the first UPDATE window holds rows 0..12 (Ip and Ip3)
# Every Ip3 window is written as EXACTLY msgwin bytes (data + zeros): the loader's
# refill overshoot reads up to that bound, and one byte more would land on the
# bngfonly arm's caprows/AES constants -- the Ip +512 slack happens to end
# exactly at ITS winend; at Ip3 sizes it corrupts .data and the capacity
# gate then rejects a good window.
MSGWIN_IP3 = 23968
ACC = 0x20                                    # the accumulator (Ip: 32 B in acc and the other 12 B right after it)

STAT_RE = re.compile(r'executed (\d+) instructions in (\d+) cycles')


def word32(addr, value):
    return bytes_to_dmem_words((value & 0xffffffff).to_bytes(4, 'little'), addr)


def zero_pad(data, length):
    return bytes(data) + bytes(max(0, length - len(data)))


def pad_to_multiple(data, multiple, slack=512):
    rounded = ((len(data) + multiple - 1) // multiple) * multiple
    return zero_pad(data, rounded + slack)


def entry_offset(oil_count, row):
    # upper-triangular P3 entries before this row (entry-major)
    return sum(oil_count - r for r in range(row))


def run_phase(sim, elf, words):
    require_dmem_profile(32768)
    inject_words_to_dmem(sim, words)
    setup_default_keys(sim)
    sim.start(collect_stats=True)
    sim.run(verbose=False, dump_file=None)
    err_bits = sim.state.ext_regs.read('ERR_BITS', False)
    if err_bits != 0:
        raise RuntimeError(f'ACC error during phase (ERR_BITS={err_bits:#x})')
    report = ExecutionStatAnalyzer(sim.stats, elf).dump()
    m = STAT_RE.search(report)
    if not m:
        raise RuntimeError('no instruction/cycle count in ISS stats report')
    return int(m.group(1)), int(m.group(2))


def read_status(sim, layout):
    dmem = sim.dump_data(include_validity=False)
    return int.from_bytes(extract_bytes_from_dmem(dmem, layout['CTRL'] + 12, 4),
                          'little', signed=True)


def window_cap(elf, base):
    """Bytes a P3 window written at `base` may occupy, taken from the ELF rather than a constant.

    The stream_uniform kernels and the deployed arms with data above the window
    export msgwin/winend, and anything the host writes past winend lands in that
    data. Is fails loudly when that happens; Ip overwrites scratch that is
    re-initialised later and passes anyway, so the violation is invisible there.
    The deployed bngfaes streamed arms export neither and link nothing in DMEM;
    they keep the 30 KiB host contract. Any other ELF without the pair is refused.
    """
    syms = _kg_objdump_syms(elf)
    pair = [s for s in ('msgwin', 'winend') if s in syms]
    if pair == ['msgwin', 'winend']:
        assert syms['msgwin'] == base, f"{elf}: msgwin {syms['msgwin']:#x}, the host writes the window at {base:#x}"
        cap = syms['winend'] - base
    else:
        assert not pair, f"{elf}: exports {pair[0]} without its pair"
        assert syms['_dmem_data_end'] == 0 and syms['_dmem_bss_end'] == 0 and elf_tier(syms) == 'bngfaes', \
            f"{elf}: no msgwin/winend, and not a bngfaes streamed arm with nothing linked in DMEM"
        cap = 30 * 1024
    bus = get_memory_layout().dmem_bus_size_bytes
    assert 0 < cap and base + cap <= bus, f"{elf}: window {base:#x} + {cap} B leaves the {bus} B bus window"
    return cap


def maxfill_schedule(oil_count, m_bytes, max_window_bytes):
    """Greedy row-aligned P3 windows, each <= max_window_bytes of entries.

    Returns a list of (row_start, row_count).
    """
    max_entries = max_window_bytes // m_bytes
    schedule = []
    row = 0
    while row < oil_count:
        entries, rows, probe = 0, 0, row
        while probe < oil_count and entries + (oil_count - probe) <= max_entries:
            entries += oil_count - probe
            rows += 1
            probe += 1
        if rows == 0:
            raise ValueError(f"row {row} has {oil_count - row} entries, a {max_window_bytes} B window holds {max_entries}")
        schedule.append((row, rows))
        row += rows
    return schedule


def measure_is(elf, cpk, sig, msg, p, sim=None):
    """GF16 (uov-Is): INIT, K maxfill UPDATE windows, FINAL. A caller that reads DMEM afterwards passes `sim`."""
    L = LAYOUT_IS
    oil_count, m_bytes, vinegar = p.o, p.pub_m // 2, p.v
    sig_x = sig[:p.pub_n_byte]

    # Pack the oil part of the signature, one GF16 nibble per element.
    oil_vec = 0
    for k in range(oil_count):
        oil_vec |= (gfv_get_ele_gf16(sig_x, vinegar + k) & 0xF) << (4 * k)

    p3 = cpk[16:]                            # P3 follows the 16-byte seed
    mask256 = (1 << 256) - 1
    schedule = maxfill_schedule(oil_count, m_bytes, window_cap(elf, L['MSG']))

    sim = StandaloneSim(pqc=True) if sim is None else sim
    load_elf(sim, elf)                       # load app once
    ti, tc, per_phase = 0, 0, []

    # INIT: msg length, signature, seed.
    words = dict(word32(L['CTRL'], INIT))
    words.update(word32(L['CTRL'] + 4, len(msg)))
    words.update(word32(L['CTRL'] + 12, 0))         # status: INIT leaves it unless an error
    words.update(bytes_to_dmem_words(bytes(sig), L['SIG']))
    words.update(bytes_to_dmem_words(bytes(cpk[:16]) + bytes(16), L['SEED']))
    if len(msg):
        words.update(bytes_to_dmem_words(pad_to_multiple(bytes(msg), 32, slack=0), L['MSG']))
    i, c = run_phase(sim, elf, words)
    per_phase.append(('INIT', i, c)); ti += i; tc += c
    if (st := read_status(sim, L)) != 0:
        return ti, tc, per_phase, st

    # UPDATE: fold one row-aligned P3 window per run; acc persists in DMEM.
    for (row_start, row_count) in schedule:
        start_entry = entry_offset(oil_count, row_start)
        win_entries = sum(oil_count - r for r in range(row_start, row_start + row_count))
        window = p3[start_entry * m_bytes:(start_entry + win_entries) * m_bytes]
        oil_aligned = ((oil_vec >> (4 * row_start)) & mask256).to_bytes(32, 'little')
        words = dict(word32(L['CTRL'], UPDATE))
        words.update(word32(L['CTRL'] + 4, row_start))
        words.update(word32(L['CTRL'] + 8, row_count))
        words.update(bytes_to_dmem_words(oil_aligned, L['OIL']))
        words.update(bytes_to_dmem_words(bytes(window), L['MSG']))
        i, c = run_phase(sim, elf, words)
        per_phase.append((f'UPD r{row_start}', i, c)); ti += i; tc += c
        if (st := read_status(sim, L)) != 0:
            return ti, tc, per_phase, st

    # FINAL: compare acc vs target.
    i, c = run_phase(sim, elf, dict(word32(L['CTRL'], FINAL)))
    per_phase.append(('FINAL', i, c)); ti += i; tc += c
    return ti, tc, per_phase, read_status(sim, L)


def measure_ip(elf, cpk, sig, msg, p, sim=None):
    """GF256 (uov-Ip): INIT, fixed 2-window split at row 13, FINAL. A caller that reads DMEM afterwards passes `sim`."""
    L = LAYOUT_IP
    oil_count, vinegar = p.o, p.v
    split_entry = entry_offset(oil_count, 13)
    oil_vec = bytes(sig[:p.pub_n_byte])[vinegar:vinegar + oil_count]   # GF256: 1 byte/elt

    sim = StandaloneSim(pqc=True) if sim is None else sim
    load_elf(sim, elf)
    ti, tc, per_phase = 0, 0, []

    # INIT
    words = dict(word32(L['CTRL'], INIT))
    words.update(word32(L['CTRL'] + 4, len(msg)))
    words.update(word32(L['CTRL'] + 12, 0))         # status: INIT leaves it unless an error
    words.update(bytes_to_dmem_words(bytes(sig), L['SIG']))
    words.update(bytes_to_dmem_words(bytes(cpk[:16]) + bytes(16), L['SEED']))
    if len(msg):
        words.update(bytes_to_dmem_words(pad_to_multiple(bytes(msg), 32, slack=0), L['MSG']))
    i, c = run_phase(sim, elf, words)
    per_phase.append(('INIT', i, c)); ti += i; tc += c
    if (st := read_status(sim, L)) != 0:
        return ti, tc, per_phase, st

    # Two windows: rows 0..12 (real seed-aligned prefix) and rows 13..43.
    windows = [
        (0, 13, bytes(cpk[0:16 + split_entry * 44])),
        (13, oil_count - 13, bytes(16) + bytes(cpk[16 + split_entry * 44:])),
    ]
    for (row_start, row_count, window) in windows:
        oil_aligned = zero_pad(oil_vec[row_start:], 64)
        words = dict(word32(L['CTRL'], UPDATE))
        words.update(word32(L['CTRL'] + 4, row_start))
        words.update(word32(L['CTRL'] + 8, row_count))
        words.update(bytes_to_dmem_words(oil_aligned, L['OIL']))
        words.update(bytes_to_dmem_words(pad_to_multiple(window, 32), L['MSG']))
        i, c = run_phase(sim, elf, words)
        per_phase.append((f'UPD r{row_start}', i, c)); ti += i; tc += c
        if (st := read_status(sim, L)) != 0:
            return ti, tc, per_phase, st

    i, c = run_phase(sim, elf, dict(word32(L['CTRL'], FINAL)))
    per_phase.append(('FINAL', i, c)); ti += i; tc += c
    return ti, tc, per_phase, read_status(sim, L)


def measure_ip3(elf, cpk, sig, msg, p, sim=None):
    """GF256 (uov-Ip3): INIT, fixed 2-window split at row 13 with MSGWIN_IP3-byte windows, FINAL."""
    L, o, v, m = LAYOUT_IP3, p.o, p.v, p.pub_m
    # the bound derives from the ELF: when it exports msgwin/winend (bngfonly arm), it must equal the padding
    cap = window_cap(elf, L['MSG'])
    assert cap in (MSGWIN_IP3, 30 * 1024), f"ELF window bound {cap} != {MSGWIN_IP3}"
    split_entry = entry_offset(o, SPLIT)
    oil = bytes(sig[:p.pub_n_byte])[v:v + o]         # GF256: one byte per element

    sim = StandaloneSim(pqc=True) if sim is None else sim
    load_elf(sim, elf)
    ti = tc = 0
    per = []

    words = dict(word32(L['CTRL'], INIT))
    words.update(word32(L['CTRL'] + 4, len(msg)))
    words.update(word32(L['CTRL'] + 12, 0))         # status: INIT leaves it unless an error
    # the 135-B sig sits in a 160-B slot and the salt read touches all of it;
    # DMEM read of an uninitialised byte is a fatal integrity error on HW
    words.update(bytes_to_dmem_words(zero_pad(sig, 160), L['SIG']))
    words.update(bytes_to_dmem_words(bytes(cpk[:16]) + bytes(16), L['SEED']))
    if len(msg):
        words.update(bytes_to_dmem_words(pad_to_multiple(bytes(msg), 32, slack=0), L['MSG']))
    i, c = run_phase(sim, elf, words); ti += i; tc += c; per.append(('INIT', i, c))
    if (st := read_status(sim, L)) != 0:
        return ti, tc, per, st

    # window 0 reuses the cpk's own 16-B seed as the prefix; window 1 fakes one
    windows = [(0, SPLIT, bytes(cpk[0:16 + split_entry * m])),
               (SPLIT, o - SPLIT, bytes(16) + bytes(cpk[16 + split_entry * m:]))]
    for row_start, row_count, window in windows:
        words = dict(word32(L['CTRL'], UPDATE))
        words.update(word32(L['CTRL'] + 4, row_start))
        words.update(word32(L['CTRL'] + 8, row_count))
        words.update(bytes_to_dmem_words(zero_pad(oil[row_start:], 64), L['OIL']))
        assert len(window) <= MSGWIN_IP3, (len(window), MSGWIN_IP3)
        words.update(bytes_to_dmem_words(zero_pad(window, MSGWIN_IP3), L['MSG']))
        i, c = run_phase(sim, elf, words); ti += i; tc += c
        per.append((f'UPD r{row_start}', i, c))
        if (st := read_status(sim, L)) != 0:
            return ti, tc, per, st

    i, c = run_phase(sim, elf, dict(word32(L['CTRL'], FINAL))); ti += i; tc += c
    per.append(('FINAL', i, c))
    return ti, tc, per, read_status(sim, L)


PARAMS = {
    'Is': (OV_IS, measure_is),
    'Ip': (OV_IP, measure_ip),
    'Ip3': (OV_IP3, measure_ip3),
}
BAZEL_BIN = os.path.join(REPO, 'bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k/verify_stream')


def vectors_of(name):
    return os.path.join(REPO, f'sw/acc/crypto/handwritten/test_data/testvectors-{name}-pkc-skc')


def streamed_verify(elf, cpk, sig, msg, param):
    """Run INIT -> UPDATE windows -> FINAL; return (accumulator, status, UPDATE runs). Ip and Is."""
    require_dmem_profile(32768)
    assert param in ('Ip', 'Is'), f'the functional check reads the Ip/Is accumulator, not {param}'
    p, measure = PARAMS[param]
    sim = StandaloneSim(pqc=True)
    _, _, per_phase, status = measure(elf, cpk, sig, msg, p, sim)
    dmem = sim.dump_data(include_validity=False)
    return (bytes(extract_bytes_from_dmem(dmem, ACC, p.pub_m_byte)), status,
            sum(name.startswith('UPD') for name, _, _ in per_phase))


def functional(a):
    """--mode functional: the accumulator against the public map over the cases, then a corrupted-signature reject."""
    p = PARAMS[a.param][0]
    testvecs = parse_pkc_test_data_file(a.vectors, p)
    missing = [c for c in a.cases if c >= len(testvecs)]
    if missing:
        sys.exit(f"--cases {missing}: the KAT file has cases 0-{len(testvecs) - 1}")
    overall = True

    for case in a.cases:
        cpk, _sk, msg, sig = testvecs[case]
        full = expand_compressed_pk(cpk, p)
        expected = bytes(ov_publicmap_reference(full, sig[:p.pub_n_byte], p.pub_n, p.pub_m, p.v, field=f'gf{p.gf}'))
        acc, status, runs = streamed_verify(a.elf, cpk, sig, msg, a.param)
        acc_ok = acc == expected
        ok = acc_ok and status == 0
        overall &= ok
        print(f"  {p.name} case{case:<2d}  {runs} UPDATE runs  acc==P(s):{'OK' if acc_ok else 'XX'}  "
              f"status={status} ({'ACCEPT' if status == 0 else 'reject'}) -> {'PASS' if ok else 'FAIL'}")
        if not acc_ok:
            print(f"     exp {expected.hex()}\n     got {acc.hex()}")

    # Negative control: a flipped signature byte must be rejected (-1), not end in a host-contract error.
    cpk, _sk, msg, sig = testvecs[0]
    bad = bytearray(sig)
    bad[0] ^= 0x10
    _, status, _ = streamed_verify(a.elf, cpk, bytes(bad), msg, a.param)
    rejected = status == -1
    overall &= rejected
    print(f"  negative control (corrupted sig) status={status} -> {'PASS (rejected)' if rejected else 'FAIL'}")

    print(f"\n{a.param.upper()} STREAMED VERIFY {'ALL PASS' if overall else 'FAILED'}")
    sys.exit(0 if overall else 1)


def flip(data, i, bit):
    out = bytearray(data)
    out[i] ^= bit
    return bytes(out)


def reject(a):
    """The mutations of test_full_verify.py must reject, the unchanged case must accept."""
    sys.path.insert(0, os.path.join(REPO, 'sw/acc/crypto/handwritten/uov/dmem_large/verify_full/tests'))
    import test_full_verify as full
    full.configure(a.param)
    p, measure = PARAMS[a.param]
    cases = [tuple(bytes(x) for x in c) for c in parse_pkc_test_data_file(a.vectors, p)]
    fails = []
    for n in a.cases:
        cpk, _sk, msg, sig = cases[n]
        others = [c for c in cases[n + 1:] + cases[:n] if c[0] != cpk]
        if not others:
            sys.exit(f"{a.vectors}: no case with another key than case {n}")
        cpk2, _sk2, msg2, sig2 = others[0]
        first, last = full.weighted_entries(sig)
        e = full.ENTRY
        runs = [('the unchanged signature', cpk, msg, sig)]
        runs += [(f'sig byte {b} ^ {bit:#04x}', cpk, msg, flip(sig, b, bit)) for b, bit in full.FLIPS]
        runs += [("the signature under the next key", cpk2, msg, sig),
                 ("the next key's signature under this key", cpk, msg2, sig2)]
        runs += [(f'the key corrupted at {what}', flip(cpk, off, 1), msg, sig)
                 for off, what in ((3, 'pk_seed byte 3'), (16 + first * e, f'P3 entry {first} byte 0'),
                                   (16 + last * e + e - 1, f'P3 entry {last} byte {e - 1}'))]
        for what, k, m, sg in runs:
            ref = full.ref_accepts(k, m, sg)
            status = measure(a.elf, k, sg, m, p)[3]
            ok = (status, ref) == ((0, True) if sg is sig and k is cpk and m is msg else (-1, False))
            print(f"  case {n:2d} {what}: status {status}, the reference {'accepts' if ref else 'rejects'}"
                  f" -> {'ok' if ok else 'FAIL'}")
            if not ok:
                fails.append((n, what))
    print(f"{a.param.upper()} STREAMED VERIFY REJECT {'PASS' if not fails else f'FAIL {fails}'}"
          f"  ({os.path.basename(a.vectors)})")
    sys.exit(1 if fails else 0)


def measure_ip3_cases(a):
    """--mode measure for Ip3: one line per case; with --negative every case must reject."""
    p = OV_IP3
    cases = parse_pkc_test_data_file(a.vectors, p)
    fails = []
    for n in a.cases:
        cpk, _sk, msg, sig = cases[n]
        if a.negative:                       # an accept-only suite proves nothing
            sig = bytearray(sig); sig[n % len(sig)] ^= 1
        ins, cyc, per, status = measure_ip3(a.elf, cpk, sig, msg, p)
        tag = "ACCEPT" if status == 0 else "REJECT (-1)" if status == -1 else f"ERROR ({status})"
        print(f"  case {n:2d}  msglen {len(msg):5d}  {ins:>9,} insns  {cyc:>9,} cyc  {tag}")
        if a.phases:
            for nm, pi, pc in per:
                print(f"      {nm:8s} {pi:>9,} insn  {pc:>9,} cyc")
        if a.dump_stats and status == 0 and not a.negative:
            with open(a.dump_stats, "w") as fh:
                fh.write(f"executed {ins} instructions in {cyc} cycles\n")
                for nm, pi, pc in per:
                    fh.write(f"# phase {nm}: {pi} insn {pc} cyc\n")
        if status != (-1 if a.negative else 0):   # -2 and -3 are errors, not a reject
            fails.append(n)
    want = "reject a corrupted signature" if a.negative else "accept"
    print((f"PASS - all cases {want}" if not fails else f"FAIL cases {fails}") +
          f"  ({os.path.basename(a.vectors)}; see PROVENANCE.md)")
    sys.exit(1 if fails else 0)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--mode', default='measure', choices=['measure', 'functional'],
                    help='measure: the KAT check with cycles (default); functional: the accumulator against the '
                         'public map, Ip and Is')
    ap.add_argument('--param', default='both', choices=['Ip', 'Is', 'Ip3', 'both'],
                    help='parameter set (default both = Ip and Is)')
    ap.add_argument('--cases', type=parse_cases, default=None, metavar='LIST',
                    help='KAT cases: 0, 0,11 or 0-11 (default 11; Ip3 0,11; functional 0-11, whose reject '
                         'check always runs on case 0)')
    ap.add_argument('--elf', default=None,
                    help='ELF to run (single --param only; default the bngfaes streamed ELF in bazel-bin)')
    ap.add_argument('--dump-stats', default=None, metavar='FILE',
                    help='write summed stats in KAT-sweep format (single param and case only)')
    ap.add_argument('--vectors', default=None, metavar='FILE',
                    help='vector file (single --param only; default test_data/testvectors-<param>-pkc-skc)')
    ap.add_argument('--phases', action='store_true', help='Ip3: per-phase lines')
    ap.add_argument('--negative', action='store_true',
                    help='Ip3: flip one signature byte per case; every case must reject (status -1)')
    ap.add_argument('--reject', action='store_true',
                    help='mutated signatures and keys must reject')
    a = ap.parse_args()

    if a.reject:
        if a.param == 'both' or not a.elf or a.mode != 'measure' or a.dump_stats or a.negative:
            ap.error('--reject takes a single --param and --elf, and no --mode, --dump-stats or --negative')
        a.cases = a.cases or parse_cases('0-11')
        a.vectors = vectors_of(a.param) if a.vectors is None else a.vectors
        reject(a)

    if a.param != 'Ip3' and (a.phases or a.negative):
        ap.error('--phases and --negative are Ip3 options (Ip and Is print the phases; their reject check '
                 'is --mode functional)')
    if a.vectors and a.param == 'both':
        ap.error('--vectors needs a single --param')
    if a.mode == 'functional':
        if a.param not in ('Ip', 'Is') or not a.elf or a.dump_stats:
            ap.error('--mode functional takes --param Ip or Is and --elf, and no --dump-stats')
        a.cases = a.cases or parse_cases('0-11')
        a.vectors = vectors_of(a.param) if a.vectors is None else a.vectors
        try:
            functional(a)
        except Exception:
            traceback.print_exc()
            sys.exit(2)
    if a.param == 'Ip3':
        a.cases = a.cases or [0, 11]
        if a.dump_stats and len(a.cases) != 1:
            ap.error('--dump-stats takes one case')
        if a.elf is None:   # an explicit path, even an empty one, is used as given
            a.elf = os.path.join(BAZEL_BIN, 'ov-Ip3-pkc', 'ov-Ip3-verify_stream_bngfaes.elf')
        a.vectors = vectors_of('Ip3') if a.vectors is None else a.vectors
        measure_ip3_cases(a)

    params = ['Ip', 'Is'] if a.param == 'both' else [a.param]
    cases = a.cases or [11]
    if a.elf and len(params) != 1:
        ap.error('--elf needs a single --param')
    if a.dump_stats and (len(params) != 1 or len(cases) != 1):
        ap.error('--dump-stats needs a single param and a single case')
    dump = open(a.dump_stats, 'w') if a.dump_stats else None   # up front: a bad path fails before the run

    failures = 0
    for name in params:
        p, measure = PARAMS[name]
        elf = a.elf or os.path.join(BAZEL_BIN, f'ov-{name}-pkc', f'ov-{name}-verify_stream_bngfaes.elf')
        testvecs = parse_pkc_test_data_file(vectors_of(name) if a.vectors is None else a.vectors, p)
        for case in cases:
            cpk, _sk, msg, sig = testvecs[case]
            ti, tc, per_phase, status = measure(elf, cpk, sig, msg, p)
            ok = status == 0
            failures += 0 if ok else 1
            print(f"\n{name} streamed verify, case {case} (msglen {len(msg)}):"
                  f" {'PASS' if ok else f'FAIL (status {status})'}")
            for phase, i, c in per_phase:
                print(f"   {phase:10s} {i:>8,} insn {c:>8,} cyc")
            print(f"   {'TOTAL':10s} {ti:>8,} insn {tc:>8,} cyc")
            if dump and ok:
                dump.write(f"executed {ti} instructions in {tc} cycles\n")
                for phase, i, c in per_phase:
                    dump.write(f"# phase {phase}: {i} insn {c} cyc\n")
    if dump:
        dump.close()
    if failures:
        print(f"\n!! {failures} FAIL")
        sys.exit(1)


if __name__ == '__main__':
    main()
