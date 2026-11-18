"""One-shot UOV keygen (keygen_min and keygen_sp; Ip, Is, Ip3): one EXECUTE per key against the recorded cpk,
and restarts on the same simulator without reloading the ELF.

Symbol-driven (sk_seed / cpk / csk only). For each case: write sk_seed, start the ACC once, read cpk + csk
(= sk_seed, untouched); both must be byte-identical to the recording. Then, on the same simulator:
  min Ip, Is   the next KAT seed (a stale accumulator or leaked loop state fails that byte-compare)
  min Ip3      the next case (the Ip3 file has one keypair: a same-seed rerun), then seed B, then A again
  sp           seed B, then A again: a natural restart from the B state (--poison-return poisons it first)
Seed B is the next KAT seed for Ip and Is and the first key of --vectors2 for Ip3 (default the .nistkat file
next to the vector file). ERR_BITS is checked after every run, and the 8-B guard after cpk for Ip and Ip3
(Is has none: its own buffers follow cpk). --poison fills with 0xA5 before the first run: the cpk payload
(min); the payload, the tri accumulator, p1buf, the group rows, p2buf and the frame (sp Ip, Ip3); the payload
(= the accumulator), O, p1buf, the T rows, ivb and the frame (sp Is). The DMEM size is the tree's hjson
profile; no cap is applied. Exit 0 when every case passes.

  python3 sw/acc/crypto/handwritten/uov/dmem_large/tests/test_oneshot_keygen.py --variant min --param Ip \\
    --elf bazel-bin/sw/acc/crypto/handwritten/uov/dmem_large/keygen_min/ov-Ip-pkc+skc/ov-Ip-keygen_min_bngfaes.elf \\
    --cases 0 --tier bngfaes --poison --stats
"""

import argparse
import hashlib
import os
import re
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), *[".."] * 7))
OWN = os.path.join(REPO, 'sw/acc/crypto/handwritten/own_utils')
sys.path.insert(0, OWN)
from ov_keygen_test_utils import _kg_parse_pkc_skc, _kg_objdump_syms

sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, 'hw/ip/acc/util'))
from acc_sim_utils import add_kat_driver_args, elf_tier, setup_default_keys
from dmem_utils import bytes_to_dmem_words, inject_words_to_dmem, extract_bytes_from_dmem
from hw.ip.acc.dv.accsim.sim.standalonesim import StandaloneSim
from hw.ip.acc.dv.accsim.sim.load_elf import load_elf
from shared.mem_layout import get_memory_layout

TEST_DATA = os.path.join(REPO, 'sw/acc/crypto/handwritten/test_data')
# cpk bytes (16-B pk_seed + the packed upper triangle), bytes per entry, zero guard the layout reserves after cpk
CPK = {'Ip': (43576, 44, 8),    # 990 x 44 B; the guard stays reserved zero
       'Is': (66576, 32, 0),    # 2,080 x 32 B; the slice (min) or o_ctx (sp) follows cpk, no guard
       'Ip3': (46591, 45, 8)}   # 1,035 x 45 B
# sp only: the tri accumulator bytes and the group-row stride (Ip, Ip3), the T-row stride (Is)
SP_TRI = {'Ip': 990 * 64, 'Ip3': 1035 * 64}
SP_ROW = {'Ip': 2816, 'Ip3': 2880, 'Is': 2048}


class Kernel:
    """The ELF's addresses and the contract of its (variant, param); load() checks the layout."""

    def __init__(self, variant, param, elf):
        self.variant, self.param, self.elf = variant, param, elf
        self.cpk_len, self.entry, self.guard = CPK[param]
        with open(elf, 'rb') as fh:
            elf_sha256 = hashlib.sha256(fh.read()).hexdigest()
        syms = _kg_objdump_syms(elf)
        if variant == 'min':
            ident = self.min_layout(syms)
        elif param == 'Is':
            ident = self.sp_is_layout(syms)
        else:
            ident = self.sp_gf256_layout(syms)
        layout = get_memory_layout()
        data_end = syms['_dmem_data_end']
        assert data_end <= layout.dmem_bus_size_bytes, \
            f"linked end {data_end} exceeds the bus window {layout.dmem_bus_size_bytes} of this profile"
        if variant == 'min':
            assert self.cpk + self.cpk_len + self.guard <= data_end, "cpk + guard must lie inside the linked image"
        self.tier = elf_tier(syms)
        if variant == 'sp':
            assert not any(s.startswith('sp_diag_stop_') for s in syms), 'production ELF required (diagnostic stop symbol found)'
        print(f"[DMEM profile: {layout.dmem_size_bytes} B total, bus {layout.dmem_bus_size_bytes}, dmem_address {layout.dmem_address:#x}, "
              f"layout module {sys.modules['shared.mem_layout'].__file__}]")
        print(f"[ELF {elf}\n sha256 {elf_sha256}\n tier by fingerprint {self.tier}{ident(data_end)}]")

    def min_layout(self, syms):
        self.sk_seed, self.csk, self.cpk, self.payload = syms['sk_seed'], syms['csk'], syms['cpk'], syms['cpk_payload']
        assert self.csk == self.sk_seed, "csk must alias sk_seed (one-shot contract)"
        assert self.payload == self.cpk + 16, (self.cpk, self.payload)
        if self.guard:
            assert self.cpk % 32 == 0, f"cpk {self.cpk} not 32-B aligned"        # Ip/Ip3: prefix aligned, payload GPR-written
        else:
            assert self.payload % 32 == 0, f"payload {self.payload} not 32-B aligned"  # Is: 32-B slots, prefix 16 B below
        assert 'ctrl' not in syms and 'slice_end' in syms, "not a one-shot ELF (identity gate)"
        self.poison_ranges = [(self.payload, self.payload + self.cpk_len - 16)]
        return lambda end: f" (rcon/AES128_TABLE/aes128hw_ symbols); _dmem_data_end {end}"

    def sp_gf256_layout(self, syms):
        for s in ('sk_seed', 'csk', 'cpk', 'cpk_payload', 'tri', 'tri_end', 'o_aligned', 'p1buf',
                  'group_buf', 'group_row1', 'group_row2', 'group_row3', 'p2buf', 'frame'):
            assert s in syms, f"missing symbol {s}: not a single-pass one-shot ELF"
        assert 'slice_end' not in syms and 'ctrl' not in syms, "identity: this is a _min or streamed ELF"
        self.sk_seed, self.csk, self.cpk, self.payload = syms['sk_seed'], syms['csk'], syms['cpk'], syms['cpk_payload']
        tri, row = syms['tri'], SP_ROW[self.param]
        assert self.csk == self.sk_seed and self.payload == self.cpk + 16 and self.cpk % 32 == 0, \
            (self.csk, self.sk_seed, self.cpk, self.payload)
        assert tri == self.payload + 80 and tri % 32 == 0 and syms['tri_end'] - tri == SP_TRI[self.param], \
            (tri, self.payload, syms['tri_end'])
        assert self.payload + self.cpk_len - 16 + self.guard <= syms['tri_end'], "guard must lie inside tri"
        rows = [syms['group_buf'], syms['group_row1'], syms['group_row2'], syms['group_row3']]
        assert [r - rows[0] for r in rows] == [0, row, 2 * row, 3 * row], rows
        assert syms['frame'] - rows[3] == row and syms['p2buf'] >= syms['frame'] + 64, syms
        # payload+tri+guard; p1buf..frame; p2buf (never the bngfonly constants)
        self.poison_ranges = [(self.payload, syms['tri_end']), (syms['p1buf'], syms['frame'] + 64),
                              (syms['p2buf'], syms['p2buf'] + 3584)]
        return lambda end: (f"; single-pass identity (tri {tri}, group rows {rows[0]}, p2buf {syms['p2buf']}); "
                            f"_dmem_data_end {end}")

    def sp_is_layout(self, syms):
        for s in ('sk_seed', 'csk', 'cpk', 'cpk_payload', 'cpk_payload_end', 'o_ctx', 'p1buf',
                  'group_buf', 'group_row1', 'group_row2', 'group_row3', 'ivb', 'frame'):
            assert s in syms, f"missing symbol {s}: not a single-pass one-shot ELF"
        assert 'slice_end' not in syms and 'ctrl' not in syms and 'tri' not in syms, "identity: not the Is single-pass ELF"
        self.sk_seed, self.csk, self.cpk, self.payload = syms['sk_seed'], syms['csk'], syms['cpk'], syms['cpk_payload']
        row = SP_ROW['Is']
        assert self.csk == self.sk_seed and self.payload == self.cpk + 16 and self.payload % 32 == 0, \
            (self.csk, self.sk_seed, self.cpk, self.payload)
        assert syms['cpk_payload_end'] - self.payload == self.cpk_len - 16, syms['cpk_payload_end']
        rows = [syms['group_buf'], syms['group_row1'], syms['group_row2'], syms['group_row3']]
        assert [r - rows[0] for r in rows] == [0, row, 2 * row, 3 * row], rows
        assert syms['o_ctx'] == syms['cpk_payload_end'] and syms['p1buf'] == syms['o_ctx'] + 3072 and \
            rows[0] == syms['p1buf'] + 3072, syms
        # the software twin keeps rkbuf between the T rows and ivb
        assert syms['ivb'] >= rows[3] + row and syms['frame'] == syms['ivb'] + 32, syms
        # payload, o_ctx, p1buf, T rows, ivb, frame (contiguous); never the constants
        self.poison_ranges = [(self.payload, syms['frame'] + 64)]
        return lambda end: (f"; Is single-pass identity (payload {self.payload} = accumulator, group rows {rows[0]}); "
                            f"_dmem_data_end {end}")

    def poison(self, sim):
        for lo, hi in self.poison_ranges:
            inject_words_to_dmem(sim, dict(bytes_to_dmem_words(bytes([0xA5]) * (hi - lo), lo)))

    def run(self, sim, seed, label, a):
        """One EXECUTE with sk_seed = seed; returns (cpk, csk, guard) after the ERR_BITS and guard checks."""
        inject_words_to_dmem(sim, dict(bytes_to_dmem_words(bytes(seed), self.sk_seed)))
        setup_default_keys(sim)
        sim.start(collect_stats=a.stats or a.dump is not None)
        sim.run(verbose=False, dump_file=None)
        err = sim.state.ext_regs.read('ERR_BITS', False)
        assert err == 0, f"{label}: ERR_BITS = {err:#x}"
        if a.stats or a.dump is not None:
            from hw.ip.acc.dv.accsim.sim.stats import ExecutionStatAnalyzer
            report = ExecutionStatAnalyzer(sim.stats, self.elf).dump()
            if a.stats:
                m = re.search(r'executed (\d+) instructions in (\d+) cycles', report)
                print(f"  {label}: {int(m.group(1)):,} insn, {int(m.group(2)):,} cyc")
            if a.dump is not None:
                a.dump.write(f"{label}: {report}\n")
        dmem = sim.dump_data(include_validity=False)
        end = self.cpk + self.cpk_len + self.guard
        if self.variant == 'min':
            assert len(dmem) >= end, f"dump {len(dmem)} B does not cover cpk end + guard {end}"
        else:
            assert len(dmem) >= end, f"dump {len(dmem)} B does not cover cpk" + (" + guard" if self.guard else "")
        cpk = bytes(extract_bytes_from_dmem(dmem, self.cpk, self.cpk_len))
        csk = bytes(extract_bytes_from_dmem(dmem, self.csk, 32))
        guard = bytes(extract_bytes_from_dmem(dmem, self.cpk + self.cpk_len, self.guard)) if self.guard else b''
        if self.variant == 'min':
            assert guard == bytes(self.guard), f"{label}: guard bytes after cpk were written: {guard.hex()}"
        return cpk, csk, guard


def report_diff(k, cpk, cpk_exp, tag, word='entry'):
    bad = [i for i in range(len(cpk)) if cpk[i] != cpk_exp[i]]
    print(f"FAIL{tag}: {len(bad)} bytes differ, first at {bad[0]} "
          f"({word} {(bad[0]-16)//k.entry}, byte {(bad[0]-16)%k.entry}); last at {bad[-1]}")


def prove_min(k, case, cases, b, a):
    """Key from case `case`, then a warm restart with the next case (Ip3: then seed B and A again)."""
    cpk_exp, sk_seed = cases[case]
    assert len(cpk_exp) == k.cpk_len, len(cpk_exp)
    print(f"case {case}: sk_seed {sk_seed[:8].hex()}.., expect cpk {len(cpk_exp)} B")
    sim = StandaloneSim(pqc=True)
    load_elf(sim, k.elf)
    if a.poison:
        k.poison(sim)
    cpk, csk, guard = k.run(sim, sk_seed, f'oneshot case {case}', a)
    assert csk == bytes(sk_seed), "csk != sk_seed"
    if cpk != cpk_exp:
        report_diff(k, cpk, cpk_exp, '')
        return False
    print(f"cpk byte-identical ({len(cpk)} B); csk OK" + (" (poisoned payload)" if a.poison else ""))
    if k.guard:
        print(f"  {k.guard}-B guard after cpk: {guard.hex()} (asserted zero after this run; checked again after the restart)")

    # warm restart: next KAT seed, SAME sim, no ELF reload
    case2 = (case + 1) % len(cases)
    cpk_exp2, sk_seed2 = cases[case2]
    cpk2, csk2, guard2 = k.run(sim, sk_seed2, f'warm restart case {case2}', a)
    assert csk2 == bytes(sk_seed2), "warm restart: csk != sk_seed"
    if cpk2 != cpk_exp2:
        report_diff(k, cpk2, cpk_exp2, ' (warm restart)')
        return False
    print(f"warm restart cpk byte-identical ({len(cpk2)} B); csk OK" + (f"; guard {guard2.hex()}" if k.guard else ""))
    if k.param != 'Ip3':
        return True
    # distinct-seed restart A -> B -> A on the same simulator: the base set has one
    # keypair, so seed B comes from a second recording (default .nistkat, 12 keys)
    cpk_b, seed_b = _kg_parse_pkc_skc(a.vectors2)[0]
    assert bytes(seed_b) != bytes(sk_seed), "--vectors2 must hold a different seed"
    cpk3, csk3, _ = k.run(sim, seed_b, 'restart with seed B', a)
    assert csk3 == bytes(seed_b), "seed B: csk != sk_seed"
    if cpk3 != cpk_b:
        report_diff(k, cpk3, cpk_b, ' (seed B after A)'); return False
    cpk4, csk4, _ = k.run(sim, sk_seed, 'restart back to seed A', a)
    assert csk4 == bytes(sk_seed)
    if cpk4 != cpk_exp:
        report_diff(k, cpk4, cpk_exp, ' (seed A after B)'); return False
    print(f"distinct-seed restart A -> B -> A byte-identical (B from {os.path.basename(a.vectors2)})")
    return True


def check_sp(k, cpk, csk, guard, seed, cpk_exp, label):
    assert csk == bytes(seed), f"{label}: csk != sk_seed"
    if k.guard:
        assert guard == bytes(k.guard), f"{label}: guard bytes after cpk not zero: {guard.hex()}"
    if cpk != cpk_exp:
        bad = [i for i in range(len(cpk)) if cpk[i] != cpk_exp[i]]
        print(f"FAIL {label}: {len(bad)} bytes differ, first at {bad[0]} "
              f"(slot {(bad[0]-16)//k.entry}, byte {(bad[0]-16)%k.entry}); last at {bad[-1]}")
        return False
    print(f"  {label}: cpk byte-identical ({len(cpk)} B); csk OK" + (f"; guard {guard.hex()}" if k.guard else ""))
    return True


def prove_sp(k, case, cases, b, a):
    """A -> B -> A from case `case` on a fresh simulator; B is the next KAT seed (Ip, Is) or the first key of
    --vectors2 (Ip3). False on the first wrong byte."""
    cpk_exp, sk_seed = cases[case]
    assert len(cpk_exp) == k.cpk_len, len(cpk_exp)
    print(f"case {case}: sk_seed {sk_seed[:8].hex()}.., expect cpk {len(cpk_exp)} B")
    sim = StandaloneSim(pqc=True)
    load_elf(sim, k.elf)
    if a.poison:
        k.poison(sim)
    if not check_sp(k, *k.run(sim, sk_seed, f'sp case {case}', a), sk_seed, cpk_exp,
                    f'sp case {case}' + (' (poisoned)' if a.poison else '')):
        return False
    if b is None:   # B: the next KAT seed, same simulator, no reload
        case2 = (case + 1) % len(cases)
        cpk_b, seed_b = cases[case2]
        assert bytes(seed_b) != bytes(sk_seed), "A -> B -> A needs distinct seeds"
        label = f'warm restart case {case2}'
    else:           # B: a different keypair from the second recording (the main file has one keypair for all cases)
        cpk_b, seed_b = b
        assert bytes(seed_b) != bytes(sk_seed), "--vectors2 must hold a different seed"
        label = 'restart with seed B'
    if not check_sp(k, *k.run(sim, seed_b, label, a), seed_b, cpk_b, label):
        return False
    # A again: a natural restart from the B state (no re-poison); --poison-return poisons first instead
    if a.poison_return:
        k.poison(sim)
    if not check_sp(k, *k.run(sim, sk_seed, f'restart A case {case}', a), sk_seed, cpk_exp,
                    f'restart A case {case}' + (' (re-poisoned)' if a.poison_return else ' (natural restart from B)')):
        return False
    print("A -> B -> A byte-identical on one simulator without reload" +
          (f" (B from {os.path.basename(a.vectors2)})" if b is not None else ""))
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--variant', required=True, choices=['min', 'sp'], help='keygen_min or keygen_sp')
    ap.add_argument('--param', required=True, choices=sorted(CPK), help='parameter set of the ELF')
    add_kat_driver_args(ap)
    ap.add_argument('--poison-return', action='store_true',
                    help='sp: poison the buffers again before the final A instead of a natural restart from B')
    ap.add_argument('--vectors2', metavar='FILE', default=None,
                    help='Ip3: a second recording with a different keypair; its first key is seed B '
                         '(default testvectors-Ip3-pkc-skc.nistkat next to the vector file)')
    a = ap.parse_args(argv)
    if a.poison_return and a.variant != 'sp':
        ap.error('--poison-return is a keygen_sp option')
    if a.vectors2 is not None and a.param != 'Ip3':
        ap.error('--vectors2 is an Ip3 option (Ip and Is take seed B from the next KAT case)')
    kat = os.path.join(TEST_DATA, f'testvectors-{a.param}-pkc-skc')
    if a.param == 'Ip3':
        if a.vectors2 is None:
            a.vectors2 = kat + '.nistkat'
        if not os.path.isfile(a.vectors2):
            sys.exit(f"--vectors2 {a.vectors2}: no such file")
    k = Kernel(a.variant, a.param, a.elf)
    if a.tier and a.tier != k.tier:
        sys.exit(f"ELF fingerprint says {k.tier}, --tier {a.tier}")
    cases = _kg_parse_pkc_skc(kat)
    bad = [c for c in a.cases if c >= len(cases)]
    if bad:
        what = 'vector' if (a.variant, a.param) == ('sp', 'Ip3') else 'KAT'
        sys.exit(f"--cases {bad}: the {what} file has cases 0-{len(cases) - 1}")
    # sp reads seed B up front; min Ip3 reads it after the warm restart, as each case runs (prove_min)
    b = _kg_parse_pkc_skc(a.vectors2)[0] if (a.variant, a.param) == ('sp', 'Ip3') else None
    prove = prove_min if a.variant == 'min' else prove_sp
    a.dump = open(a.dump_stats, 'w') if a.dump_stats else None
    try:
        if not all(prove(k, case, cases, b, a) for case in a.cases):
            return 1
    finally:
        if a.dump is not None:
            a.dump.close()
    print(f"{a.param.upper()} ONESHOT {'SP ' if a.variant == 'sp' else ''}KEYGEN PASS")
    return 0


if __name__ == '__main__':
    sys.exit(main())
