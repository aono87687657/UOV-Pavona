"""Streamed UOV-Ip, UOV-Is and UOV-Ip3 keygen: functional test vs the KAT cpk.

Drives the phased keygen (INIT -> WINDOW calls) in the ACC ISS, persistent DMEM ctx (pk_seed + aligned O),
reads each window's slice (row stride KSTRIDE = (slice_end - slice)/o; a column sits in a 64 B slot for Ip and
Ip3, 44 or 45 B valid, and in an exact 32 B entry for Is), assembles P3full host-side, folds the upper triangle
(j<k XOR), packs cpk = pk_seed || P3 and byte-compares against the KAT cpk.
Negative controls: corrupt a real byte in window 0 AND one in the short last window, expect mismatch. Each
case runs on a fresh simulator. --localize (Ip, Ip3) also compares every folded entry with the python reference
and names the first wrong one. Runs only on the 32 KiB DMEM profile. Exit 0 when every case passes.

  python3 sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/tests/test_stream_keygen.py --param Ip \\
    --elf bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Ip-pkc+skc/ov-Ip-keygen_stream_bngfaes.elf \\
    --cases 0 --stats
"""

import argparse
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), *['..'] * 8))
OWN = os.path.join(REPO, 'sw/acc/crypto/handwritten/own_utils')

sys.path.insert(0, OWN)
from ov_keygen_test_utils import _kg_parse_pkc_skc, _kg_objdump_syms

sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, 'hw/ip/acc/util'))
from acc_sim_utils import add_kat_driver_args, require_dmem_profile, setup_default_keys
from dmem_utils import bytes_to_dmem_words, inject_words_to_dmem, extract_bytes_from_dmem
from hw.ip.acc.dv.accsim.sim.standalonesim import StandaloneSim
from hw.ip.acc.dv.accsim.sim.load_elf import load_elf

# oil columns, bytes per entry, slot stride per column in the slice, the column corrupted in the last window
PARAMS = {
    'Ip': dict(o=44, entry=44, slot=64, last_col=43),
    'Ip3': dict(o=45, entry=45, slot=64, last_col=44),
    'Is': dict(o=64, entry=32, slot=32, last_col=62),
}
ELF = None           # bound by configure()


def configure(elf, param):
    """Bind the driver to one ELF and parameter set: DMEM symbols and the window geometry. Refuses a tree
    that is not at the 32 KiB DMEM profile. main() calls this once; importers call it per ELF."""
    global PARAM, O_DIM, ENTRY, SLOT, LAST_COL, ELF, CTRL, SK_SEED, PK_SEED, SLICE, KSTRIDE, WJ, WINDOWS
    require_dmem_profile(32768)
    PARAM = param
    O_DIM, ENTRY, SLOT, LAST_COL = (PARAMS[param][k] for k in ('o', 'entry', 'slot', 'last_col'))
    ELF = elf
    syms = _kg_objdump_syms(elf)
    CTRL, SK_SEED, PK_SEED, SLICE = syms['ctrl'], syms['sk_seed'], syms['pk_seed'], syms['slice']
    KSTRIDE = (syms['slice_end'] - SLICE) // O_DIM  # slice = O_DIM rows x KSTRIDE
    WJ = KSTRIDE // SLOT                            # columns per window
    if param == 'Is':
        assert WJ % 2 == 0, f"odd window width {WJ}"   # the Is kernel folds column pairs
    WINDOWS = [(cs, min(WJ, O_DIM - cs)) for cs in range(0, O_DIM, WJ)]


def word32(addr, value):
    return bytes_to_dmem_words((value & 0xffffffff).to_bytes(4, 'little'), addr)


CYCLES = []          # (label, insns, cycles) per phase when stats are collected


def run_phase(sim, words, label='', stats=False):
    inject_words_to_dmem(sim, words)
    setup_default_keys(sim)
    sim.start(collect_stats=stats)
    sim.run(verbose=False, dump_file=None)
    err = sim.state.ext_regs.read('ERR_BITS', False)
    if err != 0:
        raise SystemExit(f"ERR_BITS=0x{err:x} ({label}) at pc=0x{sim.state.pc:x}; DMEM status is stale on core error")
    if stats:
        import re
        from hw.ip.acc.dv.accsim.sim.stats import ExecutionStatAnalyzer
        report = ExecutionStatAnalyzer(sim.stats, ELF).dump()
        m = re.search(r'executed (\d+) instructions in (\d+) cycles', report)
        CYCLES.append((label, int(m.group(1)), int(m.group(2))))
    dmem = sim.dump_data(include_validity=False)
    status = int.from_bytes(bytes(extract_bytes_from_dmem(dmem, CTRL + 12, 4)), 'little', signed=True)
    return dmem, status


def streamed_keygen(elf, sk_seed, stats=False):
    """INIT + WINDOWs; return (pk_seed, P3full[O_DIM][O_DIM] of ENTRY-byte entries)."""
    sim = StandaloneSim(pqc=True)
    load_elf(sim, elf)

    words = dict(word32(CTRL, 0))
    words.update(bytes_to_dmem_words(bytes(sk_seed), SK_SEED))
    dmem, status = run_phase(sim, words, 'INIT', stats)
    assert status == 0, f"INIT status {status}"
    pk_seed = bytes(extract_bytes_from_dmem(dmem, PK_SEED, 16))

    p3full = [[None] * O_DIM for _ in range(O_DIM)]
    for cs, wc in WINDOWS:
        words = dict(word32(CTRL, 1))
        words.update(word32(CTRL + 4, cs))
        words.update(word32(CTRL + 8, wc))
        dmem, status = run_phase(sim, words, f'WINDOW({cs},{wc})', stats)
        assert status == 0, f"WINDOW({cs},{wc}) status {status}"
        for j in range(wc):
            for k in range(O_DIM):
                p3full[k][cs + j] = bytes(
                    extract_bytes_from_dmem(dmem, SLICE + k * KSTRIDE + j * SLOT, ENTRY))
    return pk_seed, p3full


def pack_cpk(pk_seed, p3full):
    out = bytearray(pk_seed)
    for k in range(O_DIM):
        for j in range(k, O_DIM):
            e = p3full[k][j]
            if j > k:
                e = bytes(a ^ b for a, b in zip(e, p3full[j][k]))
            out += e
    return bytes(out)


def localize(param, sk_seed, pk_seed, p3full):
    """Compare every folded entry with the python reference (GF(256) sets); print the first wrong one."""
    import hashlib
    from ov_pk_utils import expand_p1p2_from_pkseed
    from ov_keygen_test_utils import compute_p3_reference_gf256
    from ov_params import OV_IP, OV_IP3
    p = {'Ip': OV_IP, 'Ip3': OV_IP3}[param]
    Vv, Oo, Mb = p.v, p.o, p.pub_m_byte
    o_mat = hashlib.shake_256(bytes(sk_seed)).digest(16 + Vv*Oo)[16:]
    p1p2 = expand_p1p2_from_pkseed(bytearray(pk_seed), p)
    p1sz = Vv*(Vv+1)//2*Mb
    p3ref = compute_p3_reference_gf256(bytes(p1p2[:p1sz]), bytes(p1p2[p1sz:]), o_mat, Vv, Oo, Mb)
    idx = 0
    for k in range(Oo):
        for j in range(k, Oo):
            ref = p3ref[idx*Mb:(idx+1)*Mb]
            ker = p3full[k][j]
            if j > k:
                ker = bytes(a^b for a, b in zip(ker, p3full[j][k]))
            if bytes(ker) != bytes(ref):
                print(f"  first bad folded entry (k={k},j={j}): ref {ref[:6].hex()} ker {bytes(ker)[:6].hex()}")
                print(f"  raw p3full[{k}][{j}][:6]={p3full[k][j][:6].hex()}  p3full[{j}][{k}][:6]={p3full[j][k][:6].hex()}")
                return False
            idx += 1
    print("  all folded entries match reference")
    return True


def prove(case, cases, a):
    """One keygen from KAT case `case` on a fresh simulator; False on a wrong cpk byte."""
    cpk_exp, sk_seed = cases[case]
    print(f"case {case}: sk_seed {sk_seed[:8].hex()}.., expect cpk {len(cpk_exp)} B")

    CYCLES.clear()
    pk_seed, p3full = streamed_keygen(ELF, sk_seed, a.stats or a.dump is not None)
    assert pk_seed == cpk_exp[:16], \
        f"pk_seed mismatch: got {pk_seed.hex()} want {cpk_exp[:16].hex()}"
    print("pk_seed OK")
    entries_ok = localize(PARAM, sk_seed, pk_seed, p3full) if a.localize else True

    cpk = pack_cpk(pk_seed, p3full)
    assert len(cpk) == len(cpk_exp), f"cpk length {len(cpk)} != {len(cpk_exp)}"
    if cpk != cpk_exp:
        bad = [i for i in range(len(cpk)) if cpk[i] != cpk_exp[i]]
        print(f"FAIL: {len(bad)} bytes differ, first at {bad[0]} "
              f"(entry {(bad[0]-16)//ENTRY}, byte {(bad[0]-16)%ENTRY})")
        return False
    print(f"cpk byte-identical ({len(cpk)} B)")

    # negative controls: a real byte in window 0 and one in the short last window
    for k, j, tag in ((2, 3, "window 0"), (5, LAST_COL, "last short window")):
        p3bad = [row[:] for row in p3full]
        e = bytearray(p3bad[k][j]); e[10] ^= 0xA5; p3bad[k][j] = bytes(e)
        assert pack_cpk(pk_seed, p3bad) != cpk_exp, f"negative control ({tag}) did not trip"
    print("negative controls OK")
    if a.stats:
        total = sum(c for _, _, c in CYCLES)
        for label, _i, c in CYCLES:
            print(f"  {label}: {c:,} cyc")
        print(f"  streamed total: {total:,} cyc")
    if a.dump is not None:
        a.dump.write(f"executed {sum(i for _, i, _ in CYCLES)} instructions "
                     f"in {sum(c for _, _, c in CYCLES)} cycles\n")
    return entries_ok


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--param', required=True, choices=sorted(PARAMS), help='parameter set of the ELF')
    add_kat_driver_args(ap, tier=False, poison=False,
                        stats='print the cycles of every phase and the streamed total',
                        dump_stats='write "executed N instructions in M cycles", summed over the phases, '
                                   'to FILE (one case only)')
    ap.add_argument('--vectors', default=None, metavar='FILE',
                    help='vector file (default test_data/testvectors-<param>-pkc-skc)')
    ap.add_argument('--localize', action='store_true',
                    help='also compare every folded P3 entry with the python reference and name the first wrong one '
                         '(Ip, Ip3)')
    a = ap.parse_args(argv)
    if a.dump_stats and len(a.cases) != 1:
        ap.error('--dump-stats takes one case')
    if a.localize and a.param == 'Is':
        ap.error('--localize compares GF(256) entries: Ip and Ip3 only')
    configure(a.elf, a.param)
    cases = _kg_parse_pkc_skc(a.vectors or os.path.join(REPO, f'sw/acc/crypto/handwritten/test_data/testvectors-{a.param}-pkc-skc'))
    bad = [c for c in a.cases if c >= len(cases)]
    if bad:
        sys.exit(f"--cases {bad}: the KAT file has cases 0-{len(cases) - 1}")
    a.dump = open(a.dump_stats, 'w') if a.dump_stats else None
    try:
        if not all(prove(case, cases, a) for case in a.cases):
            return 1
    finally:
        if a.dump is not None:
            a.dump.close()
    print(f"{a.param.upper()} STREAMED KEYGEN PASS")
    return 0


if __name__ == '__main__':
    sys.exit(main())
