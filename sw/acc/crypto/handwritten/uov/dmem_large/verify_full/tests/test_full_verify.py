"""One-shot UOV-Ip, UOV-Is and UOV-Ip3 verify: cpk resident, one EXECUTE per verification.

Host contract (symbols): cpk (once per key; Ip 43,576 B + 264 B padding, Ip3 46,591 B + 225 B padding, Is
66,576 B at 16 mod 32 so the P3 entries are 32 B aligned, no padding), hdr+4 msg_len, msg (32-B granules, zero
tail), sig (Ip 128 B, Ip3 135 B in a 160 B zero-padded slot, Is 96 B), result at hdr+12: 0 accept, -1 reject,
-2 msg_len > 1,024, -5 while running. The kernel addresses hdr..msg by fixed offsets, so the ELF must place them
there (checked).
Proof per case: accept, then sequences that each run their negative checks and a recovery accept on the same
image: the resident key corrupted in pk_seed and in the first and the last P3 entry the signature weights
(o_i * o_j != 0), then the key restored; a second key (Ip, Is: the next case's; Ip3, whose twelve cases share one
key pair: case 0 of --vectors2, default the .nistkat set; --vectors2 overrides for every set): its signature under
this key, then loaded, this signature under it and its own signature, then this key restored; one flipped
signature bit at a time across vinegar, oil and salt and their boundaries (FLIPS); msg_len 1025, 0x80000000,
0xffffffff -> -2; where the key has padding (Ip, Ip3), accept with non-zero padding. Every result other than a length error
must match the Python public map (P(s) against SHAKE256(msg || salt)), which must accept every recorded
signature and reject every designed mutation, else the run fails.
--part I/N runs every N-th sequence from the I-th after the accept, on its own loaded image, so the parts of
one N together run every sequence. The resident cpk (and its padding) is checked unchanged after EVERY run;
ERR_BITS is checked after every EXECUTE. --poison fills the oil/acc blocks, target, seed and the arm's scratch
(sized from its symbols) with 0xA5, and the cpk padding with non-zero valid bytes, before every run after the
first. --stats prints the instructions and cycles next to the accepting runs; --dump-stats records every run.
Exit 0 when every check passes.

  python3 sw/acc/crypto/handwritten/uov/dmem_large/verify_full/tests/test_full_verify.py --param Ip \\
    --elf bazel-bin/sw/acc/crypto/handwritten/uov/dmem_large/verify_full/ov-Ip-pkc/ov-Ip-verify_full_bngfaes.elf \\
    --cases 0,11 --tier bngfaes --poison --stats
(Ip3: --param Ip3 with an ELF of ../ov-Ip3-pkc/.)
"""
import argparse, hashlib, os, re, sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), *[".."] * 8))
HW = f"{REPO}/sw/acc/crypto/handwritten"
sys.path[:0] = [REPO, f"{HW}/own_utils", f"{REPO}/hw/ip/acc/util"]
from ov_keygen_test_utils import _kg_objdump_syms
from ov_pk_utils import parse_pkc_test_data_file, compute_shake256_hash, expand_compressed_pk
from gf_arithmetic import ov_publicmap_reference
from ov_params import OV_IP, OV_IP3, OV_IS
from acc_sim_utils import add_kat_driver_args, elf_tier, setup_default_keys
from dmem_utils import bytes_to_dmem_words, inject_words_to_dmem, extract_bytes_from_dmem
from hw.ip.acc.dv.accsim.sim.standalonesim import StandaloneSim
from hw.ip.acc.dv.accsim.sim.load_elf import load_elf
from hw.ip.acc.dv.accsim.sim.stats import ExecutionStatAnalyzer
from shared.mem_layout import get_memory_layout

MSG_MAX = 1024
# cpk and padding bytes, signature bytes and the slot they are written into, vinegar, oil, P3 entry bytes, the fixed
# DMEM map the kernel addresses, the signature bits flipped (byte, bit), the arm scratch besides sfk_stack, the
# poisoned oil/acc/target block size, the default second-key file (None: the next case's key)
PARAMS = {
    'Ip': dict(p=OV_IP, cpk=43576, pad=264, sig=128, slot=128, v=68, o=44, entry=44,
               map=dict(hdr=0x000, accctx=0x020, oil=0x060, target=0x0A0, sig=0x0E0, seed=0x160, msg=0x180),
               flips=((0, 0x01), (67, 0x01), (68, 0x01), (90, 0x01), (111, 0x01), (112, 0x01), (120, 0x01), (127, 0x01)),
               scratch=(('rkbuf', 352),), block=64, vectors2=None),
    'Ip3': dict(p=OV_IP3, cpk=46591, pad=225, sig=135, slot=160, v=74, o=45, entry=45,
                map=dict(hdr=0x000, accctx=0x020, oil=0x060, target=0x0A0, sig=0x0E0, seed=0x180, msg=0x1A0),
                flips=((0, 0x01), (73, 0x01), (74, 0x01), (100, 0x01), (118, 0x01), (119, 0x01), (127, 0x01), (134, 0x01)),
                scratch=(('rkbuf', 352), ('blkbuf', 384)), block=64,
                vectors2=f"{HW}/test_data/testvectors-Ip3-pkc-skc.nistkat"),   # twelve key pairs, none the base set's
    'Is': dict(p=OV_IS, cpk=66576, pad=0, sig=96, slot=96, v=96, o=64, entry=32,
               map=dict(hdr=0x000, accctx=0x020, oil=0x040, target=0x060, sig=0x080, seed=0x0E0, msg=0x100),
               flips=((0, 0x01), (47, 0x10), (48, 0x01), (60, 0x01), (79, 0x10), (80, 0x01), (88, 0x01), (95, 0x01)),
               scratch=(('aes128hw_mem_scratch', 96), ('aes128hw_bank_verify_slot', 32)), block=32, vectors2=None),
}


def configure(param):
    """Bind the driver to one parameter set."""
    global PARAM, P, CPK_LEN, CPK_PAD, SIG_LEN, SIG_SLOT, V, O, ENTRY, MAP, FLIPS, SCRATCH, BLOCK, VECTORS2
    PARAM, t = param, PARAMS[param]
    P, CPK_LEN, CPK_PAD, SIG_LEN, SIG_SLOT = t['p'], t['cpk'], t['pad'], t['sig'], t['slot']
    V, O, ENTRY, MAP, FLIPS, SCRATCH, BLOCK, VECTORS2 = (t[k] for k in ('v', 'o', 'entry', 'map', 'flips', 'scratch',
                                                                       'block', 'vectors2'))


def word32(addr, value):
    return bytes_to_dmem_words((value & 0xffffffff).to_bytes(4, 'little'), addr)


def ref_accepts(cpk, msg, sig):
    """The Python public map's verdict: P(s) == SHAKE256(msg || salt); for Is s is packed, two elements a byte."""
    nb = P.pub_n_byte
    y = ov_publicmap_reference(bytes(expand_compressed_pk(bytearray(cpk), P)), sig[:nb], V + O, O, V, f'gf{P.gf}')
    return y == compute_shake256_hash(bytearray(msg), bytearray(sig[nb:]), P)


def weighted_entries(sig):
    """(first, last) P3 entry index whose weight o_i * o_j is non-zero: a flipped bit there must reject."""
    o = (sig[V:V + O] if P.gf == 256 else
         [(sig[(V + k) // 2] >> 4 * ((V + k) % 2)) & 0xF for k in range(O)])
    ks = [k for k, (i, j) in enumerate((i, j) for i in range(O) for j in range(i, O)) if o[i] and o[j]]
    return ks[0], ks[-1]


class OneShotVerify:
    def __init__(self, elf, a):
        self.elf, self.a = elf, a
        self.sha = hashlib.sha256(open(elf, 'rb').read()).hexdigest()
        s = _kg_objdump_syms(elf)
        bad = {k: s.get(k) for k, v in MAP.items() if s.get(k) != v}
        assert not bad, f"symbols off the fixed map the kernel addresses: {bad}"
        self.HDR, self.SIG, self.MSG, self.CPK = s['hdr'], s['sig'], s['msg'], s['cpk']
        self.TARGET, self.SEED, self.OIL, self.ACC = s['target'], s['seed'], s['oil'], s['accctx']
        self.scratch = [(s[k], n) for k, n in SCRATCH if k in s]
        if 'sfk_stack' in s:                       # sized per arm from its symbols
            self.scratch.append((s['sfk_stack'], s['sfk_stack_end'] - s['sfk_stack']))
        self.end = s['_dmem_data_end']
        for addr, n in self.scratch:
            assert addr + n <= self.end, (addr, n, self.end)
        assert self.SIG % 32 == 0 and self.MSG % 32 == 0
        if PARAM != 'Is':
            assert self.CPK % 32 == 0, "the P3 window (16 B prefix + entries) is read in aligned 32 B words"
        else:
            assert self.CPK % 32 == 16 and s['cpk_p3'] == self.CPK + 16, \
                "the P3 entries after the 16 B seed are read as aligned 32 B words"
        assert self.CPK + CPK_LEN + CPK_PAD <= self.end, "cpk + padding must lie inside the image"
        assert 'ctrl' not in s and 'msgwin' not in s and 'caprows' not in s, "streamed symbols in a one-shot ELF"
        lay = get_memory_layout()
        assert s['_dmem_bss_end'] <= lay.dmem_bus_size_bytes, (s['_dmem_bss_end'], lay.dmem_bus_size_bytes)
        self.tier = elf_tier(s)
        if a.tier and a.tier != self.tier:
            sys.exit(f"ELF fingerprint says {self.tier}, --tier {a.tier}")
        print(f"[DMEM profile: {lay.dmem_size_bytes} B total, bus {lay.dmem_bus_size_bytes}, dmem_address {lay.dmem_address:#x}, "
              f"layout module {sys.modules['shared.mem_layout'].__file__}]")
        print(f"[ELF {elf}\n sha256 {self.sha}\n tier by fingerprint {self.tier}; _dmem_data_end {self.end}; "
              f"_dmem_bss_end {s['_dmem_bss_end']}; cpk@{self.CPK:#x} msg@{self.MSG:#x} sig@{self.SIG:#x}]")
        print(f"[harness sha256 {hashlib.sha256(open(__file__, 'rb').read()).hexdigest()[:16]}.. options poison={a.poison} "
              f"tier={a.tier} stats={a.stats}]")
        self.sim = StandaloneSim(pqc=True)
        load_elf(self.sim, elf)
        self.runs = 0
        self.installed = None
        self.pad = bytes(CPK_PAD)

    def load_key(self, cpk, pad=None):
        pad = pad if pad is not None else bytes(CPK_PAD)
        assert len(cpk) == CPK_LEN and len(pad) == CPK_PAD
        inject_words_to_dmem(self.sim, dict(bytes_to_dmem_words(bytes(cpk) + pad, self.CPK)))
        self.installed, self.pad = bytes(cpk), pad

    def poison(self):
        words = {}
        for addr, n in ((self.OIL, BLOCK), (self.ACC, BLOCK), (self.TARGET, BLOCK), (self.SEED, 32)) + tuple(self.scratch):
            words.update(bytes_to_dmem_words(bytes([0xA5]) * n, addr))
        if CPK_PAD:
            # the P3 over-read padding: non-zero but valid; the kernel must not depend on it. A key that ends
            # mid-word (Ip3: 46,591 B) has its last word rewritten with its own bytes ahead of the padding.
            pad = bytes(((self.runs * 13 + i * 37) & 0xff) | 1 for i in range(CPK_PAD))
            head = (self.CPK + CPK_LEN) % 4
            words.update(bytes_to_dmem_words(self.installed[CPK_LEN - head:] + pad, self.CPK + CPK_LEN - head))
            self.pad = pad
        inject_words_to_dmem(self.sim, words)

    def run(self, msg, sig, msg_len=None, label=''):
        msg_len = len(msg) if msg_len is None else msg_len
        if self.runs and self.a.poison:
            self.poison()
        words = dict(word32(self.HDR + 4, msg_len))
        words.update(bytes_to_dmem_words(bytes(sig) + bytes(SIG_SLOT - len(sig)), self.SIG))
        if len(msg):
            words.update(bytes_to_dmem_words(bytes(msg) + bytes((-len(msg)) % 32), self.MSG))
        inject_words_to_dmem(self.sim, words)
        setup_default_keys(self.sim)
        stats = self.a.stats or self.a.dump is not None
        self.sim.start(collect_stats=stats)
        self.sim.run(verbose=False, dump_file=None)
        err = self.sim.state.ext_regs.read('ERR_BITS', False)
        assert err == 0, f"{label}: ERR_BITS = {err:#x}"
        cyc = None
        if stats:
            report = ExecutionStatAnalyzer(self.sim.stats, self.elf).dump()
            if self.a.stats:
                m = re.search(r'executed (\d+) instructions in (\d+) cycles', report)
                cyc = (int(m.group(1)), int(m.group(2)))
            if self.a.dump is not None:
                self.a.dump.write(f"{label}: {report}\n")
        dmem = self.sim.dump_data(include_validity=False)
        status = int.from_bytes(extract_bytes_from_dmem(dmem, self.HDR + 12, 4), 'little', signed=True)
        self.runs += 1
        self.last_cpk = bytes(extract_bytes_from_dmem(dmem, self.CPK, CPK_LEN))
        assert self.last_cpk == self.installed, f"{label}: resident cpk modified by the kernel"
        assert bytes(extract_bytes_from_dmem(dmem, self.CPK + CPK_LEN, CPK_PAD)) == self.pad, f"{label}: cpk padding modified"
        return status, cyc


def part_spec(text):
    """'I/N' -> (I, N): run every N-th sequence starting with the I-th."""
    i, _, n = text.partition('/')
    if not (i.isdigit() and n.isdigit() and 1 <= int(i) <= int(n)):
        raise argparse.ArgumentTypeError(f"bad part {text!r}: use I/N with 1 <= I <= N")
    return int(i), int(n)


def prove(v, cases, a):
    """The KAT accept, then the sequences of a.part, for every case in a.cases on one simulator.
    A sequence runs its negative checks and its recovery accept on the same image and leaves the
    case's key installed (with zero padding). Returns (check, passed) pairs."""
    results = []

    def expect(got, want, what):
        ok = got == want
        print(f"  {'ok ' if ok else 'BAD'} {what}: result {got} (want {want})")
        results.append((what, ok))

    second = tuple(bytes(x) for x in parse_pkc_test_data_file(a.vectors2, P)[0]) if a.vectors2 else None
    for n in a.cases:
        cpk, _sk, msg, sig = (bytes(x) for x in cases[n])
        assert len(cpk) == CPK_LEN and len(sig) == SIG_LEN and len(msg) <= MSG_MAX, (len(cpk), len(sig), len(msg))
        if second:
            cpk2, _sk2, msg2, sig2 = second
            other = f"{os.path.basename(a.vectors2)} case 0"
        else:
            cpk2, _sk2, msg2, sig2 = (bytes(x) for x in cases[(n + 1) % len(cases)])
            other = f"case {(n + 1) % len(cases)}"
        assert cpk2 != cpk, "the second key must differ"
        first, last = weighted_entries(sig)

        def verify(m, s, what, label, valid):
            """One run under the installed key; the wanted result is the reference's verdict, which must
            accept a recorded signature (valid) and reject a designed mutation."""
            ref = ref_accepts(v.installed, m, s)
            st, cyc = v.run(m, s, label=label)
            note = f"  [{cyc[0]:,} insn, {cyc[1]:,} cyc]" if cyc and ref else ''
            expect(st, 0 if ref else -1, f"{what}, reference {'accepts' if ref else 'rejects'}{note}")
            if ref != valid:
                print(f"  BAD {what}: the reference {'rejects the recorded signature' if valid else 'accepts the mutation'}")
                results.append((what, False))

        def accept(what, label):
            verify(msg, sig, f"case {n} {what}", label, True)

        def corrupt_key():
            for off, what in ((3, 'pk_seed byte 3'), (16 + first * ENTRY, f'P3 entry {first} byte 0'),
                              (16 + last * ENTRY + ENTRY - 1, f'P3 entry {last} byte {ENTRY - 1}')):
                bad = bytearray(cpk); bad[off] ^= 1
                v.load_key(bytes(bad))
                verify(msg, sig, f"case {n} with the resident key corrupted at {what}", f'cpk {what}', False)
            v.load_key(cpk)
            accept('accept after the key is restored', 'key restored')

        def second_key():
            verify(msg2, sig2, f"{other}'s signature under case {n}'s key", 'other signature', False)
            v.load_key(cpk2)
            verify(msg, sig, f"case {n}'s signature under {other}'s key", 'signature under the other key', False)
            verify(msg2, sig2, f"{other}'s key accepts its own signature", 'other key', True)
            v.load_key(cpk)
            accept(f"accept after its key is restored over {other}'s", 'key restored over the other key')

        def flips(bs):
            for b, bit in bs:
                bad = bytearray(sig); bad[b] ^= bit
                verify(msg, bytes(bad), f"case {n} sig byte {b} ^ {bit:#04x}", f'flip {b}^{bit:#x}', False)
            accept(f"accept after the flips of bytes {', '.join(str(b) for b, _ in bs)}", 'accept after flips')

        def lengths():
            for x in (1025, 0x80000000, 0xffffffff):
                st, _ = v.run(msg, sig, msg_len=x, label=f'len {x:#x}')
                expect(st, -2, f"case {n} msg_len {x:#x} rejected as a length error (host contract)")
            accept('accept after the length errors', 'accept after length errors')

        def padding():
            v.load_key(cpk, bytes(((i * 37) & 0xff) | 1 for i in range(CPK_PAD)))   # non-zero, still valid
            accept('accept with non-zero P3 padding (padding must not contribute)', 'non-zero padding')
            v.load_key(cpk)

        # ordered so that --part I/4 gives every part about the same number of full runs
        seqs = [corrupt_key, second_key, lambda: flips(FLIPS[:4]), lambda: flips(FLIPS[4:]), lengths] + \
               ([padding] if CPK_PAD else [])
        i, parts = a.part
        print(f"case {n}: msglen {len(msg)}; sequences {i}/{parts}: {len(seqs[i - 1::parts])} of {len(seqs)}")
        v.load_key(cpk)
        accept('accept', f'case {n} accept')
        for seq in seqs[i - 1::parts]:
            seq()
        print(f"  ok  cpk unchanged after {v.runs} runs on this image")
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_kat_driver_args(ap, cases='0,11', poison=False,
                        stats='print the ACC instructions and cycles next to the timed accept results')
    ap.add_argument('--param', required=True, choices=sorted(PARAMS), help='parameter set of the ELF')
    ap.add_argument('--poison', action='store_true',
                    help='before every run after the first, fill the scratch with 0xA5 and the cpk padding (Ip) '
                         'with non-zero valid bytes')
    ap.add_argument('--vectors', default=None, metavar='FILE',
                    help='the vector file, one key pair per case (default: test_data/testvectors-<param>-pkc-skc)')
    ap.add_argument('--vectors2', default=None, metavar='FILE',
                    help='take the second key from case 0 of this file instead of the next case '
                         '(Ip3 default: test_data/testvectors-Ip3-pkc-skc.nistkat)')
    ap.add_argument('--part', type=part_spec, default=(1, 1), metavar='I/N',
                    help='after the KAT accept, run only every N-th sequence from the I-th (default 1/1: all); '
                         'the parts of one N together run every sequence')
    a = ap.parse_args(argv)
    configure(a.param)
    a.vectors = a.vectors or f"{HW}/test_data/testvectors-{a.param}-pkc-skc"
    a.vectors2 = a.vectors2 or VECTORS2
    for f, opt in ((a.vectors, '--vectors'), (a.vectors2, '--vectors2')):
        if f is not None and not os.path.isfile(f):
            sys.exit(f"{opt} {f}: no such file")
    cases = parse_pkc_test_data_file(a.vectors, P)
    bad = [c for c in a.cases if c >= len(cases)]
    if bad:
        sys.exit(f"--cases {bad}: the vector file has cases 0-{len(cases) - 1}")
    v = OneShotVerify(os.path.abspath(a.elf), a)
    a.dump = open(a.dump_stats, 'w') if a.dump_stats else None
    try:
        results = prove(v, cases, a)
    finally:
        if a.dump is not None:
            a.dump.close()
    fails = [what for what, ok in results if not ok]
    part = '' if a.part == (1, 1) else f" (sequences part {a.part[0]}/{a.part[1]})"
    print(f"{a.param.upper()} ONESHOT VERIFY {'FAIL' if fails else 'PASS'}{part}: {len(results) - len(fails)} of {len(results)} "
          f"checks passed" + (f"; failed: {fails}" if fails else ''))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
