#!/usr/bin/env python3
"""The shared KAT-driver helpers: case lists, tier fingerprints, the DMEM profile gate (CLI and
importer paths), the streamed-verify window bound and Ip3 verdict, the keygen and sign harnesses'
--tier check, the sign harness's slot-aware O checkpoint, L-direct stack slots and retry check, the
Ip3 stream keygen's --localize verdict, the Ip3 one-shot verify harness's fixed symbol map, and the
command lines of the kernel KAT sweeps and the sign vector generator."""

import argparse
import importlib.util
import io
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HW = os.path.join(REPO, 'sw/acc/crypto/handwritten')
sys.path[:0] = [REPO, os.path.join(REPO, 'hw/ip/acc/util'), os.path.join(HW, 'own_utils'),
                os.path.join(HW, 'uov/dmem32k/verify_stream/tests'),
                os.path.join(HW, 'uov/dmem32k/keygen_stream/tests'),
                os.path.join(HW, 'uov/dmem_large/verify_full/tests')]

import acc_sim_utils as asu
import measure_cycles as mc
import ov_keygen_test_utils as kgu
import ov_sign_test_utils as sgu
import test_full_verify as vf
import test_stream_keygen as kgs
from elftools.elf.elffile import ELFFile
from ov_params import OV_IP, OV_IP3, OV_IS

PROFILE_32 = SimpleNamespace(dmem_address=0x18000, dmem_bus_size_bytes=31744, dmem_size_bytes=32768)
PROFILE_128 = SimpleNamespace(dmem_address=0x80000, dmem_bus_size_bytes=130048, dmem_size_bytes=131072)


def profile(layout):
    return mock.patch('shared.mem_layout._LAYOUT', layout)


class CasesTest(unittest.TestCase):
    def test_accepted(self):
        for spec, want in (('0', [0]), ('0,11', [0, 11]), ('0-3', [0, 1, 2, 3]), ('11,0', [11, 0]), ('3-3', [3])):
            self.assertEqual(asu.parse_cases(spec), want, spec)

    def test_refused(self):
        for spec in ('', '0,0', '3-1', '-1', 'a', '1-', '0,,1', '0-1,1'):
            with self.subTest(spec=spec), self.assertRaises(argparse.ArgumentTypeError):
                asu.parse_cases(spec)


class TierTest(unittest.TestCase):
    def test_fingerprints(self):
        self.assertEqual(asu.elf_tier({'rcon'}), 'bngfonly')
        self.assertEqual(asu.elf_tier({'AES128_TABLE'}), 'sw')
        self.assertEqual(asu.elf_tier({'aes128hw_col_is'}), 'bnaesonly')
        self.assertEqual(asu.elf_tier({'ctrl', 'slice'}), 'bngfaes')


class ProfileTest(unittest.TestCase):
    def test_helper(self):
        with profile(PROFILE_32):
            self.assertIs(asu.require_dmem_profile(32768), PROFILE_32)
        with profile(PROFILE_128), self.assertRaises(SystemExit) as e:
            asu.require_dmem_profile(32768)
        self.assertIn('--profile 32', str(e.exception))

    def test_importer_paths_refuse_before_any_work(self):
        # importers call configure(); every measure_* phase goes through measure_cycles.run_phase()
        with profile(PROFILE_128), mock.patch.object(kgs, '_kg_objdump_syms') as syms:
            self.assertRaises(SystemExit, kgs.configure, 'any.elf', 'Ip3')
            syms.assert_not_called()
        with profile(PROFILE_128):
            self.assertRaises(SystemExit, mc.run_phase, None, 'any.elf', {})
        for param in ('Ip', 'Is'):   # the functional check's callable entry
            with self.subTest(param=param), profile(PROFILE_128), mock.patch.object(mc, 'StandaloneSim') as sim:
                self.assertRaises(SystemExit, mc.streamed_verify, 'any.elf', b'', b'', b'', param)
                sim.assert_not_called()


class WindowTest(unittest.TestCase):
    BASE = 0x100

    def cap(self, syms, base=BASE):
        with profile(PROFILE_32), mock.patch.object(mc, '_kg_objdump_syms', return_value=syms):
            return mc.window_cap('x.elf', base)

    def test_pair(self):
        self.assertEqual(self.cap({'msgwin': 0x100, 'winend': 0x100 + 26624, '_dmem_data_end': 0x7000, '_dmem_bss_end': 0x7000}), 26624)

    def test_deployed_bngfaes_arm(self):
        self.assertEqual(self.cap({'_dmem_data_end': 0, '_dmem_bss_end': 0}), 30 * 1024)

    def test_refused(self):
        for syms in (
            {'msgwin': 0x1A0, 'winend': 0x1A0 + 23968, '_dmem_data_end': 0, '_dmem_bss_end': 0},  # other base
            {'msgwin': 0x100, '_dmem_data_end': 0, '_dmem_bss_end': 0},                            # half a pair
            {'winend': 0x7000, '_dmem_data_end': 0, '_dmem_bss_end': 0},
            {'_dmem_data_end': 0x6000, '_dmem_bss_end': 0x6000},                                  # data, no pair
            {'rcon': 0x6000, '_dmem_data_end': 0, '_dmem_bss_end': 0},                            # not bngfaes
            {'msgwin': 0x100, 'winend': 0x100, '_dmem_data_end': 0, '_dmem_bss_end': 0},          # empty window
            {'msgwin': 0x100, 'winend': 31745, '_dmem_data_end': 0, '_dmem_bss_end': 0},          # past the bus
        ):
            with self.subTest(syms=syms), self.assertRaises(AssertionError):
                self.cap(syms)

    def test_schedule_is_greedy_and_bounded(self):
        o, m = 64, 32
        for cap in (30720, 26624, 22496):
            sched = mc.maxfill_schedule(o, m, cap)
            rows = [r for start, n in sched for r in range(start, start + n)]
            self.assertEqual(rows, list(range(o)), cap)
            for i, (start, n) in enumerate(sched):
                size = sum(o - r for r in range(start, start + n)) * m
                self.assertLessEqual(size, cap)
                if i + 1 < len(sched):   # one row more would not fit
                    self.assertGreater(size + (o - start - n) * m, cap)

    def test_schedule_refuses_a_row_that_does_not_fit(self):
        self.assertRaises(ValueError, mc.maxfill_schedule, 64, 32, 64 * 32 - 1)


class Ip3VerdictTest(unittest.TestCase):
    """An accepting Ip3 run must end with status 0, a --negative run with -1 (the reject); -2 and -3 fail both."""
    def verdict(self, status, negative):
        a = SimpleNamespace(vectors=mc.vectors_of('Ip3'), cases=[0], negative=negative, phases=False,
                            dump_stats=None, elf='x.elf')
        out = io.StringIO()
        with mock.patch.object(mc, 'measure_ip3', return_value=(1, 2, [], status)), redirect_stdout(out), \
                self.assertRaises(SystemExit) as e:
            mc.measure_ip3_cases(a)
        return e.exception.code, out.getvalue()

    def test_exit_code_and_label(self):
        label = {0: 'ACCEPT', -1: 'REJECT (-1)', -2: 'ERROR (-2)', -3: 'ERROR (-3)', 1: 'ERROR (1)'}
        for negative in (False, True):
            for status in label:
                with self.subTest(status=status, negative=negative):
                    code, out = self.verdict(status, negative)
                    self.assertEqual(code, 0 if status == (-1 if negative else 0) else 1)
                    self.assertIn(f'cyc  {label[status]}\n', out)


class PhaseStatusTest(unittest.TestCase):
    """INIT and UPDATE write only an error status, which FINAL would overwrite: the first nonzero one ends the case."""
    SETS = (('Is', OV_IS, mc.LAYOUT_IS, 66576, 96), ('Ip', OV_IP, mc.LAYOUT_IP, 43576, 128),
            ('Ip3', OV_IP3, mc.LAYOUT_IP3, 46591, 135))

    def run_case(self, param, p, cpk_len, sig_len, error_after=-1, code=-2):
        phases = []

        def run_phase(sim, elf, words):
            phases.append(words)
            return 1, 10

        def read_status(sim, layout):
            return code if len(phases) == error_after else 0

        measure = mc.PARAMS[param][1]
        with mock.patch.object(mc, 'load_elf'), mock.patch.object(mc, 'run_phase', side_effect=run_phase), \
                mock.patch.object(mc, 'read_status', side_effect=read_status), \
                mock.patch.object(mc, 'window_cap', return_value=mc.MSGWIN_IP3 if param == 'Ip3' else 30 * 1024):
            _, _, per, status = measure('x.elf', bytes(cpk_len), bytes(sig_len), b'', p, sim=object())
        return [name for name, _, _ in per], status, phases

    def test_error_after_init_or_any_update_ends_the_case(self):
        for param, p, _, cpk_len, sig_len in self.SETS:
            total = len(self.run_case(param, p, cpk_len, sig_len)[0])     # INIT, the UPDATEs, FINAL
            for error_after in range(1, total):
                for code in (-2, -3):
                    with self.subTest(param=param, error_after=error_after, code=code):
                        names, status, _ = self.run_case(param, p, cpk_len, sig_len, error_after, code)
                        self.assertEqual(status, code)
                        self.assertEqual(len(names), error_after)
                        self.assertNotIn('FINAL', names)

    def test_clean_run_reaches_final_and_init_clears_the_status(self):
        for param, p, layout, cpk_len, sig_len in self.SETS:
            with self.subTest(param=param):
                names, status, phases = self.run_case(param, p, cpk_len, sig_len)
                self.assertEqual(status, 0)
                self.assertEqual((names[0], names[-1]), ('INIT', 'FINAL'))
                self.assertLessEqual(mc.word32(layout['CTRL'] + 12, 0).items(), phases[0].items())

    def test_functional_counts_the_update_runs_it_made(self):
        for error_after, want in ((1, 0), (2, 1), (-1, 2)):
            per = [('INIT', 1, 1), ('UPD r0', 1, 1), ('UPD r13', 1, 1), ('FINAL', 1, 1)][:error_after if error_after > 0 else 4]
            with self.subTest(error_after=error_after), mock.patch.object(mc, 'StandaloneSim'), \
                    mock.patch.object(mc, 'require_dmem_profile'), mock.patch.object(mc, 'extract_bytes_from_dmem', return_value=b''), \
                    mock.patch.dict(mc.PARAMS, {'Ip': (OV_IP, mock.Mock(return_value=(0, 0, per, -2 if error_after > 0 else 0)))}):
                self.assertEqual(mc.streamed_verify('x.elf', b'', b'', b'', 'Ip')[2], want)


class KeygenTierTest(unittest.TestCase):
    def test_wrong_tier_refused_before_any_run(self):
        elf = os.path.abspath(__file__)          # any existing file; the symbols are mocked
        argv = ['run_test.py', '--elf', elf, '--tier', 'bngfaes', '--cases', '0']
        out = io.StringIO()
        with mock.patch.object(sys, 'argv', argv), \
                mock.patch.object(kgu, '_kg_objdump_syms', return_value={'rcon': 0, 'sk_seed': 0, 'cpk': 0, 'csk': 0}), \
                mock.patch('acc_sim_utils.run_acc_test') as run, redirect_stdout(out):
            self.assertEqual(kgu.keygen_main(OV_IP), 1)
        run.assert_not_called()
        self.assertIn('ELF fingerprint says bngfonly, --tier bngfaes', out.getvalue())


class OneShotVerifyMapTest(unittest.TestCase):
    # the bngfaes Ip3 one-shot verify ELF's symbols; its kernel addresses hdr..msg by number
    SYMS = dict(hdr=0x000, accctx=0x020, oil=0x060, target=0x0A0, sig=0x0E0, seed=0x180, msg=0x1A0, cpk=0x5A0,
                _dmem_data_end=0xBC80, _dmem_bss_end=0xBC80)

    def make(self, **moved):
        a = SimpleNamespace(poison=False, tier=None, stats=False)
        vf.configure('Ip3')
        with profile(PROFILE_128), mock.patch.object(vf, '_kg_objdump_syms', return_value={**self.SYMS, **moved}), \
                mock.patch.object(vf, 'StandaloneSim'), mock.patch.object(vf, 'load_elf'), redirect_stdout(io.StringIO()):
            return vf.OneShotVerify(os.path.abspath(__file__), a)

    def test_kernel_layout_passes(self):
        self.assertEqual(self.make().MSG, 0x1A0)

    def test_aligned_wrong_map_refused(self):
        for sym in ('hdr', 'accctx', 'oil', 'target', 'sig', 'seed', 'msg'):    # every address the kernel hardcodes
            with self.subTest(sym=sym), self.assertRaisesRegex(AssertionError, 'off the fixed map'):
                self.make(**{sym: self.SYMS[sym] + 32})

    def test_bss_past_the_bus_refused(self):
        with self.assertRaises(AssertionError):
            self.make(_dmem_bss_end=PROFILE_128.dmem_bus_size_bytes + 32)


SIGN_BIN = os.path.join(REPO, 'bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k')
SIGN_SW = os.path.join(SIGN_BIN, 'sign_ldirect/ov-Is-skc/ov-Is-sign_ldirect_testvec_sw.elf')
LDIRECT = [(OV_IP, os.path.join(SIGN_BIN, 'sign_ldirect/ov-Ip-skc/ov-Ip-sign_ldirect_testvec_bngfaes.elf')),
           (OV_IS, os.path.join(SIGN_BIN, 'sign_ldirect/ov-Is-skc/ov-Is-sign_ldirect_testvec_bngfaes.elf')),
           (OV_IP3, os.path.join(SIGN_BIN, 'sign_ldirect/ov-Ip3-skc/ov-Ip3-sign_ldirect_testvec_bngfaes.elf'))]


def elf_syms(path):
    with open(path, 'rb') as fh:
        return {s.name: s['st_value'] for s in ELFFile(fh).get_section_by_name('.symtab').iter_symbols()}


class DefaultElfTest(unittest.TestCase):
    def test_sign_precompute_default_is_the_parameter_package(self):
        # without --elf the driver resolves its ELF below bazel-bin; from an empty directory it stops on the missing file
        # and names it, before any simulation
        sys.path.insert(0, os.path.join(REPO, 'tools'))
        import gather_kat_stats as gks
        for p in ('Ip', 'Is'):
            with self.subTest(param=p), tempfile.TemporaryDirectory() as tmp:
                r = subprocess.run([sys.executable, os.path.join(HW, 'own_utils/run_test.py'), 'sign', '--param', p,
                                    '--precompute', '--tier', 'bngfaes'], cwd=tmp, capture_output=True, text=True)
                want = os.path.dirname(gks.elf_of('sign', p, 'bngfaes', 'sprec'))
                self.assertIn(f'missing sign ELF: bazel-bin/{want}/ov-{p}-sign_sprec_bngfaes.elf', r.stdout)


class SignTierTest(unittest.TestCase):
    def sign(self, tier, out):
        argv = ['run_test.py', '--elf', SIGN_SW, '--tier', tier, '--output-dir', out]
        text = io.StringIO()
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(sgu, 'run_acc_test') as run, \
                mock.patch('acc_sim_utils.run_test_suite', return_value=0) as suite, redirect_stdout(text):
            rc = sgu.sign_main(OV_IS)
        return rc, text.getvalue(), run, suite

    @unittest.skipUnless(os.path.isfile(SIGN_SW), 'build //sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Is-skc:'
                         'ov-Is-sign_ldirect_testvec_sw first')
    def test_wrong_tier_refused_before_any_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, 'out')
            rc, text, run, suite = self.sign('bngfaes', out)
            self.assertEqual(rc, 1)
            self.assertIn(f'ERROR: {SIGN_SW}: ELF fingerprint says sw, --tier bngfaes', text)
            run.assert_not_called()
            suite.assert_not_called()
            self.assertFalse(os.path.exists(out))
            rc, text, run, suite = self.sign('sw', out)          # the matching tier goes on to the run
            self.assertEqual(rc, 0, text)
            suite.assert_called_once()


class SignSlotsTest(unittest.TestCase):
    def test_ip3_o_slots(self):
        p, base = OV_IP3, OV_IP3.sign_o_output_addr
        col = p.o_size // p.pub_m                                   # 74 B of data, 22 B of zero slack per slot
        o = bytes((7 * i + 1) & 0xFF for i in range(p.o_size))
        dmem = bytearray(base + p.o_size_padded + 64)
        for j in range(p.pub_m):
            dmem[base + j * p.o_slot_bytes:base + j * p.o_slot_bytes + col] = o[j * col:(j + 1) * col]
        ok, msgs = sgu.validate_step_2_o_matrix(bytes(dmem), o, p)
        self.assertTrue(ok, msgs)
        self.assertEqual(msgs, ['[2] O matrix data matches (3330 bytes)',
                                '[2] O slot padding correct (bytes 74..95 of all 45 column slots are zero)'])
        for at, why in ((5 * p.o_slot_bytes + col + 3, 'O slot padding MISMATCH in 1 column(s); column 5'),
                        (5 * p.o_slot_bytes + 3, f'First diff at byte {5 * col + 3}')):
            bad = bytearray(dmem)
            bad[base + at] ^= 0x40
            with self.subTest(offset=at):
                ok, msgs = sgu.validate_step_2_o_matrix(bytes(bad), o, p)
                self.assertFalse(ok)
                self.assertTrue(any(why in m for m in msgs), msgs)

    @unittest.skipUnless(all(os.path.isfile(e) for _, e in LDIRECT), 'build the bngfaes L-direct sign_testvec_test ELFs first')
    def test_ldirect_pk_seed_and_o_are_the_wrapper_labels(self):
        # every L-direct wrapper puts pk_seed and O at the top of the stack, where the body writes them
        for p, elf in LDIRECT:
            with self.subTest(param=p.short):
                syms, q = elf_syms(elf), sgu._with_testvec_offset(sgu._with_ldirect_layout(p))
                self.assertEqual((q.sign_pkseed_output_addr, q.sign_o_output_addr), (syms['pk_seed'], syms['O']))


class SignRetryTest(unittest.TestCase):
    """The sign harness against synthetic attempts: no ISS, the run's DMEM holds the inputs, the salt and the
    KAT signature of Ip3 case 0, and the test sets the ACC's retry counter and whether each attempt's L is
    invertible. Every attempt before the counter must be singular, the one at the counter invertible."""
    KAT = os.path.join(HW, 'test_data/testvectors-Ip3-pkc-skc')

    def sign(self, counter, invertible):
        p = OV_IP3
        _, _, _, sig, salt = sgu.parse_sign_testvec_file(self.KAT, p)[0]
        q = sgu._with_testvec_offset(sgu._with_ldirect_layout(p))

        def run(elf_path, dmem_words, **_):
            dmem = bytearray(32768)
            for addr, word in dmem_words.items():
                dmem[addr:addr + 4] = word.to_bytes(4, 'little')
            dmem[q.sign_salt_addr:q.sign_salt_addr + len(salt)] = salt
            dmem[q.sign_sig_addr:q.sign_sig_addr + len(sig)] = sig
            return True, bytes(dmem), mock.sentinel.sim

        text = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(sys, 'argv', ['run_test.py', '--elf', os.path.abspath(__file__),
                                                '--test-data-file', self.KAT, '--cases', '0', '--output-dir', tmp]), \
                mock.patch('hw.ip.acc.util.shared.elf.read_elf',
                           return_value=(None, None, {'salt_input': p.sign_salt_input_addr})), \
                mock.patch.object(sgu, 'run_acc_test', side_effect=run), \
                mock.patch.object(sgu, 'read_gpr_register', return_value=counter), \
                mock.patch.object(sgu, '_is_matrix_invertible', side_effect=invertible) as oracle, \
                redirect_stdout(text):
            rc = sgu.sign_main(p)
        text = text.getvalue()
        self.assertEqual(oracle.call_count, counter + 1)
        for line in ('[12] Signature verification PASSED', '[KAT] OK Testvec sig byte-wise MATCH'):
            self.assertIn(line, text)       # the signature is good: the retry check alone decides the run
        return rc, text

    def test_first_attempt(self):
        rc, text = self.sign(0, [True])
        self.assertEqual(rc, 0, text)
        self.assertIn('Counter 0: L invertible (GE success)', text)

    def test_singular_then_success(self):
        rc, text = self.sign(1, [False, True])
        self.assertEqual(rc, 0, text)
        self.assertIn('Counter 0: L singular (GE fail) -- skipped', text)

    def test_invertible_attempt_skipped_fails(self):
        rc, text = self.sign(1, [True, True])
        self.assertEqual(rc, 1, text)
        self.assertIn('[ERROR] Counter 0: L is invertible but ACC skipped it!', text)

    def test_singular_attempt_used_fails(self):
        rc, text = self.sign(0, [False])
        self.assertEqual(rc, 1, text)
        self.assertIn('[ERROR] Counter 0: L is singular but ACC used it!', text)


class LocalizeTest(unittest.TestCase):
    def test_reference_mismatch_fails(self):
        cpk, sk_seed = kgu._kg_parse_pkc_skc(os.path.join(HW, 'test_data/testvectors-Ip3-pkc-skc'))[0]
        o, n = 45, 45
        body = bytes(cpk[16:])
        p3full = [[bytes(n)] * o for _ in range(o)]
        idx = 0
        for k in range(o):
            for j in range(k, o):
                p3full[k][j] = body[idx * n:(idx + 1) * n]   # lower triangle zero: the fold leaves it
                idx += 1
        with redirect_stdout(io.StringIO()):
            self.assertTrue(kgs.localize('Ip3', sk_seed, bytes(cpk[:16]), p3full))
            bad = [row[:] for row in p3full]
            bad[3][7] = bytes([bad[3][7][0] ^ 1]) + bad[3][7][1:]
            self.assertFalse(kgs.localize('Ip3', sk_seed, bytes(cpk[:16]), bad))


D32 = os.path.join(HW, 'uov/dmem32k')
SWEEPS = [os.path.join(D32, d, 'run_ldirect_kats.py') for d in ('sign_ldirect/ov-Ip-skc', 'sign_ldirect/ov-Ip3-skc')]
SIGN_VECTORS = os.path.join(D32, 'sign_rtl/gen_sign_testvec.py')
# scripts whose work is cheap or fails at once on an ELF that is not there: script -> it takes --elf
NAMED = {os.path.join(D32, 'verify_stream/ov-Ip3-pkc/window_model.py'): False}
# scripts that build, simulate or rewrite tracked files: checked in-process, their work replaced and their
# tracked inputs pointed at a temporary directory
WORK = {**{s: 'run_case' for s in SWEEPS}, SIGN_VECTORS: 'generate'}
COLLECTOR = os.path.join(REPO, 'tools/gather_kat_stats.py')


def cli(*argv):
    return subprocess.run([sys.executable, *argv], capture_output=True, text=True)


def load(path):
    spec = importlib.util.spec_from_file_location('script_under_test', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class NamedOptionsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        os.mkdir(os.path.join(self.tmp.name, 'd'))
        with open(os.path.join(self.tmp.name, 'd', 'ldirect_test_inputs.s'), 'wb') as fh:
            fh.write(b'not the tracked inputs\n')

    def contained(self, mod, work):
        """The script's work replaced by a failure, and the files it would touch around it kept in the temp directory."""
        where = {'ROOT': self.tmp.name, 'DIR': 'd'} if work == 'run_case' else {'HERE': pathlib.Path(self.tmp.name)}
        return mock.patch.multiple(mod, **where, **{work: mock.Mock(side_effect=AssertionError('the script started its work'))})

    def test_help_works_and_positionals_are_refused(self):
        absent = os.path.join(self.tmp.name, 'absent.elf')
        for script, takes_elf in NAMED.items():
            with self.subTest(script=os.path.relpath(script, REPO)):
                r = cli(script, '--help')
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn('usage:', r.stdout)
                r = cli(script, *(['--elf', absent] if takes_elf else []), 'stray')
                self.assertEqual(r.returncode, 2)
                self.assertIn('unrecognized arguments: stray', r.stderr)
        for script, work in WORK.items():
            mod = load(script)
            for argv, code, text in ((['--help'], 0, 'usage:'), (['stray'], 2, 'unrecognized arguments: stray')):
                out, err = io.StringIO(), io.StringIO()
                with self.subTest(script=os.path.relpath(script, REPO), argv=argv), self.contained(mod, work), \
                        mock.patch.object(sys, 'argv', [script, *argv]), redirect_stdout(out), redirect_stderr(err), \
                        self.assertRaises(SystemExit) as e:
                    mod.main()
                self.assertEqual(e.exception.code, code)
                self.assertIn(text, out.getvalue() + err.getvalue())

    def test_sweep_runs_its_cases_and_puts_the_tracked_inputs_back(self):
        found = b'as found\r\nno final newline'                             # restored byte for byte
        for script in SWEEPS:
            run = load(script)
            for outcome, ran in ((True, [0, 3]), (False, [0, 3]), (AssertionError('sim did not complete cleanly'), [0])):
                with self.subTest(script=os.path.relpath(script, REPO), outcome=outcome), \
                        tempfile.TemporaryDirectory() as tmp:
                    inputs = os.path.join(tmp, 'd', 'ldirect_test_inputs.s')
                    os.makedirs(os.path.dirname(inputs))
                    with open(inputs, 'wb') as fh:
                        fh.write(found)
                    cases = []

                    def case(c, *tier):
                        cases.append(c)
                        with open(inputs, 'w') as fh:
                            fh.write(f'case {c}\n')
                        if isinstance(outcome, Exception):
                            raise outcome
                        return outcome

                    with mock.patch.multiple(run, ROOT=tmp, DIR='d', run_case=case), \
                            mock.patch.object(sys, 'argv', [script, '--cases', '0,3']), \
                            redirect_stdout(io.StringIO()), \
                            self.assertRaises(type(outcome) if isinstance(outcome, Exception) else SystemExit) as e:
                        run.main()
                    if isinstance(outcome, Exception):
                        self.assertIs(e.exception, outcome)
                    else:
                        self.assertEqual(e.exception.code, 0 if outcome else 1)
                    self.assertEqual(cases, ran)                            # the cases ran, so the file was rewritten
                    with open(inputs, 'rb') as fh:
                        self.assertEqual(fh.read(), found)

    def test_sweep_never_reads_past_the_dump(self):
        # a read past the dump must fail: zero padding would satisfy the all-zero case
        for script in SWEEPS:
            run = load(script)
            with self.subTest(script=os.path.relpath(script, REPO)), tempfile.TemporaryDirectory() as tmp:
                zeros = os.path.join(tmp, 'expected.bin')
                with open(zeros, 'wb') as fh:
                    fh.write(bytes(4096))
                r2 = hasattr(run, 'ELF')
                if r2:
                    with open(zeros, 'wb') as fh:
                        fh.write(bytes(2816))
                full, at = bytes(64 + 4096), {'ld_L_out': 64, 'ld_y_out': 64}
                for dump, addr, why in ((full, at, None), (bytes(64 + 100), at, 'ld_L_out at 0x40 + '),
                                        *([] if r2 else [(full, dict(at, ld_y_out=len(full) - 32), 'ld_y_out at 0x1020 + 64 B')])):
                    with mock.patch.multiple(run, sh=lambda cmd: '', sym_addr=lambda elf, name: addr[name], EXPECTED=zeros,
                                             **({} if r2 else {'EXPECTED_Y': zeros})), \
                            mock.patch('acc_sim_utils.run_acc_test', return_value=(True, dump, None)), \
                            redirect_stdout(io.StringIO()):
                        if why is None:
                            self.assertTrue(run.run_case(2, *([] if r2 else ['ldirect_kat_test_bngfaes'])))   # positive control
                        else:
                            with self.assertRaises(AssertionError) as e:
                                run.run_case(2, *([] if r2 else ['ldirect_kat_test_bngfaes']))
                            self.assertIn(why, str(e.exception))
                            self.assertIn(f'is outside the {len(dump)} B DMEM dump', str(e.exception))

    def test_sign_vectors_are_the_generators_output(self):
        gen = load(SIGN_VECTORS)
        self.assertEqual(len(gen.ALL), 25)
        with tempfile.TemporaryDirectory() as tmp:
            real = gen.HERE
            for p in ('Ip', 'Is', 'Ip3'):
                (pathlib.Path(tmp) / f'ov-{p}-skc' / 'testvectors').mkdir(parents=True)
            with mock.patch.object(gen, 'HERE', pathlib.Path(tmp)), mock.patch.object(sys, 'argv', [SIGN_VECTORS]), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(gen.main(), 0)                              # no option: every vector, none there before
            # each parameter set's vectors in its own ov-<P>-skc/testvectors/, byte for byte the committed ones
            made = sorted(str(f.relative_to(tmp)) for f in pathlib.Path(tmp).rglob('*') if f.is_file())
            self.assertEqual(made, sorted(str(f.relative_to(real)) for f in real.glob('ov-*-skc/testvectors/testvectors-*-sign_msglen*.s')))
            self.assertEqual(len(made), 25)
            for name in made:
                with self.subTest(name):
                    self.assertTrue(name.startswith(f"ov-{name.split('testvectors-')[1].split('-')[0]}-skc/testvectors/"))
                    self.assertEqual((pathlib.Path(tmp) / name).read_bytes(), (real / name).read_bytes())

    def test_one_sign_vector_needs_all_three_options(self):
        gen, out = load(SIGN_VECTORS), os.path.join(self.tmp.name, 'vector.s')
        for argv in (['--param', 'Ip'], ['--msglen', '0', '--out', out], ['--param', 'Ip', '--out', out]):
            err = io.StringIO()
            with self.subTest(argv=argv), self.contained(gen, 'generate'), mock.patch.object(sys, 'argv', [SIGN_VECTORS, *argv]), \
                    redirect_stderr(err), self.assertRaises(SystemExit) as e:
                gen.main()
            self.assertEqual(e.exception.code, 2)
            self.assertIn('--param, --msglen and --out go together', err.getvalue())

    def test_collector_takes_the_shared_case_grammar(self):
        # one verify cell and an ELF root without ELFs: whatever the collector makes of the list, no simulation starts
        out, root = os.path.join(self.tmp.name, 'out'), os.path.join(self.tmp.name, 'root')
        os.mkdir(root)
        one_cell = ['--out', out, '--ops', 'verify', '--params', 'Ip', '--tiers', 'bngfaes', '--variants', 'stream',
                    '--workers', '1', '--elf-root', root]
        for spec, why in (('0,0', 'listed twice'), ('3-1', 'descending range'), ('', 'bad case list')):
            r = cli(COLLECTOR, *one_cell, '--cases', spec)
            with self.subTest(spec=spec):
                self.assertEqual(r.returncode, 2)
                self.assertIn(why, r.stderr)
                self.assertFalse(os.path.exists(out))
        # a list that is not ascending is taken as given; the csv is sorted whatever the order
        r = cli(COLLECTOR, *one_cell, '--cases', '11,0')
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn('gathering 2 cells', r.stdout)
        with open(os.path.join(out, 'results.csv')) as fh:
            self.assertEqual([line.split(',')[4:6] for line in fh.read().splitlines()[1:]],
                             [['0', 'FAIL:elf-identity(stream-bngfaes)'], ['11', 'FAIL:elf-identity(stream-bngfaes)']])


if __name__ == '__main__':
    unittest.main()
