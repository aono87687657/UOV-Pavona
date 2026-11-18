#!/usr/bin/env python3
"""The collector's catalog and routes: the 32 KiB hardware-AES tier reaches every supported cell,
the campaign catalog is exactly the specified 102 cells and every one runs its driver on the ELF
under --elf-root, measurements are read from exactly one record, a timeout ends the driver's whole
process group, a stopped collector leaves no driver running, and a bad invocation never touches an
existing output directory."""

import io
import os
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # tools/
import gather_kat_stats as gks
from gather_kat_stats import cell_valid

TOOL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gather_kat_stats.py")


def _own_children_only(real):
    def call(target, sig):
        if type(target) is not int or target <= 1:
            raise RuntimeError(f"refusing to signal {target!r}")
        return real(target, sig)
    return call


# kill(-1), kill(0) and killpg(0 or 1) reach far beyond a test's own children: refused for the whole module
SIGNAL_CHECKS = [mock.patch.object(os, name, _own_children_only(getattr(os, name))) for name in ("kill", "killpg")]


def setUpModule():
    for check in SIGNAL_CHECKS:
        check.start()


def tearDownModule():
    for check in SIGNAL_CHECKS:
        check.stop()


class TierCoverageTest(unittest.TestCase):
    def test_hardware_aes_cells_are_runnable(self):
        for param in ("Ip", "Is", "Ip3"):
            for op, variant in (
                ("keygen", "stream"),
                ("keygen", "stream_uniform"),
                ("sign", "ldirect"),
                ("verify", "stream"),
                ("verify", "stream_uniform"),
            ):
                with self.subTest(param=param, op=op, variant=variant):
                    self.assertTrue(cell_valid(op, param, "bnaesonly", variant))

    def test_hardware_aes_does_not_select_unsupported_large_dmem_variants(self):
        # keygen min/sp and verify full have hardware-AES arms; keygen full and sprec do not
        for param in ("Ip", "Is", "Ip3"):
            for op, variant in (
                ("keygen", "full"),
                ("sign", "sprec"),
            ):
                with self.subTest(param=param, op=op, variant=variant):
                    self.assertFalse(cell_valid(op, param, "bnaesonly", variant))

    def test_sign_elf_must_carry_its_own_l_builder(self):
        for param, (sprec, ldirect) in gks._SIGN_SYMS.items():
            with self.subTest(param=param):
                self.assertTrue(gks._sign_variant_ok({sprec, "S"}, param, "sprec"))
                self.assertFalse(gks._sign_variant_ok({ldirect, "S"}, param, "sprec"))      # an L-direct ELF at the sprec path
                self.assertTrue(gks._sign_variant_ok({ldirect}, param, "ldirect"))
                self.assertFalse(gks._sign_variant_ok({sprec, ldirect}, param, "ldirect"))


U = "sw/acc/crypto/handwritten/uov"
RUN_TEST = "sw/acc/crypto/handwritten/own_utils/run_test.py"


def spec_cells():
    """The campaign catalog as specified, written out independently of gather_kat_stats.CAMPAIGN."""
    t4, p3 = ("bngfaes", "bngfonly", "bnaesonly", "sw"), ("Ip", "Is", "Ip3")
    out = set()
    for op, v in (("sign", "ldirect"), ("verify", "stream"), ("verify", "stream_uniform"),
                  ("keygen", "stream"), ("keygen", "stream_uniform")):
        out |= {(32, op, v, p, t) for p in p3 for t in t4}
    out |= {(128, "keygen", v, p, t) for v in ("min", "sp") for p in p3 for t in t4}
    out |= {(128, "verify", "full", p, t) for p in p3 for t in t4}
    out |= {(512, op, v, p, "bngfaes") for op, v in (("keygen", "full"), ("sign", "sprec")) for p in p3}
    return out


def spec_route(op, v, p, t):
    """(driver script, ELF) a cell must run, below the repo and the ELF root."""
    if op == "keygen":
        sub = f"ov-{p}-pkc+skc/ov-{p}-keygen_{v}_{t}.elf"
        if v in ("stream", "stream_uniform"):
            return f"{U}/dmem32k/keygen_stream/tests/test_stream_keygen.py", f"{U}/dmem32k/keygen_{v}/{sub}"
        return RUN_TEST, f"{U}/dmem_large/keygen_{v}/{sub}"
    if op == "sign":
        size = "dmem_large" if v == "sprec" else "dmem32k"
        return RUN_TEST, f"{U}/{size}/sign_{v}/ov-{p}-skc/ov-{p}-sign_{v}_testvec_{t}.elf"
    if v in ("stream", "stream_uniform"):
        return f"{U}/dmem32k/verify_stream/tests/measure_cycles.py", f"{U}/dmem32k/verify_{v}/ov-{p}-pkc/ov-{p}-verify_{v}_{t}.elf"
    return f"{U}/dmem_large/verify_full/tests/test_full_verify.py", f"{U}/dmem_large/verify_full/ov-{p}-pkc/ov-{p}-verify_full_{t}.elf"


def spec_route_flat(op, v, p, t):
    """spec_route in the folders before the 2026-10-19 reorg, which the earlier rounds name."""
    r3 = "_round3" if p == "Ip3" else ""
    if op == "keygen":
        if v in ("stream", "stream_uniform"):
            return f"{U}/dmem32k/keygen_stream/tests/test_stream_keygen.py", f"{U}/dmem32k/keygen_{v}{r3}/ov-{p}-keygen_{v}_{t}.elf"
        elf = {"full": f"{U}/dmem_large/keygen_full/ov-{p}-pkc+skc/ov-{p}-keygen_full_{t}.elf",
               "min": f"{U}/dmem_large/keygen_min{r3}/ov-{p}-keygen_min_{t}.elf",
               "sp": f"{U}/dmem_large/keygen_sp{r3}/ov-{p}-keygen_sp_{t}.elf"}[v]
        return RUN_TEST, elf
    if op == "sign":
        drv = RUN_TEST
        if v == "sprec":
            return drv, f"{U}/dmem_large/sign_sprec/ov-{p}-sign_sprec_testvec_{t}.elf"
        return drv, f"{U}/dmem32k/sign_ldirect{r3}/ov-{p}-skc/ov-{p}-sign_ldirect_testvec_{t}.elf"
    if v in ("stream", "stream_uniform"):
        drv = (f"{U}/dmem32k/verify_stream_round3/tests/test_ip3_stream.py" if p == "Ip3"
               else f"{U}/dmem32k/verify_stream/tests/measure_cycles.py")
        return drv, f"{U}/dmem32k/verify_{v}{r3}/ov-{p}-verify_{v}_{t}.elf"
    return f"{U}/dmem_large/verify_full/tests/test_full_verify.py", f"{U}/dmem_large/verify_full{r3}/ov-{p}-verify_full_{t}.elf"


FINGERPRINT = {"bngfaes": set(), "bngfonly": {"rcon"}, "sw": {"AES128_TABLE"}, "bnaesonly": {"aes128hw_col"}}
IDENTITY = {("keygen", "stream"): {"ctrl", "slice", "slice_end"},
            ("keygen", "stream_uniform"): {"ctrl", "slice", "slice_end", "backend_init_once"},
            ("keygen", "full"): {"cpk"}, ("keygen", "min"): {"cpk", "cpk_payload", "slice_end"},
            ("keygen", "sp"): {"cpk", "cpk_payload"},
            ("verify", "stream_uniform"): {"initdone", "msgwin"}, ("verify", "full"): {"cpk", "hdr", "accctx"}}


class CatalogTest(unittest.TestCase):
    def test_exact_cells(self):
        got = {(prof, op, v, p, t) for (prof, op, v), (ps, ts) in gks.CAMPAIGN.items() for p in ps for t in ts}
        self.assertEqual(got, spec_cells())
        self.assertEqual([sum(1 for c in got if c[0] == prof) for prof in (32, 128, 512)], [60, 36, 6])
        self.assertEqual(12 * len(got), 1224)

    def test_every_campaign_cell_is_a_collector_cell_with_a_protocol(self):
        for prof, op, v, p, t in spec_cells():
            with self.subTest(cell=(prof, op, v, p, t)):
                self.assertTrue(cell_valid(op, p, t, v))
                self.assertIn((op, v), gks.PROTOCOL)


class DispatchTest(unittest.TestCase):
    def test_flat_layout_names_the_folders_before_the_reorg(self):
        for prof, op, v, p, t in sorted(spec_cells()):
            drv, rel = spec_route_flat(op, v, p, t)
            with self.subTest(cell=(prof, op, v, p, t)):
                self.assertEqual(gks.elf_of(op, p, t, v, "flat"), rel)
                want = [drv, f"{U}/dmem32k/verify_stream/tests/measure_cycles.py"] if drv.endswith("test_ip3_stream.py") else [drv]
                self.assertEqual(gks.driver_of(op, p, v, "flat"), want)

    def test_every_campaign_cell_runs_its_driver_on_the_elf_under_the_root(self):
        for prof, op, v, p, t in sorted(spec_cells()):
            drv, rel = spec_route(op, v, p, t)
            with self.subTest(cell=(prof, op, v, p, t)), tempfile.TemporaryDirectory() as root:
                elf = os.path.join(root, rel)
                os.makedirs(os.path.dirname(elf))
                open(elf, "w").close()
                calls = []
                def drive(cmd):
                    calls.append(cmd)
                    return 0, "", False
                syms = {"sk_seed"} | FINGERPRINT[t] | IDENTITY.get((op, v), set())
                if op == "sign":
                    syms |= {gks._SIGN_SYMS[p][0 if v == "sprec" else 1]}
                with mock.patch.object(gks, "BAZEL_BIN", root), mock.patch.object(gks, "drive", drive), \
                        mock.patch.object(gks, "_elf_symbols", return_value=syms):
                    gks.OP_RUNNERS[op](p, t, v, 7, os.path.join(root, "cell"))
                self.assertEqual(len(calls), 1)
                cmd = calls[0]
                self.assertEqual(cmd[1], os.path.join(gks.REPO, drv))
                self.assertEqual(cmd[cmd.index("--elf") + 1], elf)
                self.assertIn("7", cmd[cmd.index("--case-start" if op == "sign" else "--cases") + 1])
                self.assertEqual(gks.driver_of(op, p, v), [drv])
                self.assertEqual(cmd[cmd.index("--param") + 1], p)         # one driver serves every parameter set
                if drv == RUN_TEST:
                    self.assertEqual(cmd[2], op)                           # the launcher's test name
                # only the one-shot verify proof reads a second key file, and its path is passed explicitly
                want = [f"{gks.HANDWRITTEN_DIR}/test_data/testvectors-{p}-pkc-skc.nistkat"] if (op, v, p) == ("verify", "full", "Ip3") else []
                self.assertEqual(("--vectors2" in cmd, cmd[cmd.index("--vectors2") + 1:] if "--vectors2" in cmd else []), (bool(want), want))
                self.assertEqual(gks.aux_inputs(op, p, v), want)



class VectorSetTest(unittest.TestCase):
    """--vectors: sign reads testvectors-<P>-pkc-skc.NAME, its evidence names carry the set, bad requests stop early."""

    def test_sign_reads_the_vector_set_and_names_its_evidence(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(gks, "VECTORS", "retrygrid"):
            rel = gks.elf_of("sign", "Is", "bngfaes", "sprec")
            elf = os.path.join(root, rel)
            os.makedirs(os.path.dirname(elf))
            open(elf, "w").close()
            calls = []
            syms = {"sk_seed", gks._SIGN_SYMS["Is"][0]} | FINGERPRINT["bngfaes"]
            with mock.patch.object(gks, "BAZEL_BIN", root), \
                    mock.patch.object(gks, "drive", lambda cmd: (calls.append(cmd), (0, "", False))[1]), \
                    mock.patch.object(gks, "_elf_symbols", return_value=syms):
                gks.run_sign("Is", "bngfaes", "sprec", 35, os.path.join(root, "cell"))
            cmd = calls[0]
            self.assertEqual(cmd[cmd.index("--test-data-file") + 1],
                             f"{gks.HANDWRITTEN_DIR}/test_data/testvectors-Is-pkc-skc.retrygrid")
            self.assertEqual(cmd[cmd.index("--case-start") + 1], "35")
            self.assertEqual(gks.stats_name("sign", "Is", "bngfaes", "sprec", 35), "sign_Is_bngfaes_sprec_retrygrid_case35.txt")
            self.assertEqual(gks.stats_name("sign", "Is", "bngfaes", "ldirect", 3), "sign_Is_bngfaes_retrygrid_case3.txt")
        self.assertEqual(gks.stats_name("sign", "Is", "bngfaes", "ldirect", 3), "sign_Is_bngfaes_case3.txt")

    def test_bad_requests_stop_before_any_output(self):
        for args, why in ((["--ops", "verify", "--params", "Ip"], "sign only"),
                          (["--ops", "sign", "--params", "Ip", "--cases", "36"], "has 36 cases"),
                          (["--ops", "sign", "--params", "Ip", "--vectors", "Retry"], "lower-case"),
                          (["--ops", "sign", "--params", "Ip", "--vectors", "nosuchset"], "no vector file")):
            with self.subTest(args=args), tempfile.TemporaryDirectory() as out:
                vec = [] if "--vectors" in args else ["--vectors", "retrygrid"]
                ran, err = [], io.StringIO()
                with mock.patch.object(sys, "argv", [TOOL, "--out", os.path.join(out, "o")] + args + vec), \
                        mock.patch.object(gks, "cell_job", lambda *c: ran.append(c)), \
                        mock.patch.object(gks, "VECTORS", None), mock.patch("sys.stderr", err), \
                        self.assertRaises(SystemExit) as e:
                    gks.main()
                self.assertEqual(e.exception.code, 2)
                self.assertIn(why, err.getvalue())
                self.assertEqual(ran, [])
                self.assertFalse(os.path.exists(os.path.join(out, "o")))

    def test_case_count_of_a_vector_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "v")
            with open(path, "w") as fh:
                fh.write("a\nb\nc\nd\ne\nf\n")
            self.assertEqual(gks.vector_cases(path), 2)
            with open(path, "a") as fh:
                fh.write("g\n")
            with self.assertRaises(ValueError):
                gks.vector_cases(path)

class MeasurementTest(unittest.TestCase):
    REPORT = "\nExecution time\n--------------\nACC executed {} instructions in {} cycles.\nloops  \n"

    def check(self, text, label, want):
        with tempfile.TemporaryDirectory() as d:
            raw, tidied = os.path.join(d, "raw"), os.path.join(d, "tidy")
            open(raw, "w").write(text)
            open(tidied, "w").write("\n".join(x.rstrip() for x in text.strip("\n").split("\n")) + "\n")
            self.assertEqual(gks.measurement(raw, label), want)
            self.assertEqual(gks.measurement(tidied, label), want)

    def test_single_summary(self):
        self.check(self.REPORT.format(5, 7) + "# elf: x.elf\n", None, (5, 7))

    def test_two_summaries_without_a_label_refused(self):
        self.check(self.REPORT.format(5, 7) + self.REPORT.format(6, 8), None, (None, None))

    def test_labelled_records(self):
        text = "".join(f"{lab}: {self.REPORT.format(i, i + 1)}" for lab, i in
                       (("case 3 accept", 10), ("flip 0", 20), ("accept again", 30)))
        self.check(text, "case 3 accept", (10, 11))
        self.check(text, "accept again", (30, 31))
        self.check(text, "case 4 accept", (None, None))
        self.check(text + "case 3 accept: " + self.REPORT.format(40, 41), "case 3 accept", (None, None))

    def test_record_without_a_summary_refused(self):
        self.check("case 0 accept: \nExecution time\n--------------\nnothing\n", "case 0 accept", (None, None))


def gone(pid, wait=5.0):
    """The process has ended: no longer listed, or a zombie its new parent has not reaped yet."""
    end = time.time() + wait
    while time.time() < end:
        try:
            with open(f"/proc/{pid}/stat") as fh:
                if fh.read().rsplit(")", 1)[1].split()[0] in ("Z", "X"):
                    return True
        except (FileNotFoundError, ProcessLookupError):     # gone before or while its stat file was read
            return True
        time.sleep(0.1)
    return False


def stubborn(pidfile):
    """A driver whose child ignores SIGTERM; the child's pid lands in pidfile before the driver prints."""
    child = ("import os, signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
             f"open({pidfile!r} + '.tmp', 'w').write(str(os.getpid())); os.rename({pidfile!r} + '.tmp', {pidfile!r}); "
             "time.sleep(60)")
    return (f"import os, subprocess, sys, time; subprocess.Popen([sys.executable, '-c', {child!r}])\n"
            f"while not os.path.exists({pidfile!r}): time.sleep(0.05)\n"
            "print('PASS', flush=True); time.sleep(60)")


class TimeoutTest(unittest.TestCase):
    def test_the_whole_group_ends_and_the_cell_fails(self):
        with tempfile.TemporaryDirectory() as d:
            pidfile = os.path.join(d, "child.pid")
            parent = stubborn(pidfile)
            start = time.time()
            with mock.patch.object(gks, "TIMEOUT", 3), mock.patch.object(gks, "KILL_GRACE", 1):
                rc, out, timed_out = gks.drive([sys.executable, "-c", parent])
            self.assertLess(time.time() - start, 3 + 1 + 3)          # the stubborn child did not hold drive() open
            self.assertEqual((rc, timed_out), (None, True))
            self.assertIn("PASS", out)
            pid = int(open(pidfile).read())
            self.assertTrue(gone(pid))
            os.makedirs(os.path.join(d, "cell"))
            self.assertEqual(gks.verdict(os.path.join(d, "cell"), rc, out, timed_out, True), "FAIL:timeout")
            self.assertIn("PASS", open(os.path.join(d, "cell", "driver.log")).read())

    def test_an_error_while_waiting_ends_and_reaps_the_driver(self):
        with tempfile.TemporaryDirectory() as d:
            pidfile = os.path.join(d, "child.pid")
            seen = []

            def interrupted(p, *a, **kw):
                seen.append(p)
                while not os.path.exists(pidfile):
                    time.sleep(0.05)
                raise KeyboardInterrupt
            with mock.patch.object(gks, "KILL_GRACE", 1), mock.patch.object(subprocess.Popen, "communicate", interrupted), \
                    self.assertRaises(KeyboardInterrupt):
                gks.drive([sys.executable, "-c", stubborn(pidfile)])
            p = seen[0]                                  # the driver's own Popen, as drive() left it
            self.assertIsNotNone(p.returncode)           # reaped by drive(); nothing here waits for it
            self.assertTrue(p.stdout.closed)
            self.assertNotIn(p, gks.LIVE)
            self.assertTrue(gone(int(open(pidfile).read())))


class UnresolvedTest(unittest.TestCase):
    def test_a_denied_signal_is_reported_within_a_bound(self):
        child = [sys.executable, "-c", "import time; time.sleep(8)"]      # real, ends by itself
        start = time.time()
        with mock.patch.object(gks, "TIMEOUT", 1), mock.patch.object(gks, "KILL_GRACE", 1), \
                mock.patch.object(gks, "STOPPING", False), \
                mock.patch.object(gks.os, "killpg", side_effect=PermissionError("denied")) as killpg:
            with self.assertRaises(gks.Unresolved) as failure:
                gks.drive(child)
            self.assertLess(time.time() - start, 1 + 3)                   # not the child's 8 s
            self.assertIn("may still be running", str(failure.exception))
            killpg.assert_called_once()                                   # no grace and no SIGKILL after the denial
            self.assertEqual(gks.LIVE, set())
            self.assertEqual(gks.drive(child), (None, "not started: the collector is stopping\n", False))

    def test_an_unresolved_process_is_not_a_cell_result(self):
        with tempfile.TemporaryDirectory() as out:
            os.makedirs(os.path.join(out, "stats"))
            cell = (out, "keygen", "Ip", "bngfaes", "full", 0)
            with mock.patch.dict(gks.OP_RUNNERS, {"keygen": mock.Mock(side_effect=gks.Unresolved("driver 7"))}), \
                    self.assertRaises(gks.Unresolved):
                gks.cell_job(*cell)
            with mock.patch.dict(gks.OP_RUNNERS, {"keygen": mock.Mock(side_effect=ValueError("x"))}):
                self.assertEqual(gks.cell_job(*cell)[5], "ERR:x")          # any other error is the cell's own


class SignalGuardTest(unittest.TestCase):
    def test_only_a_real_process_group_id_is_signalled(self):
        with mock.patch.object(gks.os, "killpg") as killpg:          # recorded, never sent
            for bad in (1, 0, -5, True, "7", None, mock.MagicMock()):
                with self.subTest(pid=bad), self.assertRaises(RuntimeError):
                    gks._signal_group(types.SimpleNamespace(pid=bad), signal.SIGKILL)
            killpg.assert_not_called()
            self.assertIs(gks._signal_group(types.SimpleNamespace(pid=4242), signal.SIGKILL), True)
            killpg.assert_called_once_with(4242, signal.SIGKILL)
            killpg.side_effect = ProcessLookupError                  # the group is gone already
            self.assertIs(gks._signal_group(types.SimpleNamespace(pid=4242), signal.SIGKILL), False)
            killpg.side_effect = PermissionError                     # a denied signal is not a kill
            with self.assertRaises(PermissionError):
                gks._signal_group(types.SimpleNamespace(pid=4242), signal.SIGKILL)

    def test_a_driver_that_cannot_be_ended_is_unresolved(self):
        never = mock.Mock(side_effect=subprocess.TimeoutExpired("x", 1))
        cases = {"signal denied": (PermissionError("denied"), mock.Mock()), "does not end": (None, never)}
        for name, (denial, wait) in cases.items():
            p = types.SimpleNamespace(pid=4242, returncode=None, wait=wait)
            with self.subTest(name), mock.patch.object(gks.os, "killpg", side_effect=denial), \
                    mock.patch.object(gks.time, "sleep"), mock.patch.object(gks, "STOPPING", False):
                with self.assertRaises(gks.Unresolved) as failure:
                    gks._end_group(p)
                self.assertIs(gks.STOPPING, True)                      # no driver starts after this
            self.assertIn("driver 4242 may still be running", str(failure.exception))
        never.assert_called_once_with(timeout=gks.KILL_GRACE)          # the reap is bounded

    def test_a_reaped_driver_is_not_signalled(self):
        with mock.patch.object(gks.os, "killpg") as killpg, mock.patch.object(gks.time, "sleep") as sleep:
            gks._end_group(types.SimpleNamespace(pid=4242, returncode=0))
        killpg.assert_not_called()
        sleep.assert_not_called()


DRIVER = """import os, signal, subprocess, sys, time
d, c, mode = sys.argv[1], sys.argv[2], sys.argv[3]
def mark(name):
    with open(os.path.join(d, name + '.tmp'), 'w') as fh:
        fh.write(str(os.getpid()))
    os.rename(os.path.join(d, name + '.tmp'), os.path.join(d, name))
if mode == 'child':                     # ignores SIGTERM: only a group SIGKILL ends it
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    mark('child-' + c)
    time.sleep(60)
    sys.exit(0)
if mode == 'stubborn':
    subprocess.Popen([sys.executable, __file__, d, c, 'child'])
    while not os.path.exists(os.path.join(d, 'child-' + c)):
        time.sleep(0.02)
mark('driver-' + c)
if mode == 'stubborn':
    time.sleep(60)
"""

# gather_kat_stats.main() with every cell running DRIVER through gks.drive(): modes[c] picks case c's behaviour
COLLECTOR = """import os, sys, time
sys.path.insert(0, {tools!r})
import gather_kat_stats as gks
d, modes, workers = sys.argv[1], sys.argv[2].split(','), sys.argv[3]
def fake_cell_job(out, op, param, tier, variant, c):
    open(os.path.join(d, 'started-%d' % c), 'w').close()
    if modes[c] == 'inspect':           # the ELF inspection of a cell, with HELPER as the objdump tool
        gks.REPO = d
        gks._elf_symbols(os.path.join(d, 'x.elf'))
    if modes[c] == 'unresolved':        # once cell 0's driver and its child run
        while not all(os.path.exists(os.path.join(d, n)) for n in ('child-0', 'driver-0')):
            time.sleep(0.02)
        raise gks._unresolved('driver 4242 may still be running')
    rc, _, _ = gks.drive([sys.executable, os.path.join(d, 'driver.py'), d, str(c), modes[c]])
    return (op, param, tier, variant, c, 'PASS' if rc == 0 else 'FAIL', None, None)
gks.cell_job = fake_cell_job
sys.argv = ['gather_kat_stats.py', '--out', os.path.join(d, 'out'), '--ops', 'keygen', '--params', 'Ip', '--tiers', 'bngfaes',
            '--variants', 'full', '--cases', '0-%d' % (len(modes) - 1), '--workers', workers]
sys.exit(gks.main())
"""


# stands in for hw/ip/acc/util/acc_objdump.py: leaves its pid in driver-inspect and stays
HELPER = """import os, time
with open({marker!r} + '.tmp', 'w') as fh:
    fh.write(str(os.getpid()))
os.rename({marker!r} + '.tmp', {marker!r})
time.sleep(60)
"""


class ElfSymbolsTest(unittest.TestCase):
    def test_a_tool_failure_is_an_error_not_missing_symbols(self):
        with tempfile.NamedTemporaryFile(suffix=".elf") as fh:
            fh.write(b"not an ELF")
            fh.flush()
            with self.assertRaises(RuntimeError):
                gks._elf_symbols(fh.name)


class StopTest(unittest.TestCase):
    """A stopped collector leaves no driver or driver child running and starts no further cell. The test
    signals only processes it started and has not reaped; drivers a failed test leaves end by themselves
    within a minute."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        with open(os.path.join(self.d, "driver.py"), "w") as fh:
            fh.write(DRIVER)
        with open(os.path.join(self.d, "collector.py"), "w") as fh:
            fh.write(COLLECTOR.format(tools=os.path.dirname(TOOL)))
        os.makedirs(os.path.join(self.d, "hw/ip/acc/util"))
        with open(os.path.join(self.d, "hw/ip/acc/util/acc_objdump.py"), "w") as fh:
            fh.write(HELPER.format(marker=os.path.join(self.d, "driver-inspect")))
        self.procs = []

    def tearDown(self):
        for p in self.procs:
            if p.poll() is None:
                p.kill()
                p.wait()
        self.tmp.cleanup()

    def pid(self, name):
        return int(open(os.path.join(self.d, name)).read())

    def wait_for(self, *names, timeout=30):
        end = time.time() + timeout
        while not all(os.path.exists(os.path.join(self.d, n)) for n in names):
            self.assertLess(time.time(), end, f"waiting for {names}")
            time.sleep(0.05)

    def collector(self, modes, workers=2):
        p = subprocess.Popen([sys.executable, os.path.join(self.d, "collector.py"), self.d, ",".join(modes), str(workers)],
                             start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        self.procs.append(p)
        return p

    def stopped(self, p, *signals):
        for sig in signals:                          # a lane is stopped through its process group
            os.killpg(p.pid, sig)
        _, err = p.communicate(timeout=20)           # a deadlock in the stop path fails here
        return p.returncode, err

    def test_sigterm_kills_every_driver_and_starts_no_queued_cell(self):
        unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
        self.procs.append(unrelated)
        p = self.collector(["stubborn"] * 4)
        self.wait_for("driver-0", "driver-1", "child-0", "child-1")
        rc, err = self.stopped(p, signal.SIGTERM)
        self.assertEqual(rc, 128 + signal.SIGTERM)
        self.assertIn("stopped by signal 15: SIGKILL sent to 2 driver groups, 0 already gone", err)
        self.assertNotIn("NOT signalled", err)
        for name in ("driver-0", "driver-1", "child-0", "child-1"):
            self.assertTrue(gone(self.pid(name)), name)
        time.sleep(0.5)
        self.assertFalse(any(os.path.exists(os.path.join(self.d, f"started-{c}")) for c in (2, 3)))
        self.assertIsNone(unrelated.poll())

    def test_sigint_then_sigterm_stop_once_without_deadlock(self):
        p = self.collector(["stubborn", "stubborn"])
        self.wait_for("driver-0", "driver-1", "child-0", "child-1")
        rc, _ = self.stopped(p, signal.SIGINT, signal.SIGTERM)
        self.assertEqual(rc, 128 + signal.SIGINT)
        for name in ("driver-0", "driver-1", "child-0", "child-1"):
            self.assertTrue(gone(self.pid(name)), name)

    def test_a_finished_driver_and_a_running_one(self):
        p = self.collector(["quick", "stubborn", "stubborn"])
        self.wait_for("driver-0", "driver-1", "driver-2", "child-1", "child-2")
        rc, _ = self.stopped(p, signal.SIGTERM)
        self.assertEqual(rc, 128 + signal.SIGTERM)
        for name in ("driver-1", "driver-2", "child-1", "child-2"):
            self.assertTrue(gone(self.pid(name)), name)

    def test_a_running_elf_inspection_is_stopped_with_the_collector(self):
        p = self.collector(["inspect"], workers=1)
        self.wait_for("driver-inspect")
        rc, err = self.stopped(p, signal.SIGTERM)
        self.assertEqual(rc, 128 + signal.SIGTERM)
        self.assertIn("SIGKILL sent to 1 driver groups", err)
        self.assertTrue(gone(self.pid("driver-inspect")))

    def test_an_unresolved_process_abandons_the_run(self):
        p = self.collector(["stubborn", "unresolved", "stubborn"])
        _, err = p.communicate(timeout=30)                                # the collector gives up by itself
        self.assertEqual(p.returncode, 3)
        self.assertIn("abandoned, driver 4242 may still be running: SIGKILL sent to 1 driver groups", err)
        for name in ("driver-0", "child-0"):
            self.assertTrue(gone(self.pid(name)), name)
        time.sleep(1)                                                     # cell 2 may be picked up, its driver never starts
        self.assertFalse(any(os.path.exists(os.path.join(self.d, n)) for n in ("driver-2", "child-2")))

    def test_no_driver_starts_once_stopping(self):
        marker = os.path.join(self.d, "started")
        cmd = [sys.executable, "-c", f"open({marker!r}, 'w').close()"]     # a real, harmless driver
        with mock.patch.object(gks, "STOPPING", True):
            self.assertEqual(gks.drive(cmd), (None, "not started: the collector is stopping\n", False))
        self.assertFalse(os.path.exists(marker))
        self.assertEqual(gks.drive(cmd)[::2], (0, False))                  # the same command runs otherwise
        self.assertTrue(os.path.exists(marker))


class OutputDirTest(unittest.TestCase):
    def run_tool(self, out, *args):
        return subprocess.run([sys.executable, TOOL, "--out", out, *args], capture_output=True, text=True)

    ONE_CELL = ("--ops", "keygen", "--params", "Ip", "--tiers", "bngfaes", "--variants", "full", "--cases", "0")

    def seed(self, out):
        prior = os.path.join(out, "results.csv")
        with open(prior, "w") as fh:
            fh.write("previous run\n")
        return prior

    def unchanged(self, prior):
        with open(prior) as fh:
            self.assertEqual(fh.read(), "previous run\n")

    def test_invalid_arguments_leave_previous_results(self):
        with tempfile.TemporaryDirectory() as out:
            prior = self.seed(out)
            r = self.run_tool(out, "--ops", "keygen", "--params", "Ip", "--tiers", "nosuchtier")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("unknown tier 'nosuchtier'", r.stderr)
            self.unchanged(prior)
            self.assertFalse(os.path.exists(os.path.join(out, "stats")))

    def test_a_refused_call_without_out_makes_no_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, TMPDIR=tmp)
            for args, why in ((("--params", "Ip"), "--ops"), (("--ops", "keygen"), "--params"),
                              (("--ops", "keygen", "--params", "Ip", "--tiers", "nosuchtier"), "unknown tier")):
                r = subprocess.run([sys.executable, TOOL, *args], capture_output=True, text=True, env=env)
                self.assertEqual(r.returncode, 2, args)
                self.assertIn(why, r.stderr)
            self.assertEqual(os.listdir(tmp), [])

    def test_zero_workers_leave_previous_results(self):
        with tempfile.TemporaryDirectory() as out:
            prior = self.seed(out)
            r = self.run_tool(out, "--workers", "0", *self.ONE_CELL)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("--workers", r.stderr)
            self.unchanged(prior)

    def test_bad_timeout_refused(self):
        for bad in ("0", "-5", "inf", "nan"):
            with self.subTest(timeout=bad), tempfile.TemporaryDirectory() as out:
                prior = self.seed(out)
                r = self.run_tool(out, "--timeout", bad, *self.ONE_CELL)
                self.assertEqual(r.returncode, 2)
                self.assertIn("--timeout must be positive", r.stderr)
                self.unchanged(prior)

    def test_empty_elf_root_refused(self):
        with tempfile.TemporaryDirectory() as out:
            prior = self.seed(out)
            r = self.run_tool(out, "--elf-root", "", *self.ONE_CELL)
            self.assertEqual(r.returncode, 2)
            self.assertIn("--elf-root  is not a directory", r.stderr)
            self.unchanged(prior)
            self.assertFalse(os.path.exists(os.path.join(out, "stats")))

    def test_fresh_refuses_a_non_empty_directory(self):
        with tempfile.TemporaryDirectory() as out:
            prior = self.seed(out)
            r = self.run_tool(out, "--fresh", *self.ONE_CELL)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("exists and is not empty", r.stderr)
            self.unchanged(prior)


if __name__ == "__main__":
    unittest.main()
