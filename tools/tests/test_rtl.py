"""One-shot "meters v2" harvest: protocol roles in order, PASS marker, own identity.

rtl_campaign.sh's bookkeeping, run as shell functions on temporary trees: the snapshot fails
closed, the evidence inventory appears only complete, re-reading needs the complete inventory and
a clean DONE; --verify-only runs those two checks and writes nothing.

gather_chip_matrix.py firmware: the firmware's embedded ranges against the apps' .text/.data bytes."""
import csv
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # tools/
import gather_chip_matrix as g

CELL = ("keygen", "sp", "ip", "bngfaes")
XML_PASS = '<testsuites><testsuite failures="0" errors="0"/></testsuites>'


def write(path, text):
    with open(path, "w") as fh:
        fh.write(text)


def line(run, proto="aba", tier="bngfaes", op_total=6):
    return (f"I0 x] meters v2 protocol={proto} op=keygen param=ip family=sp tier={tier} "
            f"run={run} acc_insn=1 exec_wait=2 host_io_fold=3 op_total_v2={op_total} app_load=5\r\n")   # UART CRLF


class LargeHarvest(unittest.TestCase):
    def harvest(self, log, xml=XML_PASS):
        d = tempfile.mkdtemp()
        cd = os.path.join(d, g.target(*CELL))
        os.makedirs(cd)
        with open(os.path.join(cd, "test.xml"), "w") as fh:
            fh.write(xml)
        with open(os.path.join(cd, "test.log"), "w") as fh:
            fh.write(log)
        return g.harvest_runs(*CELL, logdir=d)

    def test_brackets_exceed_total(self):
        rows = self.harvest(line("accept") + line("restart_b", op_total=4) + line("restart_a2") + "PASS!\n")
        self.assertEqual([r["verdict"] for r in rows], ["BAD_RECORD"])

    def test_aba(self):
        rows = self.harvest(line("accept") + line("restart_b") + line("restart_a2") + "PASS!\nExecuted cycles:  99\n")
        self.assertEqual([r["run"] for r in rows], list(g.PROTOCOL_RUNS["aba"]))
        self.assertTrue(all(r["verdict"] == "PASS" for r in rows))
        self.assertEqual([r["whole_test_cycles"] for r in rows], ["99", "", ""])   # once per test, not per run

    def test_accept_only_is_for_software_tiers(self):
        # a bngfaes cell must run A -> B -> A; declaring accept_only is rejected
        self.assertEqual(self.harvest(line("accept", "accept_only") + "PASS!\n")[0]["verdict"], "BAD_RECORD")
        cell = ("keygen", "sp", "ip", "sw")
        d = tempfile.mkdtemp()
        cd = os.path.join(d, g.target(*cell))
        os.makedirs(cd)
        write(os.path.join(cd, "test.xml"), XML_PASS)
        write(os.path.join(cd, "test.log"), line("accept", "accept_only", "sw") + "PASS!\n")
        rows = g.harvest_runs(*cell, logdir=d)
        self.assertEqual([(r["protocol"], r["verdict"]) for r in rows], [("accept_only", "PASS")])

    def test_bad_records(self):
        for log in (line("accept") * 2 + line("restart_a2") + "PASS!\n",                     # duplicate role
                    line("restart_b") + line("accept") + line("restart_a2") + "PASS!\n",     # wrong order
                    line("accept", tier="sw") + line("restart_b") + line("restart_a2") + "PASS!\n",  # other cell
                    line("accept") + line("restart_b") + line("restart_a2"),                 # no PASS marker
                    line("accept") + "meters v2 garbled\n" + line("restart_b") + line("restart_a2") + "PASS!\n"):
            self.assertEqual(self.harvest(log)[0]["verdict"], "BAD_RECORD", log)

    def test_failed_xml(self):
        rows = self.harvest(line("accept") + line("restart_b") + line("restart_a2") + "PASS!\n",
                            '<testsuites><testsuite failures="1" errors="0"/></testsuites>')
        self.assertEqual(rows[0]["verdict"], "FAIL")


class Contract2Harvest(unittest.TestCase):
    """32 KiB drivers: one accepting record; sign's empty family prints as ldirect."""
    def harvest(self, cell, log):
        d = tempfile.mkdtemp()
        cd = os.path.join(d, g.target(*cell))
        os.makedirs(cd)
        write(os.path.join(cd, "test.xml"), XML_PASS)
        write(os.path.join(cd, "test.log"), log)
        return g.harvest_runs(*cell, logdir=d)

    def rec(self, proto, op, fam, param="ip", tier="sw"):
        return (f"meters v2 protocol={proto} op={op} param={param} family={fam} tier={tier} "
                f"run=accept acc_insn=1 exec_wait=2 host_io_fold=3 op_total_v2=6 app_load=5\r\n")

    def test_32k_cells(self):
        for cell, proto, fam in ((("sign", "", "ip", "sw"), "accept_negative", "ldirect"),
                                 (("verify", "stream", "ip", "sw"), "accept_reject", "stream"),
                                 (("keygen", "stream_uniform", "ip", "sw"), "accept_only", "stream_uniform")):
            rows = self.harvest(cell, self.rec(proto, cell[0], fam) + "PASS!\n")
            self.assertEqual([(r["family"], r["verdict"]) for r in rows], [(fam, "PASS")], cell)
            # a verify cell claiming the keygen protocol is not this cell's record
            bad = self.harvest(cell, self.rec("aba", cell[0], fam) + "PASS!\n")
            self.assertEqual(bad[0]["verdict"], "BAD_RECORD", cell)

    def test_bep_names_this_invocations_results(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "bep.json")
        with open(p, "w") as fh:
            fh.write('{"id": {"progress": {}}}\n')
            fh.write('{"id": {"testResult": {"label": "//sw/device/tests/acc_uov:acc_uov_sign_ip_sw_test_sim_verilator"}},'
                     ' "testResult": {"status": "PASSED", "testActionOutput": [{"name": "test.log",'
                     ' "uri": "file:///x/testlogs/acc_uov_sign_ip_sw_test_sim_verilator/test.log"}]}}\n')
        self.assertEqual(g.bep_results(p), {"acc_uov_sign_ip_sw_test_sim_verilator":
                                            ("PASSED", "/x/testlogs/acc_uov_sign_ip_sw_test_sim_verilator")})

    def test_cells_unique_with_op(self):
        # keygen and verify share param/family/tier; the completion key must keep op
        keys = [(c[0], c[2], c[1] or "ldirect", c[3]) for c in g.CELLS]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertGreater(len(keys), len({k[1:] for k in keys}))

    def test_full_verify_roles(self):
        cell = ("verify", "full", "ip3", "sw")
        recs = "".join(self.rec("verify_oneshot", "verify", "full", "ip3").replace("run=accept", f"run={r}")
                       for r in ("accept", "reject_resident", "accept_resident"))
        rows = self.harvest(cell, recs + "PASS!\n")
        self.assertEqual([(r["run"], r["verdict"]) for r in rows],
                         [("accept", "PASS"), ("reject_resident", "PASS"), ("accept_resident", "PASS")])
        # the keygen min/sp protocol is not a verify cell's; a family the catalog does not have gets the 32 KiB one
        self.assertEqual(g.expected_protocol("keygen", "min", "sw"), "accept_only")
        self.assertEqual(g.expected_protocol("keygen", "sp", "bngfaes"), "aba")
        self.assertEqual(g.expected_protocol("verify", "oneshot", "sw"), "accept_reject")

    def test_every_32k_cell_has_a_protocol(self):
        for c in g.CELLS:
            self.assertIn(g.expected_protocol(c[0], c[1], c[3]), g.PROTOCOL_RUNS)


def bep_line(name, d, status="PASSED", attempt=1):
    return ('{"id": {"testResult": {"label": "//sw/device/tests/acc_uov:%s", "run": 1, "shard": 1, "attempt": %d}},'
            ' "testResult": {"status": "%s", "testActionOutput": [{"name": "test.log", "uri": "file://%s/test.log"}]}}\n'
            % (name, attempt, status, d))


class RunAndCollect(unittest.TestCase):
    """--run archives only this invocation's outputs into a fresh --out; --collect re-reads them
    with the run's own selection, event log and bazel exit."""
    name = g.target(*CELL)
    cells = name.replace("_sim_verilator", "")

    def main(self, *args, sweep=None):
        saved = g.run_sweep, sys.argv
        g.run_sweep = sweep or (lambda *a, **k: self.fail("launched"))
        sys.argv = ["gather_chip_matrix.py", *args]
        try:
            g.main()
            return None
        except SystemExit as e:
            return str(e)
        finally:
            g.run_sweep, sys.argv = saved

    def fake_run(self, out, files, bep_extra=""):
        cur = tempfile.mkdtemp()
        for f, text in files.items():
            with open(os.path.join(cur, f), "w") as fh:
                fh.write(text)

        def sweep(*a, **k):
            with open(os.path.join(out, "bep.json"), "w") as fh:
                fh.write(bep_line(self.name, cur) + bep_extra)
            return 0
        return sweep

    def rows(self, out):
        with open(os.path.join(out, "results_128k.csv")) as fh:
            return [r["verdict"] for r in csv.DictReader(fh)]

    def test_missing_current_output_is_not_harvested(self):
        out = tempfile.mkdtemp()
        msg = self.main("--dmem128k", "--run", "--strict", "--out", out, "--cells", self.cells,
                        sweep=self.fake_run(out, {"test.log": "partial\n"}))
        self.assertIn("STRICT", msg)
        self.assertEqual(self.rows(out), ["NO_OUTPUT"])
        self.assertTrue(os.path.exists(os.path.join(out, "logs", self.name, "test.log")))   # kept as evidence

    def test_non_empty_out_is_refused_before_launch(self):
        out = tempfile.mkdtemp()
        open(os.path.join(out, "old.csv"), "w").close()
        self.assertIn("not empty", self.main("--dmem128k", "--run", "--out", out, "--cells", self.cells))

    def test_duplicate_results_are_not_picked(self):
        out = tempfile.mkdtemp()
        log = line("accept") + line("restart_b") + line("restart_a2") + "PASS!\n"
        msg = self.main("--dmem128k", "--run", "--strict", "--out", out, "--cells", self.cells,
                        sweep=self.fake_run(out, {"test.log": log, "test.xml": XML_PASS},
                                            bep_extra=bep_line(self.name, "/elsewhere", attempt=2)))
        self.assertIn("STRICT", msg)
        self.assertEqual(self.rows(out), ["DUPLICATE"])

    def test_collect_keeps_the_runs_selection_and_exit(self):
        out = tempfile.mkdtemp()
        log = line("accept") + line("restart_b") + line("restart_a2") + "PASS!\n"
        self.assertIsNone(self.main("--dmem128k", "--run", "--strict", "--out", out, "--cells", self.cells,
                                    sweep=self.fake_run(out, {"test.log": log, "test.xml": XML_PASS})))
        self.assertIsNone(self.main("--dmem128k", "--collect", out, "--strict"))
        self.assertEqual(self.rows(out), ["PASS"] * 3)
        self.assertIn("pass neither", self.main("--dmem128k", "--collect", out, "--cells", self.cells))
        self.assertIn("not a finished dmem32k run", self.main("--dmem32k", "--collect", out))
        with open(os.path.join(out, "run.json"), "w") as fh:
            fh.write('{"mode": "dmem128k", "bazel_exit": 3, "baseline": null, "cells": ["%s"]}' % self.cells)
        self.assertIn("bazel exit 3", self.main("--dmem128k", "--collect", out, "--strict"))

    def test_only_this_packages_uncached_result_counts(self):
        log = line("accept") + line("restart_b") + line("restart_a2") + "PASS!\n"
        ours = bep_line(self.name, "CUR")
        for what, bep, verdict in (
                ("as run", ours, ["PASS"] * 3),
                ("taken from the local cache", ours.replace('"status"', '"cachedLocally": true, "status"'), ["CACHED"]),
                ("taken from a remote cache",
                 ours.replace('"status"', '"executionInfo": {"cachedRemotely": true}, "status"'), ["CACHED"]),
                ("the same basename in another package", ours.replace("acc_uov:", "other:"), ["NOT_RUN"])):
            with self.subTest(what):
                out, cur = tempfile.mkdtemp(), tempfile.mkdtemp()
                write(os.path.join(cur, "test.log"), log)
                write(os.path.join(cur, "test.xml"), XML_PASS)

                def sweep(*a, **k):
                    write(os.path.join(out, "bep.json"), bep.replace("CUR", cur))
                    return 0
                msg = self.main("--dmem128k", "--run", "--strict", "--out", out, "--cells", self.cells, sweep=sweep)
                self.assertEqual(self.rows(out), verdict)
                self.assertEqual(msg is None, verdict == ["PASS"] * 3)
                self.assertEqual(g.replay(out, "dmem128k")[2][0]["verdict"], verdict[0])     # re-read the same way

    def test_replay_writes_nothing(self):
        out = tempfile.mkdtemp()
        log = line("accept") + line("restart_b") + line("restart_a2") + "PASS!\n"
        self.assertIsNone(self.main("--dmem128k", "--run", "--strict", "--out", out, "--cells", self.cells,
                                    sweep=self.fake_run(out, {"test.log": log, "test.xml": XML_PASS})))

        def tree():
            return {os.path.join(r, f): open(os.path.join(r, f), "rb").read() for r, _, fs in os.walk(out) for f in fs}
        before = tree()
        os.remove(os.path.join(out, "results_128k.csv"))                 # derived files are not replay inputs
        os.remove(os.path.join(out, "status.json"))
        run, cells, rows, gate = g.replay(out, "dmem128k")
        self.assertEqual((run["bazel_exit"], cells, [r["run"] for r in rows], gate),
                         (0, [CELL], ["accept", "restart_b", "restart_a2"], None))
        self.assertEqual(set(tree()), set(before) - {os.path.join(out, f) for f in ("results_128k.csv", "status.json")})
        with self.assertRaises(SystemExit) as e:
            g.replay(out, "dmem32k")
        self.assertIn("not a finished dmem32k run", str(e.exception))

    def test_recollection_keeps_the_baseline_gate(self):
        # a phase-vector mismatch found by the run must still fail when the run is re-read
        out, cell = tempfile.mkdtemp(), g.target(*VCELL)
        ledger = os.path.join(tempfile.mkdtemp(), "ledger.csv")
        with open(ledger, "w") as fh:
            fh.write("cell,acc_insn,accept,reject,status\n"
                     "verify_stream_is_bngfaes,13,phase INIT=11;phase UPDATE=1;phase FINAL=1,"
                     "phase INIT=10;phase UPDATE=2;phase FINAL=1,OK\n")
        cur = tempfile.mkdtemp()
        write(os.path.join(cur, "test.log"), LEG + LEG + VMETER + "PASS!\n")
        write(os.path.join(cur, "test.xml"), XML_PASS)

        def sweep(*a, **k):
            write(os.path.join(out, "bep.json"), bep_line(cell, cur))
            return 0
        args = ("--dmem32k", "--strict")
        self.assertIn("baseline mismatch in ['verify_stream_is_bngfaes']",
                      self.main(*args, "--run", "--out", out, "--expected-insn-counts", ledger,
                                "--cells", cell.replace("_sim_verilator", ""), sweep=sweep))
        self.assertIn("baseline mismatch in ['verify_stream_is_bngfaes']", self.main(*args, "--collect", out))
        with open(os.path.join(out, "expected_insn_counts_32k.csv"), "a") as fh:
            fh.write("\n")
        self.assertIn("differs from the hash", self.main(*args, "--collect", out))

    def test_a_mode_is_required(self):
        for args in (("--run",), (), ("--dmem128k", "--dmem32k", "--run")):
            self.assertIn("pick one of --dmem32k/--dmem128k", self.main(*args))


class Ledger(unittest.TestCase):
    def load(self, body):
        f = os.path.join(tempfile.mkdtemp(), "ledger.csv")
        with open(f, "w") as fh:
            fh.write("cell,acc_insn,accept,reject,status\n" + body)
        return g.load_ledger(f)[1]

    def test_complete_rows_pass(self):
        self.assertEqual(self.load("verify_stream_is_bngfaes,13,phase INIT=10;phase FINAL=3,phase INIT=10,OK\n"
                                   "sign_ip_bngfaes,5,sign=5,,OK\nkeygen_stream_ip_sw,9,,,MISSING\n"), [])

    def test_incomplete_rows_are_refused(self):
        for body in ("sign_ip_bngfaes,5,sign=4,,OK\n",                      # vector does not sum
                     "sign_ip_bngfaes,x,sign=5,,OK\n",                      # not a number
                     "verify_stream_is_bngfaes,13,phase INIT=13,,OK\n",      # no rejecting leg
                     "sign_ip_bngfaes,5,,,OK\n",                            # empty vector
                     "sign_ip_bngfaes,5,sign=5,,OK\nsign_ip_bngfaes,5,sign=5,,OK\n"):
            with self.subTest(body=body):
                self.assertTrue(self.load(body))


VCELL = ("verify", "stream", "is", "bngfaes")
VMETER = ("I0 x] meters v2 protocol=accept_reject op=verify param=is family=stream tier=bngfaes "
          "run=accept acc_insn=13 exec_wait=2 host_io_fold=3 op_total_v2=6 app_load=5\r\n")
LEG = "I0 x] phase INIT: 10 instructions\r\nI0 x] phase UPDATE: 2 instructions\r\nI0 x] phase FINAL: 1 instructions\r\n"
VBASE = {"cell": "verify_stream_is_bngfaes", "acc_insn": "13", "status": "OK",
         "accept": "phase INIT=10;phase UPDATE=2;phase FINAL=1", "reject": "phase INIT=10;phase UPDATE=2;phase FINAL=1"}


class BaselineGate(unittest.TestCase):
    def problems(self, log, base=VBASE):
        d = tempfile.mkdtemp()
        cd = os.path.join(d, g.target(*VCELL))
        os.makedirs(cd)
        with open(os.path.join(cd, "test.xml"), "w") as fh:
            fh.write(XML_PASS)
        with open(os.path.join(cd, "test.log"), "w") as fh:
            fh.write(log)
        return g.baseline_problems(*VCELL, base, d)

    def test_identical(self):
        self.assertEqual(self.problems(LEG + LEG + VMETER + "PASS!\n"), [])

    def test_equal_total_phase_shift_fails(self):
        shifted = LEG.replace("INIT: 10", "INIT: 11").replace("UPDATE: 2", "UPDATE: 1")
        self.assertTrue(self.problems(shifted + LEG + VMETER + "PASS!\n"))

    def test_missing_rejecting_leg_fails(self):
        self.assertTrue(self.problems(LEG + VMETER + "PASS!\n"))

    def test_missing_baseline_fails(self):
        self.assertEqual(self.problems(LEG + LEG + VMETER + "PASS!\n", base=None), ["no baseline"])
        self.assertEqual(self.problems(LEG + LEG + VMETER + "PASS!\n", base=dict(VBASE, status="MISSING")),
                         ["no baseline"])

    def test_labelled_negative_init_does_not_open_a_leg(self):
        neg = "I0 x] phase INIT (flipped seed): 9 instructions\r\n"
        self.assertEqual(g.phase_groups(LEG + LEG + neg).count("phase INIT=10;phase UPDATE=2;phase FINAL=1"), 1)


class BaselineCli(unittest.TestCase):
    def main(self, *args):
        saved = g.run_sweep, sys.argv
        g.run_sweep = lambda *a, **k: self.fail("launched")
        sys.argv = ["gather_chip_matrix.py", *args]
        try:
            with self.assertRaises(SystemExit) as cm:
                g.main()
        finally:
            g.run_sweep, sys.argv = saved
        return str(cm.exception)

    def test_baseline_needs_dmem32k(self):
        self.assertIn("nothing launched", self.main("--run", "--expected-insn-counts", "x.csv", "--out", tempfile.mkdtemp()))

    def test_duplicate_ledger_cells_refused(self):
        f = os.path.join(tempfile.mkdtemp(), "ledger.csv")
        with open(f, "w") as fh:
            fh.write("cell,acc_insn,accept,reject,status\nsign_ip_bngfaes,1,sign=1,,OK\nsign_ip_bngfaes,2,sign=2,,OK\n")
        self.assertIn("nothing launched", self.main("--dmem32k", "--run", "--expected-insn-counts", f,
                                                    "--cells", "acc_uov_sign_ip_bngfaes_test", "--out", tempfile.mkdtemp()))


RUNNER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rtl_campaign.sh")


def functions(*names):
    with open(RUNNER) as fh:
        src = fh.read()
    return "\n".join(re.search(rf"^{n}\(\) {{\n.*?^}}\n", src, re.M | re.S).group(0) for n in names)


def sh(cwd, call, *names):
    script = "set -euo pipefail\n" + functions(*names) + "\n" + call
    return subprocess.run(["bash", "-c", script], cwd=cwd, capture_output=True, text=True)


class Snapshot(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = self.tmp.name
        def run(*a):
            return subprocess.run(a, cwd=self.repo, check=True, capture_output=True)
        run("git", "init", "-q")
        with open(os.path.join(self.repo, "a.txt"), "w") as fh:
            fh.write("a\n")
        run("git", "-c", "user.name=t", "-c", "user.email=t@t", "add", "a.txt")
        run("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "a")

    def tearDown(self):
        rc = os.path.join(self.repo, ".bazelrc-site")
        if os.path.exists(rc):
            os.chmod(rc, stat.S_IRUSR | stat.S_IWUSR)
        self.tmp.cleanup()

    def snap(self):
        r = sh(self.repo, "snapshot", "snapshot")
        return r.returncode, r.stdout.strip()

    def test_clean_tree_without_rc_file(self):
        rc, h = self.snap()
        self.assertEqual((rc, len(h)), (0, 64))
        self.assertEqual(self.snap(), (rc, h))                     # deterministic

    def test_every_change_moves_it(self):
        base = self.snap()[1]
        with open(os.path.join(self.repo, "a.txt"), "a") as fh:
            fh.write("b\n")
        tracked = self.snap()[1]
        with open(os.path.join(self.repo, "new.txt"), "w") as fh:
            fh.write("n\n")
        untracked = self.snap()[1]
        with open(os.path.join(self.repo, ".bazelrc-site"), "w") as fh:
            fh.write("common --x\n")
        self.assertEqual(len({base, tracked, untracked, self.snap()[1]}), 4)

    def test_unreadable_input_fails_with_no_hash(self):
        with open(os.path.join(self.repo, ".bazelrc-site"), "w") as fh:
            fh.write("common --x\n")
        os.chmod(os.path.join(self.repo, ".bazelrc-site"), 0)
        self.assertEqual(self.snap(), (1, ""))

    def test_the_preflight_call_aborts_when_the_final_hash_fails(self):
        # SNAP=$(snapshot) is how the preflight calls it; errexit does not reach into $(...)
        stdin_fails = 'sha256sum() { [ $# -gt 0 ] || return 1; command sha256sum "$@"; }\n'
        ok = sh(self.repo, 'SNAP=$(snapshot); echo "reached $SNAP"', "snapshot")
        self.assertRegex(ok.stdout, r"^reached [0-9a-f]{64}$")
        bad = sh(self.repo, stdin_fails + 'SNAP=$(snapshot); echo "reached $SNAP"', "snapshot")
        self.assertNotEqual(bad.returncode, 0)
        self.assertNotIn("reached", bad.stdout)

    def test_outside_a_repository_fails(self):
        with tempfile.TemporaryDirectory() as d:
            r = sh(d, "snapshot", "snapshot")
        self.assertEqual((r.returncode, r.stdout), (1, ""))


class Help(unittest.TestCase):
    def test_help_is_the_header_and_no_code(self):
        r = subprocess.run(["bash", RUNNER, "--help"], capture_output=True, text=True)
        lines = r.stdout.splitlines()
        self.assertEqual(r.returncode, 0)
        self.assertTrue(lines[0].startswith("RTL campaign for the UOV chip tests"))
        self.assertTrue(lines[-1].startswith("The run passed when DONE reads"))
        self.assertNotIn("set -euo pipefail", r.stdout)


class Evidence(unittest.TestCase):
    NAMES = ("evidence_files", "archive", "evidence_ok", "done_ok")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.run = self.tmp.name
        for rel, text in (("manifest.txt", "m\n"), ("results/run.json", "{}\n"), ("results/logs/c/test.log", "PASS!\n"),
                          ("results/results_32k.csv", "rewritten\n"), ("campaign.log", "log\n"), ("bin/abc", "x")):
            os.makedirs(os.path.dirname(os.path.join(self.run, rel)), exist_ok=True)
            with open(os.path.join(self.run, rel), "w") as fh:
                fh.write(text)

    def tearDown(self):
        os.chmod(os.path.join(self.run, "bin/abc"), stat.S_IRUSR | stat.S_IWUSR)
        self.tmp.cleanup()

    def call(self, what):
        return sh(self.run, f"{what} .", *self.NAMES).returncode

    def inventory(self):
        with open(os.path.join(self.run, "evidence.sha256")) as fh:
            return fh.read().splitlines()

    def test_archive_lists_exactly_the_evidence(self):
        self.assertEqual(self.call("archive"), 0)
        self.assertEqual([ln.split("  ", 1)[1] for ln in self.inventory()],
                         ["./bin/abc", "./manifest.txt", "./results/logs/c/test.log", "./results/run.json"])
        self.assertEqual(self.call("evidence_ok"), 0)

    def test_failed_hashing_leaves_no_inventory(self):
        os.chmod(os.path.join(self.run, "bin/abc"), 0)
        self.assertNotEqual(self.call("archive"), 0)
        self.assertFalse(os.path.exists(os.path.join(self.run, "evidence.sha256")))

    def test_a_dropped_entry_an_extra_file_or_a_changed_byte_is_refused(self):
        self.assertEqual(self.call("archive"), 0)
        full = self.inventory()
        with open(os.path.join(self.run, "evidence.sha256"), "w") as fh:
            fh.write("\n".join(ln for ln in full if "test.log" not in ln) + "\n")
        self.assertNotEqual(self.call("evidence_ok"), 0)           # a log missing from the inventory
        with open(os.path.join(self.run, "evidence.sha256"), "w") as fh:
            fh.write("\n".join(full) + "\n")
        with open(os.path.join(self.run, "results/logs/c/extra.log"), "w") as fh:
            fh.write("late\n")
        self.assertNotEqual(self.call("evidence_ok"), 0)           # a file the inventory does not name
        os.remove(os.path.join(self.run, "results/logs/c/extra.log"))
        with open(os.path.join(self.run, "results/logs/c/test.log"), "w") as fh:
            fh.write("PASS! exec_wait=9\n")
        self.assertNotEqual(self.call("evidence_ok"), 0)           # changed bytes

    def test_done_needs_every_exit_zero(self):
        for text, ok in (("collector_exit=0 postcheck_exit=0 archive_exit=0 finished=20261002T165007Z", True),
                         ("collector_exit=1 postcheck_exit=0 archive_exit=0 finished=20261002T165007Z", False),
                         ("collector_exit=0 postcheck_exit=0 archive_exit=1 finished=20261002T165007Z", False),
                         ("collector_exit=0 postcheck_exit=0 finished=20261002T165007Z", False),
                         ("collector_exit=0 postcheck_exit=0 archive_exit=0 finished=20261002T165007Z\n"
                          "collector_exit=1 postcheck_exit=0 archive_exit=0 finished=20261002T170000Z", False)):
            with self.subTest(text=text):
                with open(os.path.join(self.run, "DONE"), "w") as fh:
                    fh.write(text + "\n")
                self.assertEqual(self.call("done_ok") == 0, ok)
        clean = "collector_exit=0 postcheck_exit=0 archive_exit=0 finished=20261002T165007Z"
        for what, text in (("a second record without its line end", clean + "\ncollector_exit=1 postcheck_exit=0 archive_exit=0 finished=1"),
                           ("the clean record without its line end", clean), ("an empty file", "")):
            with self.subTest(what):
                with open(os.path.join(self.run, "DONE"), "w") as fh:
                    fh.write(text)
                self.assertNotEqual(self.call("done_ok"), 0)
        os.remove(os.path.join(self.run, "DONE"))
        self.assertNotEqual(self.call("done_ok"), 0)               # no DONE at all

    def test_verify_only_runs_both_checks_and_writes_nothing(self):
        clean = "collector_exit=0 postcheck_exit=0 archive_exit=0 finished=20261002T165007Z\n"
        self.assertEqual(self.call("archive"), 0)

        def tree():
            return {os.path.join(r, f): open(os.path.join(r, f), "rb").read() for r, _, fs in os.walk(self.run) for f in fs}

        def verify(done):
            with open(os.path.join(self.run, "DONE"), "w") as fh:
                fh.write(done)
            before = tree()
            r = subprocess.run(["bash", RUNNER, "--verify-only", self.run], capture_output=True, text=True)
            self.assertEqual(tree(), before)
            return r.returncode, r.stdout, r.stderr
        self.assertEqual(verify(clean), (0, "", ""))
        rc, _, err = verify(clean + clean.replace("collector_exit=0", "collector_exit=1"))
        self.assertEqual(rc, 3)
        self.assertIn("DONE is not the one line", err)
        with open(os.path.join(self.run, "results/logs/c/test.log"), "w") as fh:
            fh.write("PASS! exec_wait=9\n")
        rc, _, err = verify(clean)
        self.assertEqual(rc, 3)
        self.assertIn("archived evidence differs from evidence.sha256", err)


TEXT, DATA = b"\x13\x00\x00\x00" * 4, b"\x01\x02\x03\x04"


def firmware(apps, text_at=0x1000, data_at=0x2000):
    """One rodata section per kind holding every app back to back, with the local symbols."""
    syms, text, data = {}, b"", b""
    for app, (t, d) in apps.items():
        p = f"_acc_local_app_{app}_"
        syms[p + "_imem_start"], syms[p + "_imem_end"] = text_at + len(text), text_at + len(text) + len(t)
        syms[p + "_dmem_data_start"], syms[p + "_dmem_data_end"] = data_at + len(data), data_at + len(data) + len(d)
        text, data = text + t, data + d
    return [(text_at, text), (data_at, data)], syms


class Check(unittest.TestCase):
    def test_exact_bytes_pass(self):
        self.assertEqual(g.check(*firmware({"a": (TEXT, DATA)}), {"a": (TEXT, DATA)}), [])

    def test_two_apps(self):
        apps = {"uni": (TEXT, DATA), "str": (TEXT[::-1], b"")}
        self.assertEqual(g.check(*firmware(apps), apps), [])

    def test_empty_dmem_is_valid_but_empty_imem_is_not(self):
        self.assertEqual(g.check(*firmware({"a": (TEXT, b"")}), {"a": (TEXT, b"")}), [])
        self.assertTrue(g.check(*firmware({"a": (b"", DATA)}), {"a": (b"", DATA)}))

    def test_changed_byte_fails(self):
        self.assertTrue(g.check(*firmware({"a": (TEXT, DATA)}), {"a": (TEXT, b"\x01\x02\x03\x05")}))

    def test_wrong_or_extra_app_fails(self):
        self.assertTrue(g.check(*firmware({"a": (TEXT, DATA)}), {"b": (TEXT, DATA)}))
        self.assertTrue(g.check(*firmware({"a": (TEXT, DATA), "b": (TEXT, DATA)}), {"a": (TEXT, DATA)}))

    def test_bss_zeros_are_not_appended(self):
        # the embedded data stops at .data's end; a .bss reservation is not part of the image
        self.assertTrue(g.check(*firmware({"a": (TEXT, DATA)}), {"a": (TEXT, DATA + b"\x00" * 8)}))

    def test_range_outside_any_section_fails(self):
        sections, syms = firmware({"a": (TEXT, DATA)})
        syms["_acc_local_app_a__imem_end"] += 64
        self.assertTrue(g.check(sections, syms, {"a": (TEXT, DATA)}))


class Meters(unittest.TestCase):
    ID = "op=sign param=ip family=ldirect tier=bngfaes"

    def test_one_format_one_identity(self):
        fmt = b"meters v2 protocol=accept_negative " + ID_BYTES + b" run=%s acc_insn=%u\0"
        self.assertEqual(g.meters([(0, b"x" + fmt), (0x100, b"PASS!\0")]), (1, {self.ID}))

    def test_comparison_firmware_has_none(self):
        self.assertEqual(g.meters([(0, b"op_total_v2 %u\0")]), (0, set()))


ID_BYTES = Meters.ID.encode()


class FirmwareCli(unittest.TestCase):
    """The exit status of each firmware check reaches the shell (rtl_campaign.sh stops on it)."""

    def run_tool(self, *args):
        tool = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gather_chip_matrix.py")
        r = subprocess.run([sys.executable, tool, "firmware", *args], capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr

    def test_exit_status(self):
        a, b = os.path.realpath(sys.executable), os.path.realpath(shutil.which("sh"))
        self.assertEqual(self.run_tool("--same-image", a, a), (0, f"same image: {a} {a}\n"))
        self.assertEqual(self.run_tool("--same-image", a, b), (1, f"DIFFERENT image: {a} {b}\n"))
        self.assertEqual(self.run_tool("--symbols", a, "no_such_symbol_here"), (1, "no_such_symbol_here MISSING\n"))
        rc, out = self.run_tool("--firmware", a, "--app", f"x={a}")         # embeds no ACC app: a mismatch
        self.assertEqual(rc, 1)
        self.assertIn("MISMATCH firmware embeds [], expected ['x']", out)
        self.assertEqual(self.run_tool("--firmware", a)[0], 2)               # no --app
        self.assertEqual(self.run_tool("--symbols", a, "x", "--firmware", a, "--app", f"x={a}")[0], 2)   # one mode at a time


if __name__ == "__main__":
    unittest.main()
