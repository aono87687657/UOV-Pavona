#!/usr/bin/env python3
"""Run the acc_uov chip-RTL tests and gather their "meters v2" lines into CSV.

tools/rtl_campaign.sh wraps the runs with their preflight and manifest; tools/uov.py rtl-import re-reads a
finished run directory through replay(). One row per metered run:

    <out>/results_32k.csv (32 KiB DMEM tests) or <out>/results_128k.csv (128 KiB keygen min/sp, verify full)

Usage (from repo root):
    tools/gather_chip_matrix.py --dmem32k --run --out DIR [--cells A,B] [--expected-insn-counts CSV]
    tools/gather_chip_matrix.py --dmem128k --run --out DIR [--cells A,B]
    tools/gather_chip_matrix.py --dmem32k --collect DIR          # re-read a run's own outputs
    tools/gather_chip_matrix.py firmware --firmware FW.elf --app NAME=APP.elf [--app ...] [--meter-id ID]
    tools/gather_chip_matrix.py firmware --same-image A.elf B.elf
    tools/gather_chip_matrix.py firmware --symbols APP.elf NAME [NAME ...]
"""
import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from urllib.parse import unquote, urlparse

PKG = "//sw/device/tests/acc_uov"
# bazel repoints the workspace convenience symlinks on EVERY invocation, so a
# build in a second output base leaves bazel-testlogs pointing somewhere else
# entirely.
LOGDIR = "bazel-testlogs/sw/device/tests/acc_uov"

# The ablation family's name, single-sourced.
FAM_UNIFORM = "stream_uniform"

# Hardware AES with software GF is available in both rounds.
R2_TIERS = ("bngfaes", "bngfonly", "bnaesonly", "sw")
R3_TIERS = R2_TIERS

# op, family, param, tier  ->  target basename
CELLS = (
    [("keygen", "stream", p, t) for p in ("ip", "is")
     for t in R2_TIERS] +
    [("keygen", FAM_UNIFORM, p, t) for p in ("ip", "is")
     for t in R2_TIERS] +
    [("verify", FAM_UNIFORM, p, t) for p in ("ip", "is")
     for t in R2_TIERS] +
    [("verify", "stream", p, t) for p in ("ip", "is")
     for t in R2_TIERS] +
    [("sign", "", p, t) for p in ("ip", "is")
     for t in R2_TIERS] +
    # Round-3 Ip3: every family on all four tiers (the tuned verify too, since
    # each tier has its own R3 kernel arm).
    [(op, fam, "ip3", t)
     for op, fam in (("keygen", "stream"), ("keygen", FAM_UNIFORM),
                     ("verify", "stream"), ("verify", FAM_UNIFORM), ("sign", ""))
     for t in R3_TIERS]
)


# 128 KiB one-shot keygen (single pass and _min) and verify, every tier.
# Separate list: these need the 128 KiB DMEM profile.
ONESHOT_CELLS = ([("keygen", f, p, t) for f in ("sp", "min") for p in ("ip", "ip3", "is") for t in R3_TIERS] +
                 [("verify", "full", p, t) for p in ("ip", "ip3", "is") for t in R3_TIERS])


def target(op, family, param, tier):
    fam = f"{family}_" if family else ""
    return f"acc_uov_{op}_{fam}{param}_{tier}_test_sim_verilator"


RE_CHIP = re.compile(r"Executed cycles:\s+(\d+)")
RE_METERS = re.compile(r"meters v2 protocol=(\w+) op=(\w+) param=(\w+) family=(\w+) tier=(\w+) "
                       r"run=(\w+) acc_insn=(\d+) exec_wait=(\d+) host_io_fold=(\d+) op_total_v2=(\d+) "
                       r"app_load=(\d+)\r?$", re.M)   # UART lines end in CRLF
RE_WALL = re.compile(r"Wallclock time:\s+([\d.]+) s")
# protocol -> the run roles its driver must print, in order (the reject and
# negative runs of the 32 KiB drivers are checked but never metered)
PROTOCOL_RUNS = {"aba": ("accept", "restart_b", "restart_a2"), "accept_only": ("accept",),
                 "accept_reject": ("accept",), "accept_negative": ("accept",),
                 "verify_oneshot": ("accept", "reject_resident", "accept_resident")}


def expected_protocol(op, family, tier):
    """128 KiB (keygen min/sp, verify full): software-GF keygen cells run the accepting keygen only, every other
    keygen cell A -> B -> A. 32 KiB: verify accept + reject, sign accept + negatives, keygen accept."""
    if family in ("min", "sp", "full"):
        if op == "verify":
            return "verify_oneshot"
        return "accept_only" if tier in ("bnaesonly", "sw") else "aba"
    return {"verify": "accept_reject", "sign": "accept_negative"}.get(op, "accept_only")
ONESHOT_FIELDS = ("op", "family", "param", "tier", "contract", "protocol", "run", "acc_insn", "exec_wait",
                  "host_io_fold", "op_total_v2", "app_load", "whole_test_cycles", "wall_s", "verdict")


def bazel_verdict(test_xml):
    """PASS/FAIL from bazel's <testsuite failures= errors=>. Timeouts land in
    errors, so both counters matter; console text cannot forge XML structure."""
    try:
        ts = ET.parse(test_xml).getroot().find("testsuite")
        if ts is None:
            return "?"
        return "PASS" if ts.get("failures") == "0" and ts.get("errors") == "0" else "FAIL"
    except (OSError, ET.ParseError):
        return "?"


def read(path):
    try:
        with open(path, "rb") as fh:
            return fh.read().decode("utf-8", "replace")
    except FileNotFoundError:
        return ""




def harvest_runs(op, family, param, tier, logdir=None):
    """Metered cells: one row per run. A cell counts only with a PASS verdict, the
    firmware's PASS marker, well-formed meters lines naming this very cell, and exactly
    the run roles of its declared protocol, in order."""
    d = os.path.join(logdir or LOGDIR, target(op, family, param, tier))
    xml, log = read(os.path.join(d, "test.xml")), read(os.path.join(d, "test.log"))
    if not xml and not log:
        return []
    verdict = bazel_verdict(os.path.join(d, "test.xml"))
    recs = RE_METERS.findall(log)
    proto = expected_protocol(op, family, tier)
    if verdict == "PASS" and (
            "PASS!" not in log
            or log.count("meters v2") != len(recs)
            or {r[0] for r in recs} != {proto}
            or tuple(r[5] for r in recs) != PROTOCOL_RUNS[proto]
            or any(r[1:5] != (op, param, family or "ldirect", tier) for r in recs)
            # exec_wait and host_io_fold are disjoint brackets inside op_total_v2
            or any(int(r[7]) + int(r[8]) > int(r[9]) for r in recs)):
        verdict = "BAD_RECORD"
    chip, wall = RE_CHIP.search(log), RE_WALL.search(log)
    if verdict != "PASS":
        return [dict(dict.fromkeys(ONESHOT_FIELDS, ""), op=op, family=family or "ldirect", param=param,
                     tier=tier, verdict=verdict)]
    return [{"op": op, "family": family or "ldirect", "param": param, "tier": tier, "contract": 2,
             "protocol": r[0], "run": r[5], "acc_insn": r[6], "exec_wait": r[7],
             "host_io_fold": r[8], "op_total_v2": r[9], "app_load": r[10],
             # whole simulation incl. boot and every leg: never an operation latency
             "whole_test_cycles": (chip.group(1) if chip else "") if r[5] == "accept" else "",
             "wall_s": (wall.group(1) if wall else "") if r[5] == "accept" else "", "verdict": verdict}
            for r in recs]


def file_sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def write_json(path, obj):
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=1, sort_keys=True)
        fh.write("\n")




def bep_results(path):
    """target basename -> (bazel status, directory holding its test.log) for every test of this
    package this very invocation ran, from its --build_event_json_file. A target with a second
    result, or one that is not run 1 / shard 1 / attempt 1, is DUPLICATE: never pick one of them.
    A result bazel took from a cache is CACHED: the test did not run in this invocation."""
    out = {}
    with open(path) as fh:
        for ln in fh:
            ev = json.loads(ln)
            tr = ev.get("id", {}).get("testResult")
            if not tr:
                continue
            pkg, _, name = tr["label"].rpartition(":")
            if pkg != PKG:
                continue
            res = ev.get("testResult", {})
            logs = [o["uri"] for o in res.get("testActionOutput", []) if o.get("name") == "test.log"]
            d = os.path.dirname(unquote(urlparse(logs[0]).path)) if logs else ""
            cached = res.get("cachedLocally") or res.get("executionInfo", {}).get("cachedRemotely")
            single = name not in out and (tr.get("run", 1), tr.get("shard", 1), tr.get("attempt", 1)) == (1, 1, 1)
            out[name] = ("CACHED" if cached else res.get("status", "?"), d) if single else ("DUPLICATE", "")
    return out


def run_sweep(jobs, make_opts, timeout, cells=CELLS, extra=(), startup=()):
    """Run all matrix targets. Two traps this works around:

    - the targets are tagged `manual`, so a `:all` wildcard matches NOTHING
      ("Found 0 test targets") - they must be named explicitly;
    - changing --//hw:make_options between runs switches bazel's configuration,
      which repoints bazel-testlogs at a different (empty) directory, so keep
      it identical across run and harvest.

    The two keygen sw cells need ~11,200 s and ~10,300 s, past the 7200 s
    `eternal` category in .bazelrc, so the sweep sets its own limit and finishes
    in one pass. A single integer applies to every category; the literal -1 does
    NOT mean "no limit", it reverts to bazel's built-in 3600 s and cuts the cap.
    A ceiling costs nothing when a cell finishes early.
    """
    labels = [f"{PKG}:{target(*c)}" for c in cells]
    # Measurement runs always re-execute: without this, unchanged targets come
    # back from bazel's test cache and old numbers get republished under a
    # fresh harvest stamp.
    cmd = (["./bazelisk.sh", *startup, "test", "--test_output=summary",
            "--cache_test_results=no",
            f"--test_timeout={timeout}", f"--local_test_jobs={jobs}"]
           + ([f"--//hw:make_options={make_opts}"] if make_opts else [])
           + list(extra)
           + labels)
    print(f"+ bazelisk test ... {len(labels)} targets", flush=True)
    return subprocess.call(cmd)





















RE_PHASE = re.compile(r"\] (phase [^:]+|WINDOW\(\d+,\d+\)): (\d+) instructions")


def phase_groups(log):
    """Labelled phase groups in log order; a group starts at an exact 'phase INIT' line
    (the negative tests label theirs), so verify logs hold the accepting then the rejecting leg."""
    groups = []
    for label, n in RE_PHASE.findall(log):
        if label == "phase INIT":
            groups.append([])
        if groups:
            groups[-1].append(f"{label}={n}")
    return [";".join(g) for g in groups]




def ledger_key(op, family, param, tier):
    return target(op, family, param, tier)[len("acc_uov_"):-len("_test_sim_verilator")]


def baseline_problems(op, family, param, tier, base, logdir):
    """Contract rev 3 gate: the accepting acc_insn and the labelled, ordered phase groups (verify:
    both legs) must equal the baseline ledger row; a cell without an OK row fails."""
    if not base or base.get("status") != "OK":
        return ["no baseline"]
    log = read(os.path.join(logdir, target(op, family, param, tier), "test.log"))
    probs = []
    acc = [r for r in harvest_runs(op, family, param, tier, logdir=logdir) if r.get("run") == "accept"]
    if not (len(acc) == 1 and acc[0]["acc_insn"] == base["acc_insn"]):
        probs.append(f"acc_insn {acc[0]['acc_insn'] if len(acc) == 1 else 'missing'} != {base['acc_insn']}")
    if op != "sign":
        want = [base["accept"]] + ([base["reject"]] if op == "verify" else [])
        got = phase_groups(log)
        if got != want:
            probs.append(f"phase groups {got} != {want}")
    return probs


def load_ledger(path):
    """cell -> row of the baseline ledger, and its problems: duplicate cells, an OK row whose
    acc_insn is not the sum of its accepting phase vector, an OK verify row without a rejecting one."""
    with open(path, newline="") as fh:
        rows = list(csv.DictReader(fh))
    ledger = {r["cell"]: r for r in rows}
    problems = [] if len(ledger) == len(rows) else ["duplicate cells"]
    for r in rows:
        if r.get("status") != "OK":
            continue
        try:
            total = sum(int(x.rsplit("=", 1)[1]) for x in r["accept"].split(";"))
            ok = r["accept"] != "" and total == int(r["acc_insn"])
        except (ValueError, IndexError):
            ok = False
        if not ok:
            problems.append(f"{r['cell']}: accepting vector does not sum to acc_insn")
        if r["cell"].startswith("verify_") and not r.get("reject"):
            problems.append(f"{r['cell']}: no rejecting vector")
    return ledger, problems


def finished_run(out, mode):
    """run.json of a finished run of this mode and its baseline ledger file (None without a gate)."""
    with open(os.path.join(out, "run.json")) as fh:
        run = json.load(fh)
    if run.get("mode") != mode or run.get("bazel_exit") is None:
        sys.exit(f"{out}: run.json is not a finished {mode} run")
    base_file = os.path.join(out, "expected_insn_counts_32k.csv") if run.get("baseline") else None
    if base_file and file_sha256(base_file) != run["baseline"]:
        sys.exit(f"{base_file} differs from the hash in run.json")
    return run, base_file


def select_cells(wanted, mode, base_file):
    """The catalog cells behind the target basenames and the baseline ledger gating them (None without one)."""
    names = {target(*c).replace("_sim_verilator", ""): c for c in (ONESHOT_CELLS if mode == "dmem128k" else CELLS)}
    unknown = [w for w in wanted if w not in names]
    if unknown or not wanted or len(set(wanted)) != len(wanted):
        sys.exit(f"bad --cells: unknown {unknown}, {len(wanted)} given, duplicates "
                 f"{sorted({w for w in wanted if wanted.count(w) > 1})}")
    cells = [names[w] for w in wanted]
    ledger = None
    if base_file:
        ledger, problems = load_ledger(base_file)
        unready = [ledger_key(*c) for c in cells if (ledger.get(ledger_key(*c)) or {}).get("status") != "OK"]
        if problems or unready:
            sys.exit(f"baseline ledger {problems}, no OK row for {unready}; nothing launched")
    return cells, ledger


def harvest_cells(cells, out):
    """One row per metered run of every cell, from the run's own event log and archived logs."""
    logs = os.path.join(out, "logs")
    ran = bep_results(os.path.join(out, "bep.json"))
    rows = []
    for c in cells:
        status = ran.get(target(*c), ("NOT_RUN", ""))[0]
        have = all(os.path.exists(os.path.join(logs, target(*c), f)) for f in ("test.log", "test.xml"))
        if status == "PASSED" and have:
            rows += harvest_runs(*c, logdir=logs)
        else:
            rows.append(dict(dict.fromkeys(ONESHOT_FIELDS, ""), op=c[0], family=c[1] or "ldirect",
                             param=c[2], tier=c[3], verdict=status if status != "PASSED" else "NO_OUTPUT"))
    return rows


def baseline_gate(cells, ledger, out):
    """cell -> its problems against the baseline ledger (empty: identical), every cell listed."""
    logs = os.path.join(out, "logs")
    gate = {}
    for c in cells:
        gate[ledger_key(*c)] = baseline_problems(*c, ledger.get(ledger_key(*c)), logs)
    return gate


def replay(out, mode):
    """A finished run's results directory read again, nothing written: (run.json, cells, rows, baseline gate
    or None). SystemExit names what is wrong with the directory."""
    run, base_file = finished_run(out, mode)
    cells, ledger = select_cells(run["cells"], mode, base_file)
    return run, cells, harvest_cells(cells, out), None if ledger is None else baseline_gate(cells, ledger, out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", action="store_true",
                    help="with --dmem32k/--dmem128k: run the selected targets into a fresh --out, "
                         "then harvest exactly what this invocation produced")
    ap.add_argument("--jobs", type=int, default=3,
                    help="parallel test jobs for --run (3 is the measured sweet spot)")
    ap.add_argument("--make-options", default="-j,8",
                    help="value for --//hw:make_options; keep it constant across runs, "
                         "changing it switches bazel's configuration and empties "
                         "bazel-testlogs (pass '' to omit the flag)")
    ap.add_argument("--test-timeout", type=int, default=21600,
                    help="per-test limit in seconds for --run (default 21600). The two "
                         "keygen sw cells exceed .bazelrc's 7200 s eternal category; "
                         "never pass -1, which reverts to bazel's smaller 3600 s default")
    ap.add_argument("--out", default="chip-matrix",
                    help="output directory (created if absent)")
    ap.add_argument("--strict", action="store_true",
                    help="exit nonzero unless the bazel exit is 0, every cell PASS and the baseline gate identical")
    ap.add_argument("--dmem128k", action="store_true",
                    help="the 128 KiB DMEM tests (keygen min/sp, verify full; one row per metered run, "
                         "results_128k.csv); needs a 128 KiB tree")
    ap.add_argument("--dmem32k", action="store_true",
                    help="the 32 KiB DMEM tests (one row per metered run, results_32k.csv)")
    ap.add_argument("--expected-insn-counts", dest="baseline", default=None, metavar="CSV",
                    help="with --dmem32k: expected instruction counts csv (cell, acc_insn, accept, reject, status); "
                         "every selected cell needs an OK row, and after the harvest its accepting "
                         "acc_insn and phase groups must equal it (with --strict, a mismatch fails)")
    ap.add_argument("--collect", default=None, metavar="DIR",
                    help="with --dmem32k/--dmem128k: re-read an earlier run's --out DIR (its logs, event log, "
                         "selection and bazel exit) instead of running")
    ap.add_argument("--cells", default=None,
                    help="with --dmem32k/--dmem128k: comma-separated target basenames to restrict to")
    ap.add_argument("--bazel-startup", action="append", default=[],
                    help="bazel startup option for --run (repeatable), e.g. --output_base=DIR")
    ap.add_argument("--bazel-flag", action="append", default=[],
                    help="extra flag for the --run test invocation (repeatable), e.g. "
                         "--//hw:verilator_options=--threads,8; use the flags the model was built with")
    a = ap.parse_args()
    if a.baseline and not a.dmem32k:
        sys.exit("--expected-insn-counts applies to --dmem32k; nothing launched")

    if a.dmem128k == a.dmem32k:
        sys.exit("pick one of --dmem32k/--dmem128k; nothing launched")
    if a.run == bool(a.collect):
        sys.exit("pass --run with a fresh --out, or --collect DIR of an earlier run; nothing launched")
    mode = "dmem128k" if a.dmem128k else "dmem32k"
    out = a.collect or a.out
    logs = os.path.join(out, "logs")
    if a.collect:
        # re-reading takes the run's own mode, selection and baseline: nothing is chosen again
        if a.cells is not None or a.baseline:
            sys.exit("--collect takes the run's own cells and baseline from its run.json; pass neither")
        run, cells, rows, gate = replay(out, mode)
    else:
        all_cells = ONESHOT_CELLS if a.dmem128k else CELLS
        wanted = ([target(*c).replace("_sim_verilator", "") for c in all_cells] if a.cells is None
                  else [w for w in a.cells.split(",") if w])
        cells, ledger = select_cells(wanted, mode, a.baseline)
    if a.run:
        if os.path.exists(out) and os.listdir(out):
            sys.exit(f"{out} exists and is not empty; nothing launched")
        os.makedirs(out, exist_ok=True)
        run = {"mode": mode, "cells": wanted, "baseline": None, "bazel_exit": None}
        if a.baseline:
            shutil.copyfile(a.baseline, os.path.join(out, "expected_insn_counts_32k.csv"))   # the gate travels with the run
            run["baseline"] = file_sha256(os.path.join(out, "expected_insn_counts_32k.csv"))
        write_json(os.path.join(out, "run.json"), run)
        # records count only if THIS invocation ran them: bazel's event log names the
        # result directory and status of every test it executed
        rc = run_sweep(a.jobs, a.make_options, a.test_timeout, cells,
                       ["-k", f"--build_event_json_file={os.path.join(out, 'bep.json')}"] + a.bazel_flag,
                       a.bazel_startup)
        write_json(os.path.join(out, "run.json"), dict(run, bazel_exit=rc))
        for name, (status, d) in bep_results(os.path.join(out, "bep.json")).items():
            # this invocation's own outputs, failed cells included (their logs are evidence)
            for f in ("test.log", "test.xml"):
                if d and os.path.exists(os.path.join(d, f)):
                    os.makedirs(os.path.join(logs, name), exist_ok=True)
                    shutil.copy2(os.path.join(d, f), os.path.join(logs, name))
        rows, gate = harvest_cells(cells, out), None if ledger is None else baseline_gate(cells, ledger, out)
    else:
        rc = run["bazel_exit"]
    path = os.path.join(out, "results_128k.csv" if a.dmem128k else "results_32k.csv")
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=ONESHOT_FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    print("| op | cell | protocol | run | acc_insn | exec_wait | host_io_fold | op_total_v2 | app_load | verdict |")
    print("|---|---|---|---|---:|---:|---:|---:|---:|---|")
    for r in rows:
        print(f"| {r['op']} | {r['param']} {r['family']} {r['tier']} | {r['protocol']} | {r['run']} | {r['acc_insn']} | "
              f"{r['exec_wait']} | {r['host_io_fold']} | {r['op_total_v2']} | {r['app_load']} | {r['verdict']} |")
    passed = {(r["op"], r["param"], r["family"], r["tier"]) for r in rows if r["verdict"] == "PASS"}
    print(f"{len(passed)}/{len(cells)} cells PASS -> {path}")
    for cell, probs in (gate or {}).items():
        print(f"baseline {cell}: {'identical' if not probs else '; '.join(probs)}")
    bad = {cell: probs for cell, probs in (gate or {}).items() if probs}
    # a PASS row alone never accepts a cell: bazel exit, every cell and the baseline gate together
    write_json(os.path.join(out, "status.json"), {"bazel_exit": rc, "cells": len(cells), "pass": len(passed),
                                                 "baseline": None if gate is None else (bad or "identical")})
    if a.strict and (rc or len(passed) != len(cells) or bad):
        sys.exit(f"STRICT: bazel exit {rc}, {len(passed)}/{len(cells)} cells PASS, "
                 f"baseline mismatch in {sorted(bad)}")



# ---------------------------------------------------------------------------------------------
# firmware: the preflight checks of tools/rtl_campaign.sh

RE_LOCAL = re.compile(r"^_acc_local_app_(.+)__imem_start$")


def symbols(elf):
    tab = elf.get_section_by_name(".symtab")
    return {s.name: s["st_value"] for s in tab.iter_symbols()} if tab else {}


def range_bytes(sections, start, end):
    """The file bytes behind [start, end): exactly one initialized section must cover it."""
    if end < start:
        raise ValueError(f"reversed range {start:#x}..{end:#x}")
    if end == start:
        return b""
    cover = [(addr, data) for addr, data in sections if addr <= start and end <= addr + len(data)]
    if len(cover) != 1:
        raise ValueError(f"{start:#x}..{end:#x} is covered by {len(cover)} initialized sections")
    addr, data = cover[0]
    return data[start - addr:end - addr]


def embedded(sections, syms, app):
    """(imem, dmem) bytes the firmware embeds for one app."""
    p = f"_acc_local_app_{app}_"
    need = [p + n for n in ("_imem_start", "_imem_end", "_dmem_data_start", "_dmem_data_end")]
    missing = [n for n in need if n not in syms]
    if missing:
        raise ValueError(f"firmware lacks {missing}")
    imem = range_bytes(sections, syms[need[0]], syms[need[1]])
    if not imem:
        raise ValueError(f"{app}: empty IMEM")
    return imem, range_bytes(sections, syms[need[2]], syms[need[3]])


def check(fw_sections, fw_syms, apps):
    """apps: name -> (text bytes, data bytes) of the ACC ELF. Returns a list of problems."""
    problems = []
    found = {m.group(1) for n in fw_syms for m in [RE_LOCAL.match(n)] if m}
    if found != set(apps):
        problems.append(f"firmware embeds {sorted(found)}, expected {sorted(apps)}")
    for app, (text, data) in apps.items():
        try:
            imem, dmem = embedded(fw_sections, fw_syms, app)
        except ValueError as e:
            problems.append(f"{app}: {e}")
            continue
        if imem != text:
            problems.append(f"{app}: embedded IMEM ({len(imem)} B) differs from .text ({len(text)} B)")
        if dmem != data:
            problems.append(f"{app}: embedded DMEM data ({len(dmem)} B) differs from .data ({len(data)} B)")
    return problems


RE_ID = re.compile(rb"op=\w+ param=\w+ family=\w+ tier=\w+")


def meters(sections):
    """(number of "meters v2" formats, set of meter identities) in the firmware's data."""
    blob = b"\0".join(data for _, data in sections)
    return blob.count(b"meters v2"), {m.decode() for m in RE_ID.findall(blob)}


def load_sections(elf):
    return [(s["sh_addr"], s.data()) for s in elf.iter_sections()
            if s["sh_type"] == "SHT_PROGBITS" and s["sh_flags"] & 0x2]   # SHF_ALLOC with file bytes


def app_facts(elf):
    sec = {n: elf.get_section_by_name(n) for n in (".text", ".data")}
    return {"entry": elf["e_entry"],
            "segments": [{"paddr": s["p_paddr"], "vaddr": s["p_vaddr"], "filesz": s["p_filesz"],
                          "memsz": s["p_memsz"], "sha256": hashlib.sha256(s.data()).hexdigest()}
                         for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"],
            "text": sec[".text"].data() if sec[".text"] else b"",
            "data": sec[".data"].data() if sec[".data"] else b""}


def image(path):
    from elftools.elf.elffile import ELFFile
    with open(path, "rb") as fh:
        f = app_facts(ELFFile(fh))
    return f["entry"], f["segments"]


def firmware_main(argv):
    """The preflight checks of tools/rtl_campaign.sh. A firmware must embed exactly its ACC apps' .text and .data
    (util/acc_build.py bounds each by _acc_local_app_<NAME>__imem_start/_end and __dmem_data_start/_end) and, with
    --meter-id, exactly one "meters v2" format naming that identity; one JSON line per app. --same-image: two ACC
    ELFs with the same entry point and load segments. --symbols: print the values, fail if one is missing."""
    from elftools.elf.elffile import ELFFile
    ap = argparse.ArgumentParser(prog="gather_chip_matrix.py firmware", description=firmware_main.__doc__)
    ap.add_argument("--firmware", help="the chip test's firmware ELF")
    ap.add_argument("--app", action="append", metavar="NAME=ELF",
                    help="an ACC app the firmware must embed: its acc_binary name and ELF (repeatable)")
    ap.add_argument("--meter-id", help="the one meters identity the firmware must print (op=.. param=.. family=.. tier=..)")
    ap.add_argument("--same-image", nargs=2, metavar=("A", "B"), help="compare two ACC ELFs' loadable images")
    ap.add_argument("--symbols", nargs="+", metavar=("ELF", "NAME"), help="print symbol values; fail if one is missing")
    a = ap.parse_args(argv)
    if sum(map(bool, (a.symbols, a.same_image, a.firmware or a.app))) > 1:
        ap.error("--symbols, --same-image and --firmware/--app go one at a time")
    if a.symbols:
        with open(a.symbols[0], "rb") as fh:
            syms = symbols(ELFFile(fh))
        missing = [n for n in a.symbols[1:] if n not in syms]
        for n in a.symbols[1:]:
            print(f"{n}={syms[n]:#x}" if n in syms else f"{n} MISSING")
        return 1 if missing or len(a.symbols) < 2 else 0
    if a.same_image:
        same = image(a.same_image[0]) == image(a.same_image[1])
        print(f"{'same' if same else 'DIFFERENT'} image: {a.same_image[0]} {a.same_image[1]}")
        return 0 if same else 1
    if not (a.firmware and a.app):
        ap.error("--firmware and at least one --app are required")
    apps = dict(x.split("=", 1) for x in a.app)
    with open(a.firmware, "rb") as fh:
        fw = ELFFile(fh)
        fw_sections, fw_syms = load_sections(fw), symbols(fw)
    facts = {}
    for name, path in apps.items():
        with open(path, "rb") as fh:
            facts[name] = app_facts(ELFFile(fh))
    problems = check(fw_sections, fw_syms, {n: (f["text"], f["data"]) for n, f in facts.items()})
    if a.meter_id:
        n, ids = meters(fw_sections)
        want = (1, {a.meter_id})
        if (n, ids) != want:
            problems.append(f"meters formats {n}, identities {sorted(ids)}; expected {want[0]}, {sorted(want[1])}")
    for name, f in facts.items():
        print(json.dumps({"app": name, "elf": apps[name], "entry": f["entry"], "segments": f["segments"],
                          "imem_sha256": hashlib.sha256(f["text"]).hexdigest(),
                          "dmem_data_sha256": hashlib.sha256(f["data"]).hexdigest()}, sort_keys=True))
    for p in problems:
        print(f"MISMATCH {p}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["firmware"]:
        sys.exit(firmware_main(sys.argv[2:]))
    main()
