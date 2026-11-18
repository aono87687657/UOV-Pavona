#!/usr/bin/env python3
"""gather_kat_stats.py — reusable KAT + cycle-count sweep for UOV {keygen,sign,verify}.

Grid: ops x params x tiers x variants x cases, run on the Python ISS, each cell
KAT-validated. Tier legend:
  sw       = no gfmul/aes128 (T-table AES + SW GF; GF256 helpers use bn.mulv.l)
  bngfonly = HW bn.gfmul, SW AES
  bngfaes  = HW bn.gfmul + HW bn.aes128
  bnaesonly = HW bn.aes128, SW GF (32 KiB variants)
Variants (per op; the first is the default):
  sign:   ldirect  = L-direct fused-y default kernel
          sprec    = precompute-S (cached S + raw-P1 cache, cached-y recompute)
  verify: stream   = phase-dispatch streamed verify, the DEFAULT (all four tiers,
                     32 KiB DMEM)
          full     = the whole public key resident, one EXECUTE per verification (128 KiB DMEM)
          stream_uniform = backend-ablation family (ONE outer, tier-swapped backends;
                        all tiers, both params; windows capped to the outer ABI)
  keygen: stream   = phase-dispatch streamed keygen (32 KiB DMEM)
          full     = single-run keygen (512 KiB reference)
          min, sp  = single-EXECUTE keygen, smallest footprint and single pass (128 KiB DMEM)
          stream_uniform = one shared outer kernel, backend swaps via
                     backend_* adapters (both params; isolates the ISE effect)
NOTE: 'all' means every swept variant, NOT every variant. Off the grid: sign
sprec, verify full and keygen full/min/sp need a bigger DMEM than the chip
ships. Name one to run it anyway; each SKIP row carries its reason. 'all'
still includes keygen stream/stream_uniform sw-tier cells at ~100M+ simulated
cycles per case.
--vectors NAME (sign only) reads test_data/testvectors-<param>-pkc-skc.NAME instead of the KAT file, e.g. retrygrid
(36 cases with a known number of retries each, testvectors-retrygrid-index.csv); its stats names end in _NAME.
Outputs:
  <out>/stats/<op>_<param>_<tier>_case<c>.txt            (default variants — legacy name)
  <out>/stats/<op>_<param>_<tier>_<variant>_case<c>.txt  (non-default variants)
  <out>/results.csv   op,param,tier,variant,case,kat,instructions,cycles
No resume cache: every invocation re-runs every requested cell and OVERWRITES
any prior data in --out, so a reused dir can never mix stale and fresh numbers
(an interrupted sweep restarts from scratch — rerun it whole). A FAILed cell
leaves no stats file behind. Rebuild ELFs after source edits; the sweep runs
prebuilt binaries.

--ops and --params are required. Without --out the sweep goes to a new temporary folder; the default cases are
0,11 (msglen 0 and 1024).

Examples:
  # dev loop: default tiers and variants, cases 0,11
  python3 tools/gather_kat_stats.py --ops verify --params Ip,Is
  # full sweep: every 32 KiB variant, all tiers it applies to, 12 cases
  python3 tools/gather_kat_stats.py --ops keygen,sign,verify --params Ip,Is,Ip3 --out ~/kat_paper --variants all --cases 0-11 \
      --tiers sw,bngfonly,bngfaes,bnaesonly
  # add an off-grid kernel (needs a DMEM resize first)
  python3 tools/gather_kat_stats.py --ops keygen,sign,verify --params Ip,Is --out ~/kat_paper --variants all,full --cases 0-11
"""
import os, re, sys, csv, math, time, shutil, signal, argparse, tempfile, threading, subprocess
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY   = sys.executable
HANDWRITTEN_DIR = f"{REPO}/sw/acc/crypto/handwritten"
sys.path.insert(0, f"{HANDWRITTEN_DIR}/own_utils")
from acc_sim_utils import parse_cases
# Where the prebuilt ELFs live; --elf-root points it at frozen copies (tools/uov.py)
# so a sweep cannot pick up a rebuild in bazel-bin. Every 32 KiB variant passes its
# selected ELF explicitly to the driver.
BAZEL_BIN = f"{REPO}/bazel-bin"

TIERS_BASE = ["sw", "bngfonly", "bngfaes"]
# Hardware AES with software GF is available for every 32 KiB cell.
# Keep the default tier selection stable; request bnaesonly explicitly.
TIERS_ALL = TIERS_BASE + ["bnaesonly"]
# The kernels a clean checkout can build and run at the shipped 32 KiB DMEM.
# First entry = the op's default, and the one that gets the untagged stats
# filename.
VARIANTS = {
    "sign":   ["ldirect"],
    "verify": ["stream", "stream_uniform"],
    "keygen": ["stream", "stream_uniform"],
}
# Variant -> why it is not swept by 'default' or 'all'. Naming one explicitly
# still runs it, and the reason travels into the SKIP row so a reader can tell
# "too big for this chip" from "not in this tree".
OFF_GRID = {
    "sign":   {"sprec":   "offgrid-32KiB"},   # .data overflows by ~312 KB
    "verify": {"full":     "offgrid-32KiB"},  # 128 KiB, the whole key resident
    "keygen": {"full":     "offgrid-32KiB",   # 512 KiB reference
               "min":      "offgrid-32KiB",   # 128 KiB, smallest footprint
               "sp":       "offgrid-32KiB"},  # 128 KiB, single pass
}
TIERS4 = ("bngfaes", "bngfonly", "bnaesonly", "sw")
PARAMS3 = ("Ip", "Is", "Ip3")
# The cells tools/uov.py campaigns run, by DMEM profile: (profile, op, variant) -> (params, tiers).
# Every one is also a valid collector cell; the 512 KiB cells are bngfaes only.
CAMPAIGN = {
    (32, "sign", "ldirect"): (PARAMS3, TIERS4),
    (32, "verify", "stream"): (PARAMS3, TIERS4),
    (32, "verify", "stream_uniform"): (PARAMS3, TIERS4),
    (32, "keygen", "stream"): (PARAMS3, TIERS4),
    (32, "keygen", "stream_uniform"): (PARAMS3, TIERS4),
    (128, "keygen", "min"): (PARAMS3, TIERS4),
    (128, "keygen", "sp"): (PARAMS3, TIERS4),
    (128, "verify", "full"): (PARAMS3, TIERS4),
    (512, "keygen", "full"): (PARAMS3, ("bngfaes",)),
    (512, "sign", "sprec"): (PARAMS3, ("bngfaes",)),
}
# What one published measurement is, per route.
PROTOCOL = {
    ("keygen", "full"): "keygen-single-execution-kat",          # one EXECUTE; cpk = KAT, csk = sk_seed
    ("keygen", "min"): "keygen-single-execution-kat",
    ("keygen", "sp"): "keygen-single-execution-kat",
    ("keygen", "stream"): "stream-keygen-kat",                   # INIT + every window, summed
    ("keygen", "stream_uniform"): "stream-keygen-kat",
    ("verify", "stream"): "stream-verify-accept",                # INIT + updates + FINAL, summed
    ("verify", "stream_uniform"): "stream-verify-accept",
    ("verify", "full"): "oneshot-verify-resident-accept",        # the 'case <c> accept' run, key installed
    ("sign", "ldirect"): "sign-kat",
    ("sign", "sprec"): "sign-kat",
}

EXEC_RE = re.compile(r"executed (\d+) instructions in (\d+) cycles")

def measurement(path, label=None):
    """(instructions, cycles) of one measurement in a statistics file, else (None, None).

    Without a label the file must hold exactly one execution summary. With a label it must hold
    exactly one record headed '<label>:' (a line ending in a colon right before 'Execution time',
    as drivers that write one record per run do) whose report holds exactly one summary. The space
    after the colon is optional, so a raw file and its published (tidied) copy read the same."""
    try:
        lines = open(path).read().split("\n")
    except OSError:
        return (None, None)
    if label is not None:
        heads = [i for i in range(len(lines) - 1)
                 if lines[i + 1] == "Execution time" and lines[i].rstrip().endswith(":")]
        mine = [i for i in heads if lines[i].rstrip()[:-1] == label]
        if len(mine) != 1:
            return (None, None)
        end = min([i for i in heads if i > mine[0]] + [len(lines)])
        lines = lines[mine[0] + 1:end]
    hits = [m for line in lines for m in EXEC_RE.finditer(line)]
    return (int(hits[0].group(1)), int(hits[0].group(2))) if len(hits) == 1 else (None, None)

def measurement_label(op, variant, c):
    """The record a route's statistics file is read at (None: the file's only summary)."""
    return f"case {c} accept" if (op, variant) == ("verify", "full") else None

TIMEOUT = None   # seconds per driver run, --timeout
VECTORS = None   # --vectors: suffix of the vector file sign reads instead of the KAT file
KILL_GRACE = 10  # seconds between SIGTERM and SIGKILL to a driver's process group
LIVE = set()                  # running drivers, each the leader of its own process group
LIVE_LOCK = threading.Lock()  # guards LIVE and STOPPING; a driver starts and registers under it
STOPPING = False
SIGNALS = []                  # SIGTERM/SIGINT received; the handler only records, main() stops

class Unresolved(Exception):
    """A process the collector started and could not end. Nothing bounds it any more, so the run is abandoned."""

def _unresolved(what):
    """The error for such a process. From here on no driver starts; main() abandons the run when it arrives."""
    global STOPPING
    with LIVE_LOCK:
        STOPPING = True
    return Unresolved(what)

def drive(cmd):
    """Run one driver in its own session: (exit code or None, stdout+stderr, timed out). On --timeout, or an
    error while waiting, its whole process group gets SIGTERM, then SIGKILL after KILL_GRACE (a descendant
    may ignore SIGTERM); a timed-out driver's output so far is returned. A driver that cannot be ended
    raises Unresolved instead. Once the collector is stopping, no driver starts.
    After a normal exit nothing is signalled, because the group id of a reaped driver is no longer its own.
    A driver must therefore have ended every process it started before it exits, error exits included."""
    with LIVE_LOCK:
        if STOPPING:
            return None, "not started: the collector is stopping\n", False
        p = subprocess.Popen(cmd, cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, start_new_session=True)
        LIVE.add(p)
    try:
        try:
            out, _ = p.communicate(timeout=TIMEOUT)
            return p.returncode, out, False
        except subprocess.TimeoutExpired:
            _end_group(p)
            try:
                return None, p.communicate(timeout=KILL_GRACE)[0], True
            except subprocess.TimeoutExpired:    # a process that left the group still holds the pipe
                raise _unresolved(f"the output of driver {p.pid} is still open after its group was killed") from None
        except BaseException:
            _end_group(p)                # any other error ends the driver too, or is Unresolved
            raise
    finally:
        p.stdout.close()
        with LIVE_LOCK:
            LIVE.discard(p)

def _signal_group(p, sig):
    """Signal a driver's process group: True if sent, False if the group is gone. For a driver not yet
    reaped, whose group id is still its own."""
    pid = p.pid
    if type(pid) is not int or pid <= 1:     # killpg(1) is kill(-1): every process of this user
        raise RuntimeError(f"refusing to signal process group {pid!r}")
    try:
        os.killpg(pid, sig)
        return True
    except ProcessLookupError:
        return False

def _end_group(p):
    """SIGTERM, KILL_GRACE, SIGKILL, then reap within KILL_GRACE. The grace is always waited in full: the
    driver is reaped only at the end, so both signals go to its own group. A driver that cannot be
    signalled or does not end is Unresolved; nothing here waits for it without a bound."""
    if p.returncode is not None:
        return
    try:
        _signal_group(p, signal.SIGTERM)
        time.sleep(KILL_GRACE)
        _signal_group(p, signal.SIGKILL)
        p.wait(timeout=KILL_GRACE)
    except (PermissionError, subprocess.TimeoutExpired) as e:
        raise _unresolved(f"driver {p.pid} may still be running ({e!r})") from None

def _abandon(code, why):
    """Give the run up (a stop signal, or an Unresolved process): start no other driver, SIGKILL every
    running driver's group, say what was done and exit with code, without a DONE line."""
    global STOPPING
    sent, gone, failed = 0, 0, []
    try:
        with LIVE_LOCK:
            STOPPING = True
            procs = list(LIVE)
        for p in procs:
            try:
                if p.returncode is not None:     # checked, not locked: a driver reaped right here leaves a stale id
                    gone += 1
                elif _signal_group(p, signal.SIGKILL):
                    sent += 1
                else:
                    gone += 1
            except Exception as e:
                failed.append(f"{p.pid}: {e!r}")
        print(f"{why}: SIGKILL sent to {sent} driver groups, {gone} already gone, no further driver started"
              + (f"; NOT signalled: {'; '.join(failed)}" if failed else ""), file=sys.stderr, flush=True)
    finally:
        os._exit(code)

def verdict(cell, rc, out, timed_out, passed):
    """Keep the driver's output as the cell's driver.log; a timeout fails the cell whatever it printed."""
    with open(os.path.join(cell, "driver.log"), "w") as fh:
        fh.write(out)
    if timed_out:
        return "FAIL:timeout"
    return "PASS" if rc == 0 and passed else "FAIL"

def testvec_path(param):
    return f"{HANDWRITTEN_DIR}/test_data/testvectors-{param}-pkc-skc" + (f".{VECTORS}" if VECTORS else "")

def vector_cases(path):
    """Number of 3-line cases in a vector file."""
    lines = open(path).read().split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if len(lines) % 3:
        raise ValueError(f"{path}: {len(lines)} lines, not whole 3-line cases")
    return len(lines) // 3

def aux_inputs(op, param, variant):
    """Vector files besides testvec_path whose bytes decide a cell: the Ip3 one-shot verify proof's second key
    (the Ip and Is drivers take theirs from the next case of testvec_path)."""
    return [f"{testvec_path(param)}.nistkat"] if (op, variant, param) == ("verify", "full", "Ip3") else []

def stats_name(op, param, tier, variant, c):
    # default variants keep the pre-variant filename: the published records name their evidence by it
    tag = ("" if variant == VARIANTS[op][0] else f"_{variant}") + (f"_{VECTORS}" if VECTORS else "")
    return f"{op}_{param}_{tier}{tag}_case{c}.txt"

UOV = "sw/acc/crypto/handwritten/uov"
# fail-closed ELF identity: required / forbidden symbols per keygen variant
# (all variants emit identical KAT bytes, so wrong routing would pass silently)
_KG_SYMS = {"full": ({"cpk"}, {"ctrl", "slice_end", "cpk_payload"}),
            "stream": ({"ctrl", "slice", "slice_end"}, {"cpk"}),
            "stream_uniform": ({"ctrl", "slice", "slice_end", "backend_init_once"}, {"cpk"}),
            "min":  ({"cpk", "cpk_payload", "slice_end"}, {"ctrl"}),
            "sp": ({"cpk", "cpk_payload"}, {"ctrl", "slice_end"})}

# sign: the L builder of each variant and set (sprec forms L from S, ldirect from one pass over the stream)
_SIGN_SYMS = {"Ip": ("gf256_matvec_2816_68", "gf256_ldirect_68_44"), "Is": ("gf16_matvec_2048_96", "gf16_ldirect_96_64"),
              "Ip3": ("gf256_matvec_2880_74", "gf256_ldirect_74_45")}

def _sign_variant_ok(syms, param, variant):
    sprec, ldirect = _SIGN_SYMS[param]
    return (sprec in syms and ldirect not in syms) if variant == "sprec" else (ldirect in syms and sprec not in syms)

def _tier_fingerprint_ok(syms, tier):
    # Arm identity from the deps that make the arm what it is: bngfonly carries
    # rcon in .data, sw the re-emitted AES128_TABLE, bnaesonly the aes128hw_*
    # leaf (prefix match survives leaf renames); bngfaes carries none of them.
    # Holds for stream, stream_uniform and R3 sign alike.
    want = {"bngfaes": (False, False), "bngfonly": (True, False),
            "sw": (False, True), "bnaesonly": (False, False)}[tier]
    if not syms or ("rcon" in syms, "AES128_TABLE" in syms) != want:
        return False
    return (tier == "bnaesonly") == any(x.startswith("aes128hw_") for x in syms)


def _elf_symbols(elf):
    # through drive(): the tool runs under --timeout and is stopped with the collector, like a driver
    rc, out, timed_out = drive([PY, f"{REPO}/hw/ip/acc/util/acc_objdump.py", "-t", elf])
    if rc != 0:                          # a tool failure, a timeout or a stop is not a missing symbol
        raise RuntimeError(f"acc_objdump {'timed out' if timed_out else 'failed'} on {elf}: "
                           f"{(out.strip().splitlines() or ['?'])[-1]}")
    return {ln.split()[-1] for ln in out.splitlines() if ln.split()}

SUB = {"keygen": "pkc+skc", "sign": "skc", "verify": "pkc"}   # the parameter subfolder: ov-<param>-<SUB[op]>

def elf_of(op, param, tier, variant, layout="current"):
    """A cell's ELF, relative to the ELF root (the file is named after its target, in its parameter set's subfolder).
    layout "flat": the folders before the 2026-10-19 reorg (Ip and Is side by side, Round 3 in *_round3 folders), which
    the rounds measured before it name."""
    if layout == "flat":
        r3 = "_round3" if param == "Ip3" else ""
        if op == "sign":
            if variant == "sprec":
                return f"{UOV}/dmem_large/sign_sprec/ov-{param}-sign_sprec_testvec_{tier}.elf"
            return f"{UOV}/dmem32k/sign_ldirect{r3}/ov-{param}-skc/ov-{param}-sign_ldirect_testvec_{tier}.elf"
        if (op, variant) == ("keygen", "full"):
            return f"{UOV}/dmem_large/keygen_full/ov-{param}-pkc+skc/ov-{param}-keygen_full_{tier}.elf"
        size = "dmem32k" if variant in ("stream", "stream_uniform") else "dmem_large"
        return f"{UOV}/{size}/{op}_{variant}{r3}/ov-{param}-{op}_{variant}_{tier}.elf"
    sub = f"ov-{param}-{SUB[op]}"
    if op == "sign":
        size = "dmem_large" if variant == "sprec" else "dmem32k"
        return f"{UOV}/{size}/sign_{variant}/{sub}/ov-{param}-sign_{variant}_testvec_{tier}.elf"
    size = "dmem32k" if variant in ("stream", "stream_uniform") else "dmem_large"
    return f"{UOV}/{size}/{op}_{variant}/{sub}/ov-{param}-{op}_{variant}_{tier}.elf"

RUN_TEST = "sw/acc/crypto/handwritten/own_utils/run_test.py"   # the keygen and sign drivers: run_test.py keygen|sign

def driver_of(op, param, variant, layout="current"):
    """The scripts a cell's driver consists of, relative to the repo; the first one is run. Each takes --param.
    layout as in elf_of."""
    if op == "keygen":
        if variant in ("stream", "stream_uniform"):
            return [f"{UOV}/dmem32k/keygen_stream/tests/test_stream_keygen.py"]
        return [RUN_TEST]
    if op == "sign":
        return [RUN_TEST]
    if variant == "full":
        return [f"{UOV}/dmem_large/verify_full/tests/test_full_verify.py"]
    mc = f"{UOV}/dmem32k/verify_stream/tests/measure_cycles.py"
    if layout == "flat" and param == "Ip3":   # before the 2026-10-19 reorg Ip3 had its own driver
        return [f"{UOV}/dmem32k/verify_stream_round3/tests/test_ip3_stream.py", mc]
    return [mc]

def run_sign(param, tier, variant, c, cell):
    os.makedirs(cell, exist_ok=True)
    elf = f"{BAZEL_BIN}/{elf_of('sign', param, tier, variant)}"
    src = os.path.join(cell, "statistics_0.txt")
    syms = _elf_symbols(elf) if os.path.exists(elf) else set()
    if not _sign_variant_ok(syms, param, variant):
        return f"FAIL:elf-identity(sign-{variant})", src
    if param == "Ip3" or tier == "bnaesonly":
        # R3 and hardware-AES arms prove their tier by fingerprint, like the stream verify
        if not _tier_fingerprint_ok(syms, tier):
            return f"FAIL:elf-identity(sign-{tier})", src
    args = ["--elf", elf] if param == "Ip3" else ["--tier", tier, "--elf", elf]
    if variant == "sprec":
        args.append("--precompute")
    rc, out, timed_out = drive([PY, f"{REPO}/{driver_of('sign', param, variant)[0]}", "sign", "--param", param] + args + [
        "--test-data-file", testvec_path(param), "--case-start", str(c), "--iterations", "1", "--output-dir", cell])
    return verdict(cell, rc, out, timed_out, "byte-wise MATCH" in out), src

def run_keygen(param, tier, variant, c, cell):
    os.makedirs(cell, exist_ok=True)
    elf = f"{BAZEL_BIN}/{elf_of('keygen', param, tier, variant)}"
    script = f"{REPO}/{driver_of('keygen', param, variant)[0]}"
    stream = variant in ("stream", "stream_uniform")   # stream_uniform speaks the stream host contract
    src = os.path.join(cell, "keygen_stats.txt" if stream else f"keygen_stats_{param}_{tier}_{c}.txt")
    need, forbid = _KG_SYMS[variant]
    syms = _elf_symbols(elf) if os.path.exists(elf) else set()
    if not need <= syms or syms & forbid:
        return f"FAIL:elf-identity({variant})", src
    if stream:
        # variant identity alone passes any correctly-routed tier: the arm must prove its tier too
        if not _tier_fingerprint_ok(syms, tier):
            return f"FAIL:elf-identity({variant}-{tier})", src
        rc, out, timed_out = drive([PY, script, "--param", param, "--elf", elf, "--cases", str(c), "--dump-stats", src])
        kat = verdict(cell, rc, out, timed_out, f"{param.upper()} STREAMED KEYGEN PASS" in out)
    else:
        # full, min and sp share the symbol-driven contract: the common harness with an explicit
        # --elf, which refuses a --tier the ELF's fingerprint contradicts
        rc, out, timed_out = drive([PY, script, "keygen", "--param", param, "--tier", tier, "--cases", str(c), "--output-dir", cell,
                                    "--test-data-file", testvec_path(param), "--elf", elf])
        kat = verdict(cell, rc, out, timed_out, "[PASS]" in out)
    if kat == "PASS" and os.path.exists(src):
        with open(src, "a") as fh:
            fh.write(f"# elf: {elf}\n")
    return kat, src

def run_verify(param, tier, variant, c, cell):
    os.makedirs(cell, exist_ok=True)
    src = os.path.join(cell, "verify_stats.txt")
    elf = f"{BAZEL_BIN}/{elf_of('verify', param, tier, variant)}"
    script = f"{REPO}/{driver_of('verify', param, variant)[0]}"
    if variant in ("stream", "stream_uniform"):
        # Every tier emits identical KAT bytes, so the arm must prove its tier: a misrouted BUILD
        # row would otherwise pass while reporting another arm's cycles. stream_uniform is one
        # outer per param (initdone, msgwin) with tier-swapped backends; the driver sizes Is
        # windows from the ELF's msgwin/winend.
        syms = _elf_symbols(elf) if os.path.exists(elf) else set()
        if variant == "stream_uniform" and not {"initdone", "msgwin"} <= syms:
            return "FAIL:elf-identity(stream_uniform)", src
        if not _tier_fingerprint_ok(syms, tier):
            return f"FAIL:elf-identity({variant}-{tier})", src
        rc, out, timed_out = drive([PY, script, "--param", param, "--cases", str(c), "--elf", elf, "--dump-stats", src])
        return verdict(cell, rc, out, timed_out, "PASS" in out), src
    if variant == "full":
        syms = _elf_symbols(elf) if os.path.exists(elf) else set()
        if not {"cpk", "hdr", "accctx"} <= syms:
            return "FAIL:elf-identity(full)", src
        # the whole proof runs; the measurement is its 'case <c> accept' record (measurement_label)
        aux = aux_inputs("verify", param, variant)
        rc, out, timed_out = drive([PY, script, "--param", param, "--elf", elf, "--cases", str(c), "--tier", tier,
                                    "--dump-stats", src, *(["--vectors2", *aux] if aux else [])])
        return verdict(cell, rc, out, timed_out, f"{param.upper()} ONESHOT VERIFY PASS" in out), src
    raise ValueError(f"no verify variant {variant}")

OP_RUNNERS = {"sign": run_sign, "keygen": run_keygen, "verify": run_verify}

def cell_job(out, op, param, tier, variant, c):
    stats_file = os.path.join(out, "stats", stats_name(op, param, tier, variant, c))
    # always re-run and replace: clear this cell's prior data first so a FAIL
    # can't leave a stale (possibly different-code) measurement lying around
    for leftover in (stats_file, stats_file + ".pass", stats_file + ".log"):
        if os.path.exists(leftover):
            os.remove(leftover)
    tmp = os.path.join(out, "_tmp", f"{op}_{param}_{tier}_{variant}_{c}")
    try:
        kat, src = OP_RUNNERS[op](param, tier, variant, c, tmp)
        if kat == "PASS" and os.path.exists(src):
            shutil.copy(src, stats_file)
            shutil.copy(os.path.join(tmp, "driver.log"), stats_file + ".log")
        i, cy = measurement(stats_file, measurement_label(op, variant, c)) if kat == "PASS" else (None, None)
        if kat == "PASS" and (i is None or cy is None):
            kat = "FAIL:stats"   # a measurement cell without exactly one selected count is a failure
        return (op, param, tier, variant, c, kat, i, cy)
    except Unresolved:
        raise                            # not a cell result: main() abandons the run
    except Exception as e:
        return (op, param, tier, variant, c, f"ERR:{e}", None, None)

def cell_valid(op, param, tier, variant):
    if variant not in VARIANTS[op] + list(OFF_GRID[op]):
        return False
    if param == "Ip3":
        # R3 tree: every 32 KiB family, keygen min/sp, verify full; keygen full and sprec with the bngfaes arm only
        if (op, variant) in (("keygen", "full"), ("sign", "sprec")):
            return tier == "bngfaes"
        return (op, variant) in (("sign", "ldirect"), ("verify", "stream"),
                                 ("verify", "stream_uniform"), ("verify", "full"),
                                 ("keygen", "stream"), ("keygen", "stream_uniform"),
                                 ("keygen", "min"), ("keygen", "sp"))
    if tier == "bnaesonly":
        return variant in VARIANTS[op] or (op, variant) in (("keygen", "min"), ("keygen", "sp"), ("verify", "full"))
    return True

def main():
    global BAZEL_BIN, TIMEOUT, VECTORS
    ap = argparse.ArgumentParser(description="Reusable UOV KAT + cycle-count gatherer.")
    ap.add_argument("--out", help="output dir (created; prior cell data is replaced); default: a new temporary folder")
    ap.add_argument("--ops", required=True, help="keygen, sign, verify or a comma list")
    ap.add_argument("--tiers", default=",".join(TIERS_BASE),
                    help="comma list of sw,bngfonly,bngfaes,bnaesonly (legend in module "
                         "docstring); bnaesonly is available for all 32 KiB cells")
    ap.add_argument("--params", required=True, help="Ip, Is, Ip3 or a comma list")
    ap.add_argument("--cases", type=parse_cases, default=parse_cases("0,11"), metavar="LIST",
                    help="KAT cases: 0, 0,11 or 0-11 (default 0,11)")
    ap.add_argument("--variants", default="default",
                    help="'default' (per-op defaults), 'all', or comma list; "
                         "'default' in the list expands to each op's default")
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--fresh", action="store_true",
                    help="refuse an --out that already exists and is not empty (campaign runs)")
    ap.add_argument("--timeout", type=float, metavar="SECONDS",
                    help="end a driver run after this many seconds (its whole process group); the cell is FAIL:timeout")
    ap.add_argument("--elf-root", metavar="DIR",
                    help="tree of prebuilt ELFs laid out like bazel-bin (default: the repo's bazel-bin)")
    ap.add_argument("--vectors", metavar="NAME",
                    help="sign only: read test_data/testvectors-<param>-pkc-skc.NAME instead of the KAT file (e.g. retrygrid)")
    a = ap.parse_args()
    out = os.path.expanduser(a.out) if a.out else None
    if a.elf_root is not None:
        if not os.path.isdir(a.elf_root):
            ap.error(f"--elf-root {a.elf_root} is not a directory")
        BAZEL_BIN = os.path.abspath(a.elf_root)
    ops = a.ops.split(","); tiers = a.tiers.split(","); params = a.params.split(",")
    for t in tiers:
        if t not in TIERS_ALL:
            hint = " (the *_acch labels are gone: acch is the default kernel; use --variants sprec for precompute-S)" if t.endswith("_acch") else ""
            ap.error(f"unknown tier '{t}'{hint}")
    for p in params:
        if p not in ("Is", "Ip", "Ip3"):
            ap.error(f"unknown param '{p}' (expect Ip, Is or Ip3)")
    cases = a.cases
    if a.vectors is not None:
        if ops != ["sign"]:
            ap.error("--vectors applies to --ops sign only")
        if not re.fullmatch(r"[a-z0-9]+", a.vectors):
            ap.error("--vectors takes a file suffix of lower-case letters and digits, e.g. retrygrid")
        VECTORS = a.vectors
        for p in params:
            if not os.path.isfile(testvec_path(p)):
                ap.error(f"no vector file {testvec_path(p)}")
            n = vector_cases(testvec_path(p))
            if max(cases) >= n:
                ap.error(f"{os.path.basename(testvec_path(p))} has {n} cases, asked for case {max(cases)}")
    req = a.variants.split(",")
    known = {v for vs in list(VARIANTS.values()) + [list(d) for d in OFF_GRID.values()]
             for v in vs} | {"default", "all"}
    for v in req:
        if v not in known:
            ap.error(f"unknown variant '{v}' (known: {sorted(known)})")
    def op_variants(op):
        # 'all' stays inside the 32 KiB grid; off-grid kernels must be named.
        # 'all' combined with a name still runs the name - never silently drop it.
        vs = [VARIANTS[op][0] if v == "default" else v for v in req]
        if "all" in req:
            vs += VARIANTS[op]
        return [v for v in VARIANTS[op] + list(OFF_GRID[op]) if v in vs]
    asked = [(op, p, t, v) for op in ops for p in params for t in tiers
             for v in op_variants(op)]
    cells = [(op, p, t, v, c) for (op, p, t, v) in asked for c in cases
             if cell_valid(op, p, t, v)]
    if not cells:
        ap.error("requested grid is empty (op/tier/variant combination enumerates zero cells)")
    if a.workers < 1:
        ap.error("--workers must be at least 1")
    if a.timeout is not None and not (math.isfinite(a.timeout) and a.timeout > 0):
        ap.error("--timeout must be positive and finite")
    TIMEOUT = a.timeout
    if out is None:
        out = tempfile.mkdtemp(prefix="kat.")
    if a.fresh and os.path.isdir(out) and os.listdir(out):
        ap.error(f"--fresh: {out} exists and is not empty")
    # only now touch the out dir. Replace its data, not just the requested cells: a reused
    # dir with a narrower cell subset must not keep stale stats from a prior run
    for stale in ("stats", "_tmp"):
        shutil.rmtree(os.path.join(out, stale), ignore_errors=True)
    for f in ("results.csv",):
        if os.path.exists(os.path.join(out, f)):
            os.remove(os.path.join(out, f))
    os.makedirs(os.path.join(out, "stats"), exist_ok=True)
    os.makedirs(os.path.join(out, "_tmp"), exist_ok=True)
    # Say which requested combinations the variant does not have. Silence here
    # reads as full coverage; name what was dropped.
    dropped = sorted({f"{op}/{t}/{v}" for (op, p, t, v) in asked
                      if not cell_valid(op, p, t, v)})
    if dropped:
        print(f"not applicable to this variant, skipped: {', '.join(dropped)}", flush=True)
    print(f"gathering {len(cells)} cells -> {out}  ({a.workers}-way)", flush=True)
    # In an 'all' sweep, off-grid kernels get a SKIP row rather than vanishing:
    # simply omits them looks complete, and a reader cannot tell "not run" from
    # "does not exist". Only static OFF_GRID membership may skip - a link
    # regression inside the grid must stay a hard FAIL.
    rows = [(op, p, t, v, c, f"SKIP:{OFF_GRID[op][v]}", None, None)
            for op in ops for p in params for t in tiers
            for v in OFF_GRID[op] if v not in op_variants(op)
            for c in cases] if "all" in req else []
    done = 0
    for s in (signal.SIGTERM, signal.SIGINT):
        signal.signal(s, lambda sig, frame: SIGNALS.append(sig))
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        pending = {ex.submit(cell_job, out, *c) for c in cells}
        while pending:
            finished, pending = wait(pending, timeout=1, return_when=FIRST_COMPLETED)
            if SIGNALS:
                _abandon(128 + SIGNALS[0], f"stopped by signal {SIGNALS[0]}")
            for f in finished:
                try:
                    r = f.result()
                except Unresolved as e:
                    _abandon(3, f"abandoned, {e}")
                rows.append(r); done += 1
                print(f"[{done}/{len(cells)}] {r[0]} {r[1]} {r[2]} {r[3]} case{r[4]}: {r[5]} cycles={r[7]}", flush=True)
                with open(os.path.join(out, "results.csv"), "w", newline="") as fh:
                    w = csv.writer(fh); w.writerow(["op", "param", "tier", "variant", "case", "kat", "instructions", "cycles"])
                    for x in sorted(rows): w.writerow(x)
    if SIGNALS:                              # stopped while the last results were written: no DONE line
        _abandon(128 + SIGNALS[0], f"stopped by signal {SIGNALS[0]}")
    fails = [r for r in rows if not r[5].startswith(("PASS", "SKIP"))]
    skips = [r for r in rows if r[5].startswith("SKIP")]
    tail = f"  !! {len(fails)} FAIL: {fails}" if fails else "  (all PASS)"
    print(f"DONE {done}/{len(cells)} -> {out}/results.csv" + tail
          + (f"  [{len(skips)} off-grid SKIP]" if skips else ""), flush=True)
    return 1 if fails else 0

if __name__ == "__main__":
    sys.exit(main())
