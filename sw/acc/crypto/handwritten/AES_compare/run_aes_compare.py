#!/usr/bin/env python3
"""Reproducible cycle comparison of the three ACC AES-128 implementations.

Measures each variant's key schedule and encryption separately on ACCSim and
prints two tables plus a CSV. Plain AES (no CTR); encryption is measured with
round keys already in place; UOV kernels use different key-schedule strategies.

Variants
  ISE        AES instructions  bn.aes128.kf / .encz.swap / .encm / .encf
  compute-GF compute-AES        Itoh-Tsujii inverse + MixCols via bn.gfmul.8
  T-table    software AES       4 KiB T-table, pure 32-bit GPR path

Work units differ and are labelled: ISE and compute-GF encrypt a dual-block
(32 B, both 128-bit lanes of a 256-bit WDR) per call; the T-table encrypts a
single 16-byte block per call. cycles/byte is the throughput equalizer.

Each number is op-driver run MINUS setup-only baseline run (both standalone
ACCSim runs); the subtraction isolates the op from the fixed operand/constant
load, same method as GF_compare.

Reproduce (from the repo root):
    python3 \\
        sw/acc/crypto/handwritten/AES_compare/run_aes_compare.py

Writes aes_compare.csv next to this script.
"""
import csv
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", ".."))
HW = "sw/acc/crypto/handwritten"
STANDALONE = os.path.join(REPO, "hw/ip/acc/dv/accsim/standalone.py")

# variant, op, op-driver target, setup-baseline target, bytes/call, datapath.
# Op cost = op-driver run - setup-only run (the baseline is the op driver
# minus exactly the measured op; setup = its own fixed per-call number).
TARGETS = [
    ("ISE",        "keyschedule", "AES_ext:aes128_ext_ks_test",      "AES_ext:aes128_ext_setup_test",              None, "256-bit"),
    ("ISE",        "encrypt",     "AES_ext:aes128_ext_enc_test",     "AES_ext:aes128_ext_setup_test",              32,   "256-bit dual-block"),
    ("compute-GF", "keyschedule", "AES_gf:aes128_fullks_test",       "AES_gf:aes128_fullks_setup_test",            None, "256-bit"),
    ("compute-GF", "encrypt",     "AES_gf:aes128_encrypt_only_test", "AES_gf:aes128_encrypt_only_setup_test",      32,   "256-bit dual-block"),
    ("T-table",    "keyschedule", "AES_table:aes_keyschedule_test",  "AES_table:aes_keyschedule_setup_test",       None, "32-bit GPR"),
    ("T-table",    "encrypt",     "AES_table:aes_encrypt_only_test", "AES_table:aes_encrypt_only_setup_test",      16,   "32-bit GPR"),
]

_STAT = re.compile(r"executed (\d+) instructions in (\d+) cycles")
_ERR = re.compile(r"^ ERR_BITS = 0x([0-9a-f]{8})$", re.M)


def sh(cmd):
    return subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)


def measure(target):
    label = f"//{HW}/{target}"
    b = sh([os.path.join(REPO, "bazelisk.sh"), "build", label])
    if b.returncode != 0:
        sys.exit(f"build failed: {label}\n{b.stderr}")
    pkg, name = target.split(":")
    elf = os.path.join(REPO, "bazel-bin", HW, pkg, name + ".elf")
    stats, regs = os.path.join(HERE, "_stats.txt"), os.path.join(HERE, "_regs.txt")
    r = sh([sys.executable, STANDALONE,
            elf, "--pqc", "1", "--dump-stats", stats, "--dump-regs", regs])
    if r.returncode != 0:
        sys.exit(f"sim failed: {label}\n{r.stderr}")
    n = cycles(label, open(stats).read(), open(regs).read())
    os.remove(stats)
    os.remove(regs)
    return n


def cycles(label, stats_text, regs_text):
    """Cycles of a run without a simulator fault, from its statistics and register dumps."""
    m, errs = _STAT.search(stats_text), _ERR.findall(regs_text)
    if not m:
        sys.exit(f"no execution summary: {label}")
    # An ILLEGAL_INSN trap exits 0 and still writes a well-formed summary, so
    # the return code proves nothing; ERR_BITS is the tell: exactly one
    # complete line, all zero. (The ISE runs are 18 and 19 cycles long, so a
    # cycle count cannot be.)
    if len(errs) != 1 or int(errs[0], 16):
        sys.exit(f"{label}: ERR_BITS {errs or 'missing'}: a trapped run, not a measurement")
    return int(m.group(2))


def anchor():
    commit = sh(["git", "rev-parse", "--short", "HEAD"]).stdout.strip()
    dirty = "-dirty" if sh(["git", "status", "--porcelain"]).stdout.strip() else ""
    return commit + dirty


def main():
    rows = []
    for variant, op, target, setup_t, nbytes, datapath in TARGETS:
        run = measure(target)
        setup = measure(setup_t)
        cyc = run - setup
        rows.append(dict(variant=variant, op=op, target=target, bytes=nbytes,
                         datapath=datapath, cycles=cyc, setup=setup,
                         cyc_per_byte=(cyc / nbytes if nbytes else None)))

    ks = {r["variant"]: r for r in rows if r["op"] == "keyschedule"}
    enc = {r["variant"]: r for r in rows if r["op"] == "encrypt"}
    order = ["ISE", "compute-GF", "T-table"]

    print(f"\nACC AES-128 cycle comparison  (ACCSim cycles, --pqc 1, commit {anchor()})")
    print("op cyc = op-driver run - setup-only run (the AES work on its own).\n")

    print("Key schedule  (16 B key -> 11 round keys)")
    print(f"  {'variant':<12}{'op cyc':>8}")
    for v in order:
        print(f"  {v:<12}{ks[v]['cycles']:>8}")

    print("\nEncryption  (round keys resident)")
    print(f"  {'variant':<12}{'bytes/call':>11}{'datapath':>20}{'op cyc':>8}{'cyc/byte':>10}{'cyc/16B':>9}")
    base = enc["ISE"]["cyc_per_byte"]
    for v in order:
        e = enc[v]
        print(f"  {v:<12}{e['bytes']:>11}{e['datapath']:>20}{e['cycles']:>8}"
              f"{e['cyc_per_byte']:>10.2f}{e['cyc_per_byte']*16:>9.0f}")
    print("\n  encryption cost vs ISE (cycles/byte):")
    for v in order:
        rel = enc[v]["cyc_per_byte"] / base
        print(f"    {v:<12}{'1x (ISE)' if v == 'ISE' else f'{rel:.1f}x slower':>12}")

    setups = sorted({r["setup"] for r in rows})
    print(f"\nSetup (operand/constant load) is a separate fixed {setups[0]}-{setups[-1]} cyc per")
    print("call site, not part of the op cost above.")
    print("Notes: the T-table does data-dependent loads (not SCA-equivalent) and costs 4 KiB of")
    print("  constant table; ISE/compute-GF exploit the 256-bit datapath (dual-block).")

    out = os.path.join(HERE, "aes_compare.csv")
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["variant", "op", "bytes_per_call", "datapath",
                    "op_cycles", "setup_cycles", "cycles_per_byte", "commit"])
        anc = anchor()
        for r in rows:
            w.writerow([r["variant"], r["op"], r["bytes"] or "", r["datapath"],
                        r["cycles"], r["setup"],
                        f"{r['cyc_per_byte']:.3f}" if r["cyc_per_byte"] else "", anc])
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
