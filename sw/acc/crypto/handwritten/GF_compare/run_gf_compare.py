#!/usr/bin/env python3
"""Reproducible cycle comparison of the GF-multiply implementations on ACC.

Measures one vector x scalar GF multiply per variant and prints a table plus a
CSV. Companion to AES_compare/ - together they quantify what the two PQC
instruction families (bn.aes128, bn.gfmul) buy over software.

Variants (all produce one 256-bit WDR = vector x scalar):
  GF16  HW   bn.gfmul.4            64 GF(2^4) elements, one instruction
  GF16  SW   gf16_mul             64 nibbles, shift/xor (no mul instruction)
  GF256 HW   bn.gfmul.8           32 GF(2^8) elements, one instruction
  GF256 SW   gf256_mul            32 bytes, shift/xor
  GF256 SW   gf256_mul_pqc        32 bytes, bn.mulv.l-accelerated software

Each number is a standalone ACCSim run (load operands -> one op/call -> halt).
Data-independent ops, so operand values do not affect the cycle count.

Reproduce (from the repo root):
    python3 \\
        sw/acc/crypto/handwritten/GF_compare/run_gf_compare.py

Writes gf_compare.csv next to this script.
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

# field, impl, kind, op-driver target, setup-baseline target, elements/op.
# Op cost = op-driver run - setup-only baseline run. Each op driver is its
# baseline plus exactly one multiply, so the subtraction isolates the op. The
# setup cost (operand load + mod-CSR config) is reported as its own number -
# a fixed per-call-site overhead to note, not part of the op.
TARGETS = [
    ("GF16",  "bn.gfmul.4",    "HW", "gf16:gf16_gfmul_op_test",     "gf16:gf16_setup_hw_test",   64),
    ("GF16",  "gf16_mul",      "SW", "gf16:gf16_mul_op_test",       "gf16:gf16_setup_sw_test",   64),
    ("GF256", "bn.gfmul.8",    "HW", "gf256:gf256_gfmul_op_test",   "gf256:gf256_setup_hw_test", 32),
    ("GF256", "gf256_mul",     "SW", "gf256:gf256_mul_op_test",     "gf256:gf256_setup_sw_test", 32),
    ("GF256", "gf256_mul_pqc", "SW", "gf256:gf256_mul_pqc_op_test", "gf256:gf256_setup_sw_test", 32),
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
    # a trap exits 0 and still writes a summary; ERR_BITS tells: exactly one complete line, all zero
    if len(errs) != 1 or int(errs[0], 16):
        sys.exit(f"{label}: ERR_BITS {errs or 'missing'}: a trapped run, not a measurement")
    return int(m.group(2))


def anchor():
    commit = sh(["git", "rev-parse", "--short", "HEAD"]).stdout.strip()
    dirty = "-dirty" if sh(["git", "status", "--porcelain"]).stdout.strip() else ""
    return commit + dirty


def main():
    rows = []
    for field, impl, kind, op_t, setup_t, elems in TARGETS:
        op_run = measure(op_t)
        setup = measure(setup_t)
        op = op_run - setup
        rows.append(dict(field=field, impl=impl, kind=kind, elems=elems,
                         setup=setup, op=op, cyc_per_elem=op / elems))

    print(f"\nACC GF-multiply cycle comparison  (ACCSim cycles, --pqc 1, commit {anchor()})")
    print("op cyc = op-driver run - setup-only run (the multiply on its own).\n")
    print(f"  {'field':<7}{'impl':<16}{'':<4}{'op cyc':>7}{'cyc/elem':>10}{'  vs HW':>12}")
    for f in ("GF16", "GF256"):
        hw = next(r for r in rows if r["field"] == f and r["kind"] == "HW")
        for r in [x for x in rows if x["field"] == f]:
            speed = "1x (HW)" if r["kind"] == "HW" else f"{r['op']/hw['op']:.0f}x slower"
            print(f"  {r['field']:<7}{r['impl']:<16}{r['kind']:<4}"
                  f"{r['op']:>7.0f}{r['cyc_per_elem']:>10.3f}{speed:>12}")
    setups = sorted({r["setup"] for r in rows})
    print(f"\nOne HW instruction (~1 cyc) vs a 40-100 instruction software routine.")
    print(f"Setup (operand load + mod-CSR config) is a separate fixed {min(setups):.0f}-{max(setups):.0f} cyc,")
    print("paid once per call site, not per element; it is not part of the op cost.")
    print("SW paths data-independent.")

    out = os.path.join(HERE, "gf_compare.csv")
    with open(out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["field", "impl", "kind", "elements_per_op",
                    "op_cycles", "setup_cycles", "cycles_per_element", "commit"])
        anc = anchor()
        for r in rows:
            w.writerow([r["field"], r["impl"], r["kind"], r["elems"],
                        f"{r['op']:.0f}", f"{r['setup']:.0f}",
                        f"{r['cyc_per_elem']:.4f}", anc])
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
