#!/usr/bin/env python3
"""
Verify gf16_mul correctness against galois library.

For each iteration:
  1. Generate random 32-byte vector (val_a = 64 GF(16) nibbles) and random scalar (0-15)
  2. Compute expected result: for each nibble, expected[i] = GF16(a[i]) * GF16(b)
  3. Run gf16_mul on ACC ISS -> compare with expected

Usage:
  # Build ELF first:
  ./bazelisk.sh build //sw/acc/crypto/handwritten/gf16:gf16_mul_rand_test

  # Run verification (from repo root):
  python3 sw/acc/crypto/handwritten/gf16/test_scripts/gf16_mul_verify.py
  python3 sw/acc/crypto/handwritten/gf16/test_scripts/gf16_mul_verify.py --iterations 100 --seed 42
"""

import os
import random
import sys

# --- Path setup (canonical) ---
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_SCRIPT_DIR, *['..'] * 6)))
sys.path.insert(0, os.path.abspath(os.path.join(_SCRIPT_DIR, '..', '..', 'own_utils')))

from acc_sim_utils import (
    run_acc_test, read_wdr_register,
    create_common_argparser, run_test_suite,
)
from dmem_utils import bytes_to_dmem_words, validate_bytes
from gf_arithmetic import gf16_mul_reference

# DMEM addresses (must match assembly harness)
ADDR_VAL_A    = 0x000
ADDR_VAL_B    = 0x020
ADDR_MSB_MASK = 0x040

# Default ELF path (relative to workspace root)
_WORKSPACE_ROOT = os.path.abspath(os.path.join(_SCRIPT_DIR, *['..'] * 6))
DEFAULT_ELF = "bazel-bin/sw/acc/crypto/handwritten/gf16/gf16_mul_rand_test.elf"


def compute_expected(val_a: bytearray, scalar: int) -> bytearray:
    """Compute expected GF(16) element-wise product using galois library."""
    result = bytearray(32)
    for i in range(32):
        lo = val_a[i] & 0x0F
        hi = (val_a[i] >> 4) & 0x0F
        res_lo = gf16_mul_reference(lo, scalar)
        res_hi = gf16_mul_reference(hi, scalar)
        result[i] = (res_hi << 4) | res_lo
    return result


def build_injection_words(val_a: bytearray, scalar: int) -> dict:
    """Build DMEM word dict for gf16_mul test."""
    val_b_bytes = bytearray([scalar] + [0] * 31)
    msb_mask_bytes = bytearray([0x88] * 32)

    words = {}
    words.update(bytes_to_dmem_words(bytearray(val_a), ADDR_VAL_A))
    words.update(bytes_to_dmem_words(val_b_bytes, ADDR_VAL_B))
    words.update(bytes_to_dmem_words(msb_mask_bytes, ADDR_MSB_MASK))
    return words


def main():
    parser = create_common_argparser(
        description="GF16 Multiply Verification (galois reference)",
        default_elf=DEFAULT_ELF,
        default_iterations=10,
    )
    args = parser.parse_args()

    elf_path = os.path.join(_WORKSPACE_ROOT, args.elf) if not os.path.isabs(args.elf) else args.elf

    def test_func(iteration_num, regs_file, stats_file):
        val_a = bytearray(random.getrandbits(8) for _ in range(32))
        scalar = random.randint(0, 15)
        print(f"  scalar b = 0x{scalar:x}")

        expected = compute_expected(val_a, scalar)

        words = build_injection_words(val_a, scalar)
        success, dmem, sim = run_acc_test(
            elf_path, pqc=False, verbose=args.verbose,
            dump_regs_file=regs_file, dump_stats_file=stats_file,
            dmem_words=words,
        )
        if not success:
            print(f"  [gf16_mul] Simulation FAILED (ecall / ERR_BITS error)")
            return False

        w0 = read_wdr_register(sim, 0)
        result = bytearray(w0.to_bytes(32, byteorder='little'))

        ok, _ = validate_bytes(expected, result, data_name="gf16_mul")
        return ok

    return run_test_suite(
        test_name="GF16 Multiply Verification",
        test_func=test_func,
        elf_path=elf_path,
        iterations=args.iterations,
        output_dir=args.output_dir,
        seed=args.seed,
    )


if __name__ == "__main__":
    sys.exit(main())
