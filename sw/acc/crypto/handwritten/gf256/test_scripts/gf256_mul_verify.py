#!/usr/bin/env python3
"""
Verify gf256_mul and gf256_mul_pqc correctness against galois library.

For each iteration:
  1. Generate random 32-byte vector (val_a) and random scalar (val_b)
  2. Compute expected result: for each byte, expected[i] = GF256(a[i]) * GF256(b)
  3. Run gf256_mul on ACC ISS -> compare with expected
  4. Run gf256_mul_pqc on ACC ISS -> compare with expected
  5. Cross-check: both ISS results must be identical

Usage:
  # Build ELFs first:
  ./bazelisk.sh build //sw/acc/crypto/handwritten/gf256:gf256_mul_rand_test
  ./bazelisk.sh build //sw/acc/crypto/handwritten/gf256:gf256_mul_pqc_rand_test

  # Run verification (from repo root):
  python3 sw/acc/crypto/handwritten/gf256/test_scripts/gf256_mul_verify.py
  python3 sw/acc/crypto/handwritten/gf256/test_scripts/gf256_mul_verify.py --iterations 100 --seed 42
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
from gf_arithmetic import gf256_mul_reference

# DMEM addresses (must match assembly harness)
ADDR_VAL_A    = 0x000
ADDR_VAL_B    = 0x020
ADDR_MSB_MASK = 0x040

# Default ELF paths (relative to workspace root)
_WORKSPACE_ROOT = os.path.abspath(os.path.join(_SCRIPT_DIR, *['..'] * 6))
DEFAULT_ELF     = "bazel-bin/sw/acc/crypto/handwritten/gf256/gf256_mul_rand_test.elf"
DEFAULT_ELF_PQC = "bazel-bin/sw/acc/crypto/handwritten/gf256/gf256_mul_pqc_rand_test.elf"


def compute_expected(val_a: bytearray, scalar: int) -> bytearray:
    """Compute expected GF(256) element-wise product using galois library."""
    return bytearray(gf256_mul_reference(val_a[i], scalar) for i in range(32))


def build_injection_words(val_a: bytearray, scalar: int) -> dict:
    """Build DMEM word dict for gf256_mul test."""
    val_b_bytes = bytearray([scalar] + [0] * 31)
    msb_mask_bytes = bytearray([0x80] * 32)

    words = {}
    words.update(bytes_to_dmem_words(bytearray(val_a), ADDR_VAL_A))
    words.update(bytes_to_dmem_words(val_b_bytes, ADDR_VAL_B))
    words.update(bytes_to_dmem_words(msb_mask_bytes, ADDR_MSB_MASK))
    return words


def run_single_variant(elf_path, val_a, scalar, expected, pqc, name, verbose,
                       regs_file=None, stats_file=None):
    """Run one ELF variant and validate against expected. Returns (ok, result_bytes)."""
    words = build_injection_words(val_a, scalar)
    success, dmem, sim = run_acc_test(
        elf_path, pqc=pqc, verbose=verbose,
        dump_regs_file=regs_file, dump_stats_file=stats_file,
        dmem_words=words,
    )
    if not success:
        print(f"  [{name}] Simulation FAILED (ecall / ERR_BITS error)")
        return False, bytearray(32)

    w0 = read_wdr_register(sim, 0)
    result = bytearray(w0.to_bytes(32, byteorder='little'))

    ok, _ = validate_bytes(expected, result, data_name=name)
    return ok, result


def main():
    parser = create_common_argparser(
        description="GF256 Multiply Verification (galois reference)",
        default_elf=DEFAULT_ELF,
        default_iterations=10,
    )
    parser.add_argument(
        '--elf-pqc', type=str, default=DEFAULT_ELF_PQC,
        help=f'Path to PQC variant ELF (default: {DEFAULT_ELF_PQC})',
    )
    parser.add_argument(
        '--skip-original', action='store_true',
        help='Skip gf256_mul (original) tests, only test PQC variant',
    )
    parser.add_argument(
        '--skip-pqc', action='store_true',
        help='Skip gf256_mul_pqc tests, only test original',
    )
    args = parser.parse_args()

    elf_path = os.path.join(_WORKSPACE_ROOT, args.elf) if not os.path.isabs(args.elf) else args.elf
    elf_pqc_path = os.path.join(_WORKSPACE_ROOT, args.elf_pqc) if not os.path.isabs(args.elf_pqc) else args.elf_pqc
    test_original = not args.skip_original
    test_pqc = not args.skip_pqc

    def test_func(iteration_num, regs_file, stats_file):
        val_a = bytearray(random.getrandbits(8) for _ in range(32))
        scalar = random.randint(0, 255)
        print(f"  scalar b = 0x{scalar:02x}")

        expected = compute_expected(val_a, scalar)
        iteration_ok = True

        result_orig = None
        result_pqc = None

        # Test original gf256_mul
        if test_original:
            ok, result_orig = run_single_variant(
                elf_path, val_a, scalar, expected,
                pqc=False, name="gf256_mul", verbose=args.verbose,
                regs_file=regs_file, stats_file=stats_file,
            )
            if not ok:
                iteration_ok = False

        # Test PQC variant
        if test_pqc:
            ok, result_pqc = run_single_variant(
                elf_pqc_path, val_a, scalar, expected,
                pqc=True, name="gf256_mul_pqc", verbose=args.verbose,
            )
            if not ok:
                iteration_ok = False

        # Cross-check: only if both ran and both produced results
        if test_original and test_pqc and result_orig is not None and result_pqc is not None:
            if result_orig != result_pqc:
                print(f"  [CROSS-CHECK] gf256_mul != gf256_mul_pqc!")
                iteration_ok = False
            elif args.verbose:
                print(f"  [CROSS-CHECK] OK (both implementations agree)")

        return iteration_ok

    # Validate that at least one ELF exists before entering the suite.
    # run_test_suite validates the primary ELF; we check the PQC one here.
    if test_pqc and not os.path.exists(elf_pqc_path):
        print(f"Error: PQC ELF not found: {elf_pqc_path}")
        print("Build it first: ./bazelisk.sh build "
              "//sw/acc/crypto/handwritten/gf256:gf256_mul_pqc_rand_test")
        return 1

    # Use original ELF as the primary; if skipped, use the PQC ELF for validation.
    primary_elf = elf_path if test_original else elf_pqc_path

    return run_test_suite(
        test_name="GF256 Multiply Verification",
        test_func=test_func,
        elf_path=primary_elf,
        iterations=args.iterations,
        output_dir=args.output_dir,
        seed=args.seed,
    )


if __name__ == "__main__":
    sys.exit(main())
