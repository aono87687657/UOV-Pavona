#!/usr/bin/env python3

"""
Shared Hash Salted Message Test Utilities

Common logic for testing SHAKE256(message || salt) on the ACC simulator.

The ACC assembly reads RND once to obtain a 16-byte salt, appends it to the
message, and feeds the result into KMAC/SHAKE256.  The test scripts inject a
random message, run the simulation, then compare the WDR output against a
Python reference hash (hashlib.shake_256).

Key differences between parameter sets:
  Is: 32-byte output from W30 only
  Ip: 44-byte output from W29+W30 (64 bytes extracted, trailing 20 must be 0)
"""

import argparse
import random
from hashlib import shake_256
from typing import Optional, TextIO, Tuple

from dmem_utils import (
    bytes_to_dmem_words,
    validate_bytes,
)

from acc_sim_utils import (
    run_acc_test,
    print_test_header,
    read_wdr_register,
    run_acc_test_iteration,
    print_test_summary,
)

from ov_params import OVParams

# WDR width in bytes (256 bits). Used when serialising a single WDR readout
# via .to_bytes() and when slicing message previews to one wide-register row.
_WDR_BYTES = 32


# ------------------------------------------------------------------ #
#  Known simulator salt constants
# ------------------------------------------------------------------ #
# The ACC standalone simulator provides deterministic RND output instead
# of true randomness.  It cycles through two hard-coded 256-bit constants
# using itertools.cycle:
#   _TEST_RND_DATA = cycle([
#     0xAAAAAAAA_99999999_AAAAAAAA_99999999_AAAAAAAA_99999999_AAAAAAAA_99999999,
#     0xCCCCCCCC_BBBBBBBB_CCCCCCCC_BBBBBBBB_CCCCCCCC_BBBBBBBB_CCCCCCCC_BBBBBBBB,
#   ])
# The test assembly reads RND once for the 16-byte salt, so depending on
# which cycle fires we get one of two known salt values.
SALT_1 = bytes.fromhex('BBBBBBBBCCCCCCCCBBBBBBBBCCCCCCCC')
SALT_2 = bytes.fromhex('99999999AAAAAAAA99999999AAAAAAAA')


# ------------------------------------------------------------------ #
#  Argument parser
# ------------------------------------------------------------------ #

def create_hash_argparser(params: OVParams) -> argparse.ArgumentParser:
    """
    Create an argparser with --start, --end, --quick, --elf, --dump-regs,
    --dump-stats, and --verbose flags.

    Args:
        params: OVParams instance (used for default ELF path).

    Returns:
        Configured ArgumentParser.
    """
    parser = argparse.ArgumentParser(
        description='Test KMAC SHAKE256 implementation')
    parser.add_argument(
        '--elf', type=str, default=params.default_hash_elf,
        help=f'Path to ACC ELF file (default: {params.default_hash_elf})')
    parser.add_argument(
        '--start', type=int, default=0,
        help='Starting message length (default: 0)')
    parser.add_argument(
        '--end', type=int, default=5,
        help='Ending message length (default: 5)')
    parser.add_argument(
        '--verbose', action='store_true',
        help='Print verbose output')
    parser.add_argument(
        '--quick', action='store_true',
        help='Quick test mode (boundary cases only)')
    parser.add_argument(
        '--dump-regs', metavar="FILE",
        type=argparse.FileType('w'),
        help=("after execution, write the GPR and WDR contents to this file. "
              "Use '-' to write to STDOUT."))
    parser.add_argument(
        '--dump-stats', metavar="FILE",
        type=argparse.FileType('w'),
        help=("after execution, write execution statistics to this file. "
              "Use '-' to write to STDOUT."))
    return parser


# ------------------------------------------------------------------ #
#  Reference hash
# ------------------------------------------------------------------ #

def compute_shake256_reference(
    message: bytes,
    salt: bytes,
    output_size: int,
) -> bytes:
    """
    Compute SHAKE256(message || salt) with the given output size.

    Args:
        message:     Message bytes.
        salt:        16-byte salt.
        output_size: Number of output bytes (e.g. 32 for Is, 44 for Ip).

    Returns:
        Digest of *output_size* bytes.
    """
    hasher = shake_256()
    hasher.update(message)
    hasher.update(salt)
    return hasher.digest(output_size)


# ------------------------------------------------------------------ #
#  DMEM injection
# ------------------------------------------------------------------ #

def _build_hash_test_words(
    message: bytes,
    msg_len: int,
    params: OVParams,
) -> dict:
    """Build DMEM word dict for message length and message bytes.

    Returns:
        Dict mapping DMEM word addresses to 32-bit values.
    """
    words = {params.hash_msg_len_addr: msg_len}

    if len(message) > 0:
        msg_words = bytes_to_dmem_words(bytearray(message),
                                        params.hash_msg_addr)
        words.update(msg_words)

    return words


# ------------------------------------------------------------------ #
#  WDR extraction helpers
# ------------------------------------------------------------------ #

def _extract_digest_is(sim) -> bytes:
    """Extract 32-byte digest from W30 (Is variant)."""
    w30_value = read_wdr_register(sim, 30)
    return w30_value.to_bytes(_WDR_BYTES, byteorder='little')


def _extract_digest_ip(sim) -> bytes:
    """Extract full 64 bytes from W29+W30 (Ip variant).

    W29 holds the first 32 bytes; W30 holds the next 32 bytes.
    The caller validates that bytes [44:64] are zero.
    """
    w29_value = read_wdr_register(sim, 29)
    w29_bytes = w29_value.to_bytes(_WDR_BYTES, byteorder='little')
    w30_value = read_wdr_register(sim, 30)
    w30_bytes = w30_value.to_bytes(_WDR_BYTES, byteorder='little')
    return w29_bytes + w30_bytes


# ------------------------------------------------------------------ #
#  Salt detection
# ------------------------------------------------------------------ #

def _detect_salt_is(sim) -> bytes:
    """Detect salt from W1 lower 128 bits (Is variant)."""
    w1_value = sim.state.wdrs.get_reg(1).read_unsigned()
    actual_salt = (w1_value & ((1 << 128) - 1)).to_bytes(16, byteorder='little')
    print(f"  Salt from W1: {actual_salt.hex()}")
    return actual_salt


def _detect_salt_ip(sim, predicted_salt: bytes) -> bytes:
    """Detect salt from W1/W2 pattern matching (Ip variant).

    Checks both W1 and W2 for characteristic hex patterns:
      CYCLE_1 ('cc'/'bb') -> SALT_1
      CYCLE_2 ('aa'/'99') -> SALT_2

    Falls back to *predicted_salt* if no pattern is recognised.
    """
    try:
        w1_value = sim.state.wdrs.get_reg(1).read_unsigned()
        w2_value = sim.state.wdrs.get_reg(2).read_unsigned()
        w1_hex = w1_value.to_bytes(_WDR_BYTES, byteorder='little').hex()
        w2_hex = w2_value.to_bytes(_WDR_BYTES, byteorder='little').hex()

        if 'cc' in w1_hex or 'bb' in w1_hex or 'cc' in w2_hex or 'bb' in w2_hex:
            print(f"  Detected CYCLE_1 pattern (cc/bb)")
            return SALT_1
        elif 'aa' in w1_hex or '99' in w1_hex or 'aa' in w2_hex or '99' in w2_hex:
            print(f"  Detected CYCLE_2 pattern (aa/99)")
            return SALT_2
        else:
            print(f"  Warning: No known pattern detected, using predicted salt")
            return predicted_salt
    except Exception as e:
        print(f"  Warning: Could not read W1/W2 values: {e}")
        return predicted_salt


# ------------------------------------------------------------------ #
#  Single-length test
# ------------------------------------------------------------------ #

def run_hash_salted_msg_test(
    msg_len: int,
    elf_path: str,
    params: OVParams,
    iteration_num: int,
    verbose: bool = False,
    dump_regs_file: Optional[TextIO] = None,
    dump_stats_file: Optional[TextIO] = None,
) -> bool:
    """
    Run one SHAKE256 test for a specific message length.

    Args:
        msg_len:         Number of message bytes.
        elf_path:        Path to ACC ELF.
        params:          OVParams for the variant (Is or Ip).
        iteration_num:   Iteration index (0-based, determines RND cycle prediction).
        verbose:         Print extra information.
        dump_regs_file:  Optional file for register dump.
        dump_stats_file: Optional file for statistics dump.

    Returns:
        True if the test passed.
    """
    # Generate random message
    message = bytes([random.randint(0, 255) for _ in range(msg_len)])

    if verbose:
        print(f"  Message length: {msg_len} bytes")
        print(f"  Message (first {_WDR_BYTES} bytes): {message[:_WDR_BYTES].hex()}")

    # Run ACC simulation
    words = _build_hash_test_words(message, msg_len, params)

    success, dmem_bytes, sim = run_acc_test(
        elf_path=elf_path,
        dmem_words=words,
        verbose=False,
        dump_regs_file=dump_regs_file,
        dump_stats_file=dump_stats_file,
    )

    if not success:
        print(f"  ✗ ACC execution failed")
        return False

    # ---- Is variant: 32-byte digest from W30 ----
    if params.pub_m_byte_padded == params.pub_m_byte and params.pub_m_byte == 32:
        try:
            actual_digest = _extract_digest_is(sim)
        except Exception as e:
            print(f"  ✗ Failed to extract digest: {e}")
            return False

        actual_salt = _detect_salt_is(sim)
        expected_digest = compute_shake256_reference(
            message, actual_salt, params.pub_m_byte)

        print(f"  Expected digest: {expected_digest.hex()}")
        print(f"  W30 digest:      {actual_digest.hex()}")

        if verbose:
            print(f"  Actual digest:   {actual_digest.hex()}")

        ok, _ = validate_bytes(expected_digest, actual_digest,
                               f"Digest (len={msg_len})")
        return ok

    # ---- Ip variant: 44-byte digest + 20 zero-padding from W29+W30 ----
    else:
        try:
            actual_full = _extract_digest_ip(sim)
        except Exception as e:
            print(f"  ✗ Failed to extract digest: {e}")
            return False

        # Predict salt from iteration number, then detect from registers
        predicted_salt = SALT_1 if (iteration_num % 2 == 0) else SALT_2
        actual_salt = _detect_salt_ip(sim, predicted_salt)

        expected_digest = compute_shake256_reference(
            message, actual_salt, params.pub_m_byte)

        # Build full 64-byte expected: 44-byte digest + 20 zero-padding
        padding_len = params.pub_m_byte_padded - params.pub_m_byte
        expected_full = expected_digest + bytes(padding_len)

        print(f"  Expected digest ({params.pub_m_byte}B): {expected_digest.hex()}")
        print(f"  W29+W30 ({params.pub_m_byte_padded}B):        {actual_full.hex()}")
        print(f"  Trailing {padding_len} bytes:    {actual_full[params.pub_m_byte:].hex()}")

        ok, _ = validate_bytes(expected_full, actual_full,
                               f"Digest+padding (len={msg_len})")
        return ok


# ------------------------------------------------------------------ #
#  Range test
# ------------------------------------------------------------------ #

def run_hash_range_test(
    elf_path: str,
    params: OVParams,
    start: int,
    end: int,
    verbose: bool = False,
    dump_regs_file: Optional[TextIO] = None,
    dump_stats_file: Optional[TextIO] = None,
) -> Tuple[int, int]:
    """
    Test message lengths from *start* to *end* (inclusive).

    Args:
        elf_path:        Path to ACC ELF.
        params:          OVParams for the variant.
        start:           Starting message length.
        end:             Ending message length (inclusive).
        verbose:         Print extra information.
        dump_regs_file:  Optional file for register dump.
        dump_stats_file: Optional file for statistics dump.

    Returns:
        (total_tests, passed_tests)
    """
    total = 0
    passed = 0

    for iteration_num, msg_len in enumerate(range(start, end + 1)):
        def test_iteration(
            _msg_len=msg_len,
            _iter=iteration_num,
        ):
            return run_hash_salted_msg_test(
                _msg_len, elf_path, params, _iter,
                verbose, dump_regs_file, dump_stats_file)

        if run_acc_test_iteration(test_iteration, iteration_num):
            passed += 1
        total += 1

    return (total, passed)


# ------------------------------------------------------------------ #
#  Main driver (called by thin wrappers)
# ------------------------------------------------------------------ #

# Quick-mode boundary lengths shared by both variants.
QUICK_TEST_LENGTHS = [
    0, 1, 15, 16, 17, 31, 32, 33,
    63, 64, 65, 127, 128, 129, 255, 256, 257,
]


def run_hash_test_main(params: OVParams, suite_label: str) -> int:
    """
    Entry-point driver for a hash salted-message test script.

    Parses CLI arguments, prints header, runs either quick or range
    mode, and prints the summary.

    Args:
        params:       OVParams for the variant.
        suite_label:  Human-readable label for the summary line
                      (e.g. "KMAC SHAKE256 (Is)").

    Returns:
        Exit code (0 = all passed, 1 = some failed).
    """
    parser = create_hash_argparser(params)
    args = parser.parse_args()

    print_test_header("KMAC SHAKE256 Test Suite")
    print(f"ELF: {args.elf}")
    print(f"Salt (Cycle 1): {SALT_1.hex()}")
    print(f"Salt (Cycle 2): {SALT_2.hex()}")

    dump_regs = getattr(args, 'dump_regs', None)
    dump_stats = getattr(args, 'dump_stats', None)

    if args.quick:
        print("\nQuick test mode: testing boundary cases")
        total = 0
        passed = 0

        for iteration_num, msg_len in enumerate(QUICK_TEST_LENGTHS):
            def test_iteration(
                _msg_len=msg_len,
                _iter=iteration_num,
            ):
                return run_hash_salted_msg_test(
                    _msg_len, args.elf, params, _iter,
                    args.verbose, dump_regs, dump_stats)

            if run_acc_test_iteration(test_iteration, iteration_num):
                passed += 1
            total += 1
    else:
        print(f"\nTesting message lengths: {args.start} to {args.end}")
        total, passed = run_hash_range_test(
            args.elf, params, args.start, args.end,
            args.verbose, dump_regs, dump_stats)

    print_test_summary(passed, total, suite_label)
    return 0 if passed == total else 1
