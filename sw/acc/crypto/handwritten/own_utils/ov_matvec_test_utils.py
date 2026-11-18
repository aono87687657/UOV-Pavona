#!/usr/bin/env python3

"""
Shared Matvec Test Utilities for OV Sign

Provides common logic for both small matvec (WDR result) and large matvec
(DMEM result) test scripts.  Each concrete test script becomes a thin wrapper
that selects an OVParams variant and calls one of the two entry points here.

Small matvec (WDR result):
  - Is: result in w7+w8  (64 bytes; upper 128 bits of w8 must be zero)
  - Ip: result in w28+w29+w30 (96 bytes; also cross-checks DMEM accumulator)

Large matvec (DMEM result):
  - Parameters (n_a_byte, width) injected at param addresses in DMEM
  - Result validated from DMEM accumulator region

Last updated: 2026-06-10 — replaced local _add_dump_args with shared add_dump_args
imported from acc_sim_utils.
"""

import os
import sys
import random
from typing import Dict, Optional, Tuple, TextIO

# ---------------------------------------------------------------------------
#  Imports from own_utils (always on sys.path when callers set it up)
# ---------------------------------------------------------------------------
from dmem_utils import (
    extract_bytes_from_dmem,
    validate_bytes,
)
from acc_sim_utils import (
    run_acc_test,
    read_wdr_register,
    create_common_argparser,
    print_test_summary,
    add_dump_args,
)
from gf_arithmetic import (
    generate_random_gf_matrix,
    generate_random_gf_vector,
    gf_matrix_to_dmem_words,
    gf_vector_to_dmem_words,
    compute_gf_matvec_reference,
    gf_elements_to_bytes,
)
from ov_params import OVParams


###############################################################################
# Data generation
###############################################################################

def generate_random_matrix_vector(rows: int, cols: int, gf: int):
    """
    Generate a random column-major matrix and matching vector.

    Args:
        rows: Number of rows (GF elements per column).
        cols: Number of columns / vector length.
        gf:   16 or 256.

    Returns:
        (matrix, vector) where matrix is list-of-columns and vector is a list.
    """
    field = f"gf{gf}"
    matrix = generate_random_gf_matrix(rows=rows, cols=cols, field=field)
    vector = generate_random_gf_vector(length=cols, field=field)
    return matrix, vector


###############################################################################
# Reference computation
###############################################################################

def compute_matvec_reference(matrix, vector, params: OVParams):
    """
    Compute the reference matrix-vector product using pure-Python GF math.

    Returns:
        List of GF elements (the product vector).
    """
    field = f"gf{params.gf}"
    return compute_gf_matvec_reference(matrix, vector, field=field)


###############################################################################
# DMEM injection helpers
###############################################################################

def build_small_matvec_words(matrix, vector, params: OVParams) -> dict:
    """
    Build DMEM word dict for matrix and vector for a *small* matvec test.

    Uses params.small_matvec_matrix_addr and params.small_matvec_vector_addr.

    Returns:
        Dict mapping DMEM word addresses to 32-bit values.
    """
    field = f"gf{params.gf}"
    # Compute bytes_per_column from matrix shape
    num_rows = len(matrix[0]) if matrix else 0
    if params.gf == 16:
        bytes_per_col = (num_rows + 1) // 2
    else:
        bytes_per_col = num_rows

    matrix_words = gf_matrix_to_dmem_words(
        matrix, params.small_matvec_matrix_addr, bytes_per_col, field=field
    )
    vector_words = gf_vector_to_dmem_words(
        vector, params.small_matvec_vector_addr, field=field
    )
    words = {}
    words.update(matrix_words)
    words.update(vector_words)
    return words


def build_large_matvec_words(matrix, vector, params: OVParams) -> dict:
    """
    Build DMEM word dict for matrix, vector, and dimension parameters for a
    *large* matvec test.

    Uses params.large_matvec_* addresses; also writes n_a_byte and n_a_width.

    Returns:
        Dict mapping DMEM word addresses to 32-bit values.
    """
    field = f"gf{params.gf}"
    num_rows = len(matrix[0]) if matrix else 0
    if params.gf == 16:
        bytes_per_col = (num_rows + 1) // 2
    else:
        bytes_per_col = num_rows
    num_cols = len(matrix)

    matrix_words = gf_matrix_to_dmem_words(
        matrix, params.large_matvec_matrix_addr, bytes_per_col, field=field
    )
    vector_words = gf_vector_to_dmem_words(
        vector, params.large_matvec_vector_addr, field=field
    )
    words: Dict[int, int] = {
        params.large_matvec_n_a_byte_addr: bytes_per_col,
        params.large_matvec_n_a_width_addr: num_cols,
    }
    words.update(matrix_words)
    words.update(vector_words)
    return words


###############################################################################
# WDR result extraction
###############################################################################

def _wdr_name_to_index(name: str) -> int:
    """Convert 'w7' -> 7, 'w28' -> 28, etc."""
    assert name.startswith("w"), f"Invalid WDR name: {name}"
    return int(name[1:])


def extract_wdr_result(sim, wdr_names: Tuple[str, ...], total_bytes: int) -> bytearray:
    """
    Read consecutive WDR registers and concatenate into a byte array.

    Each WDR contributes 32 bytes (256 bits, little-endian).  The returned
    bytearray is exactly ``total_bytes`` long (which may be less than
    ``len(wdr_names) * 32`` -- the caller pads/truncates as needed for
    comparison).

    Args:
        sim:         Simulator instance (after execution).
        wdr_names:   Tuple of WDR names, e.g. ("w7", "w8") or ("w28","w29","w30").
        total_bytes: How many bytes to return (len(wdr_names)*32 by default).

    Returns:
        bytearray of length ``len(wdr_names) * 32`` (full WDR contents).
    """
    result = bytearray()
    for name in wdr_names:
        idx = _wdr_name_to_index(name)
        val = read_wdr_register(sim, idx)
        result.extend(val.to_bytes(32, 'little'))
    return result


###############################################################################
# Small matvec test
###############################################################################

def run_small_matvec_test(
    test_num: int,
    elf_path: str,
    params: OVParams,
    matrix=None,
    vector=None,
    output_dir: Optional[str] = None,
    verbose: bool = False,
    dump_regs_file: Optional[TextIO] = None,
    dump_stats_file: Optional[TextIO] = None,
) -> bool:
    """
    Run one iteration of a *small* matvec test (result in WDR registers).

    Handles:
      - Data generation (if matrix/vector not supplied)
      - DMEM injection
      - ACC execution
      - Reference computation
      - WDR result extraction and validation
      - Is-specific: upper 128 bits of last WDR must be zero
      - Ip-specific: cross-check against DMEM accumulator

    Returns:
        True if the test passed, False otherwise.
    """
    field = f"gf{params.gf}"
    wdr_names = params.small_matvec_result_wdrs
    # Matrix dimensions: v elements per column, o columns
    # Is: 96 elems/col (48 bytes/col), 64 cols
    # Ip: 68 elems/col (68 bytes/col), 44 cols
    rows_elem = params.v
    cols = params.o

    if matrix is None or vector is None:
        matrix, vector = generate_random_matrix_vector(rows_elem, cols, params.gf)

    print(f"\n========== TEST ITERATION {test_num + 1} ==========")

    # Injection
    words = build_small_matvec_words(matrix, vector, params)

    success, dmem_bytes, sim = run_acc_test(
        elf_path=elf_path,
        dmem_words=words,
        verbose=verbose,
        dump_regs_file=dump_regs_file,
        dump_stats_file=dump_stats_file,
    )

    if not success:
        print("Test failed during ACC execution")
        return False

    # Reference result
    expected_elements = compute_matvec_reference(matrix, vector, params)
    expected_bytes = gf_elements_to_bytes(expected_elements, field=field)

    # Total bytes covered by WDRs
    total_wdr_bytes = len(wdr_names) * 32
    # Zero-pad expected to full WDR span (this also validates upper zero bytes)
    expected_padded = expected_bytes + bytearray(total_wdr_bytes - len(expected_bytes))

    # Extract actual WDR result (full WDR contents)
    actual_bytes = extract_wdr_result(sim, wdr_names, total_wdr_bytes)

    # Determine result element count for display
    # Validate WDR result (includes upper-zero-bits check via padding)
    wdr_label = "+".join(wdr_names)
    wdr_success, wdr_mismatches = validate_bytes(
        expected_padded, actual_bytes,
        data_name=f"GF{params.gf} small matvec result ({wdr_label})"
    )

    overall_success = wdr_success

    # Ip-specific: cross-check DMEM accumulator
    if params.small_matvec_accum_addr != 0:
        dmem_result = bytearray(
            dmem_bytes[params.small_matvec_accum_addr:
                       params.small_matvec_accum_addr + total_wdr_bytes]
        )
        dmem_success, dmem_mismatches = validate_bytes(
            expected_padded, dmem_result,
            data_name=f"GF{params.gf} small matvec result (DMEM accumulator)"
        )
        overall_success = overall_success and dmem_success

    # Print summary
    status = "PASS" if overall_success else "FAIL"
    print(f"Test result: {status}")

    return overall_success


###############################################################################
# Large matvec test
###############################################################################

def run_large_matvec_test(
    test_num: int,
    elf_path: str,
    params: OVParams,
    rows: int,
    cols: int,
    matrix=None,
    vector=None,
    output_dir: Optional[str] = None,
    verbose: bool = False,
    dump_regs_file: Optional[TextIO] = None,
    dump_stats_file: Optional[TextIO] = None,
) -> bool:
    """
    Run one iteration of a *large* matvec test (result in DMEM accumulator).

    The caller must supply ``rows`` and ``cols`` because the large matvec
    dimensions differ from the core OV (v, o) parameters (e.g. 2048x96 for
    Is, 2816x68 for Ip).

    Returns:
        True if the test passed, False otherwise.
    """
    field = f"gf{params.gf}"

    # Determine element count for matrix generation
    if params.gf == 16:
        # rows is bytes_per_column; elements = rows * 2
        num_elements_per_col = rows * 2
    else:
        num_elements_per_col = rows

    if matrix is None or vector is None:
        matrix, vector = generate_random_matrix_vector(num_elements_per_col, cols, params.gf)

    print(f"\n========== TEST ITERATION {test_num + 1} ==========")

    # Injection
    words = build_large_matvec_words(matrix, vector, params)

    success, dmem_bytes, _sim = run_acc_test(
        elf_path=elf_path,
        dmem_words=words,
        verbose=verbose,
        dump_regs_file=dump_regs_file,
        dump_stats_file=dump_stats_file,
    )

    if not success:
        print("Test failed during ACC execution")
        return False

    # Reference result
    expected_elements = compute_matvec_reference(matrix, vector, params)
    expected_bytes = gf_elements_to_bytes(expected_elements, field=field)

    # Determine how many bytes to validate from DMEM
    if params.gf == 16:
        result_size_bytes = (num_elements_per_col + 1) // 2
    else:
        result_size_bytes = num_elements_per_col

    # For GF256 large matvec (Ip), the accumulator may be larger than the
    # logical result.  Pad expected to match allocated size if needed.
    # The GF256 2816x68 script uses ACCUMULATOR_ALLOCATED_SIZE = rows (2816),
    # since rows == bytes_per_column for GF256.
    if params.gf == 256:
        accum_size = rows  # accumulator allocated = bytes_per_column
        if accum_size > len(expected_bytes):
            expected_padded = expected_bytes + bytes(accum_size - len(expected_bytes))
        else:
            expected_padded = expected_bytes
        actual_bytes = extract_bytes_from_dmem(dmem_bytes, params.large_matvec_accum_addr, accum_size)
    else:
        expected_padded = expected_bytes
        actual_bytes = extract_bytes_from_dmem(dmem_bytes, params.large_matvec_accum_addr, result_size_bytes)

    # Validate
    match, mismatches = validate_bytes(
        expected_padded, actual_bytes,
        data_name=f"GF{params.gf} large matvec {rows}x{cols}"
    )

    status = "PASS" if match else "FAIL"
    print(f"Test result: {status}")

    return match


###############################################################################
# CLI main helpers (used by thin wrappers)
###############################################################################

def small_matvec_main(params: OVParams) -> int:
    """
    Standard main() for a small-matvec test wrapper.

    Parses CLI args, runs iterations, prints summary.
    Returns exit code (0 = all passed).
    """
    rows_elem = params.v
    cols = params.o
    if params.gf == 16:
        bytes_per_col = (rows_elem + 1) // 2
    else:
        bytes_per_col = rows_elem

    wdr_label = "+".join(params.small_matvec_result_wdrs)
    test_name = f"GF{params.gf} Small Matvec {bytes_per_col}x{cols}"

    parser = create_common_argparser(
        description=f'ACC {test_name} Tester',
        default_elf=params.default_small_matvec_elf,
        default_iterations=1,
    )
    add_dump_args(parser)
    args = parser.parse_args()

    elf_path = os.path.abspath(args.elf)
    if not os.path.isfile(elf_path):
        print(f"Error: ELF file '{elf_path}' not found", file=sys.stderr)
        return 1

    if args.seed is not None:
        random.seed(args.seed)
        print(f"Using random seed: {args.seed}")

    print("=" * 60)
    print(test_name)
    print("=" * 60)
    print(f"ELF File: {elf_path}")
    print(f"Matrix: {rows_elem} elements/col x {cols} cols ({bytes_per_col} bytes/col)")
    print(f"Result WDRs: {wdr_label}")
    print(f"Iterations: {args.iterations}")
    print("=" * 60)

    passed = 0
    for i in range(args.iterations):
        matrix, vector = generate_random_matrix_vector(rows_elem, cols, params.gf)
        ok = run_small_matvec_test(
            test_num=i,
            elf_path=elf_path,
            params=params,
            matrix=matrix,
            vector=vector,
            output_dir=args.output_dir,
            verbose=args.verbose,
            dump_regs_file=getattr(args, 'dump_regs', None),
            dump_stats_file=getattr(args, 'dump_stats', None),
        )
        if ok:
            passed += 1

    print_test_summary(passed, args.iterations, test_name)
    return 0 if passed == args.iterations else 1


def large_matvec_main(params: OVParams, rows: int, cols: int) -> int:
    """
    Standard main() for a large-matvec test wrapper.

    ``rows`` / ``cols`` are the physical matrix dimensions (bytes_per_column
    and number of columns), since these differ from the core OV (v, o) params.
    Returns exit code (0 = all passed).
    """
    test_name = f"GF{params.gf} Large Matvec {rows}x{cols}"

    parser = create_common_argparser(
        description=f'ACC {test_name} Tester',
        default_elf=params.default_large_matvec_elf,
        default_iterations=1,
    )
    add_dump_args(parser)
    args = parser.parse_args()

    elf_path = os.path.abspath(args.elf)
    if not os.path.isfile(elf_path):
        print(f"Error: ELF file '{elf_path}' not found", file=sys.stderr)
        return 1

    if args.seed is not None:
        random.seed(args.seed)
        print(f"Using random seed: {args.seed}")

    output_dir = args.output_dir
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    print("=" * 60)
    print(test_name)
    print("=" * 60)
    print(f"ELF File: {elf_path}")
    print(f"Matrix: {rows} rows x {cols} cols")
    print(f"Iterations: {args.iterations}")
    print("=" * 60)

    passed = 0
    for i in range(args.iterations):
        ok = run_large_matvec_test(
            test_num=i,
            elf_path=elf_path,
            params=params,
            rows=rows,
            cols=cols,
            output_dir=output_dir,
            verbose=args.verbose,
            dump_regs_file=getattr(args, 'dump_regs', None),
            dump_stats_file=getattr(args, 'dump_stats', None),
        )
        if ok:
            passed += 1

    print_test_summary(passed, args.iterations, test_name)
    return 0 if passed == args.iterations else 1
