#!/usr/bin/env python3

"""
Shared Gaussian Elimination Test Utilities for OV-Is (GF16) and OV-Ip (GF256)
-------------------------------------------------------------------------------
Provides all logic needed to test ACC Gaussian elimination routines:
  - Matrix generation (invertible / non-invertible)
  - Reference GE computation (using universal pivot**-1)
  - DMEM injection with correct packing/padding
  - Result extraction and validation

run_test.py ge|backsub passes the OVParams instance that selects the
concrete dimensions and memory layout.
"""

import os
import random
import numpy as np
from typing import List, TextIO

from ov_params import OVParams
from gf_arithmetic import (
    GF16,
    GF256,
    generate_random_gf_vector,
    gf_elements_to_bytes,
)
from dmem_utils import (
    extract_bytes_from_dmem,
    bytes_to_dmem_words,
    validate_bytes,
)
from acc_sim_utils import (
    run_acc_test,
    read_wdr_register,
)


# All-ones value of a 256-bit WDR. Used as the GE status flag indicating
# a singular (non-invertible) input matrix; all-zeros indicates success.
_WDR_ALL_ONES = (1 << 256) - 1


# ------------------------------------------------------------------ #
#  Helpers: GF field selection
# ------------------------------------------------------------------ #

def _gf_class(params: OVParams):
    """Return the galois field class (GF16 or GF256) for *params*."""
    return GF16 if params.gf == 16 else GF256


def _field_tag(params: OVParams) -> str:
    """Return 'gf16' or 'gf256' for use in gf_arithmetic helpers."""
    return "gf16" if params.gf == 16 else "gf256"


def _element_max(params: OVParams) -> int:
    """Max element value (exclusive) for the field: 16 or 256."""
    return 16 if params.gf == 16 else 256


def _dim(params: OVParams) -> int:
    """Matrix/vector dimension derived from params (pub_m = oil = o)."""
    return params.o


def _status_wdr_index(params: OVParams) -> int:
    """WDR register index for the GE status flag (e.g. 24 for 'w24')."""
    return int(params.ge_status_wdr.lstrip("wW"))


# ------------------------------------------------------------------ #
#  Row size helpers
# ------------------------------------------------------------------ #

def _row_bytes(params: OVParams) -> int:
    """
    Number of *data* bytes per matrix row (before padding).

    GF16: dim/2  (nibble-packed, 2 elements per byte)
    GF256: dim   (1 byte per element)
    """
    dim = _dim(params)
    if params.gf == 16:
        return dim // 2
    return dim


def _padded_row_bytes(params: OVParams) -> int:
    """
    Total bytes per row *as stored in DMEM*, including any zero padding.

    If ge_row_padding > 0, each row is padded to that many bytes.
    Otherwise, the row is its natural size (already 32-byte aligned for GF16 64x64).
    """
    if params.ge_row_padding > 0:
        return params.ge_row_padding
    return _row_bytes(params)


# ------------------------------------------------------------------ #
#  Matrix invertibility check
# ------------------------------------------------------------------ #

def is_matrix_invertible(matrix: np.ndarray, params: OVParams) -> bool:
    """
    Check if *matrix* is invertible under the assembly's pivot strategy:
    when the diagonal is zero, XOR (add in GF) rows below into the pivot
    row until the diagonal becomes non-zero.

    Uses universal ``pivot ** -1`` for the pivot inverse.
    """
    GF = _gf_class(params)
    n = matrix.shape[0]
    M = GF(matrix.copy())

    for pivot_row in range(n):
        if M[pivot_row, pivot_row] == 0:
            found = False
            for add_row in range(pivot_row + 1, n):
                M[pivot_row, :] += M[add_row, :]
                if M[pivot_row, pivot_row] != 0:
                    found = True
                    break
            if not found:
                return False

        pivot_inv = M[pivot_row, pivot_row] ** -1
        M[pivot_row, :] *= pivot_inv
        for row in range(pivot_row + 1, n):
            if M[row, pivot_row] != 0:
                factor = M[row, pivot_row]
                M[row, :] -= factor * M[pivot_row, :]

    return True


# ------------------------------------------------------------------ #
#  Matrix generation
# ------------------------------------------------------------------ #

def generate_invertible_matrix(params: OVParams,
                               max_attempts: int = 100) -> np.ndarray:
    """
    Generate a random invertible square matrix in GF16 or GF256.

    Raises RuntimeError after *max_attempts* failures.
    """
    dim = _dim(params)
    elem_max = _element_max(params)

    for attempt in range(max_attempts):
        if params.gf == 16:
            # Original GF16 script: elements in [1, 15], force two zeros
            matrix = np.random.randint(1, elem_max, size=(dim, dim), dtype=np.uint8)
            matrix[0][0] = matrix[1][0] = 0
        else:
            # Original GF256 script: elements in [0, 255], force some zeros
            matrix = np.random.randint(0, elem_max, size=(dim, dim), dtype=np.uint8)
            matrix[0][0] = 0
            matrix[np.random.randint(0, dim)][np.random.randint(0, dim)] = 0

        if is_matrix_invertible(matrix, params):
            print(f"[INFO] Generated invertible matrix on attempt {attempt + 1}")
            return matrix

    raise RuntimeError(
        f"Failed to generate invertible matrix after {max_attempts} attempts"
    )


def generate_non_invertible_matrix(params: OVParams) -> np.ndarray:
    """
    Generate a deliberately singular matrix by duplicating one row.
    """
    dim = _dim(params)
    elem_max = _element_max(params)
    matrix = np.random.randint(1, elem_max, size=(dim, dim), dtype=np.uint8)

    row1 = np.random.randint(0, dim)
    row2 = np.random.randint(0, dim)
    while row2 == row1:
        row2 = np.random.randint(0, dim)
    matrix[row2] = matrix[row1].copy()

    print(f"[INFO] Generated non-invertible matrix (row {row2} = row {row1})")
    return matrix


# ------------------------------------------------------------------ #
#  Reference Gaussian elimination
# ------------------------------------------------------------------ #

def compute_ge_reference(matrix: np.ndarray, vector: List[int],
                         params: OVParams):
    """
    Gaussian elimination reference using universal ``pivot ** -1``.

    Returns (M_out, v_out) where M_out is an upper-triangular numpy
    uint8 array with ones on the diagonal, and v_out is a list of ints.
    """
    GF = _gf_class(params)
    n = matrix.shape[0]
    M = GF(matrix.copy())
    v = GF(np.array(vector))

    for pivot_row in range(n):
        # Row-addition pivot fix
        if M[pivot_row, pivot_row] == 0:
            for add_row in range(pivot_row + 1, n):
                M[pivot_row, :] += M[add_row, :]
                v[pivot_row] += v[add_row]
                if M[pivot_row, pivot_row] != 0:
                    break

        pivot = M[pivot_row, pivot_row]
        if pivot != 0:
            pivot_inv = pivot ** -1
            M[pivot_row, :] *= pivot_inv
            v[pivot_row] *= pivot_inv
            assert M[pivot_row, pivot_row] == 1, (
                f"Row {pivot_row}: diagonal should be 1 after scaling"
            )

        # Eliminate below
        for row in range(pivot_row + 1, n):
            if M[row, pivot_row] != 0:
                factor = M[row, pivot_row]
                M[row, :] -= factor * M[pivot_row, :]
                v[row] -= factor * v[pivot_row]

    M_out = np.array([int(x) for x in M.flatten()], dtype=np.uint8).reshape(n, n)
    v_out = [int(x) for x in v]
    return M_out, v_out


# ------------------------------------------------------------------ #
#  Packing helpers
# ------------------------------------------------------------------ #

def _pack_matrix(matrix: np.ndarray, params: OVParams) -> bytearray:
    """
    Pack a matrix into bytes matching the DMEM layout for this param set.

    GF16: nibble-packed row-major, no padding (32 bytes/row for dim=64).
    GF256: 1 byte/element, each row zero-padded to ge_row_padding bytes.
    """
    if params.gf == 16:
        elements = matrix.flatten().tolist()
        return gf_elements_to_bytes(elements, field="gf16")
    else:
        # GF256 with row padding
        rows, cols = matrix.shape
        rp = _padded_row_bytes(params)
        result = bytearray()
        for row_idx in range(rows):
            row_data = matrix[row_idx, :].astype(np.uint8).tobytes()
            padding = rp - cols
            if padding < 0:
                raise ValueError(f"Row size {cols} exceeds padding size {rp}")
            result.extend(row_data)
            result.extend(bytearray(padding))
        return result


def _pack_vector(vector: List[int], params: OVParams) -> bytearray:
    """
    Pack a vector into bytes matching the DMEM layout for this param set.

    GF16: nibble-packed (32 bytes for 64 elements).
    GF256: 1 byte/element, zero-padded to ge_row_padding bytes.
    """
    if params.gf == 16:
        return gf_elements_to_bytes(vector, field="gf16")
    else:
        rp = _padded_row_bytes(params)
        result = bytearray(vector)
        padding = rp - len(vector)
        if padding < 0:
            raise ValueError(
                f"Vector size {len(vector)} exceeds padding size {rp}"
            )
        result.extend(bytearray(padding))
        return result


# ------------------------------------------------------------------ #
#  DMEM injection
# ------------------------------------------------------------------ #

def build_ge_words(matrix_bytes: bytearray, vector_bytes: bytearray,
                   params: OVParams) -> dict:
    """
    Build DMEM word dict for packed matrix and vector at the addresses
    specified by *params*.

    Returns:
        Dict mapping DMEM word addresses to 32-bit values.
    """
    words = {}
    words.update(bytes_to_dmem_words(matrix_bytes, params.ge_input_matrix_addr))
    words.update(bytes_to_dmem_words(vector_bytes, params.ge_input_vector_addr))
    return words


# ------------------------------------------------------------------ #
#  Result extraction
# ------------------------------------------------------------------ #

def _matrix_size_bytes(params: OVParams) -> int:
    """Total byte size of the matrix region in DMEM."""
    return _dim(params) * _padded_row_bytes(params)


def _vector_size_bytes(params: OVParams) -> int:
    """Total byte size of the vector region in DMEM."""
    return _padded_row_bytes(params) if params.gf == 256 else _row_bytes(params)


def extract_ge_result(dmem_bytes: bytes, params: OVParams):
    """
    Extract matrix and vector bytes from DMEM after GE simulation.

    Returns (actual_matrix_bytes, actual_vector_bytes).
    """
    mat_bytes = extract_bytes_from_dmem(
        dmem_bytes, params.ge_input_matrix_addr, _matrix_size_bytes(params)
    )
    vec_bytes = extract_bytes_from_dmem(
        dmem_bytes, params.ge_input_vector_addr, _vector_size_bytes(params)
    )
    return mat_bytes, vec_bytes


# ------------------------------------------------------------------ #
#  Status register
# ------------------------------------------------------------------ #

def check_ge_status(sim, params: OVParams) -> int:
    """Read the WDR holding the GE status flag and return its integer value."""
    return read_wdr_register(sim, _status_wdr_index(params))


# ------------------------------------------------------------------ #
#  Single-test runner
# ------------------------------------------------------------------ #

def run_ge_test(
    iteration: int,
    params: OVParams,
    is_invertible: bool = True,
    elf_path: str = None,
    verbose: bool = False,
    dump_regs_file: TextIO = None,
    dump_stats_file: TextIO = None,
) -> bool:
    """
    Run a single GE test iteration.

    1. Generate matrix + vector
    2. Compute reference (invertible only)
    3. Inject into simulator
    4. Validate status register and outputs

    Returns True on pass, False on fail.
    """
    dim = _dim(params)
    gf_name = f"GF{params.gf}"
    wdr_name = params.ge_status_wdr.upper()

    print(
        f"\n--- Iteration {iteration + 1} "
        f"{'(INVERTIBLE)' if is_invertible else '(NON-INVERTIBLE)'} ---"
    )
    print(
        f"[INFO] Generating {'invertible' if is_invertible else 'non-invertible'} "
        f"{dim}x{dim} {gf_name} matrix..."
    )
    random.seed(iteration)
    np.random.seed(iteration)

    # Generate matrix
    if is_invertible:
        matrix = generate_invertible_matrix(params)
    else:
        matrix = generate_non_invertible_matrix(params)

    # Generate vector
    vector = generate_random_gf_vector(dim, field=_field_tag(params))

    # Reference (invertible only)
    expected_matrix = None
    expected_vector = None
    if is_invertible:
        print("[INFO] Computing expected Gaussian elimination output...")
        expected_matrix, expected_vector = compute_ge_reference(
            matrix, vector, params
        )

    # Pack
    matrix_bytes = _pack_matrix(matrix, params)
    vector_bytes = _pack_vector(vector, params)

    expected_matrix_bytes = None
    expected_vector_bytes = None
    if is_invertible:
        expected_matrix_bytes = _pack_matrix(expected_matrix, params)
        expected_vector_bytes = _pack_vector(expected_vector, params)

    print(f"[INFO] Input matrix size: {len(matrix_bytes)} bytes")
    print(f"[INFO] Input vector size: {len(vector_bytes)} bytes")

    # Inject & run
    words = build_ge_words(matrix_bytes, vector_bytes, params)

    _elf = elf_path or os.path.abspath(params.default_ge_elf)
    success, dmem_bytes, sim = run_acc_test(
        elf_path=_elf,
        dmem_words=words,
        verbose=verbose,
        dump_regs_file=dump_regs_file,
        dump_stats_file=dump_stats_file,
    )

    if not success or sim is None:
        print("[ERROR] ACC simulation failed")
        return False

    # Status register
    status_value = check_ge_status(sim, params)
    status_all_zeros = status_value == 0
    status_all_ones = status_value == _WDR_ALL_ONES

    print(f"[INFO] {wdr_name} register value: 0x{status_value:064x}")
    print(f"[INFO] {wdr_name} all zeros: {status_all_zeros}")
    print(f"[INFO] {wdr_name} all ones: {status_all_ones}")

    # Extract results
    actual_matrix_bytes, actual_vector_bytes = extract_ge_result(
        dmem_bytes, params
    )

    print(f"[INFO] Actual output matrix extracted: {len(actual_matrix_bytes)} bytes")
    print(f"[INFO] Actual output vector extracted: {len(actual_vector_bytes)} bytes")

    # Validation
    if is_invertible:
        print("\n[INFO] Validating INVERTIBLE matrix...")

        if not status_all_zeros:
            print(
                f"\n\u2717 Test FAILED - {wdr_name} should be all zeros "
                f"for invertible matrix"
            )
            print(f"  {wdr_name} = 0x{status_value:064x}")
            return False

        matrix_match, matrix_mismatches = validate_bytes(
            expected_matrix_bytes, actual_matrix_bytes, "Output Matrix"
        )
        vector_match, vector_mismatches = validate_bytes(
            expected_vector_bytes, actual_vector_bytes, "Output Vector"
        )

        if matrix_match and vector_match:
            print(
                f"\n\u2713 Test PASSED - {wdr_name} is all zeros AND "
                "outputs match expected values"
            )
            return True
        else:
            print("\n\u2717 Test FAILED - Outputs do not match expected values")
            if not matrix_match:
                print(f"  Matrix mismatches: {len(matrix_mismatches)} bytes")
            if not vector_match:
                print(f"  Vector mismatches: {len(vector_mismatches)} bytes")
            return False

    else:
        print("\n[INFO] Validating NON-INVERTIBLE matrix...")

        if status_all_ones:
            print(
                f"\n\u2713 Test PASSED - {wdr_name} is all ones "
                "(correctly detected non-invertible matrix)"
            )
            return True
        else:
            print(
                f"\n\u2717 Test FAILED - {wdr_name} should be all ones "
                "for non-invertible matrix"
            )
            print(f"  {wdr_name} = 0x{status_value:064x}")
            return False


# ================================================================== #
#  BACK-SUBSTITUTION FUNCTIONS
# ================================================================== #


# ------------------------------------------------------------------ #
#  Upper triangular matrix generation
# ------------------------------------------------------------------ #

def generate_upper_triangular(params: OVParams) -> np.ndarray:
    """
    Generate a random upper triangular matrix with diagonal = 1.

    GF16: elements in [0, 15].  GF256: elements in [0, 255].
    Diagonal is forced to 1; lower triangle is 0.

    Returns an (o x o) uint8 numpy array.
    """
    from gf_arithmetic import generate_random_gf_element

    dim = _dim(params)
    matrix = np.zeros((dim, dim), dtype=np.uint8)

    # Set diagonal to 1
    for i in range(dim):
        matrix[i, i] = 1

    # Set upper triangle to random field elements
    for i in range(dim):
        for j in range(i + 1, dim):
            matrix[i, j] = generate_random_gf_element(_field_tag(params))

    return matrix


# ------------------------------------------------------------------ #
#  Back-substitution reference
# ------------------------------------------------------------------ #

def compute_backsub_reference(
    matrix: np.ndarray,
    vector: List[int],
    params: OVParams,
):
    """
    Back elimination reference: given upper-triangular A' (diagonal=1)
    and vector x', eliminate above the diagonal to produce [I | x].

    Algorithm (Gauss-Jordan on upper triangle):
        For pivot_row from n-1 down to 1:
            For row from pivot_row-1 down to 0:
                factor = A[row, pivot_row]
                if factor != 0:
                    A[row, :] -= factor * A[pivot_row, :]
                    x[row]    -= factor * x[pivot_row]

    Returns (identity_matrix, transformed_vector) as (np.ndarray, list[int]).
    """
    GF = _gf_class(params)
    n = matrix.shape[0]

    A = GF(matrix.copy())
    x = GF(np.array(vector.copy()))

    # Back elimination: eliminate above diagonal
    for pivot_row in range(n - 1, 0, -1):
        for row in range(pivot_row - 1, -1, -1):
            factor = A[row, pivot_row]
            if factor != 0:
                A[row, :] -= factor * A[pivot_row, :]
                x[row] -= factor * x[pivot_row]

    # Verify result is identity matrix
    for i in range(n):
        assert A[i, i] == 1, f"Diagonal [{i},{i}] should be 1"
        for j in range(n):
            if i != j:
                assert A[i, j] == 0, f"Off-diagonal [{i},{j}] should be 0"

    A_out = np.array([int(val) for val in A.flatten()], dtype=np.uint8).reshape(n, n)
    x_out = [int(val) for val in x]

    return A_out, x_out


# ------------------------------------------------------------------ #
#  Back-substitution DMEM injection
# ------------------------------------------------------------------ #

def build_backsub_words(
    matrix_bytes: bytearray,
    vector_bytes: bytearray,
    params: OVParams,
) -> dict:
    """
    Build DMEM word dict for upper triangular matrix and vector at the
    back-substitution addresses from *params*.

    Returns:
        Dict mapping DMEM word addresses to 32-bit values.
    """
    words = {}
    words.update(bytes_to_dmem_words(
        matrix_bytes, params.backsub_input_matrix_addr
    ))
    words.update(bytes_to_dmem_words(
        vector_bytes, params.backsub_input_vector_addr
    ))
    return words


# ------------------------------------------------------------------ #
#  Back-substitution result extraction
# ------------------------------------------------------------------ #

def extract_backsub_result(dmem_bytes: bytes, params: OVParams) -> bytearray:
    """
    Extract the solution vector from DMEM after back-substitution.

    Returns the raw bytes (including any padding for GF256).
    """
    vec_size = _vector_size_bytes(params)
    return extract_bytes_from_dmem(
        dmem_bytes, params.backsub_output_vector_addr, vec_size
    )


# ------------------------------------------------------------------ #
#  Back-substitution vector verification helper
# ------------------------------------------------------------------ #

def _verify_backsub_vector(
    computed_vector: List[int],
    expected_vector: List[int],
) -> bool:
    """
    Element-wise comparison of computed vs expected vector.
    Prints diagnostics on mismatch.  Returns True on match.
    """
    if len(computed_vector) != len(expected_vector):
        print("[ERROR] Vector length mismatch!")
        return False

    match = all(c == e for c, e in zip(computed_vector, expected_vector))

    if not match:
        print("[ERROR] Vector verification failed!")
        print(f"  Expected x: {expected_vector[:8]}... (first 8 elements)")
        print(f"  Computed x: {computed_vector[:8]}... (first 8 elements)")
        mismatches = [
            i for i in range(len(expected_vector))
            if computed_vector[i] != expected_vector[i]
        ]
        print(f"  Mismatches at indices: {mismatches[:10]}... (showing first 10)")

    return match


# ------------------------------------------------------------------ #
#  Single back-substitution test runner
# ------------------------------------------------------------------ #

def run_backsub_test(
    iteration: int,
    params: OVParams,
    elf_path: str = None,
    verbose: bool = False,
    dump_regs_file: TextIO = None,
    dump_stats_file: TextIO = None,
) -> bool:
    """
    Run a single back-substitution test iteration.

    1. Generate upper triangular matrix (diagonal=1) + random vector
    2. Compute reference back elimination
    3. Inject into simulator
    4. Validate output vector (including padding for GF256)

    Returns True on pass, False on fail.
    """
    from gf_arithmetic import bytes_to_gf_elements

    dim = _dim(params)
    gf_name = f"GF{params.gf}"

    print(f"\n--- Iteration {iteration + 1} ---")
    print(
        f"[INFO] Generating random {dim}x{dim} {gf_name} upper triangular "
        f"matrix (A')..."
    )

    # Seed: GF16 original uses iteration+1, GF256 uses iteration
    if params.gf == 16:
        random.seed(iteration + 1)
        np.random.seed(iteration + 1)
    else:
        random.seed(iteration)
        np.random.seed(iteration)

    # Step 1: Generate upper triangular matrix
    input_matrix = generate_upper_triangular(params)

    # Step 2: Generate random input vector
    print("[INFO] Generating random input vector (x')...")
    input_vector = generate_random_gf_vector(dim, field=_field_tag(params))

    # Step 3: Compute expected output via back elimination
    print("[INFO] Computing expected output vector via back elimination...")
    _, expected_vector = compute_backsub_reference(
        input_matrix, input_vector, params
    )

    # Step 4: Pack inputs
    matrix_bytes = _pack_matrix(input_matrix, params)
    vector_bytes = _pack_vector(input_vector, params)
    expected_vector_bytes = _pack_vector(expected_vector, params)

    print(f"[INFO] Input matrix size: {len(matrix_bytes)} bytes"
          f"{' (upper triangular)' if params.gf == 16 else ' (' + str(dim) + ' rows * ' + str(_padded_row_bytes(params)) + ' bytes/row)'}")
    print(f"[INFO] Input vector size: {len(vector_bytes)} bytes"
          f"{'' if params.gf == 16 else ' (' + str(dim) + ' elements + padding)'}")
    print(f"[INFO] Expected output vector size: {len(expected_vector_bytes)} bytes")

    # Step 5: Inject data and run ACC
    words = build_backsub_words(matrix_bytes, vector_bytes, params)

    _elf = elf_path or os.path.abspath(params.default_backsub_elf)
    success, dmem_bytes, sim = run_acc_test(
        elf_path=_elf,
        dmem_words=words,
        verbose=verbose,
        dump_regs_file=dump_regs_file,
        dump_stats_file=dump_stats_file,
    )

    if not success or sim is None:
        print("[ERROR] ACC simulation failed")
        return False

    # Step 6: Extract actual output vector
    actual_vector_bytes = extract_backsub_result(dmem_bytes, params)

    print(f"[INFO] Actual output vector extracted: {len(actual_vector_bytes)} bytes")

    # Step 8: Validate
    print("\n[INFO] Validating ACC output vector...")

    if params.gf == 256 and params.ge_row_padding > 0:
        # GF256: validate all bytes (data + padding)
        vector_match, vector_mismatches = validate_bytes(
            expected_vector_bytes,
            actual_vector_bytes,
            "Output Vector (with padding)",
        )

        if vector_match:
            # Explicit padding zero check (preserved from original Ip script)
            actual_data = list(actual_vector_bytes[:dim])
            padding_bytes = actual_vector_bytes[dim:]

            if not all(b == 0 for b in padding_bytes):
                print("[ERROR] Padding bytes are not all zeros!")
                non_zero_indices = [
                    i + dim for i, b in enumerate(padding_bytes) if b != 0
                ]
                print(f"  Non-zero padding at indices: {non_zero_indices[:10]}")
                print("\n\u2717 Test FAILED - Padding validation failed")
                return False

            if _verify_backsub_vector(actual_data, expected_vector):
                print(f"\u2713 Data elements match ({dim} bytes)")
                print(
                    f"\u2713 Padding is all zeros "
                    f"({_vector_size_bytes(params) - dim} bytes)"
                )
                print("\n\u2713 Test PASSED - Output vector matches expected")
                return True
            else:
                print("\n\u2717 Test FAILED - Output vector does not match expected")
                return False
        else:
            print(
                f"\n\u2717 Test FAILED - Vector mismatch: "
                f"{len(vector_mismatches)} bytes differ"
            )
            return False

    else:
        # GF16: validate raw bytes, then element-wise double-check
        vector_match, vector_mismatches = validate_bytes(
            expected_vector_bytes,
            actual_vector_bytes,
            "Output Vector",
        )

        if vector_match:
            actual_vector = bytes_to_gf_elements(
                actual_vector_bytes, field=_field_tag(params)
            )
            if _verify_backsub_vector(actual_vector, expected_vector):
                print("\n\u2713 Test PASSED - Output vector matches expected")
                return True
            else:
                print("\n\u2717 Test FAILED - Output vector does not match expected")
                return False
        else:
            print(
                f"\n\u2717 Test FAILED - Vector mismatch: "
                f"{len(vector_mismatches)} bytes differ"
            )
            return False


def ge_main(params) -> int:
    """
    CLI entry point for Gaussian elimination tests.

    Handles argparse, iteration splitting (invertible vs non-invertible),
    file management, and result summary.

    Args:
        params: OV parameter set (OV_IS or OV_IP)

    Returns:
        Exit code: 0 if all passed, 1 otherwise
    """
    from acc_sim_utils import create_common_argparser, run_test_suite

    dim = params.o
    parser = create_common_argparser(
        f"GF{'16' if params.gf == 16 else '256'} Gaussian Elimination "
        f"{dim}x{dim} Test",
        default_elf=params.default_ge_elf,
        default_iterations=10,
    )
    args = parser.parse_args()

    print(f"\nConfiguration:")
    print(f"  Field: GF({params.gf})")
    print(f"  Matrix: {dim}x{dim}")
    print(f"  Row padding: {params.ge_row_padding} bytes")
    print(f"  Status WDR: {params.ge_status_wdr}")
    print(f"  ELF: {args.elf}")

    n_iters = args.iterations
    # 50/50 invertible/non-invertible split: tests both GE success path
    # (matrix has solution) and failure path (GE detects singularity via
    # status WDR — all-zeros for invertible, all-ones for singular).
    n_invertible = max(1, (n_iters + 1) // 2)
    n_non_invertible = n_iters - n_invertible
    print(f"  Iterations: {n_invertible} invertible + "
          f"{n_non_invertible} non-invertible")

    def test_func(i, regs_f, stats_f):
        is_invertible = i < n_invertible
        return run_ge_test(
            iteration=i,
            elf_path=args.elf,
            params=params,
            is_invertible=is_invertible,
            verbose=args.verbose,
            dump_regs_file=regs_f,
            dump_stats_file=stats_f,
        )

    return run_test_suite(
        f"GE_{dim}x{dim}_GF{params.gf}", test_func,
        elf_path=args.elf,
        iterations=args.iterations,
        output_dir=getattr(args, 'output_dir', None),
        seed=getattr(args, 'seed', None),
    )


def backsub_main(params) -> int:
    """
    CLI entry point for back-substitution tests.

    Args:
        params: OV parameter set (OV_IS or OV_IP)

    Returns:
        Exit code: 0 if all passed, 1 otherwise
    """
    from acc_sim_utils import create_common_argparser, run_test_suite

    dim = params.o
    parser = create_common_argparser(
        f"GF{'16' if params.gf == 16 else '256'} Back-Substitution "
        f"{dim}x{dim} Test",
        default_elf=params.default_backsub_elf,
        default_iterations=10,
    )
    args = parser.parse_args()

    print(f"\nConfiguration:")
    print(f"  Field: GF({params.gf})")
    print(f"  Matrix: {dim}x{dim}")
    print(f"  ELF: {args.elf}")

    def test_func(i, regs_f, stats_f):
        return run_backsub_test(
            iteration=i,
            elf_path=args.elf,
            params=params,
            verbose=args.verbose,
            dump_regs_file=regs_f,
            dump_stats_file=stats_f,
        )

    return run_test_suite(
        f"BackSub_{dim}x{dim}_GF{params.gf}", test_func,
        elf_path=args.elf,
        iterations=args.iterations,
        output_dir=getattr(args, 'output_dir', None),
        seed=getattr(args, 'seed', None),
    )
