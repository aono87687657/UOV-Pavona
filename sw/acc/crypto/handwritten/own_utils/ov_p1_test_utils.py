"""
OV P1P1TO Test Utilities

Shared functions for testing the (P1+P1^T)*O + P2 matrix computation
on the ACC simulator. Supports both OV-Is (GF16) and OV-Ip (GF256).

The computation for each row i:
    S[i, j] = sum_k (P1+P1^T)[i, k] * O[k, j] + P2[i, j]   for all j
"""

import random
from typing import TextIO

from dmem_utils import (
    extract_bytes_from_dmem,
    bytes_to_dmem_words,
    validate_bytes,
)
from acc_sim_utils import (
    run_acc_test,
)
from gf_arithmetic import (
    gf16v_madd,
    gf256v_madd,
    gfv_get_ele_gf16,
)
from ov_params import OVParams
from ov_pk_utils import expand_p1p2_from_pkseed


# ------------------------------------------------------------------ #
#  P1+P1^T row extraction
# ------------------------------------------------------------------ #

def get_p1p1t_row_gf16(
    p1_input: bytearray,
    row_idx: int,
    params: OVParams,
) -> bytearray:
    """
    Extract a full row from P1+P1^T (symmetric matrix) for GF16.

    P1 is upper triangular stored ROW-MAJOR with V*(V+1)/2 entries.
    Each entry is pub_m_byte (32) bytes. No padding needed (already aligned).

    For row-major upper triangular, element at (row, col) where row <= col:
        index = row * V - row * (row + 1) / 2 + col

    Returns:
        Full row (V elements x pub_m_byte bytes = V*32 bytes)
    """
    v = params.v
    pub_m_byte = params.pub_m_byte
    row = bytearray()

    for col in range(v):
        if row_idx == col:
            # Diagonal = 0 in GF(2^4): a + a = 0
            row.extend(bytearray(pub_m_byte))
        elif row_idx < col:
            # Upper triangle: P1[row_idx, col]
            index = row_idx * v - row_idx * (row_idx + 1) // 2 + col
            row.extend(p1_input[index * pub_m_byte : (index + 1) * pub_m_byte])
        else:
            # Lower triangle: P1[col, row_idx] (transpose)
            index = col * v - col * (col + 1) // 2 + row_idx
            row.extend(p1_input[index * pub_m_byte : (index + 1) * pub_m_byte])

    return row


def get_p1p1t_row_gf256(
    p1_input: bytearray,
    row_idx: int,
    params: OVParams,
) -> bytearray:
    """
    Extract a full row from P1+P1^T (symmetric matrix) for GF256.

    Same logic as GF16, but each entry is pub_m_byte (44) data bytes
    padded to pub_m_byte_padded (64) bytes.

    Returns:
        Full row (V elements x pub_m_byte_padded bytes = V*64 bytes)
    """
    v = params.v
    pub_m_byte = params.pub_m_byte
    pub_m_byte_padded = params.pub_m_byte_padded
    row = bytearray()

    for col in range(v):
        if row_idx == col:
            # Diagonal = 0 (44 bytes of zeros + 20 bytes padding)
            row.extend(bytearray(pub_m_byte_padded))
        elif row_idx < col:
            # Upper triangle: P1[row_idx, col]
            index = row_idx * v - row_idx * (row_idx + 1) // 2 + col
            row.extend(p1_input[index * pub_m_byte : (index + 1) * pub_m_byte])
            row.extend(bytearray(pub_m_byte_padded - pub_m_byte))  # padding
        else:
            # Lower triangle: P1[col, row_idx] (transpose)
            index = col * v - col * (col + 1) // 2 + row_idx
            row.extend(p1_input[index * pub_m_byte : (index + 1) * pub_m_byte])
            row.extend(bytearray(pub_m_byte_padded - pub_m_byte))  # padding

    return row


# ------------------------------------------------------------------ #
#  Row multiplication: (P1+P1^T)[row] x O
# ------------------------------------------------------------------ #

def compute_row_mul_o_gf16(
    p1p1t_row: bytearray,
    o_input: bytearray,
    params: OVParams,
) -> bytearray:
    """
    Compute (P1+P1^T)[row] x O for GF16.

    p1p1t_row: One row of P1+P1^T (V elements x pub_m_byte bytes)
    o_input: O matrix (column-major, V*O / 2 bytes, 2 GF16 elements per byte)

    Returns:
        Result row (PUB_M elements x pub_m_byte bytes = PUB_M*32 bytes)
    """
    v = params.v
    pub_m = params.pub_m
    pub_m_byte = params.pub_m_byte
    v_byte = v // 2

    result = bytearray(pub_m * pub_m_byte)

    for j in range(pub_m):
        accumulator = bytearray(pub_m_byte)

        for k in range(v):
            # Get P1P1T[row,k] (pub_m_byte-byte vector)
            p1p1t_offset = k * pub_m_byte
            p1p1t_vec = p1p1t_row[p1p1t_offset : p1p1t_offset + pub_m_byte]

            # Get O[k,j] (scalar GF16 element, column-major)
            o_col_offset = j * v_byte
            o_scalar = gfv_get_ele_gf16(o_input[o_col_offset:], k)

            if o_scalar != 0:
                gf16v_madd(accumulator, p1p1t_vec, o_scalar)

        result_offset = j * pub_m_byte
        result[result_offset : result_offset + pub_m_byte] = accumulator

    return result


def compute_row_mul_o_gf256(
    p1p1t_row: bytearray,
    o_input: bytearray,
    params: OVParams,
) -> bytearray:
    """
    Compute (P1+P1^T)[row] x O for GF256.

    p1p1t_row: One row of P1+P1^T (V elements x pub_m_byte_padded bytes)
    o_input: O matrix (column-major, V*O bytes, 1 GF256 element per byte)

    Returns:
        Result row (PUB_M elements x pub_m_byte_padded bytes = PUB_M*64 bytes)
    """
    v = params.v
    pub_m = params.pub_m
    pub_m_byte = params.pub_m_byte
    pub_m_byte_padded = params.pub_m_byte_padded

    result = bytearray(pub_m * pub_m_byte_padded)

    for j in range(pub_m):
        accumulator = bytearray(pub_m_byte)

        for k in range(v):
            # Get P1P1T[row,k] (pub_m_byte data from pub_m_byte_padded-byte padded element)
            p1p1t_offset = k * pub_m_byte_padded
            p1p1t_vec = p1p1t_row[p1p1t_offset : p1p1t_offset + pub_m_byte]

            # Get O[k,j] (scalar GF256 element, column-major)
            o_col_offset = j * v
            o_scalar = o_input[o_col_offset + k]

            if o_scalar != 0:
                gf256v_madd(accumulator, p1p1t_vec, o_scalar)

        # Store result with padding
        result_offset = j * pub_m_byte_padded
        result[result_offset : result_offset + pub_m_byte] = accumulator
        # Padding bytes remain as zeros

    return result


# ------------------------------------------------------------------ #
#  Add P2 row to result
# ------------------------------------------------------------------ #

def add_p2_row_gf16(
    result_row: bytearray,
    p2_input: bytearray,
    row_idx: int,
    params: OVParams,
) -> bytearray:
    """
    Add P2[row_idx] to result row (GF16). Addition = XOR in GF(2^4).

    P2 is stored ROW-MAJOR, no padding. Each entry is pub_m_byte bytes.
    Result entries are also pub_m_byte bytes (no padding for GF16).
    """
    pub_m = params.pub_m
    pub_m_byte = params.pub_m_byte
    result = bytearray(result_row)

    p2_row_start = row_idx * pub_m * pub_m_byte

    for j in range(pub_m):
        p2_offset = p2_row_start + j * pub_m_byte
        p2_element = p2_input[p2_offset : p2_offset + pub_m_byte]

        result_offset = j * pub_m_byte
        for b in range(pub_m_byte):
            result[result_offset + b] ^= p2_element[b]

    return result


def add_p2_row_gf256(
    result_row: bytearray,
    p2_input: bytearray,
    row_idx: int,
    params: OVParams,
) -> bytearray:
    """
    Add P2[row_idx] to result row (GF256). Addition = XOR in GF(2^8).

    P2 is stored ROW-MAJOR with no padding (entries are pub_m_byte = 44 bytes).
    Result entries are pub_m_byte_padded = 64 bytes (44 data + 20 padding).
    Only the first pub_m_byte bytes of each result entry are XORed.
    """
    pub_m = params.pub_m
    pub_m_byte = params.pub_m_byte
    pub_m_byte_padded = params.pub_m_byte_padded
    result = bytearray(result_row)

    p2_row_start = row_idx * pub_m * pub_m_byte

    for j in range(pub_m):
        p2_offset = p2_row_start + j * pub_m_byte
        p2_element = p2_input[p2_offset : p2_offset + pub_m_byte]

        result_offset = j * pub_m_byte_padded
        for b in range(pub_m_byte):
            result[result_offset + b] ^= p2_element[b]
        # Padding bytes remain unchanged

    return result


# ------------------------------------------------------------------ #
#  Reference computation: full P1P1TO
# ------------------------------------------------------------------ #

def compute_p1p1to_reference(
    aes_key: bytearray,
    o_matrix: bytearray,
    params: OVParams,
    num_rows: int = None,
) -> bytearray:
    """
    Compute (P1+P1^T)*O + P2 row-by-row using reference GF arithmetic.

    Expands P1||P2 from the AES key, then for each row:
        S[i] = (P1+P1^T)[i] x O + P2[i]

    Args:
        aes_key: 16-byte AES-128 key for P1/P2 expansion
        o_matrix: O matrix bytes (column-major)
        params: OV parameter set
        num_rows: Number of rows to process (default: params.v)

    Returns:
        Concatenated result rows as bytearray
    """
    if num_rows is None:
        num_rows = params.v

    # Expand P1||P2
    p1p2 = expand_p1p2_from_pkseed(aes_key, params)
    p1_input = p1p2[:params.p1_size]
    p2_input = p1p2[params.p1_size:]

    print(f"P1 size: {len(p1_input):,} bytes, P2 size: {len(p2_input):,} bytes")

    # Select variant-specific functions
    is_gf16 = (params.gf == 16)
    get_row = get_p1p1t_row_gf16 if is_gf16 else get_p1p1t_row_gf256
    mul_row = compute_row_mul_o_gf16 if is_gf16 else compute_row_mul_o_gf256
    add_p2 = add_p2_row_gf16 if is_gf16 else add_p2_row_gf256

    result = bytearray()
    for row_idx in range(num_rows):
        p1p1t_row = get_row(p1_input, row_idx, params)
        row_result = mul_row(p1p1t_row, o_matrix, params)
        row_result = add_p2(row_result, p2_input, row_idx, params)
        result.extend(row_result)
        print(f"  Row {row_idx}: (P1+P1^T)[{row_idx}] x O + P2[{row_idx}] computed")

    return result


# ------------------------------------------------------------------ #
#  DMEM injection
# ------------------------------------------------------------------ #

def build_p1p1to_words(
    aes_key: bytearray,
    o_matrix: bytearray,
    params: OVParams,
) -> dict:
    """
    Build DMEM word dict for AES key + O matrix for P1P1TO test.

    AES key: 16 bytes padded to 32 bytes.
    O matrix: raw size for GF16 (already 32-byte aligned),
              padded to o_size_padded for GF256.

    Returns:
        Dict mapping DMEM word addresses to 32-bit values.
    """
    words = {}

    # AES-128 key (padded to 32 bytes)
    key_words = bytes_to_dmem_words(
        data=aes_key,
        base_addr=params.p1p1to_aes128_key_addr,
        pad_to_size=32,
    )
    print(f"Injecting AES key: {len(aes_key)} bytes -> {len(key_words)} words")
    words.update(key_words)

    # O matrix (with optional padding for GF256)
    if params.o_size != params.o_size_padded:
        if params.o_slot_bytes:
            raise NotImplementedError(
                f"{params.name}: O uses {params.o_slot_bytes}-byte per-column "
                "slots; the trailing-pad model below does not describe it")
        o_words = bytes_to_dmem_words(
            data=o_matrix,
            base_addr=params.p1p1to_o_matrix_addr,
            pad_to_size=params.o_size_padded,
        )
        print(f"Injecting O matrix: {len(o_matrix)} bytes -> {len(o_words)} words "
              f"(padded to {params.o_size_padded} bytes)")
    else:
        o_words = bytes_to_dmem_words(
            data=o_matrix,
            base_addr=params.p1p1to_o_matrix_addr,
        )
        print(f"Injecting O matrix: {len(o_matrix)} bytes -> {len(o_words)} words")
    words.update(o_words)

    return words


# ------------------------------------------------------------------ #
#  Result row size helper
# ------------------------------------------------------------------ #

def _row_size(params: OVParams) -> int:
    """Bytes per output row: PUB_M * element_stride."""
    if params.needs_column_padding:
        return params.pub_m * params.pub_m_byte_padded
    else:
        return params.pub_m * params.pub_m_byte


# ------------------------------------------------------------------ #
#  Single test iteration
# ------------------------------------------------------------------ #

def run_p1p1to_test(
    test_num: int,
    elf_path: str,
    params: OVParams,
    num_rows: int = None,
    verbose: bool = False,
    dump_regs_file: TextIO = None,
    dump_stats_file: TextIO = None,
) -> bool:
    """
    Run a single (P1+P1^T)*O + P2 test iteration.

    Generates random AES key and O matrix, computes reference result,
    runs ACC simulation, and validates output.

    Args:
        test_num: Test iteration number
        elf_path: Path to ELF file
        params: OV parameter set
        num_rows: Rows to test (default: params.v)
        verbose: Verbose ACC output
        dump_regs_file: Optional file for register dump
        dump_stats_file: Optional file for statistics

    Returns:
        True if test passed
    """
    if num_rows is None:
        num_rows = params.v

    row_sz = _row_size(params)

    print(f"\n--- Iteration {test_num + 1} ---")
    print(f"Testing {num_rows} row(s): 0 to {num_rows - 1}")

    # Generate random AES-128 key
    aes_key = bytearray([random.randint(0, 255) for _ in range(16)])
    print(f"AES Key: {aes_key.hex()}")

    # Generate random O matrix
    print("Generating random O matrix...")
    o_matrix = bytearray([random.randint(0, 255) for _ in range(params.o_size)])

    # Compute expected result
    print(f"Computing expected result for {num_rows} rows...")
    print(f"  Formula: S[i] = (P1+P1^T)[i] x O + P2[i]")
    result_expected = compute_p1p1to_reference(aes_key, o_matrix, params, num_rows)

    actual_result_size = num_rows * row_sz
    print(f"\nExpected result: {len(result_expected)} bytes ({num_rows} rows x {row_sz} bytes)")

    # Print first few rows for debugging
    for i in range(min(4, num_rows)):
        start = i * row_sz
        print(f"Row {i} first 16 bytes: {result_expected[start:start+16].hex(' ')}")

    # Run ACC simulation
    print("\nRunning ACC simulation...")

    words = build_p1p1to_words(aes_key, o_matrix, params)

    success, dmem_bytes, sim = run_acc_test(
        elf_path=elf_path,
        dmem_words=words,
        verbose=verbose,
        dump_regs_file=dump_regs_file,
        dump_stats_file=dump_stats_file,
    )

    if not success or sim is None:
        print("[ERROR] ACC simulation failed")
        return False

    # GF256 variant: extra ERR_BITS check (matches original Ip script)
    if params.gf == 256:
        err_bits = sim.state.ext_regs.read('ERR_BITS', False)
        if err_bits != 0:
            print(f"[ERROR] ACC ERR_BITS = 0x{err_bits:x}")
            return False

    # Extract and validate result
    if params.gf == 256:
        print(f"\n========== Verifying Final Result ==========")
    print(f"Extracting result from DMEM ({num_rows} rows)...")
    test_name = f"(P1+P1^T)xO + P2 rows 0-{num_rows - 1}"

    result_actual = extract_bytes_from_dmem(
        dmem_bytes, params.p1p1to_result_addr, actual_result_size
    )

    print(f"Actual result: {len(result_actual)} bytes")
    for i in range(min(4, num_rows)):
        start = i * row_sz
        print(f"Row {i} first 16 bytes: {result_actual[start:start+16].hex(' ')}")

    # Validate
    print(f"\nValidating {test_name}...")
    match, mismatches = validate_bytes(result_expected, result_actual, test_name)

    if match:
        print(f"Test PASSED - {test_name} matches expected result")
        return True
    else:
        print(f"Test FAILED - Found {len(mismatches)} mismatches")
        # Mismatch detail
        element_stride = params.pub_m_byte_padded if params.needs_column_padding else params.pub_m_byte
        for idx in mismatches[:10]:
            row = idx // row_sz
            col_offset = idx % row_sz
            oil = col_offset // element_stride
            byte_in_entry = col_offset % element_stride
            print(f"  Offset 0x{idx:05x} (row={row}, oil={oil}, byte={byte_in_entry}): "
                  f"expected=0x{result_expected[idx]:02x}, actual=0x{result_actual[idx]:02x}")
        if len(mismatches) > 10:
            print(f"  ... and {len(mismatches) - 10} more mismatches")
        return False


# ------------------------------------------------------------------ #
#  CLI entry point
# ------------------------------------------------------------------ #

def p1p1to_main(params: OVParams) -> int:
    """
    CLI entry point for (P1+P1^T)*O + P2 tests.

    Args:
        params: OV parameter set (OV_IS or OV_IP)

    Returns:
        Exit code: 0 if all passed, 1 otherwise
    """
    from acc_sim_utils import create_common_argparser, run_test_suite

    field = f"GF({'16' if params.gf == 16 else '256'})"
    num_rows = params.v
    row_sz = _row_size(params)

    parser = create_common_argparser(
        f"OV{'16' if params.gf == 16 else '256'}_P1P1TO Test",
        default_elf=params.default_p1p1to_elf,
        default_iterations=1,
    )
    args = parser.parse_args()

    print(f"\n(P1+P1^T)xO + P2 Row-by-Row Test Configuration:")
    print(f"  Field: {field}")
    print(f"  V={params.v}, M={params.pub_m}")
    print(f"  P1 monomials: {params.v * (params.v + 1) // 2}")
    print(f"  P1 size: {params.p1_size:,} bytes")
    print(f"  P2 size: {params.p2_size:,} bytes ({params.v}x{params.pub_m}x{params.pub_m_byte})")
    print(f"  P2 row size: {params.pub_m * params.pub_m_byte:,} bytes ({params.pub_m}x{params.pub_m_byte})")
    print(f"  O matrix size: {params.o_size:,} bytes")
    print(f"  Num rows: {num_rows}")
    print(f"  Row size: {row_sz:,} bytes")
    print(f"  Result size: {num_rows * row_sz:,} bytes ({num_rows}x{row_sz})")
    print(f"  ELF: {args.elf}")

    def test_func(i, regs_f, stats_f):
        return run_p1p1to_test(
            i, args.elf, params,
            num_rows=num_rows,
            verbose=args.verbose,
            dump_regs_file=regs_f,
            dump_stats_file=stats_f,
        )

    return run_test_suite(
        f"OV{'16' if params.gf == 16 else '256'}_P1P1TO", test_func,
        elf_path=args.elf,
        iterations=args.iterations,
        output_dir=args.output_dir,
        seed=args.seed,
    )
