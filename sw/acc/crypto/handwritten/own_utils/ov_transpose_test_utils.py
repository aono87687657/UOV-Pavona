#!/usr/bin/env python3

"""
Shared Transpose Test Utilities for OV GF16 and GF256

Provides common unpack/pack/reference/test functions for matrix transpose tests.
Handles both GF16 (nibble-packed, 4-bit elements) and GF256 (byte-packed, 8-bit elements).

GF16 (OV-Is): 64x64 col-major -> 64x64 row-major (pure storage format conversion)
GF256 (OV-Ip): 64x44 col-major -> 44x64 row-major (reshape with padding)
"""

import os
import random
from typing import List, TextIO

from dmem_utils import (
    extract_bytes_from_dmem,
    bytes_to_dmem_words,
    validate_bytes,
)
from acc_sim_utils import run_acc_test


# --------------------------------------------------------------------------- #
#  Unpack / Pack
# --------------------------------------------------------------------------- #

def unpack_matrix(data: bytes, element_bits: int, rows: int, cols: int) -> List[List[int]]:
    """
    Unpack bytes into a logical matrix assuming COLUMN-MAJOR storage.

    For GF16 (element_bits=4):
        Two elements per byte. Even rows in low nibble, odd rows in high nibble.
        bytes_per_col = rows // 2.

    For GF256 (element_bits=8):
        One element per byte.
        bytes_per_col = rows.

    Args:
        data: Input bytes
        element_bits: 4 for GF16, 8 for GF256
        rows: Number of rows in the stored matrix
        cols: Number of columns in the stored matrix

    Returns:
        2D list matrix[row][col]
    """
    matrix = [[0 for _ in range(cols)] for _ in range(rows)]

    if element_bits == 4:
        bytes_per_col = rows // 2
        for c in range(cols):
            col_byte_offset = c * bytes_per_col
            for r in range(rows):
                byte_idx = col_byte_offset + (r // 2)
                byte_val = data[byte_idx]
                if r % 2 == 0:
                    val = byte_val & 0x0F
                else:
                    val = (byte_val >> 4) & 0x0F
                matrix[r][c] = val
    elif element_bits == 8:
        for c in range(cols):
            col_byte_offset = c * rows
            for r in range(rows):
                byte_idx = col_byte_offset + r
                matrix[r][c] = data[byte_idx]
    else:
        raise ValueError(f"Unsupported element_bits: {element_bits}")

    return matrix


def pack_matrix(matrix: List[List[int]], element_bits: int, rows: int, cols: int) -> bytearray:
    """
    Pack a logical matrix into bytes assuming ROW-MAJOR storage.

    For GF16 (element_bits=4):
        Two elements per byte. Even columns in low nibble, odd columns in high nibble.
        bytes_per_row = cols // 2.

    For GF256 (element_bits=8):
        One element per byte.
        bytes_per_row = cols.

    Args:
        matrix: 2D list matrix[row][col]
        element_bits: 4 for GF16, 8 for GF256
        rows: Number of rows in the output
        cols: Number of columns in the output

    Returns:
        Packed bytearray in row-major order
    """
    if element_bits == 4:
        bytes_per_row = cols // 2
        total_bytes = rows * bytes_per_row
        packed_data = bytearray(total_bytes)
        for r in range(rows):
            row_byte_offset = r * bytes_per_row
            for c in range(cols):
                byte_idx = row_byte_offset + (c // 2)
                val = matrix[r][c] & 0x0F
                if c % 2 == 0:
                    packed_data[byte_idx] |= val
                else:
                    packed_data[byte_idx] |= (val << 4)
        return packed_data
    elif element_bits == 8:
        total_bytes = rows * cols
        packed_data = bytearray(total_bytes)
        for r in range(rows):
            row_byte_offset = r * cols
            for c in range(cols):
                byte_idx = row_byte_offset + c
                packed_data[byte_idx] = matrix[r][c] & 0xFF
        return packed_data
    else:
        raise ValueError(f"Unsupported element_bits: {element_bits}")


# --------------------------------------------------------------------------- #
#  Random Matrix Generation
# --------------------------------------------------------------------------- #

def generate_random_matrix(params, seed: int = None) -> bytearray:
    """
    Generate a random column-major matrix as raw bytes.

    For GF16: All bytes are random (full 64x64 matrix, no padding rows).
    For GF256: Only data rows (0..o-1) get random data per column;
               padding rows (o..input_rows-1) are zero.

    Args:
        params: OVParams instance with transpose_input_rows, transpose_input_cols, gf, o
        seed: Optional random seed

    Returns:
        bytearray of the input matrix in column-major byte layout
    """
    if seed is not None:
        random.seed(seed)

    element_bits = 4 if params.gf == 16 else 8
    input_rows = params.transpose_input_rows
    input_cols = params.transpose_input_cols

    if element_bits == 4:
        # GF16: bytes_per_col = rows // 2, total = cols * bytes_per_col
        bytes_per_col = input_rows // 2
        total_size = input_cols * bytes_per_col
        return bytearray([random.randint(0, 255) for _ in range(total_size)])
    else:
        # GF256: column-major with zero-padding rows
        total_size = input_rows * input_cols
        data = bytearray(total_size)
        data_rows = params.o  # Only rows 0..o-1 have data
        for col in range(input_cols):
            col_offset = col * input_rows
            for row in range(data_rows):
                data[col_offset + row] = random.randint(0, 255)
            # Rows data_rows..input_rows-1 remain zero (padding)
        return data


# --------------------------------------------------------------------------- #
#  Reference Computation
# --------------------------------------------------------------------------- #

def compute_transpose_reference(input_data: bytearray, params) -> bytearray:
    """
    Compute the expected transpose output.

    Process:
    1. Unpack input (column-major) into a logical matrix
    2. Copy the data portion (rows 0..data_rows-1, cols 0..data_cols-1)
       into the output matrix
    3. Pack the output (row-major) with appropriate padding

    For GF16 (Is): 64x64 -> 64x64, data portion is 64x64 (no padding),
                    this is a pure col-major to row-major conversion.
    For GF256 (Ip): 64x44 -> 44x64, data portion is 44x44,
                     output columns 44-63 are zero padding.

    Args:
        input_data: Raw input bytes (column-major)
        params: OVParams instance

    Returns:
        Expected output bytearray (row-major)
    """
    element_bits = 4 if params.gf == 16 else 8
    input_rows = params.transpose_input_rows
    input_cols = params.transpose_input_cols
    output_rows = params.transpose_output_rows
    output_cols = params.transpose_output_cols

    # Step 1: Unpack input (column-major)
    M_input = unpack_matrix(input_data, element_bits, input_rows, input_cols)

    # Step 2: Create output matrix (initialized to zeros for padding)
    M_output = [[0 for _ in range(output_cols)] for _ in range(output_rows)]

    # Step 3: Copy data portion.
    # data_rows = output_rows (the non-padding rows in input = rows in output)
    # data_cols = input_cols  (the columns in input = non-padding cols in output)
    data_rows = output_rows
    data_cols = input_cols
    for r in range(data_rows):
        for c in range(data_cols):
            M_output[r][c] = M_input[r][c]

    # Step 4: Pack as row-major
    return pack_matrix(M_output, element_bits, output_rows, output_cols)


# --------------------------------------------------------------------------- #
#  Debug Dump
# --------------------------------------------------------------------------- #

def write_256bit_dump(f: TextIO, data: bytes, start_addr: int) -> None:
    """
    Write data as 256-bit Little Endian words.
    Format: 0xAddress : 0x<64 hex chars>
    """
    chunk_size = 32  # 256 bits = 32 bytes
    for i in range(0, len(data), chunk_size):
        chunk = data[i : i + chunk_size]
        if len(chunk) < chunk_size:
            chunk = chunk + b'\x00' * (chunk_size - len(chunk))
        val_int = int.from_bytes(chunk, byteorder='little')
        current_addr = start_addr + i
        f.write(f"0x{current_addr:06x}: 0x{val_int:064x}\n")


def debug_dump_matrices_to_file(
    sim,
    input_bytes: bytes,
    input_addr: int,
    output_addr: int,
    output_size: int,
    output_dir: str,
) -> None:
    """
    Write input (pre-execution) and output (post-execution) as 256-bit words
    to 'matrix_dump.txt' in *output_dir*.

    Args:
        sim: ACC simulator instance (after execution)
        input_bytes: Original input data BEFORE execution
        input_addr: Memory address where input was stored
        output_addr: Memory address where output is stored
        output_size: Number of output bytes to extract
        output_dir: Directory for output files
    """
    filepath = os.path.join(output_dir, "matrix_dump.txt")
    print(f"[DEBUG] Dumping 256-bit word state to: {filepath}")

    os.makedirs(output_dir, exist_ok=True)

    dmem_dump = sim.state.dmem.dump_le_words(include_validity=False)
    output_bytes = extract_bytes_from_dmem(dmem_dump, output_addr, output_size)

    with open(filepath, "w") as f:
        f.write("=" * 80 + "\n")
        f.write(" ACC 256-BIT MEMORY DUMP\n")
        f.write("=" * 80 + "\n\n")

        f.write(f"--- INPUT DATA (Start: 0x{input_addr:x}) ---\n")
        write_256bit_dump(f, input_bytes, input_addr)

        f.write(f"\n--- OUTPUT DATA (Start: 0x{output_addr:x}) ---\n")
        write_256bit_dump(f, output_bytes, output_addr)

        f.write("\n" + "=" * 80 + "\n")


# --------------------------------------------------------------------------- #
#  Single Test Runner
# --------------------------------------------------------------------------- #

def run_transpose_test(
    test_num: int,
    elf_path: str,
    params,
    verbose: bool = False,
    output_dir: str = "output",
    dump_regs_file: TextIO = None,
    dump_stats_file: TextIO = None,
    seed: int = None,
) -> bool:
    """
    Run a single transpose test iteration.

    Args:
        test_num: Iteration index (0-based, added to the seed)
        elf_path: Path to ELF file
        params: OVParams instance
        verbose: Verbose ACC output
        output_dir: Directory for debug dumps
        dump_regs_file: Optional register dump file handle
        dump_stats_file: Optional stats dump file handle
        seed: Base random seed (default 0); iteration i uses seed + i

    Returns:
        True if test passed, False otherwise
    """
    element_bits = 4 if params.gf == 16 else 8
    output_rows = params.transpose_output_rows
    output_cols = params.transpose_output_cols
    input_addr = params.transpose_input_addr
    output_addr = input_addr  # Output overwrites input (in-place)

    # Compute sizes
    if element_bits == 4:
        bytes_per_row_out = output_cols // 2
        total_output_size = output_rows * bytes_per_row_out
    else:
        total_output_size = output_rows * output_cols

    print(f"\n--- Iteration {test_num + 1} ---")

    # One matrix per iteration: seed + iteration (seed 0 when none is given)
    input_bytes = generate_random_matrix(params, seed=(seed or 0) + test_num)

    # Compute expected output
    expected_output_bytes = compute_transpose_reference(input_bytes, params)

    # Inject and run
    input_words = bytes_to_dmem_words(
        data=input_bytes,
        base_addr=input_addr,
        pad_to_size=None,
    )

    success, dmem_bytes, sim = run_acc_test(
        elf_path=elf_path,
        dmem_words=input_words,
        verbose=verbose,
        dump_regs_file=dump_regs_file,
        dump_stats_file=dump_stats_file,
    )

    if not success or sim is None:
        print("[ERROR] ACC simulation failed")
        return False

    # Debug dump
    debug_dump_matrices_to_file(
        sim, input_bytes, input_addr, output_addr, total_output_size, output_dir,
    )

    # Validate
    actual_output_bytes = extract_bytes_from_dmem(dmem_bytes, output_addr, total_output_size)

    label = f"GF{params.gf} Transpose"
    if element_bits == 4:
        label += " (Full Matrix)"
    else:
        label += f" ({output_rows}x{output_cols} padded)"

    match, mismatches = validate_bytes(expected_output_bytes, actual_output_bytes, label)

    if match:
        print(f"Test PASSED")
        return True
    else:
        print(f"Test FAILED - {len(mismatches)} byte mismatches")
        if element_bits == 8:
            for idx in mismatches[:10]:
                print(f"  Mismatch at byte {idx}: expected 0x{expected_output_bytes[idx]:02x}, got 0x{actual_output_bytes[idx]:02x}")
            if len(mismatches) > 10:
                print(f"  ... and {len(mismatches) - 10} more mismatches")
        return False


# --------------------------------------------------------------------------- #
#  CLI Entry Point
# --------------------------------------------------------------------------- #

def transpose_main(params) -> int:
    """
    CLI entry point for matrix transpose tests.

    Args:
        params: OV parameter set (OV_IS or OV_IP)

    Returns:
        Exit code: 0 if all passed, 1 otherwise
    """
    from acc_sim_utils import create_common_argparser, run_test_suite

    field = f"GF({'16' if params.gf == 16 else '256'})"
    in_rows = params.transpose_input_rows
    in_cols = params.transpose_input_cols
    out_rows = params.transpose_output_rows
    out_cols = params.transpose_output_cols

    parser = create_common_argparser(
        f"{field} {out_rows}x{out_cols} Transpose Test",
        default_elf=params.default_transpose_elf,
        default_iterations=1,
    )
    args = parser.parse_args()

    output_dir = args.output_dir or "output"

    print(f"\nConfiguration:")
    print(f"  Field: {field}")
    print(f"  Input matrix:  {in_rows}x{in_cols} (col-major)")
    print(f"  Output matrix: {out_rows}x{out_cols} (row-major)")
    print(f"  ELF: {args.elf}")

    def test_func(i, regs_f, stats_f):
        return run_transpose_test(
            test_num=i,
            elf_path=args.elf,
            params=params,
            verbose=args.verbose,
            output_dir=output_dir,
            dump_regs_file=regs_f,
            dump_stats_file=stats_f,
            seed=args.seed,
        )

    return run_test_suite(
        f"{field}_Transpose_{out_rows}x{out_cols}", test_func,
        elf_path=args.elf,
        iterations=args.iterations,
        output_dir=args.output_dir,
        seed=args.seed,
    )
