"""
OV ExpandSK Test Utilities

Shared functions for testing the SHAKE256-based secret key expansion:
  sk_seed (32 bytes) -> SHAKE256 -> pk_seed (16 bytes) + O matrix

Supports both OV-Is (GF16) and OV-Ip (GF256) parameter sets via OVParams.
"""

import hashlib
import os
import random
from typing import Tuple

from dmem_utils import (
    extract_bytes_from_dmem,
    bytes_to_dmem_words,
)
from acc_sim_utils import (
    run_acc_test,
    print_test_header,
)
from ov_params import OVParams

# pk_seed lives in a single WDR-aligned 32-byte slot; the actual seed is
# params.len_pkseed bytes (16) and the rest is zero padding.
_PKSEED_SLOT_BYTES = 32


def compute_expandsk_reference(
    sk_seed: bytes,
    params: OVParams,
) -> Tuple[bytes, bytes]:
    """
    Generate SHAKE256 digest from sk_seed (reference implementation).

    Args:
        sk_seed: 32-byte secret key seed
        params: OV parameter set (provides len_pkseed, o_size)

    Returns:
        Tuple of (pk_seed, O_matrix)
        - pk_seed: params.len_pkseed bytes (16)
        - O_matrix: params.o_size bytes
    """
    total_digest_size = params.len_pkseed + params.o_size
    shake = hashlib.shake_256()
    shake.update(sk_seed)
    digest = shake.digest(total_digest_size)

    pk_seed = digest[:params.len_pkseed]
    O_matrix = digest[params.len_pkseed:]

    return pk_seed, O_matrix


def build_expandsk_words(
    sk_seed: bytes,
    params: OVParams,
) -> dict:
    """
    Build DMEM word dict for sk_seed at the expandsk_skseed_addr.

    Args:
        sk_seed: 32-byte secret key seed
        params: OV parameter set (provides expandsk_skseed_addr)

    Returns:
        Dict mapping DMEM word addresses to 32-bit values.
    """
    return bytes_to_dmem_words(bytearray(sk_seed), params.expandsk_skseed_addr)


def extract_expandsk_result(
    dmem_bytes: bytes,
    params: OVParams,
) -> Tuple[bytes, bytes, bytes]:
    """
    Extract pk_seed (padded) and O matrix from DMEM.

    For variants with padding (o_size != o_size_padded), also extracts
    the padded O region for trailing-zero validation.

    Args:
        dmem_bytes: Raw DMEM contents
        params: OV parameter set

    Returns:
        Tuple of (pk_seed_padded, O_matrix, O_matrix_padded)
        - pk_seed_padded: 32 bytes (16-byte pk_seed + 16 trailing zeros)
        - O_matrix: params.o_size bytes (actual data only)
        - O_matrix_padded: params.o_size_padded bytes (data + alignment padding)
          (same as O_matrix when o_size == o_size_padded)
    """
    # Extract pk_seed (32 bytes: 16-byte value + 16 zero-pad)
    pk_seed_padded = extract_bytes_from_dmem(dmem_bytes, params.expandsk_pkseed_addr, _PKSEED_SLOT_BYTES)

    # Extract O matrix (padded size for full validation)
    O_matrix_padded = extract_bytes_from_dmem(dmem_bytes, params.expandsk_o_addr, params.o_size_padded)
    O_matrix = bytes(O_matrix_padded[:params.o_size])

    return bytes(pk_seed_padded), O_matrix, bytes(O_matrix_padded)


def _write_expected_file(
    filepath: str,
    sk_seed: bytes,
    expected_pk_seed_padded: bytes,
    expected_O: bytes,
    params: OVParams,
) -> None:
    """Write expected results to a text file."""
    with open(filepath, "w") as f:
        f.write(f"Expected Output from expandsk_ret_O_pkseed ({params.name})\n")
        f.write("=" * 80 + "\n\n")
        f.write("sk_seed (32 bytes):\n")
        f.write(f"  {sk_seed.hex()}\n\n")
        f.write(f"pk_seed ({params.len_pkseed} bytes, padded to 32 with trailing zeros):\n")
        for i in range(0, 32, 16):
            chunk = expected_pk_seed_padded[i:i + 16]
            f.write(f"  {chunk.hex(' ')}\n")
        f.write(f"\nO matrix ({len(expected_O)} bytes):\n")
        for i in range(0, min(len(expected_O), 256), 32):
            chunk = expected_O[i:i + 32]
            hex_str = chunk.hex(' ')
            f.write(f"  0x{i:04x}: {hex_str}\n")
        if len(expected_O) > 256:
            f.write(f"  ... ({len(expected_O) - 256} more bytes)\n")


def _write_actual_file(
    filepath: str,
    actual_pk_seed_padded: bytes,
    actual_O: bytes,
    params: OVParams,
) -> None:
    """Write actual results to a text file."""
    with open(filepath, "w") as f:
        f.write(f"Actual Output from ACC expandsk_ret_O_pkseed ({params.name})\n")
        f.write("=" * 80 + "\n\n")
        f.write("pk_seed (padded 32 bytes from DMEM):\n")
        for i in range(0, 32, 16):
            chunk = actual_pk_seed_padded[i:i + 16]
            f.write(f"  {chunk.hex(' ')}\n")
        f.write(f"\nO matrix ({len(actual_O)} bytes from DMEM):\n")
        for i in range(0, min(len(actual_O), 256), 32):
            chunk = actual_O[i:i + 32]
            hex_str = chunk.hex(' ')
            f.write(f"  0x{params.expandsk_o_addr + i:04x}: {hex_str}\n")
        if len(actual_O) > 256:
            f.write(f"  ... ({len(actual_O) - 256} more bytes)\n")


def _write_dmem_file(
    filepath: str,
    dmem_bytes: bytes,
    params: OVParams,
) -> None:
    """Write full DMEM dump to a text file."""
    with open(filepath, "w") as f:
        f.write("Full DMEM Contents After Execution\n")
        f.write("=" * 80 + "\n\n")
        f.write("Key addresses:\n")
        f.write(f"  sk_seed:  0x{params.expandsk_skseed_addr:04x}\n")
        f.write(f"  pk_seed:  0x{params.expandsk_pkseed_addr:04x}\n")
        f.write(f"  O matrix: 0x{params.expandsk_o_addr:04x}\n\n")
        dump_end = params.expandsk_pkseed_addr + 32 + params.o_size
        for i in range(params.expandsk_pkseed_addr, dump_end, 32):
            chunk = dmem_bytes[i:i + 32]
            hex_str = chunk.hex(' ')
            f.write(f"  0x{i:04x}: {hex_str}\n")


def run_expandsk_test(
    test_num: int,
    output_dir: str,
    params: OVParams,
    elf_path: str = None,
    verbose: bool = False,
) -> Tuple[bool, str]:
    """
    Run a single expandsk test iteration.

    Generates a random sk_seed, computes the expected SHAKE256 output,
    runs the ACC simulation, and validates pk_seed + O matrix.

    For Ip (where o_size != o_size_padded), also validates that the
    trailing padding bytes are all zeros.

    For Ip, also validates sk_seed region integrity (no corruption).

    Args:
        test_num: Test iteration number
        output_dir: Output directory for test artifacts
        params: OV parameter set
        elf_path: Path to ELF file (uses params.default_expandsk_elf if None)
        verbose: Enable verbose ACC simulation output

    Returns:
        Tuple of (success, message)
    """
    variant_label = "OV-Is" if params.gf == 16 else "OV-Ip"
    print_test_header(f"Test {test_num}: expandsk_ret_O_pkseed ({variant_label})", width=80)

    # Generate random sk_seed
    sk_seed = bytes(random.randint(0, 255) for _ in range(params.len_skseed))
    print(f"sk_seed: {sk_seed.hex()}")

    # Compute expected output using Python SHAKE256
    expected_pk_seed, expected_O = compute_expandsk_reference(sk_seed, params)
    print(f"Expected pk_seed ({params.len_pkseed} bytes): {expected_pk_seed.hex()}")
    print(f"Expected O size: {len(expected_O)} bytes")

    # Zero-pad pk_seed to 32 bytes (16 bytes pk_seed + 16 trailing zeros)
    expected_pk_seed_padded = expected_pk_seed + b'\x00' * (_PKSEED_SLOT_BYTES - params.len_pkseed)
    print(f"Expected pk_seed (padded 32 bytes): {expected_pk_seed_padded.hex()}")

    # Pad O to 32-byte boundary if needed
    needs_o_padding = params.o_size != params.o_size_padded
    if needs_o_padding:
        if params.o_slot_bytes:
            raise NotImplementedError(
                f"{params.name}: O uses {params.o_slot_bytes}-byte per-column "
                "slots; the trailing-pad model below does not describe it")
        expected_O_padded = expected_O + b'\x00' * (params.o_size_padded - params.o_size)

    # Build DMEM injection words
    words = build_expandsk_words(sk_seed, params)

    # Run ACC simulation
    print("Running ACC simulation...")
    _elf = elf_path or os.path.abspath(params.default_expandsk_elf)
    success, dmem_bytes, sim = run_acc_test(
        elf_path=_elf,
        dmem_words=words,
        verbose=verbose,
    )

    if not success:
        return False, "ACC simulation failed"

    # Extract results
    actual_pk_seed_padded, actual_O, actual_O_padded = extract_expandsk_result(dmem_bytes, params)

    print(f"Actual pk_seed (padded 32 bytes): {actual_pk_seed_padded.hex()}")
    print(f"Actual O size: {len(actual_O)} bytes")
    if needs_o_padding:
        print(f"Actual O size (padded): {len(actual_O_padded)} bytes")

    # Save output files
    test_prefix = f"test_{test_num}"
    _write_expected_file(
        os.path.join(output_dir, f"{test_prefix}_expected.txt"),
        sk_seed, expected_pk_seed_padded, expected_O, params,
    )
    _write_actual_file(
        os.path.join(output_dir, f"{test_prefix}_actual.txt"),
        actual_pk_seed_padded, actual_O, params,
    )
    _write_dmem_file(
        os.path.join(output_dir, f"{test_prefix}_dmem_full.txt"),
        dmem_bytes, params,
    )

    # Validate results
    messages = []
    overall_success = True

    # Ip only: sk_seed integrity check (no write should corrupt input region)
    if needs_o_padding:
        actual_sk_seed = extract_bytes_from_dmem(dmem_bytes, params.expandsk_skseed_addr, _PKSEED_SLOT_BYTES)
        if bytes(actual_sk_seed) == sk_seed:
            messages.append(f"\u2713 sk_seed region intact (0x{params.expandsk_skseed_addr:04x}-"
                            f"0x{params.expandsk_skseed_addr + 31:04x}, no corruption)")
        else:
            messages.append("\u2717 sk_seed region corrupted!")
            messages.append(f"  Expected: {sk_seed.hex()}")
            messages.append(f"  Actual:   {bytes(actual_sk_seed).hex()}")
            overall_success = False

    # Compare pk_seed (padded)
    if actual_pk_seed_padded == expected_pk_seed_padded:
        pkseed_desc = (f"{_PKSEED_SLOT_BYTES} bytes: {params.len_pkseed}-byte value + "
                       f"{_PKSEED_SLOT_BYTES - params.len_pkseed} trailing zeros")
        messages.append(f"\u2713 pk_seed matches ({pkseed_desc})")
    else:
        messages.append("\u2717 pk_seed mismatch!")
        messages.append(f"  Expected: {expected_pk_seed_padded.hex()}")
        messages.append(f"  Actual:   {actual_pk_seed_padded.hex()}")
        overall_success = False

    # Compare O matrix data
    if actual_O == expected_O:
        gf_label = "GF16" if params.gf == 16 else "GF256"
        messages.append(f"\u2713 O matrix data matches ({params.o_size} bytes, {gf_label})")
    else:
        messages.append("\u2717 O matrix data mismatch!")
        messages.append(f"  Expected size: {len(expected_O)} bytes")
        messages.append(f"  Actual size:   {len(actual_O)} bytes")
        for i in range(min(len(expected_O), len(actual_O))):
            if expected_O[i] != actual_O[i]:
                messages.append(f"  First difference at byte {i}: "
                                f"expected 0x{expected_O[i]:02x}, got 0x{actual_O[i]:02x}")
                break
        overall_success = False

    # Ip only: O matrix alignment padding (trailing zeros)
    if needs_o_padding:
        if actual_O_padded == expected_O_padded:
            messages.append(f"\u2713 O matrix alignment padding correct "
                            f"(0x{params.expandsk_o_addr + params.o_size:04x}-"
                            f"0x{params.expandsk_o_addr + params.o_size_padded - 1:04x} are zero)")
        else:
            pad_actual = actual_O_padded[params.o_size:]
            pad_expected = expected_O_padded[params.o_size:]
            messages.append(f"\u2717 O matrix alignment padding mismatch "
                            f"(0x{params.expandsk_o_addr + params.o_size:04x}-"
                            f"0x{params.expandsk_o_addr + params.o_size_padded - 1:04x})!")
            messages.append(f"  Expected (zeros): {pad_expected.hex()}")
            messages.append(f"  Actual:           {pad_actual.hex()}")
            overall_success = False

    if overall_success:
        messages.append("\n\u2713 All validations passed!")
    else:
        messages.append("\n\u2717 Some validations failed!")

    return overall_success, "\n".join(messages)


def expandsk_main(params) -> int:
    """
    CLI entry point for expandsk tests.

    Args:
        params: OV parameter set (OV_IS or OV_IP)

    Returns:
        Exit code: 0 if all passed, 1 otherwise
    """
    from acc_sim_utils import create_common_argparser, run_test_suite

    parser = create_common_argparser(
        f"OV {params.name} ExpandSK Test",
        default_elf=params.default_expandsk_elf,
        default_iterations=10,
    )
    args = parser.parse_args()

    print(f"\nConfiguration:")
    print(f"  Params: {params.name}")
    print(f"  Field: GF({params.gf})")
    print(f"  ELF: {args.elf}")

    # run_expandsk_test returns (bool, str) and does not accept dump files
    def test_func(i, regs_f, stats_f):
        success, msg = run_expandsk_test(
            test_num=i,
            output_dir=getattr(args, 'output_dir', None) or '.',
            params=params,
            elf_path=args.elf,
            verbose=args.verbose,
        )
        if msg:
            print(msg)
        return success

    return run_test_suite(
        f"ExpandSK_{params.name}", test_func,
        elf_path=args.elf,
        iterations=args.iterations,
        output_dir=getattr(args, 'output_dir', None),
        seed=getattr(args, 'seed', None),
    )
