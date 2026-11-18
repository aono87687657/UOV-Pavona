"""
OV Trimat Eval Test Utilities

Shared helpers for batch_quad_trimat_eval tests (GF16 and GF256 variants).

Evaluates the upper-triangular quadratic form:

    y^{k} = sum_{i=0}^{v-1} sum_{j=i}^{v-1} P^{k}_{i,j} * x_i * x_j

where P1 is expanded from pk_seed via AES-CTR (delegated to ov_pk_utils).

GF16 (OV-Is): 96 vinegar vars, 32-byte batched output, gf16v_madd arithmetic.
GF256 (OV-Ip): 68 vinegar vars, 44-byte batched output, gf256v_madd arithmetic.

Extracted from batch_quad_trimat_eval_gf16.py and batch_quad_trimat_eval_gf256.py.
"""

import random
from typing import TextIO

from ov_params import OVParams
from ov_pk_utils import expand_p1p2_from_pkseed
from dmem_utils import (
    extract_bytes_from_dmem,
    bytes_to_dmem_words,
    validate_bytes,
)
from acc_sim_utils import (
    run_acc_test,
    create_common_argparser,
    run_test_suite,
)
from gf_arithmetic import (
    gf16v_madd,
    gfv_get_ele_gf16,
    gf256v_madd,
)


###########################################
# P1 EXPANSION (via ov_pk_utils)
###########################################

def expand_p1_from_pkseed(pk_seed: bytes, params: OVParams) -> bytearray:
    """
    Expand pk_seed using AES-CTR to get P1 matrix only.

    Delegates to expand_p1p2_from_pkseed and returns only the P1 portion.

    Args:
        pk_seed: 16-byte public key seed (used as AES key)
        params: OV parameter set

    Returns:
        P1 bytes (upper triangular, row-major)
    """
    p1p2 = expand_p1p2_from_pkseed(bytearray(pk_seed), params)
    return bytearray(p1p2[:params.p1_size])


###########################################
# REFERENCE COMPUTATION
###########################################

def compute_batch_trimat_eval_reference(
    p1: bytes,
    vinegar: bytes,
    params: OVParams,
) -> bytes:
    """
    Reference implementation of batch_quad_trimat_eval.

    Computes:
        y^{k} = sum_{i=0}^{dim-1} sum_{j=i}^{dim-1} P^{k}_{i,j} * x_i * x_j

    for each equation k in [0, m).

    The algorithm processes row by row:
        for each row i:
            tmp = P[i, i..dim-1] . x[i..dim-1]     (RIGHT-SIDE)
            y  += x[i] * tmp                        (LEFT-SIDE)

    Args:
        p1: Upper-triangular matrix P1, flat layout (row-major)
        vinegar: Vinegar vector (nibble-packed for GF16, byte-packed for GF256)
        params: OV parameter set

    Returns:
        y: pub_m_byte bytes (the batched quadratic evaluation result)
    """
    dim = params.v
    size_batch = params.pub_m_byte
    is_gf16 = (params.gf == 16)

    # Initialize output
    y = bytearray(size_batch)

    # Process P1 row by row
    offset = 0
    for i in range(dim):
        row_len = dim - i

        # ---- RIGHT SIDE: tmp = sum_{j>=i} P[i,j] * x[j] ----
        tmp = bytearray(size_batch)
        for j in range(row_len):
            entry = p1[offset + j * size_batch : offset + (j + 1) * size_batch]
            if is_gf16:
                x_elem = gfv_get_ele_gf16(vinegar, i + j)
                gf16v_madd(tmp, entry, x_elem)
            else:
                x_elem = vinegar[i + j]
                gf256v_madd(tmp, entry, x_elem)

        # ---- LEFT SIDE: y += x[i] * tmp ----
        if is_gf16:
            x_i = gfv_get_ele_gf16(vinegar, i)
            gf16v_madd(y, tmp, x_i)
        else:
            x_i = vinegar[i]
            gf256v_madd(y, tmp, x_i)

        offset += row_len * size_batch

    return bytes(y)


###########################################
# DATA INJECTION
###########################################

def build_trimat_eval_words(
    pk_seed: bytes,
    vinegar: bytes,
    params: OVParams,
) -> dict:
    """
    Build DMEM word dict for pk_seed and vinegar vector for trimat eval test.

    Padding rules:
      - pk_seed: 16 bytes padded to 32 in DMEM (pad_to_size=32)
      - Vinegar: GF16 = 48 bytes padded to 64; GF256 = 68 bytes padded to 96

    Args:
        pk_seed: 16-byte public key seed
        vinegar: Vinegar vector bytes
        params: OV parameter set (provides DMEM addresses)

    Returns:
        Dict mapping DMEM word addresses to 32-bit values.
    """
    words = {}

    # pk_seed (16 bytes, padded to 32)
    pk_seed_padded = pk_seed + b'\x00' * 16
    words.update(bytes_to_dmem_words(
        bytearray(pk_seed_padded), params.trimat_eval_pkseed_addr))

    # Vinegar with appropriate padding
    if params.gf == 16:
        # GF16: 48 bytes (96 nibbles), pad to 64
        vinegar_padded = vinegar + b'\x00' * (64 - len(vinegar))
    else:
        # GF256: 68 bytes, pad to 96 (3 WDRs)
        vinegar_padded = vinegar + b'\x00' * (96 - len(vinegar))
    words.update(bytes_to_dmem_words(
        bytearray(vinegar_padded), params.trimat_eval_vinegar_addr))

    print(f"  Injected pk_seed at 0x{params.trimat_eval_pkseed_addr:x}: {pk_seed[:8].hex()}...")
    print(f"  Injected vinegar at 0x{params.trimat_eval_vinegar_addr:x}: {vinegar[:16].hex()}...")

    return words


###########################################
# TEST DATA GENERATION
###########################################

def _generate_random_pkseed() -> bytes:
    """Generate random 16-byte pk_seed."""
    return bytes([random.randint(0, 255) for _ in range(16)])


def _generate_random_vinegar(params: OVParams) -> bytes:
    """Generate random vinegar vector with correct size for the parameter set."""
    if params.gf == 16:
        # GF16: v/2 bytes (nibble-packed)
        return bytes([random.randint(0, 255) for _ in range(params.v // 2)])
    else:
        # GF256: v bytes (1 byte per element)
        return bytes([random.randint(0, 255) for _ in range(params.v)])


###########################################
# SINGLE TEST
###########################################

def run_trimat_eval_test(
    test_num: int,
    elf_path: str,
    params: OVParams,
    verbose: bool = False,
    dump_regs_file: TextIO = None,
    dump_stats_file: TextIO = None,
) -> bool:
    """
    Run a single batch_quad_trimat_eval test iteration.

    Args:
        test_num: Iteration number (0-based)
        elf_path: Path to the ELF binary
        params: OV parameter set
        verbose: Enable verbose output
        dump_regs_file: Optional file for register dumps
        dump_stats_file: Optional file for statistics

    Returns:
        True if test passed, False otherwise
    """
    print(f"\n{'='*60}")
    print(f"Test Iteration {test_num + 1}")
    print(f"{'='*60}")

    # Generate random test data
    pk_seed = _generate_random_pkseed()
    vinegar = _generate_random_vinegar(params)

    print(f"\n--- Generated Test Data ---")
    print(f"  pk_seed: {pk_seed.hex()}")
    print(f"  vinegar (first 16): {vinegar[:16].hex()}")

    # Compute reference result
    print(f"\n--- Computing Reference ---")
    p1 = expand_p1_from_pkseed(pk_seed, params)
    print(f"  P1 expanded: {len(p1):,} bytes")

    expected_result = compute_batch_trimat_eval_reference(p1, vinegar, params)
    print(f"  Expected result: {expected_result.hex()}")

    # Run ACC simulation
    print(f"\n--- Running ACC Simulation ---")

    words = build_trimat_eval_words(pk_seed, vinegar, params)

    success, dmem_bytes, sim = run_acc_test(
        elf_path=elf_path,
        dmem_words=words,
        verbose=verbose,
        dump_regs_file=dump_regs_file,
        dump_stats_file=dump_stats_file,
    )

    if not success:
        print("FAIL: ACC simulation failed")
        return False

    # Extract and validate result
    print(f"\n--- Validation ---")
    actual_result = extract_bytes_from_dmem(
        dmem_bytes, params.trimat_eval_result_addr, params.pub_m_byte)
    print(f"  Actual result:   {bytes(actual_result).hex()}")

    gf_label = "gf16" if params.gf == 16 else "gf256"
    success, mismatches = validate_bytes(
        expected_result, actual_result, f"batch_quad_trimat_eval_{gf_label}")

    if success:
        print(f"PASS: Test passed")
    else:
        print(f"FAIL: Test FAILED: {len(mismatches)} byte mismatches")
        for idx in mismatches[:5]:
            exp_val = expected_result[idx]
            act_val = actual_result[idx]
            print(f"    Byte {idx}: expected 0x{exp_val:02x}, got 0x{act_val:02x}")

    return success


###########################################
# MAIN ENTRY POINT
###########################################

def trimat_eval_main(params: OVParams) -> int:
    """
    Standard main() for batch_quad_trimat_eval test wrappers.

    Parses CLI args, prints configuration, runs iterations via run_test_suite.

    Args:
        params: OV parameter set (OV_IS or OV_IP)

    Returns:
        Exit code (0 = all passed, 1 = some failed)
    """
    gf_label = "GF16" if params.gf == 16 else "GF256"
    test_name = f"Batch_Quad_Trimat_{gf_label}"

    # Default iterations: GF16 is faster so default to 10; GF256 defaults to 1
    default_iters = 10 if params.gf == 16 else 1

    parser = create_common_argparser(
        f"{test_name} Test",
        default_elf=params.default_trimat_eval_elf,
        default_iterations=default_iters,
    )
    args = parser.parse_args()

    print(f"\nConfiguration:")
    print(f"  V={params.v} (vinegar variables)")
    print(f"  M={params.pub_m} (equations)")
    print(f"  P1 size: {params.p1_size:,} bytes ({params.v * (params.v + 1) // 2} monomials x {params.pub_m_byte} bytes)")
    print(f"  Result size: {params.pub_m_byte} bytes")
    print(f"  ELF: {args.elf}")

    def test_func(i, regs_f, stats_f):
        return run_trimat_eval_test(
            i, args.elf, params, args.verbose, regs_f, stats_f)

    return run_test_suite(
        test_name, test_func,
        elf_path=args.elf,
        iterations=args.iterations,
        output_dir=args.output_dir,
        seed=args.seed,
    )
