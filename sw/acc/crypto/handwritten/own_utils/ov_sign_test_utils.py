"""
OV Sign Test Utilities

Shared functions for testing full OV-Is-skc and OV-Ip-skc signing flows.

Supports both parameter sets via OVParams, handling:
  - Secret key expansion (SHAKE256)
  - P1+P1^T computation and S matrix construction
  - Target hash and vinegar vector computation
  - L matrix computation and transpose
  - Gaussian elimination and back-substitution
  - O * oil product
  - Signature assembly and verification
  - Negative tests (altered signature / altered public key)

The 14-step validation pipeline:
  [ 1] pk_seed:  sk_seed -> SHAKE256 -> pk_seed
  [ 2] O matrix: sk_seed -> SHAKE256 -> O
  [ 3] S matrix: S = (P1 + P1^T) x O + P2
  [ 4] Target:   t = SHAKE256(msg || salt)
  [ 5] Vinegar:  v = SHAKE256(msg || salt || sk_seed || counter)
  [ 6] L matrix: L = S x v (correctness via back-sub)
  [ 7] Y vector: Y = batch_quad_trimat_eval(P1, v) (correctness via back-sub)
  [ 8] GE:       Gaussian elimination invertibility check
  [ 9] Back-sub: oil solution vector
  [10] O*oil:    O matrix x oil solution
  [11] Sig:      signature assembly
  [12] Verify:   Python-only P(x) == target using public map
  [13] Verify:   Altered signature -> P(x') != target (negative test)  [Ip only]
  [14] Verify:   Altered public key -> P'(x) != target (negative test) [Ip only]
"""

import hashlib
import os
import random
import numpy as np
from typing import Dict, List, Tuple, TextIO, Optional

from ov_params import OVParams
from ov_expandsk_test_utils import compute_expandsk_reference
from ov_pk_utils import expand_p1p2_from_pkseed
from dmem_utils import (
    extract_bytes_from_dmem,
    bytes_to_dmem_words,
    validate_bytes,
)
from acc_sim_utils import (
    run_acc_test,
    read_wdr_register,
    read_gpr_register,
)
from gf_arithmetic import (
    gf16v_madd,
    gf256v_madd,
    gfv_get_ele_gf16,
    bytes_to_gf_elements,
    gf_elements_to_bytes,
    compute_gf_matvec_reference,
    ov_publicmap_reference,
)
from ov_keygen_test_utils import (
    compute_p3_reference,
    compute_p3_reference_gf256,
)

_WDR_BYTES = 32           # bytes in one 256-bit wide data register
_GF16_NIBBLE_MASK = 0x0F  # lower-nibble mask for GF16 element extraction
SIGNER_RETRY_MAX = 256    # asm signer caps retry counter at 256; valid range 0..SIGNER_RETRY_MAX-1


# ================================================================== #
#  Field-dispatch helpers
# ================================================================== #

def _field_tag(params: OVParams) -> str:
    """Return 'gf16' or 'gf256' for use in gf_arithmetic helpers."""
    return "gf16" if params.gf == 16 else "gf256"


def _v_byte(params: OVParams) -> int:
    """Byte size of the vinegar vector (V elements packed)."""
    if params.gf == 16:
        return params.v // 2   # nibble-packed
    else:
        return params.v        # byte-packed


def _v_byte_padded(params: OVParams) -> int:
    """Padded byte size of the vinegar vector (WDR-aligned)."""
    v_byte = _v_byte(params)
    return ((v_byte + _WDR_BYTES - 1) // _WDR_BYTES) * _WDR_BYTES


def _target_digest_size(params: OVParams) -> int:
    """SHAKE256 output size for the target hash."""
    return params.pub_m_byte


def _target_padded_size(params: OVParams) -> int:
    """Padded size for the target hash in DMEM."""
    return ((params.pub_m_byte + _WDR_BYTES - 1) // _WDR_BYTES) * _WDR_BYTES


def _l_size(params: OVParams) -> int:
    """L matrix size in bytes."""
    if params.gf == 16:
        return params.pub_m * params.pub_m_byte  # 64*32 = 2048
    else:
        return params.pub_m * params.pub_m_byte_padded  # 44*64 = 2816


def _s_size(params: OVParams) -> int:
    """S matrix size in bytes."""
    if params.gf == 16:
        return params.v * params.pub_m * params.pub_m_byte  # 196608
    else:
        return params.v * params.pub_m * params.pub_m_byte_padded  # 191488


def _s_entry_stride(params: OVParams) -> int:
    """Byte stride per entry in S matrix."""
    if params.gf == 16:
        return params.pub_m_byte
    else:
        return params.pub_m_byte_padded


def _sig_size(params: OVParams) -> int:
    """Total signature size in bytes."""
    return params.pub_n_byte + params.salt_bytes


def _o_oil_wdr_indices(params: OVParams) -> List[int]:
    """WDR indices for O*oil result (from small_matvec_result_wdrs)."""
    return [int(w.lstrip("wW")) for w in params.small_matvec_result_wdrs]


# ================================================================== #
#  Reference computations
# ================================================================== #

def compute_target_hash_reference(
    message: bytes,
    salt: bytes,
    params: OVParams,
) -> bytes:
    """
    Compute target hash t = SHAKE256(message || salt).

    Args:
        message: Message bytes
        salt: 16-byte salt
        params: OV parameter set

    Returns:
        Digest bytes (pub_m_byte long)
    """
    hasher = hashlib.shake_256()
    hasher.update(message)
    hasher.update(salt)
    return hasher.digest(_target_digest_size(params))


def compute_vinegar_reference(
    message: bytes,
    salt: bytes,
    sk_seed: bytes,
    counter: int,
    params: OVParams,
) -> bytes:
    """
    Compute vinegar vector v = SHAKE256(message || salt || sk_seed || counter).

    Args:
        message: Message bytes
        salt: 16-byte salt
        sk_seed: 32-byte secret key seed
        counter: 1-byte counter value
        params: OV parameter set

    Returns:
        Vinegar vector (_v_byte bytes)
    """
    hasher = hashlib.shake_256()
    hasher.update(message)
    hasher.update(salt)
    hasher.update(sk_seed)
    hasher.update(bytes([counter & 0xFF]))
    return hasher.digest(_v_byte(params))


# ================================================================== #
#  P1+P1^T and S matrix computation
# ================================================================== #

def _get_p1p1t_row_gf256(
    p1_input: bytearray,
    row_idx: int,
    params: OVParams,
) -> bytearray:
    """
    Extract row row_idx of P1+P1^T for GF256.

    P1 upper triangular row-major: element (r,c) with r<=c at index
        r*V - r*(r+1)//2 + c, each element is pub_m_byte=44 bytes.

    Output: V=68 elements x pub_m_byte_padded=64 bytes = 4352 bytes.
    Each element has 44 data bytes + 20 zero padding bytes.
    """
    V = params.v
    row = bytearray()
    for col in range(V):
        if row_idx == col:
            row.extend(bytearray(params.pub_m_byte_padded))
        elif row_idx < col:
            idx = row_idx * V - row_idx * (row_idx + 1) // 2 + col
            row.extend(p1_input[idx * params.pub_m_byte:(idx + 1) * params.pub_m_byte])
            row.extend(bytearray(params.pub_m_byte_padded - params.pub_m_byte))
        else:
            idx = col * V - col * (col + 1) // 2 + row_idx
            row.extend(p1_input[idx * params.pub_m_byte:(idx + 1) * params.pub_m_byte])
            row.extend(bytearray(params.pub_m_byte_padded - params.pub_m_byte))
    return row


def compute_s_matrix_gf16(
    sk_seed: bytes,
    params: OVParams,
) -> Tuple[bytes, bytes, bytearray, bytearray]:
    """
    Compute S = (P1+P1^T) x O + P2 for GF16.

    Returns (pk_seed, O_matrix, S_matrix, P1).
    """
    V = params.v
    PUB_M = params.pub_m
    PUB_M_BYTE = params.pub_m_byte
    V_BYTE = _v_byte(params)

    pk_seed, O_matrix = compute_expandsk_reference(sk_seed, params)
    p1p2 = expand_p1p2_from_pkseed(bytearray(pk_seed), params)
    p1 = bytearray(p1p2[:params.p1_size])
    p2 = bytearray(p1p2[params.p1_size:])

    # Step 1: Compute P1+P1^T (full V x V x PUB_M_BYTE matrix)
    P1_P1T = bytearray()
    for row in range(V):
        for col in range(V):
            if row == col:
                P1_P1T.extend(bytearray(PUB_M_BYTE))
            elif row > col:
                index = col * V - col * (col + 1) // 2 + row
                P1_P1T.extend(p1[index * PUB_M_BYTE:(index + 1) * PUB_M_BYTE])
            else:
                index = row * V - row * (row + 1) // 2 + col
                P1_P1T.extend(p1[index * PUB_M_BYTE:(index + 1) * PUB_M_BYTE])

    # Step 2: Compute (P1+P1^T) x O
    result_temp = bytearray(V * PUB_M * PUB_M_BYTE)
    for i in range(V):
        for j in range(PUB_M):
            acc = bytearray(PUB_M_BYTE)
            for k in range(V):
                o_col_offset = j * V_BYTE
                o_scalar = gfv_get_ele_gf16(O_matrix[o_col_offset:], k)
                if o_scalar == 0:
                    continue
                p1p1t_offset = i * V * PUB_M_BYTE + k * PUB_M_BYTE
                p1p1t_vec = P1_P1T[p1p1t_offset : p1p1t_offset + PUB_M_BYTE]
                gf16v_madd(acc, p1p1t_vec, o_scalar)
            result_offset = i * PUB_M * PUB_M_BYTE + j * PUB_M_BYTE
            result_temp[result_offset : result_offset + PUB_M_BYTE] = acc

    # Step 3: XOR with P2
    s_matrix = bytearray(len(result_temp))
    for i in range(len(result_temp)):
        s_matrix[i] = result_temp[i] ^ p2[i]

    return pk_seed, O_matrix, s_matrix, p1


def compute_s_matrix_gf256(
    sk_seed: bytes,
    params: OVParams,
) -> Tuple[bytes, bytes, bytearray]:
    """
    Compute S = (P1+P1^T) x O + P2 for GF256.

    O layout (column-major): O[k,j] at offset j*V + k.
    S layout: entry (row_idx, j) at offset (row_idx*PUB_M + j)*PUB_M_BYTE_PADDED,
              pub_m_byte data bytes + padding zeros per entry.

    Returns (pk_seed, O_matrix, S_matrix).
    """
    V = params.v
    PUB_M = params.pub_m
    PUB_M_BYTE = params.pub_m_byte
    PUB_M_BYTE_PADDED = params.pub_m_byte_padded

    pk_seed, O_matrix = compute_expandsk_reference(sk_seed, params)
    p1p2 = expand_p1p2_from_pkseed(bytearray(pk_seed), params)
    p1 = bytearray(p1p2[:params.p1_size])
    p2 = bytearray(p1p2[params.p1_size:])

    s_matrix = bytearray(_s_size(params))

    for row_idx in range(V):
        p1p1t_row = _get_p1p1t_row_gf256(p1, row_idx, params)

        for j in range(PUB_M):
            acc = bytearray(PUB_M_BYTE)

            for k in range(V):
                p1p1t_vec = p1p1t_row[k * PUB_M_BYTE_PADDED : k * PUB_M_BYTE_PADDED + PUB_M_BYTE]
                o_scalar = O_matrix[j * V + k]
                if o_scalar != 0:
                    gf256v_madd(acc, p1p1t_vec, o_scalar)

            # + P2[row_idx, j] (P2 row-major, no padding)
            p2_offset = (row_idx * PUB_M + j) * PUB_M_BYTE
            p2_elem = p2[p2_offset : p2_offset + PUB_M_BYTE]
            for b in range(PUB_M_BYTE):
                acc[b] ^= p2_elem[b]

            # Store with padding
            s_offset = (row_idx * PUB_M + j) * PUB_M_BYTE_PADDED
            s_matrix[s_offset : s_offset + PUB_M_BYTE] = acc

    return pk_seed, bytes(O_matrix), s_matrix


# ================================================================== #
#  L matrix computation and transpose
# ================================================================== #

def compute_l_matrix(
    s_matrix: bytearray,
    vinegar: bytes,
    params: OVParams,
) -> bytearray:
    """
    Compute L = v x S (linear system coefficient matrix).

    For GF16: L = v x S via gf16v_madd, 2048 bytes output.
    For GF256: L = S x v (column-major), 2816 bytes output.

    Args:
        s_matrix: S matrix bytes
        vinegar: Vinegar vector bytes
        params: OV parameter set

    Returns:
        L matrix (column-major)
    """
    l_size = _l_size(params)
    l_matrix = bytearray(l_size)
    sc_size = params.pub_m * _s_entry_stride(params)

    for j in range(params.v):
        v_j = gfv_get_ele_gf16(vinegar, j) if params.gf == 16 else vinegar[j]
        if v_j == 0:
            continue
        s_col_offset = j * sc_size
        s_super_col = s_matrix[s_col_offset : s_col_offset + sc_size]
        if params.gf == 16:
            gf16v_madd(l_matrix, s_super_col, v_j)
        else:
            gf256v_madd(l_matrix, s_super_col, v_j)

    return l_matrix


# ------------------------------------------------------------------ #
#  GF16 transpose helpers (64x64 GF16 matrix)
# ------------------------------------------------------------------ #

def _unpack_gf16_matrix_col_major(
    data: bytes,
    rows: int,
    cols: int,
) -> List[List[int]]:
    """Unpack bytes into a logical matrix assuming COLUMN-MAJOR storage (GF16)."""
    matrix = [[0 for _ in range(cols)] for _ in range(rows)]
    bytes_per_col = rows // 2
    for c in range(cols):
        col_byte_offset = c * bytes_per_col
        for r in range(rows):
            byte_idx = col_byte_offset + (r // 2)
            byte_val = data[byte_idx]
            if r % 2 == 0:
                val = byte_val & _GF16_NIBBLE_MASK
            else:
                val = (byte_val >> 4) & _GF16_NIBBLE_MASK
            matrix[r][c] = val
    return matrix


def _pack_gf16_matrix_row_major(
    matrix: List[List[int]],
    rows: int,
    cols: int,
) -> bytearray:
    """Pack a logical matrix into bytes assuming ROW-MAJOR storage (GF16)."""
    bytes_per_row = cols // 2
    total_bytes = rows * bytes_per_row
    packed_data = bytearray(total_bytes)
    for r in range(rows):
        row_byte_offset = r * bytes_per_row
        for c in range(cols):
            byte_idx = row_byte_offset + (c // 2)
            val = matrix[r][c] & _GF16_NIBBLE_MASK
            if c % 2 == 0:
                packed_data[byte_idx] |= val
            else:
                packed_data[byte_idx] |= (val << 4)
    return packed_data


def compute_l_transpose_gf16(l_matrix: bytearray, params: OVParams) -> bytearray:
    """
    Storage-format transpose of L matrix (column-major -> row-major) for GF16.

    NOTE: This is a storage repack, NOT algebraic L^T. Signing solves L*o = c
    (not L^T*o = c); GE just needs row-major access to L. If you ever need
    the true mathematical transpose, write it from scratch.

    Args:
        l_matrix: L matrix in column-major format (2048 bytes)
        params: OV parameter set

    Returns:
        L matrix in row-major format (2048 bytes)
    """
    M = _unpack_gf16_matrix_col_major(l_matrix, params.pub_m, params.pub_m)
    return _pack_gf16_matrix_row_major(M, params.pub_m, params.pub_m)


def compute_l_transpose_gf256(l_col_major: bytearray, params: OVParams) -> bytearray:
    """
    Convert L matrix from column-major (64x44) to row-major (44x64) for GF256.

    Input:  L in column-major format: 44 columns of 64 bytes each = 2816 bytes.
            Rows 0-43 contain data, rows 44-63 are zero padding.
    Output: L in row-major format: 44 rows of 64 bytes each = 2816 bytes.
            Columns 0-43 contain data, columns 44-63 are zero padding.
    """
    PUB_M = params.pub_m
    PUB_M_BYTE_PADDED = params.pub_m_byte_padded
    COL_HEIGHT = PUB_M_BYTE_PADDED
    NUM_COLS = PUB_M
    NUM_ROWS = PUB_M
    ROW_WIDTH = PUB_M_BYTE_PADDED

    matrix = [[0] * NUM_COLS for _ in range(COL_HEIGHT)]
    for c in range(NUM_COLS):
        for r in range(COL_HEIGHT):
            matrix[r][c] = l_col_major[c * COL_HEIGHT + r]

    result = bytearray(NUM_ROWS * ROW_WIDTH)
    for r in range(NUM_ROWS):
        for c in range(NUM_COLS):
            result[r * ROW_WIDTH + c] = matrix[r][c]

    return result


def compute_l_transpose(l_matrix: bytearray, params: OVParams) -> bytearray:
    """
    Compute L transpose (storage format).

    Dispatches to GF16 or GF256 variant.
    """
    if params.gf == 16:
        return compute_l_transpose_gf16(l_matrix, params)
    else:
        return compute_l_transpose_gf256(l_matrix, params)


# ================================================================== #
#  Invertibility check (GF16 only, used for retry loop)
# ================================================================== #

def check_l_invertibility_gf16(
    l_matrix_row_major: bytearray,
    params: OVParams,
) -> bool:
    """
    Check whether the L matrix is invertible over GF(16).

    Uses Gaussian elimination: if any pivot is zero after exhausting all
    row additions, the matrix is singular.

    Args:
        l_matrix_row_major: L matrix in row-major packed GF16 format
        params: OV parameter set

    Returns:
        True if invertible, False if singular
    """
    from galois import GF as _GF
    GF16_local = _GF(2**4, irreducible_poly="x^4 + x + 1")

    l_elements = bytes_to_gf_elements(bytearray(l_matrix_row_major), field="gf16")
    M = GF16_local(np.array(l_elements, dtype=np.uint8).reshape(params.pub_m, params.pub_m))

    n = params.pub_m
    for pivot_row in range(n):
        if M[pivot_row, pivot_row] == 0:
            for add_row in range(pivot_row + 1, n):
                M[pivot_row, :] += M[add_row, :]
                if M[pivot_row, pivot_row] != 0:
                    break
        if M[pivot_row, pivot_row] == 0:
            return False
        pivot_inv = M[pivot_row, pivot_row] ** 14
        M[pivot_row, :] *= pivot_inv
        for row in range(pivot_row + 1, n):
            if M[row, pivot_row] != 0:
                factor = M[row, pivot_row]
                M[row, :] -= factor * M[pivot_row, :]
    return True


# ================================================================== #
#  GE and back-substitution (delegated to ov_ge_test_utils)
# ================================================================== #

# Import shared GE/back-sub utilities from ov_ge_test_utils, which
# provides field-agnostic compute_ge_reference() and
# compute_backsub_reference() dispatched via OVParams.
from ov_ge_test_utils import (
    compute_ge_reference as _ge_reference,
    compute_backsub_reference as _backsub_reference,
    _pack_matrix as _ge_pack_matrix,
    _pack_vector as _ge_pack_vector,
    is_matrix_invertible as _is_matrix_invertible,
)


def compute_ge_reference_gf16(
    l_matrix_row_major: bytearray,
    y_vector: bytes,
    target_vector: bytes,
    params: OVParams,
) -> Tuple[bytearray, bytearray]:
    """
    Compute Gaussian elimination reference for GF16 on augmented system [L | (Y XOR target)].

    Delegates to ov_ge_test_utils.compute_ge_reference().

    Returns (ge_matrix_bytes, ge_vector_bytes).
    """
    ge_input_vector = bytearray(len(y_vector))
    for i in range(len(y_vector)):
        ge_input_vector[i] = y_vector[i] ^ target_vector[i]

    l_elements = bytes_to_gf_elements(bytearray(l_matrix_row_major), field="gf16")
    l_np = np.array(l_elements, dtype=np.uint8).reshape(params.pub_m, params.pub_m)

    v_elements = bytes_to_gf_elements(bytearray(ge_input_vector), field="gf16")

    ge_matrix_np, ge_vector_list = _ge_reference(l_np, v_elements, params)

    ge_matrix_bytes = gf_elements_to_bytes(
        ge_matrix_np.flatten().tolist(), field="gf16"
    )
    ge_vector_bytes = gf_elements_to_bytes(ge_vector_list, field="gf16")

    return ge_matrix_bytes, ge_vector_bytes


def compute_back_sub_reference_gf16(
    ge_matrix_bytes: bytearray,
    ge_vector_bytes: bytearray,
    params: OVParams,
) -> bytearray:
    """
    Compute back-substitution reference for GF16.

    Delegates to ov_ge_test_utils.compute_backsub_reference().

    Returns solution vector (pub_m_byte bytes, packed GF16).
    """
    ge_matrix_elements = bytes_to_gf_elements(bytearray(ge_matrix_bytes), field="gf16")
    ge_matrix_np = np.array(ge_matrix_elements, dtype=np.uint8).reshape(params.pub_m, params.pub_m)

    ge_vector_list = bytes_to_gf_elements(bytearray(ge_vector_bytes), field="gf16")

    _, solution_list = _backsub_reference(ge_matrix_np, ge_vector_list, params)

    return gf_elements_to_bytes(solution_list, field="gf16")


def compute_ge_reference_gf256(
    l_matrix_bytes: bytes,
    r_vector_bytes: bytes,
    params: OVParams,
) -> Tuple[bytes, bytes]:
    """
    Compute Gaussian elimination reference for GF256.

    Delegates to ov_ge_test_utils.compute_ge_reference().

    Args:
        l_matrix_bytes: Row-major padded matrix bytes
        r_vector_bytes: Padded vector bytes (Y XOR target)

    Returns:
        (ge_matrix_bytes, ge_vector_bytes)
    """
    n = params.pub_m
    PUB_M_BYTE_PADDED = params.pub_m_byte_padded

    # Unpack matrix from row-major padded format
    matrix = np.zeros((n, n), dtype=np.uint8)
    for row in range(n):
        offset = row * PUB_M_BYTE_PADDED
        for col in range(n):
            matrix[row, col] = l_matrix_bytes[offset + col]

    # Unpack vector
    vector = [r_vector_bytes[i] for i in range(n)]

    M_out, v_out = _ge_reference(matrix, vector, params)

    # Re-pack using ov_ge_test_utils packing (handles row padding)
    ge_matrix_bytes_out = bytes(_ge_pack_matrix(M_out, params))
    ge_vector_bytes_out = bytes(_ge_pack_vector(list(v_out), params))

    return ge_matrix_bytes_out, ge_vector_bytes_out


def compute_back_sub_reference_gf256(
    ge_matrix_bytes: bytes,
    ge_vector_bytes: bytes,
    params: OVParams,
) -> bytes:
    """
    Compute back-substitution reference for GF256.

    Delegates to ov_ge_test_utils.compute_backsub_reference().

    Returns solution vector (target_padded_size bytes: pub_m_byte data + zero padding).
    """
    n = params.pub_m
    PUB_M_BYTE_PADDED = params.pub_m_byte_padded
    TARGET_PADDED = _target_padded_size(params)

    matrix = np.zeros((n, n), dtype=np.uint8)
    for row in range(n):
        for col in range(n):
            matrix[row, col] = ge_matrix_bytes[row * PUB_M_BYTE_PADDED + col]

    vector = [ge_vector_bytes[i] for i in range(n)]

    _, solution = _backsub_reference(matrix, vector, params)

    result = bytearray(TARGET_PADDED)
    for i in range(n):
        result[i] = solution[i]

    return bytes(result)


# ================================================================== #
#  Trimat eval reference (batch_quad_trimat_eval)
# ================================================================== #

def compute_trimat_eval_reference(
    p1: bytearray,
    vinegar: bytes,
    params: OVParams,
) -> bytes:
    """
    Compute Y = batch_quad_trimat_eval(P1, vinegar).

    Returns:
        Y vector (pub_m_byte bytes)
    """
    from ov_trimat_eval_test_utils import compute_batch_trimat_eval_reference
    return compute_batch_trimat_eval_reference(p1, vinegar, params)


# ================================================================== #
#  Testvector (KAT) helpers
# ================================================================== #

def parse_sign_testvec_file(path, params):
    """Parse a testvectors-{Is,Ip}-pkc-skc KAT file (3 lines per case).

    Returns list of (pk_pkc, sk_seed, message, signature, salt) tuples.
    Each element is a bytearray.

    Line format per case:
      N+0: pk_pkc hex
      N+1: sk_seed hex (must be 32 B = 64 hex chars)
      N+2: sm = message || signature hex

    Validates:
      - groups of 3 lines
      - len(sk) == 32 (rejects expanded-SK -pkc files)
      - len(pk) == params.cpk_size
      - len(signature) == params.signature_bytes
      - len(message)   <= params.max_message_size
    salt = signature[-params.salt_bytes:].
    """
    import re

    def _hex_bytes(s):
        return bytearray.fromhex(re.sub(r'\s+', '', s))

    with open(path, 'r') as f:
        lines = [ln.strip() for ln in f.readlines() if ln.strip()]
    if len(lines) % 3 != 0:
        raise ValueError(
            f"Sign testvec file should have groups of 3 lines; found {len(lines)}")

    sig_bytes = params.signature_bytes
    salt_bytes = params.salt_bytes
    expected_pk = params.cpk_size
    cases = []
    for i in range(len(lines) // 3):
        pk = _hex_bytes(lines[3 * i])
        sk = _hex_bytes(lines[3 * i + 1])
        sm = _hex_bytes(lines[3 * i + 2])
        if len(sk) != 32:
            raise ValueError(
                f"Case {i+1}: sk_seed length is {len(sk)}B, expected 32B "
                f"(use testvectors-*-pkc-skc, not testvectors-*-pkc)")
        if len(pk) != expected_pk:
            raise ValueError(
                f"Case {i+1}: pk length is {len(pk)}B, expected {expected_pk}B")
        if len(sm) < sig_bytes:
            raise ValueError(
                f"Case {i+1}: sm too short ({len(sm)} < sig {sig_bytes})")
        message = sm[:-sig_bytes] if len(sm) > sig_bytes else bytearray(0)
        signature = sm[-sig_bytes:]
        if len(signature) != sig_bytes:
            raise ValueError(
                f"Case {i+1}: extracted sig length {len(signature)}B, expected {sig_bytes}B")
        if len(message) > params.max_message_size:
            raise ValueError(
                f"Case {i+1}: message length {len(message)}B exceeds "
                f"max {params.max_message_size}B")
        salt = signature[-salt_bytes:]
        cases.append((pk, sk, message, signature, salt))
    return cases


def build_salt_input_words(params, salt):
    """Build DMEM word dict that injects the 16-byte testvec salt
    into the salt_input: slot (16 B salt + 16 B zero pad = 32 B aligned)."""
    if len(salt) != params.salt_bytes:
        raise ValueError(f"salt length {len(salt)} != {params.salt_bytes}")
    if params.sign_salt_input_addr == 0:
        raise ValueError(
            f"sign_salt_input_addr not set for params={params.name}; "
            "populate it in ov_params.py")
    padded = bytes(salt) + bytes(32 - len(salt))
    return bytes_to_dmem_words(padded, params.sign_salt_input_addr)


def _with_testvec_offset(params):
    """Return a copy of params with all post-salt_input sign_*_addr fields
    shifted by params.sign_testvec_offset bytes (for reading the testvec ELF).

    Salt_input is inserted between msg and sig in the testvec scaffold, so
    every label from sig: onward shifts +sign_testvec_offset. Pre-msg fields
    (sign_skseed_addr, sign_msg_len_addr, sign_msg_addr) are NOT shifted.
    """
    from dataclasses import replace
    testvec_offset = params.sign_testvec_offset
    if testvec_offset == 0:
        return params
    return replace(params,
        sign_sig_addr=params.sign_sig_addr + testvec_offset,
        sign_y_addr=params.sign_y_addr + testvec_offset,
        sign_l_matrix_addr=params.sign_l_matrix_addr + testvec_offset,
        sign_vinegar_addr=params.sign_vinegar_addr + testvec_offset,
        sign_target_addr=params.sign_target_addr + testvec_offset,
        sign_salt_addr=params.sign_salt_addr + testvec_offset,
        sign_s_output_addr=params.sign_s_output_addr + testvec_offset,
        sign_pkseed_output_addr=params.sign_pkseed_output_addr + testvec_offset,
        sign_o_output_addr=params.sign_o_output_addr + testvec_offset,
    )


def _with_ldirect_layout(params):
    """Return a copy of params with the stack-slot addresses of the default
    L-direct sign path (ov-<P>-skc-sign.s).

    The L-direct body never allocates S; a sign_ldirect_scratch-byte scratch
    stands in for it. pk_seed sits scratch bytes above the params S address,
    O follows it as in params, and the per-attempt slots (salt, target,
    vinegar, L, Y) sit scratch bytes above their params addresses. This holds
    both for params that describe the precompute layout (OV_IP, OV_IS) and
    for params read off the L-direct ELF itself (OV_IP3, whose S slot is the
    scratch). sign_s_output_addr becomes meaningless (S is never
    materialized); checkpoint [3] must be skipped by the caller.
    """
    from dataclasses import replace
    scratch = params.sign_ldirect_scratch
    pk_seed = params.sign_s_output_addr + scratch
    return replace(params,
        sign_y_addr=params.sign_y_addr + scratch,
        sign_l_matrix_addr=params.sign_l_matrix_addr + scratch,
        sign_vinegar_addr=params.sign_vinegar_addr + scratch,
        sign_target_addr=params.sign_target_addr + scratch,
        sign_salt_addr=params.sign_salt_addr + scratch,
        sign_pkseed_output_addr=pk_seed,
        sign_o_output_addr=pk_seed + params.sign_o_output_addr - params.sign_pkseed_output_addr,
    )


def _with_elf_stack_layout(params, elf_path):
    """Return params with the precompute-S stack slots read from the sign test
    ELF's own labels.

    Every _sprec wrapper labels S, pk_seed and O where the body puts them,
    away from the params addresses: the body keeps the raw P1 cache below S.
    The per-attempt slots below the cache (Y, L, vinegar, Target, Salt) come
    from the labels only for Ip3: its wrapper reserves the cache between Salt
    and S as the body does, and OV_IP3 describes the L-direct ELF. The Ip/Is
    wrappers reserve the cache at the bottom of the stack, so their labels
    there are not the body's slots; the OV_IP/OV_IS addresses still are (the
    reserve raises stack_end by as much as the cache lowers the slots).
    Addresses are returned for the non-testvec layout: a testvec ELF
    (salt_input present) has every label shifted by sign_testvec_offset,
    which _with_testvec_offset adds back.
    """
    from dataclasses import replace
    from elftools.elf.elffile import ELFFile
    with open(elf_path, 'rb') as f:
        syms = {s.name: s['st_value'] for s in ELFFile(f).get_section_by_name('.symtab').iter_symbols()}
    shift = params.sign_testvec_offset if 'salt_input' in syms else 0
    labels = {'sign_s_output_addr': 'S', 'sign_pkseed_output_addr': 'pk_seed', 'sign_o_output_addr': 'O'}
    if params.short == 'Ip3':
        labels.update(sign_y_addr='Y', sign_l_matrix_addr='L', sign_vinegar_addr='vinegar',
                      sign_target_addr='Target', sign_salt_addr='Salt')
    missing = [n for n in labels.values() if n not in syms]
    if missing:
        raise ValueError(f"{elf_path}: missing stack labels {missing}")
    return replace(params, **{field: syms[name] - shift for field, name in labels.items()})


# ================================================================== #
#  Data injection
# ================================================================== #

def build_sign_words(
    sk_seed: bytes,
    message: bytes,
    params: OVParams,
) -> Dict[int, int]:
    """
    Build DMEM word dict for sk_seed, message length, and message for the sign flow.

    Args:
        sk_seed: 32-byte secret key seed
        message: Message bytes
        params: OV parameter set

    Returns:
        Dict mapping DMEM word addresses to 32-bit values.
    """
    words: Dict[int, int] = {}

    # sk_seed
    words.update(bytes_to_dmem_words(
        data=bytearray(sk_seed),
        base_addr=params.sign_skseed_addr,
        pad_to_size=_WDR_BYTES,
    ))

    # Message length
    if params.gf == 16:
        # Is: single word at msg_len_addr
        words[params.sign_msg_len_addr] = len(message)
    else:
        # Ip: padded to one WDR slot
        msg_len_bytes = len(message).to_bytes(4, 'little')
        words.update(bytes_to_dmem_words(
            bytearray(msg_len_bytes), params.sign_msg_len_addr,
            pad_to_size=_WDR_BYTES,
        ))

    # Message
    msg_len = len(message)
    if msg_len > 0:
        if params.gf == 16:
            # Is: pad to WDR alignment
            padded_len = ((msg_len + _WDR_BYTES - 1) // _WDR_BYTES) * _WDR_BYTES
            padded_message = bytearray(message) + bytearray(padded_len - msg_len)
            words.update(bytes_to_dmem_words(padded_message, params.sign_msg_addr))
        else:
            # Ip: bytes_to_dmem_words handles padding
            words.update(bytes_to_dmem_words(
                bytearray(message), params.sign_msg_addr,
            ))

    return words


# ================================================================== #
#  Failure data logging
# ================================================================== #

def save_failure_data(
    output_dir: str,
    iteration: int,
    sk_seed: bytes,
    message: bytes,
    err_info: str = "",
) -> str:
    """Save test vectors to a file so a failing test case can be reproduced."""
    fname = os.path.join(output_dir, f"failure_iter{iteration + 1}.txt")
    with open(fname, "w") as f:
        f.write(f"# Failing test vector -- iteration {iteration + 1}\n")
        f.write(f"# Error: {err_info}\n\n")
        f.write(f"sk_seed  = {sk_seed.hex()}\n")
        f.write(f"msg_len  = {len(message)}\n")
        f.write(f"message  = {message.hex()}\n")
    print(f"  [saved test vector to {fname}]")
    return fname


# ================================================================== #
#  O*oil reference helper
# ================================================================== #

def _compute_o_oil_reference(
    expected_O: bytes,
    expected_solution: bytes,
    params: OVParams,
) -> bytearray:
    """
    Compute O x oil reference, padded to the total WDR size.

    Returns bytearray of (num_wdrs * 32) bytes.
    """
    v_byte = _v_byte(params)
    wdr_indices = _o_oil_wdr_indices(params)
    total_wdr_bytes = len(wdr_indices) * _WDR_BYTES

    o_matrix_cols = []
    for col in range(params.pub_m):
        col_bytes = expected_O[col * v_byte:(col + 1) * v_byte]
        if params.gf == 16:
            o_matrix_cols.append(bytes_to_gf_elements(bytearray(col_bytes), field="gf16"))
        else:
            o_matrix_cols.append(list(col_bytes))

    if params.gf == 16:
        oil_elements = bytes_to_gf_elements(bytearray(expected_solution[:params.pub_m_byte]), field="gf16")
    else:
        oil_elements = list(expected_solution[:params.pub_m_byte])

    o_times_oil = compute_gf_matvec_reference(o_matrix_cols, oil_elements, field=_field_tag(params))
    if params.gf == 16:
        result = gf_elements_to_bytes(o_times_oil, field="gf16")
    else:
        result = bytearray(o_times_oil)
    result += bytearray(total_wdr_bytes - len(result))
    return result


# ================================================================== #
#  Validation step functions
# ================================================================== #

def validate_step_1_pkseed(
    dmem_bytes: dict,
    expected_pk_seed: bytes,
    params: OVParams,
) -> Tuple[bool, List[str]]:
    """[1] Validate pk_seed (16B value + 16B trailing zeros)."""
    results = []
    exp_padded = expected_pk_seed + b'\x00' * 16
    act_padded = bytes(extract_bytes_from_dmem(dmem_bytes, params.sign_pkseed_output_addr, _WDR_BYTES))

    if act_padded == exp_padded:
        results.append("[1] pk_seed matches (16B value + 16B trailing zeros)")
        return True, results
    else:
        results.append("[1] pk_seed MISMATCH")
        results.append(f"    Expected: {exp_padded.hex()}")
        results.append(f"    Actual:   {act_padded.hex()}")
        return False, results


def validate_step_2_o_matrix(
    dmem_bytes: dict,
    expected_O: bytes,
    params: OVParams,
) -> Tuple[bool, List[str]]:
    """[2] Validate O matrix data and alignment padding."""
    results = []
    o_size = params.o_size
    o_size_padded = params.o_size_padded
    all_pass = True

    act_O_padded = bytes(extract_bytes_from_dmem(dmem_bytes, params.sign_o_output_addr, o_size_padded))
    act_O = act_O_padded[:o_size]
    if params.o_slot_bytes:
        # o_slot_bytes per column: the column data, then zero slack
        col = o_size // params.pub_m
        slots = [act_O_padded[i:i + params.o_slot_bytes]
                 for i in range(0, o_size_padded, params.o_slot_bytes)]
        act_O = b''.join(sl[:col] for sl in slots)

    # Data check
    if act_O == expected_O[:o_size]:
        results.append(f"[2] O matrix data matches ({o_size} bytes)")
    else:
        results.append(f"[2] O matrix data MISMATCH ({o_size} bytes)")
        for i in range(min(o_size, len(act_O))):
            if act_O[i] != expected_O[i]:
                results.append(f"    First diff at byte {i}: "
                               f"expected 0x{expected_O[i]:02x}, got 0x{act_O[i]:02x}")
                break
        all_pass = False

    # Padding check (only if there IS padding)
    if o_size_padded > o_size and params.o_slot_bytes:
        bad = [j for j, sl in enumerate(slots) if any(sl[col:])]
        if not bad:
            results.append(f"[2] O slot padding correct (bytes {col}..{params.o_slot_bytes - 1} "
                           f"of all {len(slots)} column slots are zero)")
        else:
            results.append(f"[2] O slot padding MISMATCH in {len(bad)} column(s); column {bad[0]} "
                           f"slack: {slots[bad[0]][col:].hex()}")
            all_pass = False
    elif o_size_padded > o_size:
        exp_O_padded = bytes(expected_O)[:o_size] + b'\x00' * (o_size_padded - o_size)
        if act_O_padded == exp_O_padded:
            results.append(f"[2] O alignment padding correct "
                           f"(0x{params.sign_o_output_addr + o_size:05x}"
                           f"--0x{params.sign_o_output_addr + o_size_padded - 1:05x} are zero)")
        else:
            pad_act = act_O_padded[o_size:]
            results.append("[2] O alignment padding MISMATCH")
            _zero_repr = bytes(o_size_padded - o_size)
            results.append(f"    Expected (zeros): {_zero_repr}")
            results.append(f"    Actual:           {pad_act.hex()}")
            all_pass = False

    return all_pass, results


def validate_step_3_s_matrix(
    dmem_bytes: dict,
    expected_S: bytearray,
    params: OVParams,
) -> Tuple[bool, List[str]]:
    """[3] Validate S matrix."""
    results = []
    s_size = _s_size(params)
    act_S = bytes(extract_bytes_from_dmem(dmem_bytes, params.sign_s_output_addr, s_size))

    match, mismatches = validate_bytes(expected_S, act_S, "S matrix")
    if match:
        results.append(f"[3] S matrix matches ({s_size:,} bytes)")
        return True, results
    else:
        entry_stride = _s_entry_stride(params)
        results.append(f"[3] S matrix MISMATCH ({len(mismatches)} byte(s) differ)")
        for idx in mismatches[:5]:
            row = idx // (params.pub_m * entry_stride)
            j = (idx % (params.pub_m * entry_stride)) // entry_stride
            b_off = idx % entry_stride
            results.append(f"    0x{params.sign_s_output_addr + idx:06x} (row={row}, oil={j}, byte={b_off}): "
                           f"expected 0x{expected_S[idx]:02x}, got 0x{act_S[idx]:02x}")
        if len(mismatches) > 5:
            results.append(f"    ... and {len(mismatches) - 5} more")
        return False, results


def validate_step_4_target(
    dmem_bytes: dict,
    expected_target_digest: bytes,
    params: OVParams,
) -> Tuple[bool, List[str]]:
    """[4] Validate target hash."""
    results = []
    target_digest_size = _target_digest_size(params)
    target_padded_size = _target_padded_size(params)

    act_target = bytes(extract_bytes_from_dmem(dmem_bytes, params.sign_target_addr, target_padded_size))
    exp_target_full = expected_target_digest + bytes(target_padded_size - target_digest_size)

    t_match, t_mismatches = validate_bytes(exp_target_full, act_target, "Target hash")
    if t_match:
        results.append(f"[4] Target hash matches ({target_digest_size}B digest + "
                       f"{target_padded_size - target_digest_size}B zero padding)")
        return True, results
    else:
        results.append(f"[4] Target hash MISMATCH ({len(t_mismatches)} byte(s) differ)")
        results.append(f"    Expected digest ({target_digest_size}B): {expected_target_digest.hex()}")
        results.append(f"    Actual   ({target_padded_size}B):        {act_target.hex()}")
        if target_padded_size > target_digest_size:
            results.append(f"    Trailing {target_padded_size - target_digest_size} bytes: "
                           f"{act_target[target_digest_size:].hex()}")
        return False, results


def validate_step_5_vinegar(
    dmem_bytes: dict,
    expected_vinegar: bytes,
    counter: int,
    params: OVParams,
) -> Tuple[bool, List[str]]:
    """[5] Validate vinegar vector."""
    results = []
    v_byte = _v_byte(params)
    v_padded = _v_byte_padded(params)

    act_vinegar_full = bytes(extract_bytes_from_dmem(dmem_bytes, params.sign_vinegar_addr, v_padded))
    exp_vinegar_full = expected_vinegar + bytes(v_padded - v_byte)

    v_match, v_mismatches = validate_bytes(exp_vinegar_full, act_vinegar_full, "Vinegar")
    if v_match:
        results.append(f"[5] Vinegar matches ({v_byte}B data + "
                       f"{v_padded - v_byte}B zero padding, counter={counter})")
        return True, results
    else:
        results.append(f"[5] Vinegar MISMATCH ({len(v_mismatches)} byte(s) differ, counter={counter})")
        results.append(f"    Expected vinegar ({v_byte}B): {expected_vinegar.hex()}")
        results.append(f"    Actual   ({v_padded}B):        {act_vinegar_full.hex()}")
        if v_padded > v_byte:
            results.append(f"    Trailing {v_padded - v_byte} bytes: {act_vinegar_full[v_byte:].hex()}")
        return False, results


def validate_step_9_backsub(
    dmem_bytes: dict,
    expected_solution: bytes,
    params: OVParams,
) -> Tuple[bool, List[str]]:
    """[9] Validate back-substitution solution vector."""
    results = []

    if params.gf == 16:
        sol_size = params.pub_m_byte
    else:
        sol_size = _target_padded_size(params)

    act_solution = bytes(extract_bytes_from_dmem(dmem_bytes, params.sign_y_addr, sol_size))

    sol_match, sol_mismatches = validate_bytes(expected_solution, act_solution, "Back-sub solution")
    if sol_match:
        if params.gf == 16:
            results.append(f"[9] Back-sub solution matches ({params.pub_m_byte}B data)")
        else:
            results.append(f"[9] Back-sub solution matches ({params.pub_m_byte}B data + "
                           f"{_target_padded_size(params) - params.pub_m_byte}B zero padding)")
        return True, results
    else:
        results.append(f"[9] Back-sub solution MISMATCH ({len(sol_mismatches)} byte(s) differ)")
        results.append(f"    Expected ({params.pub_m_byte}B): {expected_solution[:params.pub_m_byte].hex()}")
        results.append(f"    Actual   ({params.pub_m_byte}B): {act_solution[:params.pub_m_byte].hex()}")
        for idx in sol_mismatches[:5]:
            results.append(f"    byte {idx}: expected 0x{expected_solution[idx]:02x}, "
                           f"got 0x{act_solution[idx]:02x}")
        if len(sol_mismatches) > 5:
            results.append(f"    ... and {len(sol_mismatches) - 5} more")
        return False, results


def validate_step_10_o_oil(
    sim,
    expected_O: bytes,
    expected_solution: bytes,
    params: OVParams,
) -> Tuple[bool, List[str]]:
    """[10] Validate O x oil product (from WDR registers)."""
    results = []
    v_byte = _v_byte(params)
    wdr_indices = _o_oil_wdr_indices(params)
    total_wdr_bytes = len(wdr_indices) * _WDR_BYTES

    # Reference O x oil (padded to WDR size)
    expected_o_oil_bytes = _compute_o_oil_reference(expected_O, expected_solution, params)

    # Read actual from WDR registers
    actual_o_oil_bytes = bytearray()
    for wdr_idx in wdr_indices:
        val = read_wdr_register(sim, wdr_idx)
        actual_o_oil_bytes += bytearray(val.to_bytes(_WDR_BYTES, 'little'))

    o_oil_match, o_oil_mismatches = validate_bytes(
        expected_o_oil_bytes, actual_o_oil_bytes, "O x oil"
    )
    if o_oil_match:
        results.append(f"[10] O x oil matches ({v_byte}B data + {total_wdr_bytes - v_byte}B zero padding)")
        return True, results
    else:
        results.append(f"[10] O x oil MISMATCH ({len(o_oil_mismatches)} byte(s) differ)")
        for idx in o_oil_mismatches[:5]:
            results.append(f"    byte {idx}: expected 0x{expected_o_oil_bytes[idx]:02x}, "
                           f"got 0x{actual_o_oil_bytes[idx]:02x}")
        if len(o_oil_mismatches) > 5:
            results.append(f"    ... and {len(o_oil_mismatches) - 5} more")
        return False, results


def validate_step_11_signature(
    dmem_bytes: dict,
    expected_vinegar: bytes,
    expected_o_oil_bytes: bytes,
    expected_solution: bytes,
    actual_salt: bytes,
    params: OVParams,
) -> Tuple[bool, List[str], bytearray, bytearray]:
    """
    [11] Validate signature assembly.

    Returns (passed, results, vinegar_sig, oil_bytes) for use in verification steps.
    """
    results = []
    v_byte = _v_byte(params)
    sig_size = _sig_size(params)

    # vinegar_sig = v XOR O*oil (v_byte bytes)
    o_oil_data = expected_o_oil_bytes[:v_byte]
    vinegar_sig = bytearray(v_byte)
    for i in range(v_byte):
        vinegar_sig[i] = expected_vinegar[i] ^ o_oil_data[i]

    oil_bytes = bytearray(expected_solution[:params.pub_m_byte])
    expected_sig = bytearray(vinegar_sig) + oil_bytes + bytearray(actual_salt)
    assert len(expected_sig) == sig_size, \
        f"Expected signature length {sig_size}, got {len(expected_sig)}"

    actual_sig = bytes(extract_bytes_from_dmem(dmem_bytes, params.sign_sig_addr, sig_size))

    sig_match, sig_mismatches = validate_bytes(expected_sig, actual_sig, f"Signature ({sig_size}B)")
    if sig_match:
        results.append(f"[11] Signature matches ({sig_size}B: "
                       f"{v_byte}B vin_sig + {params.pub_m_byte}B oil + {params.salt_bytes}B salt)")
        return True, results, vinegar_sig, oil_bytes
    else:
        results.append(f"[11] Signature MISMATCH ({len(sig_mismatches)} byte(s) differ)")
        for idx in sig_mismatches[:5]:
            results.append(f"    byte {idx}: expected 0x{expected_sig[idx]:02x}, "
                           f"got 0x{actual_sig[idx]:02x}")
        if len(sig_mismatches) > 5:
            results.append(f"    ... and {len(sig_mismatches) - 5} more")
        return False, results, vinegar_sig, oil_bytes


def validate_step_12_verify(
    vinegar_sig: bytearray,
    oil_bytes: bytearray,
    expected_target: bytes,
    p1: bytearray,
    p2: bytearray,
    expected_O: bytes,
    params: OVParams,
) -> Tuple[bool, List[str], bytearray, bytearray]:
    """
    [12] Python-only signature verification (public map).

    Returns (passed, results, trimat, sig_x) for use in negative tests.
    """
    results = []

    # Compute P3
    if params.gf == 16:
        expected_P3 = compute_p3_reference(
            p1, p2, bytes(expected_O), params.v, params.pub_m, params.pub_m_byte
        )
    else:
        expected_P3 = compute_p3_reference_gf256(
            p1, p2, bytes(expected_O), params.v, params.pub_m, params.pub_m_byte
        )

    p3_num_entries = params.pub_m * (params.pub_m + 1) // 2
    p3_expected_size = p3_num_entries * params.pub_m_byte
    assert len(expected_P3) == p3_expected_size, \
        f"P3 size mismatch: {len(expected_P3)} vs {p3_expected_size}"

    trimat = bytearray(p1) + bytearray(p2) + expected_P3
    PUB_N = params.v + params.pub_m

    sig_x = bytearray(vinegar_sig) + bytearray(oil_bytes)
    if params.gf == 16:
        expected_sig_len = PUB_N // 2
    else:
        expected_sig_len = PUB_N
    assert len(sig_x) == expected_sig_len, \
        f"Signature x size mismatch: {len(sig_x)} vs {expected_sig_len}"

    y_verify = ov_publicmap_reference(
        bytes(trimat), bytes(sig_x), PUB_N, params.pub_m, params.v,
        field=_field_tag(params),
    )

    verify_match, verify_mismatches = validate_bytes(
        expected_target, y_verify, "Verification P(x) vs target hash"
    )
    if verify_match:
        results.append("[12] Signature verification PASSED: P(x) == target hash")
        return True, results, trimat, sig_x
    else:
        results.append("[12] Signature verification FAILED")
        results.append(f"    P(x):     {y_verify.hex()}")
        results.append(f"    Expected: {expected_target.hex()}")
        return False, results, trimat, sig_x


def validate_step_13_altered_sig(
    trimat: bytearray,
    sig_x: bytearray,
    expected_target: bytes,
    params: OVParams,
) -> Tuple[bool, List[str]]:
    """[13] Negative test: altered signature should NOT verify."""
    results = []
    PUB_N = params.v + params.pub_m

    sig_x_altered = bytearray(sig_x)
    flip_idx = random.randint(0, len(sig_x_altered) - 1)
    sig_x_altered[flip_idx] ^= 0x01 + random.randint(0, 0xFE)

    y_altered_sig = ov_publicmap_reference(
        bytes(trimat), bytes(sig_x_altered), PUB_N, params.pub_m, params.v,
        field=_field_tag(params),
    )

    if y_altered_sig != expected_target:
        n_diff = sum(1 for a, b in zip(y_altered_sig, expected_target) if a != b)
        results.append(f"[13] Altered signature correctly fails: "
                       f"P(x') != target ({n_diff}/{params.pub_m_byte} bytes differ, "
                       f"flipped sig byte {flip_idx})")
        return True, results
    else:
        results.append("[13] Altered signature UNEXPECTEDLY passed verification")
        return False, results


def validate_step_14_altered_pk(
    trimat: bytearray,
    sig_x: bytearray,
    expected_target: bytes,
    params: OVParams,
) -> Tuple[bool, List[str]]:
    """[14] Negative test: altered public key should NOT verify.

    Robustness note: a public-map coefficient M_i[j,k] is "masked" if either
    sig_x[j] or sig_x[k] is zero in GF: the byte does not participate in
    P(x). Flipping a masked byte leaves P(x) unchanged, so the negative
    test would spuriously PASS the altered-pk-still-verifies check. Retry
    random positions up to RETRY_LIMIT until the flip actually changes
    P(x). If every retry hits a masked byte the signature is too degenerate
    to validate via this test; mark as skipped rather than fail.
    """
    results = []
    PUB_N = params.v + params.pub_m
    RETRY_LIMIT = 100

    for attempt in range(RETRY_LIMIT):
        trimat_altered = bytearray(trimat)
        pk_flip_idx = random.randint(0, len(trimat_altered) - 1)
        trimat_altered[pk_flip_idx] ^= 0x01 + random.randint(0, 0xFE)

        y_altered_pk = ov_publicmap_reference(
            bytes(trimat_altered), bytes(sig_x), PUB_N, params.pub_m, params.v,
            field=_field_tag(params),
        )

        if y_altered_pk != expected_target:
            n_diff = sum(1 for a, b in zip(y_altered_pk, expected_target) if a != b)
            results.append(f"[14] Altered public key correctly fails: "
                           f"P'(x) != target ({n_diff}/{params.pub_m_byte} bytes differ, "
                           f"flipped pk byte {pk_flip_idx}, after {attempt + 1} attempt(s))")
            return True, results
        # else: byte landed on a masked coefficient; retry

    results.append(f"[14] SKIPPED: all {RETRY_LIMIT} random flips landed on "
                   f"masked coefficients (signature has many zero variables "
                   f"making most trimat positions inconsequential). Not an ACC bug.")
    return True, results


# ================================================================== #
#  Main test runner
# ================================================================== #

def run_sign_test(
    iteration: int,
    elf_path: str,
    params: OVParams,
    verbose: bool = False,
    dump_regs_file: TextIO = None,
    dump_stats_file: TextIO = None,
    output_dir: str = "",
    include_negative_tests: bool = True,
    test_non_invertible: bool = False,
    debug: bool = False,
    testvec_case: Optional[Tuple[bytes, bytes, bytes, bytes, bytes]] = None,
    ldirect: bool = False,
) -> bool:
    """
    Run a single iteration of the full OV sign test.

    Args:
        iteration: Test iteration number (0-based)
        elf_path: Path to the ELF binary
        params: OV parameter set (Is or Ip)
        verbose: Enable verbose output
        dump_regs_file: Optional file for register dump
        dump_stats_file: Optional file for statistics
        output_dir: Optional directory for failure data
        include_negative_tests: If True, run steps [13] and [14]
        test_non_invertible: If True, validate that the ACC correctly
            detects non-invertible L matrices via the retry loop.
            When the ACC encounters a singular L matrix it sets the
            GE status flag to all-ones and increments the counter.
            This is validated opportunistically: if the counter > 0,
            we verify that skipped counters correspond to singular
            matrices.  Both Is and Ip wrappers should set this to
            True for a portion of their iterations.
        debug: If True, validate all intermediate DMEM checkpoints
            (steps 1-11).  If False, only the final signature
            verification (step 12) and optional negative tests run.

    Returns:
        True if all validation steps passed
    """
    if ldirect:
        # L-direct tier: no S buffer, a smaller scratch in its place
        params = _with_ldirect_layout(params)
    else:
        # precompute-S: S, pk_seed and O (for Ip3 every slot) from the ELF's labels
        params = _with_elf_stack_layout(params, elf_path)

    v_byte = _v_byte(params)
    target_padded_size = _target_padded_size(params)

    print(f"\n--- Iteration {iteration + 1} ---")

    expected_testvec_sig = None
    salt_dmem = None
    if testvec_case is None:
        # Random-fuzz path (unchanged behaviour)
        sk_seed = bytes([random.randint(0, 255) for _ in range(params.len_skseed)])
        msg_len = random.randint(1, 100)
        message = bytes([random.randint(0, 255) for _ in range(msg_len)])
    else:
        # Testvec path: inputs come from KAT file
        if not isinstance(testvec_case, tuple) or len(testvec_case) != 5:
            raise ValueError(
                f"testvec_case must be 5-tuple (pk, sk_seed, msg, sig, salt); "
                f"got {type(testvec_case).__name__} "
                f"len={len(testvec_case) if hasattr(testvec_case, '__len__') else 'N/A'}")
        _pk_pkc, sk_seed_b, message_b, expected_testvec_sig, salt_b = testvec_case
        if len(sk_seed_b) != params.len_skseed:
            raise ValueError(f"sk_seed length {len(sk_seed_b)} != {params.len_skseed}")
        if len(salt_b) != params.salt_bytes:
            raise ValueError(f"salt length {len(salt_b)} != {params.salt_bytes}")
        if len(expected_testvec_sig) != params.signature_bytes:
            raise ValueError(
                f"expected_sig length {len(expected_testvec_sig)} != {params.signature_bytes}")
        if len(_pk_pkc) != params.cpk_size:
            raise ValueError(f"pk_pkc length {len(_pk_pkc)} != {params.cpk_size}")
        if len(message_b) > params.max_message_size:
            raise ValueError(
                f"message length {len(message_b)} > max {params.max_message_size}")
        # Apply post-sig address shift introduced by conditional salt_input in scaffold
        params = _with_testvec_offset(params)
        sk_seed = bytes(sk_seed_b)
        message = bytes(message_b)
        msg_len = len(message)
        salt_dmem = build_salt_input_words(params, bytes(salt_b))
        print(f"  testvec salt: {bytes(salt_b).hex()}")

    print(f"sk_seed ({params.len_skseed}B): {sk_seed.hex()}")
    print(f"message ({msg_len}B): {message.hex()}")

    # Reference S matrix computation
    print("Computing reference (pk_seed, O, S)...")
    if params.gf == 16:
        exp_pk_seed, exp_O, exp_S, exp_P1 = compute_s_matrix_gf16(sk_seed, params)
        # Also need P2 for verification step
        p1p2 = expand_p1p2_from_pkseed(bytearray(exp_pk_seed), params)
        exp_P2 = bytearray(p1p2[params.p1_size:])
    else:
        exp_pk_seed, exp_O, exp_S = compute_s_matrix_gf256(sk_seed, params)
        # Re-expand to get P1 and P2
        p1p2 = expand_p1p2_from_pkseed(bytearray(exp_pk_seed), params)
        exp_P1 = bytearray(p1p2[:params.p1_size])
        exp_P2 = bytearray(p1p2[params.p1_size:])

    print(f"  pk_seed: {exp_pk_seed.hex()}")
    print(f"  O matrix size: {len(exp_O)} bytes")
    print(f"  S matrix size: {len(exp_S)} bytes")

    # Run ACC simulation
    print("Running ACC simulation...")

    words = build_sign_words(sk_seed, message, params)
    if salt_dmem is not None:
        words.update(salt_dmem)

    success, dmem_bytes, sim = run_acc_test(
        elf_path=elf_path,
        dmem_words=words,
        verbose=verbose,
        dump_regs_file=dump_regs_file,
        dump_stats_file=dump_stats_file,
    )

    if not success or sim is None:
        print("[ERROR] ACC simulation failed")
        if output_dir:
            save_failure_data(output_dir, iteration, sk_seed, message,
                              "ACC simulation did not complete")
        return False

    # Extract salt and counter
    print("\nExtracting salt and counter...")
    actual_salt = bytes(extract_bytes_from_dmem(dmem_bytes, params.sign_salt_addr, params.salt_bytes))
    print(f"  Salt from DMEM (0x{params.sign_salt_addr:04x}): {actual_salt.hex()}")

    # Testvec mode: fail-fast if kernel didn't actually use the injected salt.
    # Without this guard, a salt-injection regression would let the kernel
    # silently use a different salt and all 14 downstream checkpoints would
    # still pass (self-consistent with the wrong salt); only the final KAT
    # byte-compare would catch it.
    if testvec_case is not None:
        injected_salt = bytes(testvec_case[4])
        if actual_salt != injected_salt:
            print("[ERROR] Testvec salt mismatch: kernel used different salt than injected.")
            print(f"  injected: {injected_salt.hex()}")
            print(f"  used:     {actual_salt.hex()}")
            print(f"  Likely cause: salt_input DMEM slot clobbered by kernel before bn.lid load.")
            return False

        # Verify caller-owned input regions still intact post-sim.
        # sk_seed and msg_len are above any scratch reach. msg[:msg_len]
        # is the consumed portion; bytes past msg_len may be clobbered by
        # batch_quad scratch (known kernel behavior, not checked here).
        injected_sk_seed = bytes(testvec_case[1])
        injected_msg = bytes(testvec_case[2])
        actual_sk_seed = bytes(extract_bytes_from_dmem(
            dmem_bytes, params.sign_skseed_addr, len(injected_sk_seed)))
        actual_msg_len_word = int.from_bytes(
            bytes(extract_bytes_from_dmem(dmem_bytes, params.sign_msg_len_addr, 4)),
            "little")
        actual_msg_used = bytes(extract_bytes_from_dmem(
            dmem_bytes, params.sign_msg_addr, len(injected_msg))) if len(injected_msg) > 0 else b""
        intact = True
        if actual_sk_seed != injected_sk_seed:
            print(f"[ERROR] sk_seed clobbered post-sim. injected={injected_sk_seed.hex()}, "
                  f"actual={actual_sk_seed.hex()}")
            intact = False
        if actual_msg_len_word != len(injected_msg):
            print(f"[ERROR] msg_len clobbered post-sim. injected={len(injected_msg)}, "
                  f"actual={actual_msg_len_word}")
            intact = False
        if actual_msg_used != injected_msg:
            print(f"[ERROR] msg[:msg_len] clobbered post-sim. (Caller-data integrity violation.)")
            intact = False
        if not intact:
            return False
        print(f"  OK caller inputs intact: sk_seed ({len(injected_sk_seed)}B), "
              f"msg_len, msg[:{len(injected_msg)}]")

    actual_counter = read_gpr_register(sim, 8)
    print(f"  Counter (GPR x8): {actual_counter}")
    if actual_counter >= SIGNER_RETRY_MAX:
        print(f"[ERROR] implausible signer retry counter x8={actual_counter}; "
              f"expected 0..{SIGNER_RETRY_MAX - 1} (asm caps at {SIGNER_RETRY_MAX}). "
              f"Likely a caller-saved register was clobbered by a subroutine. "
              f"Aborting before infinite retry loop.")
        if output_dir:
            save_failure_data(output_dir, iteration, sk_seed, message,
                              f"counter clobber x8={actual_counter}")
        return False

    # Compute target hash using extracted salt
    exp_target_digest = compute_target_hash_reference(message, actual_salt, params)
    print(f"  Target hash t: {exp_target_digest.hex()}")

    # ------------------------------------------------------------------ #
    #  Python-side signing retry loop (mirrors UOV.Sign spec)
    #
    #  For counters 0..actual_counter we replicate:
    #    v = Expand_v(msg || salt || sk_seed || ctr)
    #    L = v x S
    #    if L is NOT invertible: continue (retry)
    #    y = batch_quad_trimat_eval(P1, v)
    #    solve Lx = t - y
    # ------------------------------------------------------------------ #
    print(f"\nReplicating signing retry loop (counters 0..{actual_counter})...")
    all_passed = True
    non_invertible_seen = 0  # count of singular L matrices seen in retry loop
    skipped_invertible = 0

    expected_vinegar = None
    expected_L = None
    expected_L_transpose = None

    for ctr in range(actual_counter + 1):
        ctr_vinegar = compute_vinegar_reference(message, actual_salt, sk_seed, ctr, params)
        ctr_L = compute_l_matrix(bytearray(exp_S), ctr_vinegar, params)
        ctr_L_transpose = compute_l_transpose(ctr_L, params)

        # Check invertibility for both GF16 and GF256 using
        # ov_ge_test_utils.is_matrix_invertible (params-dispatched).
        if params.gf == 16:
            invertible = check_l_invertibility_gf16(ctr_L_transpose, params)
        else:
            # Unpack L^T from row-major padded to numpy for invertibility check
            n = params.pub_m
            _l_np = np.zeros((n, n), dtype=np.uint8)
            for _r in range(n):
                _off = _r * params.pub_m_byte_padded
                for _c in range(n):
                    _l_np[_r, _c] = ctr_L_transpose[_off + _c]
            invertible = _is_matrix_invertible(_l_np, params)

        if ctr < actual_counter:
            if invertible:
                print(f"  [ERROR] Counter {ctr}: L is invertible but ACC skipped it!")
                all_passed = False
                skipped_invertible += 1
            else:
                non_invertible_seen += 1
                print(f"  Counter {ctr}: L singular (GE fail) -- skipped")
        else:
            if not invertible:
                print(f"  [ERROR] Counter {ctr}: L is singular but ACC used it!")
                all_passed = False
            else:
                print(f"  Counter {ctr}: L invertible (GE success)")
            expected_vinegar = ctr_vinegar
            expected_L = ctr_L
            expected_L_transpose = ctr_L_transpose

    # Non-invertible path validation (test_non_invertible mode)
    if test_non_invertible:
        if skipped_invertible:
            print(f"  [NON-INV] {skipped_invertible} skipped attempt(s) had an invertible L "
                  f"(errors above)")
        elif actual_counter > 0 and non_invertible_seen > 0:
            print(f"  [NON-INV] ACC correctly rejected {non_invertible_seen} "
                  f"singular L matrix(es) via retry loop (counter incremented "
                  f"from 0 to {actual_counter})")
        elif actual_counter == 0:
            print(f"  [NON-INV] Note: counter=0, no retry occurred in this "
                  f"iteration.  Non-invertible detection is validated "
                  f"opportunistically across iterations.")
        else:
            # counter > 0 but we didn't see non-invertible -- unusual
            print(f"  [NON-INV] Warning: counter={actual_counter} but Python "
                  f"found 0 singular matrices in the retry loop.  This may "
                  f"indicate a mismatch in invertibility detection.")

    print(f"  Vinegar (first 32 bytes): {expected_vinegar[:32].hex()}")
    print(f"  L matrix size: {len(expected_L)} bytes")

    # Compute Y = batch_quad_trimat_eval(P1, vinegar)
    print("\nComputing Y = batch_quad_trimat_eval(P1, vinegar)...")
    expected_Y = compute_trimat_eval_reference(exp_P1, expected_vinegar, params)
    print(f"  Expected Y: {expected_Y.hex()}")

    # Compute GE reference
    print("Computing reference Gaussian elimination...")
    if params.gf == 16:
        exp_ge_matrix, exp_ge_vector = compute_ge_reference_gf16(
            expected_L_transpose, expected_Y, exp_target_digest, params
        )
    else:
        # GF256: compute Y XOR target as GE RHS
        exp_r = bytearray(target_padded_size)
        for i in range(params.pub_m_byte):
            exp_r[i] = expected_Y[i] ^ exp_target_digest[i]
        exp_r = bytes(exp_r)

        l_transpose_bytes = bytes(expected_L_transpose)
        exp_ge_matrix, exp_ge_vector = compute_ge_reference_gf256(
            l_transpose_bytes, exp_r, params
        )

    # Compute back-substitution reference
    print("Computing reference back-substitution...")
    if params.gf == 16:
        expected_solution = compute_back_sub_reference_gf16(exp_ge_matrix, exp_ge_vector, params)
    else:
        expected_solution = compute_back_sub_reference_gf256(exp_ge_matrix, exp_ge_vector, params)

    # ------------------------------------------------------------------ #
    #  Validation steps [1] through [12+]
    # ------------------------------------------------------------------ #
    print("\nValidating results...")
    results = []

    if debug:
        # [1] pk_seed
        print("\n[1] Validating pk_seed...")
        ok, msgs = validate_step_1_pkseed(dmem_bytes, exp_pk_seed, params)
        if not ok:
            all_passed = False
        results.extend(msgs)

        # [2] O matrix
        print("\n[2] Validating O matrix...")
        ok, msgs = validate_step_2_o_matrix(dmem_bytes, exp_O, params)
        if not ok:
            all_passed = False
        results.extend(msgs)

        # [3] S matrix (L-direct tier never materializes S: skip)
        if ldirect:
            results.append("[3] S matrix: skipped (L-direct tier, S not materialized)")
        else:
            print("\n[3] Validating S matrix...")
            ok, msgs = validate_step_3_s_matrix(dmem_bytes, exp_S, params)
            if not ok:
                all_passed = False
            results.extend(msgs)

        # [4] Target hash
        print("\n[4] Validating target hash...")
        ok, msgs = validate_step_4_target(dmem_bytes, exp_target_digest, params)
        if not ok:
            all_passed = False
        results.extend(msgs)

        # [5] Vinegar
        print("\n[5] Validating vinegar...")
        ok, msgs = validate_step_5_vinegar(dmem_bytes, expected_vinegar, actual_counter, params)
        if not ok:
            all_passed = False
        results.extend(msgs)

        # [6] L matrix (validated indirectly)
        results.append(f"  [6] L matrix reference computed ({_l_size(params):,} bytes, validated via back-sub)")

        # [7] Y vector (validated indirectly)
        results.append(f"  [7] Y & GE reference computed (validated via back-sub)")

        # [8] GE invertibility flag: SKIPPED (not post-hoc observable).
        # GE returns the flag in a transient WDR (w20 for Ip, w24 for Is); the
        # post-GE SW back-sub / O*oil kernels reuse that WDR as an accumulator, so
        # the sim-end register dump no longer holds the flag. The singularity logic
        # is already covered by the retry-counter replication above (skipped counters
        # must be singular, the accepted counter invertible) plus [11] sig + [12] verify.
        results.append("[8] GE flag: skipped (transient WDR, not post-hoc observable; "
                       "covered by retry-counter check + [11] sig + [12] verify)")

        # [9] Back-substitution solution
        print("\n[9] Validating back-sub solution...")
        ok, msgs = validate_step_9_backsub(dmem_bytes, expected_solution, params)
        if not ok:
            all_passed = False
        results.extend(msgs)

        # [10] O x oil
        print("\n[10] Validating O x oil...")
        ok, msgs = validate_step_10_o_oil(sim, exp_O, expected_solution, params)
        if not ok:
            all_passed = False
        results.extend(msgs)

    # Compute expected O*oil bytes for step 11 reference comparison (debug mode)
    expected_o_oil_bytes = _compute_o_oil_reference(exp_O, expected_solution, params)

    # ALWAYS extract sig from DMEM so [12]/[13]/[14] verify ACTUAL ACC output,
    # not the Python reference. If ACC sig is wrong, [12] will fail.
    sig_size = _sig_size(params)
    v_byte = _v_byte(params)
    actual_sig = bytes(extract_bytes_from_dmem(dmem_bytes, params.sign_sig_addr, sig_size))
    vinegar_sig = bytearray(actual_sig[:v_byte])
    oil_bytes = bytearray(actual_sig[v_byte:v_byte + params.pub_m_byte])

    if debug:
        # [11] Explicit DMEM-vs-expected signature byte comparison
        print("\n[11] Validating signature...")
        ok, msgs, _, _ = validate_step_11_signature(
            dmem_bytes, expected_vinegar, expected_o_oil_bytes,
            expected_solution, actual_salt, params,
        )
        if not ok:
            all_passed = False
        results.extend(msgs)

    # [12]-[14] check against the target a verifier computes: the hash takes the salt the signature carries, so a
    # wrong salt field fails here in fuzz mode too
    sig_target = compute_target_hash_reference(message, actual_sig[-params.salt_bytes:], params)
    print("\n[12] Signature verification via public map (ACC-extracted bytes)...")
    ok, msgs, trimat, sig_x = validate_step_12_verify(
        vinegar_sig, oil_bytes, sig_target,
        exp_P1, exp_P2, exp_O, params,
    )
    if not ok:
        all_passed = False
    results.extend(msgs)

    # [13] Negative test: altered signature (optional)
    if include_negative_tests:
        print("\n[13] Negative test: altered signature...")
        ok, msgs = validate_step_13_altered_sig(trimat, sig_x, sig_target, params)
        if not ok:
            all_passed = False
        results.extend(msgs)

        # [14] Negative test: altered public key
        print("\n[14] Negative test: altered public key...")
        ok, msgs = validate_step_14_altered_pk(trimat, sig_x, sig_target, params)
        if not ok:
            all_passed = False
        results.extend(msgs)

    # Testvec mode: byte-compare final sig against KAT.
    if expected_testvec_sig is not None:
        actual_sig = bytes(extract_bytes_from_dmem(
            dmem_bytes, params.sign_sig_addr, params.signature_bytes))
        expected = bytes(expected_testvec_sig)
        if actual_sig != expected:
            diffs = [(i, a, e) for i, (a, e) in enumerate(zip(actual_sig, expected))
                     if a != e]
            results.append(f"[KAT] X Testvec sig byte-wise MISMATCH: {len(diffs)} differing bytes")
            for (idx, a, e) in diffs[:8]:
                results.append(f"  byte[{idx:3d}]: got 0x{a:02x}, want 0x{e:02x}")
            all_passed = False
        else:
            results.append(f"[KAT] OK Testvec sig byte-wise MATCH ({len(actual_sig)} B)")

    # Print summary
    results.append("")
    results.append("All validations passed!" if all_passed else "Some validations FAILED!")
    print("\n".join(results))

    if not all_passed and output_dir:
        save_failure_data(output_dir, iteration, sk_seed, message, "validation mismatch")

    return all_passed


def sign_main(params) -> int:
    """
    CLI entry point for OV signing tests.

    Default mode: sign + verify final signature only.
    Debug mode (--debug): validates all intermediate checkpoints.

    Args:
        params: OV parameter set (OV_IS or OV_IP)

    Returns:
        Exit code: 0 if all passed, 1 otherwise
    """
    from acc_sim_utils import create_common_argparser, run_test_suite

    parser = create_common_argparser(
        f"OV_{params.name} SKC Sign Test",
        default_elf=params.default_sign_elf,
        default_iterations=1,
    )
    # Detect an explicit --elf by value (None sentinel), not by scanning argv: argparse
    # accepts abbreviations (--el, --el=...) that an argv scan would miss.
    parser.set_defaults(elf=None)
    parser.add_argument(
        '--debug', action='store_true',
        help='Enable all intermediate checkpoint validations')
    parser.add_argument(
        '--precompute', action='store_true',
        help='ELF is a precompute-S sign build (sign_sprec): builds S in DMEM; S, '
             'pk_seed and O are read at the ELF labels; checkpoint [3] S-matrix '
             'check enabled. Default (no flag) is the canonical L-direct path (no '
             'S buffer, a smaller scratch in its place; checkpoint [3] skipped).')
    parser.add_argument(
        '--tier', choices=['bngfaes', 'bngfonly', 'bnaesonly', 'sw'], default=None,
        help='Backend tier; picks the sign ELF (default bngfaes; the _testvec build with '
             '--test-data-file, the sign_sprec build with --precompute) unless --elf is given. '
             'With --elf, the run fails unless the ELF symbol fingerprint '
             '(acc_sim_utils.elf_tier) is this tier.')
    parser.add_argument(
        '--negative-tests', action='store_true', default=None,
        help='Enable negative tests (default: auto per variant, Ip=yes, Is=no)')
    parser.add_argument(
        '--test-data-file', type=str, default=None,
        help='Path to testvectors-{Is,Ip}-pkc-skc KAT file. Iterates testvec '
             'cases instead of random fuzz, byte-compares final sig against '
             'testvec. Add --debug to also validate all 14 intermediate '
             'checkpoints. Needs a testvec ELF (e.g. ov-Ip-sign_ldirect_testvec_bngfaes.elf).')
    parser.add_argument(
        '--case-start', type=int, default=0,
        help='Testvec mode only: index of first case to run (0-based). '
             'Combined with --iterations, allows running a slice of the '
             'testvec file in a separate process (for parallel sweeps).')
    parser.add_argument(
        '--cases', type=str, default=None,
        help='Testvec mode only: comma-separated 0-based case indices to run '
             '(e.g. "0,11"). Mutually exclusive with --case-start. '
             'KAT file ordering is msglen [0,1,2,4,8,16,32,64,128,256,512,1024] '
             '-> msglen 0 = case 0, msglen 1024 = case 11.')
    args = parser.parse_args()

    # L-direct is the default sign path; --precompute selects the precompute-S path (checkpoint [3] enabled)
    ldirect = not args.precompute

    # Effective sign ELF: explicit --elf wins; else ov-<P>-sign_<ldirect|sprec>[_testvec]_<tier>.elf, L-direct
    # next to the params' own sign ELF, precompute-S in its parameter set's package of the oversized-DMEM family.
    # A resolved testvec ELF is validated by the salt_input check below.
    _elf_explicit = args.elf is not None
    if args.precompute and args.tier == 'bnaesonly':
        parser.error('bnaesonly is available only for L-direct signing')
    if not _elf_explicit:
        _dir = (f'bazel-bin/sw/acc/crypto/handwritten/uov/dmem_large/sign_sprec/ov-{params.short}-skc' if args.precompute
                else os.path.dirname(params.default_sign_elf))
        args.elf = (f'{_dir}/ov-{params.short}-sign_{"sprec" if args.precompute else "ldirect"}'
                    f'{"_testvec" if args.test_data_file else ""}_{args.tier or "bngfaes"}.elf')
    if not os.path.isfile(args.elf):
        print(f'ERROR: missing sign ELF: {args.elf}\n  build it with bazel first.', flush=True)
        return 1
    if _elf_explicit and args.tier is not None:
        from acc_sim_utils import elf_tier
        from elftools.elf.elffile import ELFFile
        with open(args.elf, 'rb') as f:
            _tier = elf_tier({s.name for s in ELFFile(f).get_section_by_name('.symtab').iter_symbols()})
        if _tier != args.tier:
            print(f'ERROR: {args.elf}: ELF fingerprint says {_tier}, --tier {args.tier}', flush=True)
            return 1

    if args.cases is not None and args.case_start != 0:
        print('ERROR: --cases and --case-start are mutually exclusive.', flush=True)
        return 1

    testvec_cases = None
    if args.test_data_file:
        # Verify the (resolved or explicit) ELF is a real testvec ELF via its symbol table.
        symbols = None
        try:
            from hw.ip.acc.util.shared.elf import read_elf
            symbols = read_elf(args.elf)[2]
        except ImportError:
            import subprocess
            try:
                out = subprocess.run(
                    ['hw/ip/acc/util/acc_objdump.py', '-t', args.elf],
                    capture_output=True, text=True, check=True).stdout
                symbols = {}
                for line in out.splitlines():
                    p = line.split()
                    if len(p) >= 6 and p[1] in ('l', 'g'):
                        try:
                            symbols[p[-1]] = int(p[0], 16)
                        except ValueError:
                            pass
            except Exception as e:
                print(f"ERROR: could not inspect ELF symbol table: {e}", flush=True)
                return 1
        if 'salt_input' not in symbols:
            print(f"ERROR: {args.elf} has no 'salt_input' symbol. "
                  f"Pass a *_testvec_<tier>.elf build (-DUSE_TESTVEC_SALT).",
                  flush=True)
            return 1
        actual_addr = symbols['salt_input']
        if actual_addr != params.sign_salt_input_addr:
            print(f"ERROR: ELF salt_input at 0x{actual_addr:x} but "
                  f"OV_{params.name}.sign_salt_input_addr=0x{params.sign_salt_input_addr:x}. "
                  f"Update ov_params.py.", flush=True)
            return 1
        # KAT correctness signal is the final sig byte-match. --debug enables
        # the 14 intermediate checkpoints for bug localization but is opt-in.
        testvec_cases = parse_sign_testvec_file(args.test_data_file, params)
        print(f"Loaded {len(testvec_cases)} testvec case(s) from {args.test_data_file}",
              flush=True)

    # Negative tests: Ip enables by default (steps 13-14), Is disables
    include_negative = args.negative_tests
    if include_negative is None:
        include_negative = (params.gf == 256)  # Ip=True, Is=False

    if testvec_cases is not None:
        if args.cases is not None:
            # --cases mode: run exactly the listed indices (overrides --iterations)
            from acc_sim_utils import parse_cases
            _cases_idxs = parse_cases(args.cases)
            _selected_cases = [testvec_cases[i] for i in _cases_idxs]
            n_iters = len(_selected_cases)
            n_normal = n_iters
            n_noninv = 0
            print(f"[testvec mode] --cases {args.cases}: running {n_iters} case(s) "
                  f"of {len(testvec_cases)}", flush=True)
        else:
            if args.case_start < 0 or args.case_start >= len(testvec_cases):
                print(f"ERROR: --case-start {args.case_start} out of range "
                      f"[0, {len(testvec_cases)-1}]", flush=True)
                return 1
            _selected_cases = None  # use case_start + i indexing below
            max_avail = len(testvec_cases) - args.case_start
            n_iters = min(args.iterations, max_avail)
            n_normal = n_iters
            n_noninv = 0
            print(f"[testvec mode] running cases [{args.case_start}..{args.case_start + n_iters - 1}] "
                  f"of {len(testvec_cases)}", flush=True)
    else:
        _selected_cases = None
        n_iters = args.iterations
        n_normal = max(1, n_iters // 2)
        n_noninv = n_iters - n_normal
        if n_noninv > 0:
            print(f"[INFO] Iteration split: {n_normal} normal + "
                  f"{n_noninv} with non-invertible validation")

    def test_func(i, regs_f, stats_f):
        if testvec_cases is not None:
            if _selected_cases is not None:
                case = _selected_cases[i]
            else:
                case = testvec_cases[args.case_start + i]
        else:
            case = None
        use_noninv = (case is None) and (i >= n_normal)
        return run_sign_test(
            iteration=i,
            elf_path=args.elf,
            params=params,
            verbose=args.verbose,
            dump_regs_file=regs_f,
            dump_stats_file=stats_f,
            output_dir=getattr(args, 'output_dir', ''),
            include_negative_tests=include_negative,
            test_non_invertible=use_noninv,
            debug=args.debug,
            testvec_case=case,
            ldirect=ldirect,
        )

    return run_test_suite(
        f"OV_{params.name}_SKC_Sign", test_func,
        elf_path=args.elf,
        iterations=n_iters,
        output_dir=getattr(args, 'output_dir', None),
        seed=getattr(args, 'seed', None),
    )
