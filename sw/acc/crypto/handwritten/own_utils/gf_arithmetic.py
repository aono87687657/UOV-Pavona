#!/usr/bin/env python3

"""
Common GF (Galois Field) Arithmetic and Data Utilities for ACC OV Tests

This module provides:

1. GF(16) and GF(256) core arithmetic (multiplication, lookup tables)
2. Random test-data generation (matrices, vectors)
3. Byte ↔ GF-element packing/unpacking (nibble-packed GF16, byte GF256)
4. DMEM conversion helpers for ACC simulator injection
5. Reference matrix-vector multiplication
6. Oil-Vinegar public-map evaluation  (ov_publicmap_reference)
7. P3 computation moved to ov_keygen_test_utils.py

Supports:
- GF16 (4-bit elements, 2 elements per byte)
- GF256 (8-bit elements, 1 element per byte)

Randomly generated elements span the full field (0-15 for GF16, 0-255 for GF256).
Matrices are organized in COLUMN-MAJOR format to match ACC memory layout.
"""

import random
import galois
from typing import List, Dict

# Import common DMEM utilities for conversion
from dmem_utils import (
    bytes_to_dmem_words,
    columns_to_dmem_words_aligned,
)

# Create Galois Field objects
# GF16 uses x^4+x+1 (standard); GF256 uses x^8+x^4+x^3+x+1 (AES field polynomial)
GF16 = galois.GF(2**4, irreducible_poly="x^4 + x + 1")
GF256 = galois.GF(2**8, irreducible_poly="x^8 + x^4 + x^3 + x + 1")

# Pre-computed GF(16) multiplication table for fast lookups
# Generated using galois library to ensure correctness
# GF16_MUL_TABLE[a][b] = a * b in GF(16) with irreducible polynomial x^4 + x + 1
# Used by gf16v_madd and compute_gf_matvec_reference for table-driven GF arithmetic
GF16_MUL_TABLE = [[int(GF16(_a) * GF16(_b)) for _b in range(16)] for _a in range(16)]

# Pre-computed GF(256) multiplication table for fast lookups
# GF256_MUL_TABLE[a][b] = a * b in GF(256) with irreducible polynomial x^8 + x^4 + x^3 + x + 1
# Used by gf256v_madd and compute_gf_matvec_reference for table-driven GF arithmetic
GF256_MUL_TABLE = [[int(GF256(_a) * GF256(_b)) for _b in range(256)] for _a in range(256)]


###########################################
# GF MULTIPLICATION (CORE OPERATIONS)
###########################################

def gf16_mul_reference(a: int, b: int) -> int:
    """
    Perform GF(2^4) multiplication using galois library.
    
    Args:
        a: Element from GF(2^4) (4 bits, range 0-15)
        b: Element from GF(2^4) (4 bits, range 0-15)
        
    Returns:
        Result in GF(2^4) (4 bits, range 0-15)
        
    Example:
        >>> gf16_mul_reference(3, 5)
        15
        >>> gf16_mul_reference(7, 9)
        14
    """
    return int(GF16(a & 0xF) * GF16(b & 0xF))


def gf256_mul_reference(a: int, b: int) -> int:
    """
    Perform GF(2^8) multiplication using galois library.
    
    Args:
        a: Element from GF(2^8) (8 bits, range 0-255)
        b: Element from GF(2^8) (8 bits, range 0-255)
        
    Returns:
        Result in GF(2^8) (8 bits, range 0-255)
        
    Example:
        >>> gf256_mul_reference(3, 5)
        15
        >>> gf256_mul_reference(0x53, 0xCA)
        1
    """
    return int(GF256(a & 0xFF) * GF256(b & 0xFF))


###########################################
# ELEMENT GENERATION
###########################################

def generate_random_gf_element(field: str = "gf16") -> int:
    """
    Generate a single random GF element (including zero).
    
    Args:
        field: "gf16" or "gf256"
        
    Returns:
        Random element (0-15 for GF16, 0-255 for GF256)
        
    Example:
        >>> elem = generate_random_gf_element("gf16")
        >>> assert 0 <= elem <= 15
    """
    if field == "gf16":
        return random.randint(0, 15)
    elif field == "gf256":
        return random.randint(0, 255)
    else:
        raise ValueError(f"Unsupported field: {field}. Use 'gf16' or 'gf256'.")


###########################################
# MATRIX GENERATION (COLUMN-MAJOR)
###########################################

# Column-major matches ACC DMEM layout for batched coefficient access:
# each column holds all M polynomial coefficients for one monomial,
# so a single bn.lid loads a contiguous slice of coefficients.

def generate_random_gf_matrix(rows: int, cols: int, field: str = "gf16") -> List[List[int]]:
    """
    Generate a random GF matrix (column-major organization).

    Matrix is organized as list of columns, where each column is a list of row elements.
    This matches the ACC memory layout for matrix storage.
    
    Args:
        rows: Number of rows (elements per column)
        cols: Number of columns
        field: "gf16" or "gf256"
        
    Returns:
        Matrix as list of columns: matrix[col_idx][row_idx]
        
    Example:
        >>> matrix = generate_random_gf_matrix(rows=64, cols=32, field="gf16")
        >>> len(matrix)  # Number of columns
        32
        >>> len(matrix[0])  # Number of rows
        64
        >>> all(0 <= elem <= 15 for col in matrix for elem in col)
        True
    """
    matrix = []
    for col in range(cols):
        column = [generate_random_gf_element(field) for _ in range(rows)]
        matrix.append(column)
    return matrix


###########################################
# VECTOR GENERATION
###########################################

def generate_random_gf_vector(length: int, field: str = "gf16") -> List[int]:
    """
    Generate a random GF vector.
    
    Args:
        length: Number of elements in vector
        field: "gf16" or "gf256"
        
    Returns:
        Vector as list of elements
        
    Example:
        >>> vector = generate_random_gf_vector(length=32, field="gf16")
        >>> len(vector)
        32
        >>> all(0 <= elem <= 15 for elem in vector)
        True
    """
    return [generate_random_gf_element(field) for _ in range(length)]


###########################################
# CONVERSION: ELEMENTS ↔ BYTES
###########################################

def gf_elements_to_bytes(elements: List[int], field: str = "gf16") -> bytearray:
    """
    Convert GF elements to bytes for DMEM injection.
    
    - GF16: 2 elements per byte (4 bits each)
      Byte format: [elem0(low 4 bits), elem1(high 4 bits)]
    - GF256: 1 element per byte (8 bits each)
    
    Args:
        elements: List of GF elements
        field: "gf16" or "gf256"
        
    Returns:
        Byte array representation
        
    Example:
        >>> # GF16: elements [5, 10] -> byte 0xA5
        >>> bytes = gf_elements_to_bytes([5, 10], "gf16")
        >>> bytes[0] == 0xA5  # (10 << 4) | 5
        True
    """
    if field == "gf16":
        # GF16: 2 elements per byte, low nibble = even index, high nibble = odd index
        if len(elements) % 2 == 1:
            elements = list(elements) + [0]  # Pad to even length

        result = bytearray(len(elements) // 2)
        for i in range(0, len(elements), 2):
            result[i // 2] = (elements[i] & 0xF) | ((elements[i + 1] & 0xF) << 4)
        return result
    
    elif field == "gf256":
        # GF256: 1 element per byte
        return bytearray(elements)
    
    else:
        raise ValueError(f"Unsupported field: {field}. Use 'gf16' or 'gf256'.")


def bytes_to_gf_elements(byte_data: bytearray, field: str = "gf16") -> List[int]:
    """
    Convert bytes to GF elements.
    
    - GF16: 2 elements per byte (4 bits each)
    - GF256: 1 element per byte (8 bits each)
    
    Args:
        byte_data: Byte array
        field: "gf16" or "gf256"
        
    Returns:
        List of GF elements
        
    Example:
        >>> # GF16: byte 0xA5 -> elements [5, 10]
        >>> elems = bytes_to_gf_elements(bytearray([0xA5]), "gf16")
        >>> elems == [5, 10]
        True
    """
    if field == "gf16":
        # GF16: Unpack 2 elements per byte
        elements = []
        for byte in byte_data:
            elements.append(byte & 0xF)        # Low 4 bits
            elements.append((byte >> 4) & 0xF)  # High 4 bits
        return elements
    
    elif field == "gf256":
        # GF256: 1 element per byte
        return list(byte_data)
    
    else:
        raise ValueError(f"Unsupported field: {field}. Use 'gf16' or 'gf256'.")


###########################################
# DMEM CONVERSION WRAPPERS
###########################################

def gf_matrix_to_dmem_words(
    matrix: List[List[int]],
    base_addr: int,
    bytes_per_column: int,
    field: str = "gf16",
    aligned: bool = False
) -> Dict[int, int]:
    """
    Convert GF matrix to DMEM word dictionary for injection.
    
    Args:
        matrix: Matrix as list of columns (column-major)
        base_addr: Base address in DMEM
        bytes_per_column: Number of bytes per column in memory
        field: "gf16" or "gf256"
        aligned: If True, align columns to 32-byte boundaries (for OV operations)
                 If False, pack columns sequentially (for simple matvec)
        
    Returns:
        Dictionary mapping word addresses to 32-bit word values
        
    Example:
        >>> matrix = generate_random_gf_matrix(rows=64, cols=32, field="gf16")
        >>> words = gf_matrix_to_dmem_words(matrix, 0x0, 32, field="gf16")
        >>> # Ready to inject with inject_words_to_dmem(sim, words)
    """
    if aligned:
        # Use aligned column storage (32-byte boundaries)
        all_data = bytearray()
        for column in matrix:
            column_bytes = gf_elements_to_bytes(column, field)
            # Pad to bytes_per_column
            while len(column_bytes) < bytes_per_column:
                column_bytes.append(0)
            all_data.extend(column_bytes[:bytes_per_column])
        
        return columns_to_dmem_words_aligned(all_data, base_addr, bytes_per_column, alignment=32)
    else:
        # Sequential (no gaps) column storage
        all_data = bytearray()
        for column in matrix:
            column_bytes = gf_elements_to_bytes(column, field)
            # Pad to bytes_per_column
            while len(column_bytes) < bytes_per_column:
                column_bytes.append(0)
            all_data.extend(column_bytes[:bytes_per_column])
        
        return bytes_to_dmem_words(all_data, base_addr)


def gf_vector_to_dmem_words(
    vector: List[int],
    base_addr: int,
    field: str = "gf16"
) -> Dict[int, int]:
    """
    Convert GF vector to DMEM word dictionary for injection.
    
    Args:
        vector: Vector as list of GF elements
        base_addr: Base address in DMEM
        field: "gf16" or "gf256"
        
    Returns:
        Dictionary mapping word addresses to 32-bit word values
        
    Example:
        >>> vector = generate_random_gf_vector(length=32, field="gf16")
        >>> words = gf_vector_to_dmem_words(vector, 0x400, field="gf16")
        >>> # Ready to inject with inject_words_to_dmem(sim, words)
    """
    vector_bytes = gf_elements_to_bytes(vector, field)
    return bytes_to_dmem_words(vector_bytes, base_addr)


###########################################
# REFERENCE COMPUTATION
###########################################

def compute_gf_matvec_reference(
    matrix: List[List[int]],
    vector: List[int],
    field: str = "gf16"
) -> List[int]:
    """
    Compute reference GF matrix-vector multiplication: result = matrix × vector
    
    Matrix is column-major: matrix[col_idx][row_idx]
    
    Algorithm:
        result[row] = sum over cols: matrix[col][row] * vector[col]
        where sum is XOR and * is GF multiplication
    
    Args:
        matrix: Matrix as list of columns (column-major)
        vector: Vector as list of elements
        field: "gf16" or "gf256"
        
    Returns:
        Result vector
        
    Example:
        >>> matrix = [[1, 2], [3, 4]]  # 2 rows × 2 cols
        >>> vector = [5, 6]
        >>> result = compute_gf_matvec_reference(matrix, vector, "gf16")
        >>> # result[0] = (1*5) XOR (3*6)
        >>> # result[1] = (2*5) XOR (4*6)
    """
    if not matrix or not matrix[0]:
        return []
    if len(vector) != len(matrix) or any(len(c) != len(matrix[0]) for c in matrix):
        raise ValueError(f"matvec: {len(matrix)} columns of lengths {sorted({len(c) for c in matrix})}, "
                         f"vector of {len(vector)}")
    
    # Select lookup table
    if field == "gf16":
        mul_table = GF16_MUL_TABLE
    elif field == "gf256":
        mul_table = GF256_MUL_TABLE
    else:
        raise ValueError(f"Unsupported field: {field}. Use 'gf16' or 'gf256'.")
    
    n_rows = len(matrix[0])
    result = [0] * n_rows
    
    # Compute matrix-vector multiplication
    for col_idx, column in enumerate(matrix):
        vec_elem = vector[col_idx]
        if vec_elem == 0:
            continue
        
        tbl = mul_table[vec_elem]
        for row_idx, mat_elem in enumerate(column):
            result[row_idx] ^= tbl[mat_elem]
    
    return result


###########################################
# OIL-VINEGAR PUBLIC MAP REFERENCE
###########################################

def gfv_get_ele_gf16(data: bytes, i: int) -> int:
    """
    Extract GF16 element from packed byte representation.
    Two GF16 elements per byte (nibbles).
    
    Args:
        data: Byte array containing packed GF16 elements
        i: Element index
        
    Returns:
        GF16 element (0-15)
    """
    byte_idx = i // 2
    if i % 2 == 0:
        return data[byte_idx] & 0x0F  # Low nibble
    else:
        return (data[byte_idx] >> 4) & 0x0F  # High nibble


def gf16v_madd(a: bytearray, vec: bytes, gf16_b: int) -> None:
    """
    Vector multiply-add operation in GF16: a += vec * gf16_b
    Handles packed GF16 format (2 elements per byte).
    Uses pre-computed lookup table for fast GF(16) multiplication.
    
    Args:
        a: Accumulator vector (modified in-place)
        vec: Input vector of GF16 elements (packed, 2 elements per byte)
        gf16_b: Scalar multiplier
    """
    for i in range(len(a)):
        low = GF16_MUL_TABLE[vec[i] & 0xF][gf16_b]
        high = GF16_MUL_TABLE[vec[i] >> 4][gf16_b]
        a[i] ^= low | (high << 4)


def gf256v_madd(a: bytearray, vec: bytes, gf256_b: int) -> None:
    """
    Vector multiply-add operation in GF256: a += vec * gf256_b
    Each byte is one GF256 element (1 element per byte).
    Uses pre-computed lookup table for fast GF(256) multiplication.
    
    Args:
        a: Accumulator vector (modified in-place)
        vec: Input vector of GF256 elements (1 element per byte)
        gf256_b: Scalar multiplier
    """
    tbl = GF256_MUL_TABLE[gf256_b]
    for i in range(len(a)):
        a[i] ^= tbl[vec[i]]


def ov_publicmap_reference(
    trimat: bytes,
    x: bytes,
    n: int,
    m: int,
    v: int,
    field: str = "gf16"
) -> bytearray:
    """
    Reference implementation of Oil-Vinegar public map evaluation.
    Computes y = P(x) where P is the multivariate quadratic system.
    
    The public map is organized as three parts:
    - P1: Vinegar × Vinegar (upper triangular)
    - P2: Vinegar × Oil (full matrix)
    - P3: Oil × Oil (upper triangular)
    
    Args:
        trimat: Public key matrix in column-major format (all monomial columns concatenated)
        x: Input vector (signature part)
        n: Total variables (vinegar + oil)
        m: Number of output polynomials
        v: Number of vinegar variables
        field: "gf16" or "gf256"
        
    Returns:
        Output vector y (hash result)
        
    Notes:
        - For GF16: x is packed (2 elements/byte), output is packed
        - For GF256: x is unpacked (1 element/byte), output is unpacked
        - Trimat size: [(v*(v+1))/2 + v*o + (o*(o+1))/2] × m_bytes columns
    """
    o = n - v
    
    # Calculate sizes based on field
    if field == "gf16":
        m_bytes = m // 2
        n_bytes = n // 2
    elif field == "gf256":
        m_bytes = m
        n_bytes = n
    else:
        raise ValueError(f"Unsupported field: {field}. Use 'gf16' or 'gf256'.")
    
    # Verify input sizes: a short key would give a partial result that a broken kernel could match
    if len(x) != n_bytes:
        raise ValueError(f"Input x size mismatch: got {len(x)} bytes, expected {n_bytes} bytes")
    want = (v * (v + 1) // 2 + v * o + o * (o + 1) // 2) * m_bytes
    if len(trimat) != want:
        raise ValueError(f"Trimat size mismatch: got {len(trimat)} bytes, expected {want} bytes")
    
    # Initialize output vector
    y = bytearray(m_bytes)
    
    # Select lookup table and extraction functions
    if field == "gf16":
        mul_table = GF16_MUL_TABLE
        gfv_madd = gf16v_madd
        # Extract all input elements first (for GF16 packed format)
        _x = [gfv_get_ele_gf16(x, i) for i in range(n)]
    else:  # gf256
        mul_table = GF256_MUL_TABLE
        gfv_madd = gf256v_madd
        # For GF256, elements are already bytes
        _x = list(x)
    
    trimat_offset = 0
    
    # P1: Vinegar x Vinegar (upper triangular)
    # P1[i,j] where j>=i at flat index j*(j+1)/2 + i
    for i in range(v):
        for j in range(i, v):  # j >= i for upper triangular
            monomial_value = mul_table[_x[i]][_x[j]]
            gfv_madd(y, trimat[trimat_offset:trimat_offset + m_bytes], monomial_value)
            trimat_offset += m_bytes
    
    # P2: Vinegar × Oil (full matrix)
    for i in range(v):
        for j in range(o):
            monomial_value = mul_table[_x[i]][_x[v + j]]
            gfv_madd(y, trimat[trimat_offset:trimat_offset + m_bytes], monomial_value)
            trimat_offset += m_bytes
    
    # P3: Oil × Oil (upper triangular)
    for i in range(o):
        for j in range(i, o):  # j >= i for upper triangular
            monomial_value = mul_table[_x[v + i]][_x[v + j]]
            gfv_madd(y, trimat[trimat_offset:trimat_offset + m_bytes], monomial_value)
            trimat_offset += m_bytes
    
    return y


# P3 computation functions (compute_p3_reference, compute_p3_reference_gf256)
# have been moved to ov_keygen_test_utils.py where they belong as keygen operations.
