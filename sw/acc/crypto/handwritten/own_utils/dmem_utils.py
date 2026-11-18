#!/usr/bin/env python3

"""
Common DMEM Utilities for ACC Testing

This module provides standardized functions for DMEM injection and extraction
used across all ACC test scripts (OV publicmap/verify and GF matvec).

All functions use the standard implementation from OV test scripts, assuming
memory dumps are obtained with include_validity=False (no validity bytes).

FUNCTION SELECTION GUIDE:
========================

For INJECTION:
--------------
1. inject_words_to_dmem(sim, words)
   - Use for production/quiet injection
   - Only prints errors

For CONVERSION (Bytes → Words):
--------------------------------
1. bytes_to_dmem_words(data, base_addr, pad_to_size=None)
   - Use for: Simple vectors, sequential data, single memory blocks
   - Memory: Sequential (no gaps)
   - Padding: Optional size padding (pad_to_size parameter)
   - Example: x array, salt, message data
   
2. columns_to_dmem_words_aligned(data, base_addr, column_size, alignment=32)
   - Use for: Column-major matrices needing aligned access
   - Memory: Multiple columns with alignment gaps (32-byte boundaries)
   - Padding: Automatic alignment padding per column
   - Example: OV trimat (Macaulay matrix), GF256/GF16 matrices
   
For EXTRACTION:
---------------
1. extract_bytes_from_dmem(dmem_bytes, addr, size)
   - Extract raw bytes from DMEM dump

"""

from typing import Dict, List, Tuple

# WDR width in bytes (256 bits). Also the natural alignment for bn.lid/bn.sid.
_WDR_BYTES = 32


def extract_bytes_from_dmem(dmem_bytes: bytes, addr: int, size: int) -> bytearray:
    """
    Extract raw bytes from ACC DMEM dump (simplified - no validity bytes).
    
    Args:
        dmem_bytes: Raw DMEM contents from simulator (with include_validity=False)
        addr: Memory address to extract from (byte address)
        size: Number of bytes to extract
        
    Returns:
        Extracted bytes as bytearray
    """
    # With include_validity=False, we can directly slice the array. A read outside the dump is an error:
    # padding it with zeros would satisfy every "these bytes are zero" check.
    if addr < 0 or size < 0 or addr + size > len(dmem_bytes):
        raise ValueError(f"DMEM read {addr:#x}+{size} outside the {len(dmem_bytes)}-byte dump")
    return bytearray(dmem_bytes[addr:addr + size])


def inject_words_to_dmem(sim, words: Dict[int, int]) -> None:
    """
    Inject 32-bit words into DMEM at specific addresses without debug information.
    
    Args:
        sim: Simulator instance
        words: Dictionary mapping word addresses to 32-bit word values
    """
    for word_addr, word_value in words.items():
        # Ensure address is 4-byte aligned
        if word_addr % 4 != 0:
            raise ValueError(f"Address {word_addr:#x} is not 4-byte aligned")

        # Write the word directly to memory at the specified address
        sim.state.dmem.store_u32(word_addr, word_value)

    # Commit the changes to make them visible
    sim.state.dmem.commit()

    # Verify injection by reading back the values (no debug printing)
    for word_addr, expected_value in words.items():
        actual_value = sim.state.dmem.load_u32(word_addr)
        if actual_value != expected_value:
            raise RuntimeError(f"DMEM injection read back 0x{actual_value:08x} at 0x{word_addr:08x}, wrote 0x{expected_value:08x}")


def bytes_to_dmem_words(data: bytearray, base_addr: int, pad_to_size: int = None) -> Dict[int, int]:
    """
    Convert byte array to DMEM word dictionary (sequential/simple layout).
    
    Use this function for:
    - Simple vectors (x, salt, parameters)
    - Sequential matrix columns (GF256/GF16 matrices)
    - Any data that doesn't require memory alignment gaps
    
    Args:
        data: Byte array to convert
        base_addr: Base address for the data in DMEM
        pad_to_size: Optional size to pad the data to (in bytes). If specified and larger
                     than len(data), will pad with zeros to reach this size.
                     Useful for padding matrix columns to a specific size.
        
    Returns:
        Dictionary mapping word addresses to 32-bit word values
        
    Example:
        # Simple vector
        vector_words = bytes_to_dmem_words(vector_bytes, 0x100)
        
        # Matrix column with padding
        column_words = bytes_to_dmem_words(column_bytes, 0x800, pad_to_size=1952)
    """
    # Pad data if requested
    if pad_to_size is not None and len(data) < pad_to_size:
        data = data + bytearray(pad_to_size - len(data))
    
    words = {}
    
    for byte_offset in range(0, len(data), 4):
        word_bytes = data[byte_offset:min(byte_offset+4, len(data))]
        
        # Pad with zeros if needed to complete the word
        if len(word_bytes) < 4:
            word_bytes = word_bytes + bytearray(4 - len(word_bytes))
        
        word_addr = base_addr + byte_offset
        word_value = int.from_bytes(word_bytes, byteorder='little')
        words[word_addr] = word_value
    
    return words


def columns_to_dmem_words_aligned(data: bytearray, base_addr: int,
                                   column_size: int, alignment: int = _WDR_BYTES) -> Dict[int, int]:
    """
    Convert column-major data to DMEM word dictionary with memory alignment (for performance).
    
    Use this function for:
    - Column-major matrices requiring aligned memory access (OV trimat, GF matrices)
    - Data structures where ACC needs 32-byte aligned access for performance
    - Multiple data blocks where alignment gaps improve hardware performance
    
    This function organizes data in column-major format where each column is padded
    to maintain the specified alignment boundary (typically 32 bytes for ACC).
    
    Args:
        data: Input data organized as sequential columns (e.g., 6328 columns × 44 bytes)
        base_addr: Base memory address for injection
        column_size: Size of each column in bytes (e.g., 44 bytes per column)
        alignment: Memory alignment requirement in bytes (default: 32 for ACC)
        
    Returns:
        Dictionary mapping word addresses to 32-bit word values
        
    Memory Layout:
        Each column is padded to the next alignment boundary, creating gaps:
        - Column 0: [base_addr + 0*aligned_size] 
        - Column 1: [base_addr + 1*aligned_size]
        - Column 2: [base_addr + 2*aligned_size]
        where aligned_size = round_up(column_size, alignment)
        
    Example:
        # OV trimat: 6328 columns of 44 bytes each, 32-byte aligned
        # Each column becomes 64 bytes (44 data + 20 padding)
        trimat_words = columns_to_dmem_words_aligned(trimat, 0xC0, 
                                                      column_size=44, alignment=32)
        
    Memory Layout Example (column_size=44, alignment=32):
        aligned_size = 64 bytes (44 rounded up to next multiple of 32)

        Column 0: [base+0x000] 44 bytes data + 20 bytes zero padding
        Column 1: [base+0x040] 44 bytes data + 20 bytes zero padding
        Column 2: [base+0x080] 44 bytes data + 20 bytes zero padding
        ...

        Why 32-byte alignment: each WDR (w0-w31) is 256 bits = 32 bytes.
        bn.lid/bn.sid require 32-byte aligned addresses for WDR loads/stores.

    Note:
        This trades memory efficiency (~31% overhead for 44→64 byte columns)
        for faster aligned memory access in ACC hardware.
    """
    words = {}
    num_columns = len(data) // column_size
    
    # Calculate aligned size: round up column_size to next alignment boundary
    aligned_size = ((column_size + alignment - 1) // alignment) * alignment
    
    for col_idx in range(num_columns):
        # Extract column data from sequential input
        col_start = col_idx * column_size
        col_end = col_start + column_size
        column_data = data[col_start:col_end]
        
        # Calculate aligned memory address
        aligned_addr = base_addr + (col_idx * aligned_size)
        
        # Verify alignment
        if aligned_addr % alignment != 0:
            raise ValueError(f"Column {col_idx} address 0x{aligned_addr:x} is not {alignment}-byte aligned")
        
        # Use bytes_to_dmem_words with pad_to_size to handle padding and word conversion
        column_words = bytes_to_dmem_words(column_data, aligned_addr, pad_to_size=aligned_size)
        words.update(column_words)
    
    return words


def validate_bytes(expected: bytes, actual: bytes, data_name: str = "result", verbose: bool = True) -> Tuple[bool, List[int]]:
    """
    Validate that two byte sequences match byte-by-byte (STANDARDIZED VALIDATION).
    
    This is the fundamental validation function - compares raw bytes from DMEM.
    Works for all field types (GF256, GF16) without conversion.
    Returns ALL mismatch indices for thorough debugging.
    
    Args:
        expected: Expected byte sequence
        actual: Actual byte sequence from ACC DMEM
        data_name: Name of data for error messages (default: "result")
        
    Returns:
        Tuple of (success: bool, mismatches: List[int])
        - success: True if all bytes match, False otherwise
        - mismatches: List of byte indices where values differ (empty if success)
        
    Example:
        # Basic validation
        success, mismatches = validate_bytes(expected_bytes, actual_bytes)
        if not success:
            print(f"Failed with {len(mismatches)} mismatches")
        
        # With custom name for debugging
        success, mismatches = validate_bytes(expected, actual, "GF256 result")
        
        # Convert GF elements to bytes before validation
        from gf_arithmetic import gf_elements_to_bytes
        expected_bytes = gf_elements_to_bytes(expected_elements, field="gf16")
        actual_bytes = extract_bytes_from_dmem(dmem_bytes, addr, size)
        success, mismatches = validate_bytes(expected_bytes, actual_bytes)
    """
    # Check length first
    if len(expected) != len(actual):
        print(f"{data_name} length mismatch: expected={len(expected)} bytes, actual={len(actual)} bytes")
        return False, []
    
    # Collect all mismatches
    mismatches = []
    for i, (exp, act) in enumerate(zip(expected, actual)):
        if exp != act:
            mismatches.append(i)
    
    # Report results
    if mismatches:
        print(f"✗ {data_name} validation FAILED: {len(mismatches)} byte(s) mismatch")
        print(f"  Mismatch indices: {mismatches[:10]}{'...' if len(mismatches) > 10 else ''}")
        # Show first few byte differences for debugging
        for i in mismatches[:5]:
            print(f"  Byte [{i:04x}]: expected=0x{expected[i]:02x}, actual=0x{actual[i]:02x}")
        if len(mismatches) > 5:
            print(f"  ... and {len(mismatches) - 5} more mismatches")
    else:
        if verbose:
            print(f'✓ {data_name} validation PASSED: all {len(expected)} bytes match')
    
    return len(mismatches) == 0, mismatches