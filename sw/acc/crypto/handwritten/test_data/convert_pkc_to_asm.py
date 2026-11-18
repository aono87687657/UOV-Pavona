#!/usr/bin/env python3
"""
Convert PKC format test data to OTBN assembly files.
Supports both ov-Ip-pkc (GF256) and ov-Is-pkc (GF16) formats.

PKC format (3 lines per test case):
  Line 1: cpk - Compressed public key: Seed (16B) + P3 matrix
  Line 2: sk (variable length hex) - Secret key (skipped)
  Line 3: sm (variable length hex) - Signed message (extract signature from end)

Output: One assembly file per test case with .data section containing:
  - cpk:  Raw CPK as little-endian 32-bit words
  - sig:  Signature (x + salt) as little-endian 32-bit words
  - msg:  Message data as little-endian 32-bit words
  - msg_len: Message length in bytes

Labels match the verify test assembly (ov-*_verify_test.s) so they can
be linked directly without generating a separate harness.

Usage: python3 convert_pkc_to_asm.py input_file.txt [--format ip|is] [output_dir]
"""

import sys
import os
import re
import argparse
from typing import List, Tuple, Dict, Any
from Crypto.Hash import SHAKE256

# PKC format configurations
PKC_CONFIGS = {
    'ip': {
        'name': 'ov-Ip-pkc (GF256)',
        'pub_n': 112,
        'pub_m': 44,
        'v': 68,
        'o': 44,
        'pub_n_byte': 112,  # GF256: 1 byte/element
        'pub_m_byte': 44,   # GF256: 1 byte/element
        'salt_bytes': 16,
        'seed_bytes': 16,
        'p3_size': 43560,   # o*(o+1)/2 * pub_m_byte = 990 * 44
        'cpk_size': 43576,  # seed + p3 = 16 + 43560
        'signature_bytes': 128,  # pub_n_byte + salt_bytes = 112 + 16
        'prefix': 'Ip-pkc'
    },
    'ip3': {
        'name': 'ov-Ip3-pkc (GF256, Round-3 params)',
        'pub_n': 119,
        'pub_m': 45,
        'v': 74,
        'o': 45,
        'pub_n_byte': 119,  # GF256: 1 byte/element
        'pub_m_byte': 45,   # GF256: 1 byte/element
        'salt_bytes': 16,
        'seed_bytes': 16,
        'p3_size': 46575,   # o*(o+1)/2 * pub_m_byte = 1035 * 45
        'cpk_size': 46591,  # seed + p3 = 16 + 46575
        'signature_bytes': 135,  # pub_n_byte + salt_bytes = 119 + 16
        'prefix': 'Ip3-pkc'
    },
    'is': {
        'name': 'ov-Is-pkc (GF16)', 
        'pub_n': 160,
        'pub_m': 64,
        'v': 96,
        'o': 64,
        'pub_n_byte': 80,   # GF16: 0.5 byte/element = 160/2
        'pub_m_byte': 32,   # GF16: 0.5 byte/element = 64/2
        'salt_bytes': 16,
        'seed_bytes': 16,
        'p3_size': 66560,   # o*(o+1)/2 * pub_m_byte = 2080 * 32
        'cpk_size': 66576,  # seed + p3 = 16 + 66560
        'signature_bytes': 96,  # pub_n_byte + salt_bytes = 80 + 16
        'prefix': 'Is-pkc'
    }
}

def hex_string_to_bytes(hex_str: str) -> bytearray:
    """Convert hex string to bytes, removing whitespace."""
    s = re.sub(r'\s+', '', hex_str)
    if len(s) % 2 != 0:
        raise ValueError('Odd-length hex string')
    return bytearray(int(s[i:i+2], 16) for i in range(0, len(s), 2))

def detect_pkc_format(filepath: str) -> str:
    """
    Auto-detect PKC format by analyzing file content.
    Returns: 'ip' for ov-Ip-pkc, 'is' for ov-Is-pkc
    """
    print(f"Auto-detecting PKC format from: {filepath}")
    
    with open(filepath, 'r') as f:
        lines = [line.strip() for line in f.readlines() if line.strip()]
    
    if len(lines) < 3:
        raise ValueError('File must contain at least 3 lines (cpk,sk,sm)')
    
    # Check first CPK line to determine format
    cpk_hex = lines[0]
    cpk = hex_string_to_bytes(cpk_hex)
    cpk_size = len(cpk)
    
    if cpk_size == PKC_CONFIGS['ip']['cpk_size']:
        print(f"  Detected ov-Ip-pkc format (CPK size: {cpk_size} bytes)")
        return 'ip'
    elif cpk_size == PKC_CONFIGS['ip3']['cpk_size']:
        print(f"  Detected ov-Ip3-pkc format (CPK size: {cpk_size} bytes)")
        return 'ip3'
    elif cpk_size == PKC_CONFIGS['is']['cpk_size']:
        print(f"  Detected ov-Is-pkc format (CPK size: {cpk_size} bytes)")
        return 'is'
    else:
        raise ValueError(f'Unknown PKC format - CPK size {cpk_size} bytes does not match ov-Ip-pkc ({PKC_CONFIGS["ip"]["cpk_size"]}) or ov-Is-pkc ({PKC_CONFIGS["is"]["cpk_size"]})')

def parse_pkc_file(filepath: str, config: Dict[str, Any]) -> List[Tuple[bytearray, bytearray, bytearray]]:
    """
    Parse PKC format file and extract CPK, signature, and expected hash data.
    
    Args:
        filepath: Path to PKC format file
        config: PKC configuration dictionary
    
    Returns: List of (cpk, signature, expected_hash) tuples
    """
    print(f"Parsing PKC format file: {filepath}")
    print(f"Using config: {config['name']}")
    
    with open(filepath, 'r') as f:
        lines = [line.strip() for line in f.readlines() if line.strip()]
    
    if len(lines) % 3 != 0:
        raise ValueError(f'File must contain groups of 3 lines (cpk,sk,sm). Found {len(lines)} lines')
    
    test_cases: List[Tuple[bytearray, bytearray, bytearray]] = []
    num_cases = len(lines) // 3
    
    for i in range(num_cases):
        cpk_hex = lines[i * 3]
        sk_hex = lines[i * 3 + 1]
        sm_hex = lines[i * 3 + 2]

        # Convert hex to bytes
        cpk = hex_string_to_bytes(cpk_hex)
        sk_seed = hex_string_to_bytes(sk_hex)
        sm = hex_string_to_bytes(sm_hex)

        if len(sk_seed) != 32:
            raise ValueError(f'Case {i+1}: sk_seed size {len(sk_seed)} != 32')
        
        # Validate CPK size
        if len(cpk) != config['cpk_size']:
            raise ValueError(f'Case {i+1}: CPK size {len(cpk)} != {config["cpk_size"]}')
        
        # Extract signature from end of sm
        if len(sm) < config['signature_bytes']:
            raise ValueError(f'Case {i+1}: SM too short ({len(sm)} bytes), minimum required is {config["signature_bytes"]} bytes')
        
        signature = sm[-config['signature_bytes']:]  # Last signature_bytes
        
        if len(signature) != config['signature_bytes']:
            raise ValueError(f'Case {i+1}: Signature size error - got {len(signature)} bytes, expected {config["signature_bytes"]} bytes')
        
        # Extract message from sm (handle null message case)
        if len(sm) == config['signature_bytes']:
            message = bytearray(0)  # Empty message (null message case)
            print(f"  Case {i+1}: Null message (sm length = signature length)")
        else:
            message = sm[:-config['signature_bytes']]  # All but last signature_bytes
            print(f"  Case {i+1}: Message length = {len(message)} bytes")
        
        # Extract salt from signature (last salt_bytes)
        salt = signature[-config['salt_bytes']:]
        
        # Compute SHAKE256 hash: SHAKE256(message || salt)
        expected_hash = compute_shake256_hash(message, salt, config['pub_m_byte'])
        
        print(f"  Case {i+1}: cpk={len(cpk)}B, sk_seed={len(sk_seed)}B, sig={len(signature)}B, msg={len(message)}B, hash={len(expected_hash)}B")
        test_cases.append((cpk, sk_seed, signature, expected_hash, message))

    print(f"Successfully parsed {num_cases} test cases")
    return test_cases

def compute_shake256_hash(message: bytearray, salt: bytearray, hash_size: int) -> bytearray:
    """
    Compute SHAKE256 hash of message || salt for Oil-Vinegar verification.
    
    Args:
        message: Message bytes (can be empty for null message)
        salt: Salt bytes (16 bytes)
        hash_size: Output hash size in bytes (pub_m_byte)
    
    Returns:
        SHAKE256 hash output
    """
    if len(salt) != 16:  # SALT_BYTES is always 16 for both formats
        raise ValueError(f'Salt size mismatch: got {len(salt)}, expected 16')
    
    # Handle null message case - only hash the salt
    if len(message) == 0:
        hash_input = salt
    else:
        hash_input = message + salt
    
    # Compute SHAKE256 hash
    hash_obj = SHAKE256.new(data=hash_input)
    expected_hash = bytearray(hash_obj.read(hash_size))
    
    return expected_hash

def bytes_to_words_le(data: bytearray) -> List[int]:
    """Convert bytes to little-endian 32-bit words."""
    words = []
    for i in range(0, len(data), 4):
        chunk = data[i:i+4]
        # Pad with zeros if needed
        while len(chunk) < 4:
            chunk.append(0)
        # Convert to little-endian 32-bit word
        word = int.from_bytes(chunk, 'little')
        words.append(word)
    return words

def generate_assembly_file(cpk: bytearray, sk_seed: bytearray, signature: bytearray,
                           expected_hash: bytearray, message: bytearray, output_path: str,
                           config: Dict[str, Any], case_num: int) -> None:
    """Generate assembly file with CPK, signature, expected hash, and message data."""

    # Pad expected_hash for ov-Ip-pkc (44 bytes -> 64 bytes) to avoid uninitialized memory
    if config['prefix'] == 'Ip-pkc' and len(expected_hash) == 44:
        expected_hash_padded = expected_hash + bytearray(20)
        hash_comment_size = f"{len(expected_hash)}B padded to 64B"
        print(f"  Padding ov-Ip-pkc hash from {len(expected_hash)} to {len(expected_hash_padded)} bytes")
    else:
        expected_hash_padded = expected_hash
        hash_comment_size = f"{len(expected_hash)}B"

    # Convert to 32-bit words (little-endian)
    cpk_words = bytes_to_words_le(cpk)
    sk_seed_words = bytes_to_words_le(sk_seed)
    sig_words = bytes_to_words_le(signature)
    hash_words = bytes_to_words_le(expected_hash_padded)

    with open(output_path, 'w') as f:
        f.write(f"/* PKC format test data - {config['name']} - msglen {len(message)} */\n")
        f.write("/* Generated from convert_pkc_to_asm.py */\n\n")

        f.write(".section .data\n\n")

        # Message length
        f.write("/* Message length in bytes */\n")
        f.write(".balign 4\n")
        f.write(".global msg_len\n")
        f.write("msg_len:\n")
        f.write(f"    .word {len(message)}\n\n")

        # Message data
        f.write("/* Message data */\n")
        f.write(f"/* Size: {len(message)} bytes */\n")
        f.write(".balign 32\n")
        f.write(".global msg\n")
        f.write("msg:\n")
        if len(message) > 0:
            msg_words = bytes_to_words_le(message)
            for i in range(0, len(msg_words), 8):
                line_words = msg_words[i:i+8]
                word_strs = [f"0x{word:08x}" for word in line_words]
                f.write(f"    .word {', '.join(word_strs)}\n")
        msg_bytes_written = ((len(message) + 3) // 4) * 4
        padding = 1024 - msg_bytes_written
        if padding > 0:
            f.write(f"    .zero {padding}\n")
        f.write(f"/* Message buffer: {len(message)} bytes data + {padding} bytes padding = 1024B total */\n\n")

        # sk_seed (skc input — 32 B)
        f.write("/* Secret-key seed (skc input, 32 B) */\n")
        f.write(".balign 32\n")
        f.write(".global sk_seed\n")
        f.write("sk_seed:\n")
        word_strs = [f"0x{word:08x}" for word in sk_seed_words]
        f.write(f"    .word {', '.join(word_strs)}\n")
        f.write(f"/* sk_seed size: {len(sk_seed)} bytes ({len(sk_seed_words)} words) */\n\n")

        # CPK data
        f.write("/* Compressed Public Key (CPK) */\n")
        f.write(f"/* Format: Seed (16B) + P3 matrix ({config['p3_size']:,}B) = {config['cpk_size']:,}B total */\n")
        f.write(f"/* Parameters: n={config['pub_n']}, m={config['pub_m']}, v={config['v']}, o={config['o']} */\n")
        f.write(".balign 32\n")
        f.write(".global cpk\n")
        f.write("cpk:\n")

        for i in range(0, len(cpk_words), 8):
            line_words = cpk_words[i:i+8]
            word_strs = [f"0x{word:08x}" for word in line_words]
            f.write(f"    .word {', '.join(word_strs)}\n")

        f.write(f"/* CPK size: {len(cpk)} bytes ({len(cpk_words)} words) */\n\n")

        # Signature data
        f.write("/* Signature data */\n")
        f.write(f"/* Format: x ({config['pub_n_byte']}B) + salt ({config['salt_bytes']}B) = {config['signature_bytes']}B total */\n")
        f.write(".balign 32\n")
        f.write(".global sig\n")
        f.write("sig:\n")

        for i in range(0, len(sig_words), 8):
            line_words = sig_words[i:i+8]
            word_strs = [f"0x{word:08x}" for word in line_words]
            f.write(f"    .word {', '.join(word_strs)}\n")

        f.write(f"/* Signature size: {len(signature)} bytes ({len(sig_words)} words) */\n\n")

        # Expected hash data (SHAKE256 result)
        f.write("/* Expected Hash (SHAKE256 result) */\n")
        f.write(f"/* Format: SHAKE256(message || salt) = {hash_comment_size} total */\n")
        if config['prefix'] == 'Ip-pkc':
            f.write("/* Note: ov-Ip-pkc padded from 44B to 64B to avoid uninitialized memory issues */\n")
        f.write("/* This is the expected accumulator result from public map evaluation */\n")
        f.write(".balign 32\n")
        f.write(".global expect_acc\n")
        f.write("expect_acc:\n")

        for i in range(0, len(hash_words), 8):
            line_words = hash_words[i:i+8]
            word_strs = [f"0x{word:08x}" for word in line_words]
            f.write(f"    .word {', '.join(word_strs)}\n")

        f.write(f"/* Expected hash size: {len(expected_hash_padded)} bytes ({len(hash_words)} words) */\n")

def main():
    parser = argparse.ArgumentParser(description='Convert PKC format test data to OTBN assembly files')
    parser.add_argument('input_file', help='PKC format file (cpk,sk,sm groups)')
    parser.add_argument('--format', choices=['ip', 'ip3', 'is'], help='PKC format: ip=ov-Ip-pkc (GF256), ip3=ov-Ip3-pkc (GF256 R3), is=ov-Is-pkc (GF16). Auto-detected if not specified.')
    parser.add_argument('output_dir', nargs='?', default='.', help='Output directory (default: current directory)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input_file):
        print(f"Error: Input file '{args.input_file}' not found")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
        print(f"Created output directory: {args.output_dir}")
    
    try:
        # Determine PKC format
        if args.format:
            pkc_format = args.format
            print(f"Using specified format: {PKC_CONFIGS[pkc_format]['name']}")
        else:
            pkc_format = detect_pkc_format(args.input_file)
        
        config = PKC_CONFIGS[pkc_format]
        
        # Parse input file
        test_cases = parse_pkc_file(args.input_file, config)
        
        print(f"\nGenerating assembly files...")
        
        # Generate assembly file for each test case
        # If output dir signals combined pkc-skc data, mirror that in filename
        filename_prefix = config['prefix']
        if os.path.basename(os.path.normpath(args.output_dir)).endswith('-pkc-skc'):
            filename_prefix = f"{config['prefix']}-skc"

        for i, (cpk, sk_seed, signature, expected_hash, message) in enumerate(test_cases):
            msg_len = len(message)
            output_filename = f"testvectors-{filename_prefix}_msglen{msg_len}.s"
            output_path = os.path.join(args.output_dir, output_filename)

            generate_assembly_file(cpk, sk_seed, signature, expected_hash, message, output_path, config, i+1)
            print(f"  Generated: {output_path}")
        
        print(f"\nSuccessfully generated {len(test_cases)} assembly files")
        print(f"\nConfiguration: {config['name']}")
        print(f"  Parameters: n={config['pub_n']}, m={config['pub_m']}, v={config['v']}, o={config['o']}")
        print(f"  CPK size: {config['cpk_size']:,} bytes (Seed: {config['seed_bytes']}B + P3: {config['p3_size']:,}B)")
        print(f"  Signature size: {config['signature_bytes']} bytes (x: {config['pub_n_byte']}B + salt: {config['salt_bytes']}B)")
        print(f"  Expected hash size: {config['pub_m_byte']} bytes (SHAKE256 output)")
        print(f"  Format: Little-endian 32-bit words, 32-byte aligned")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()