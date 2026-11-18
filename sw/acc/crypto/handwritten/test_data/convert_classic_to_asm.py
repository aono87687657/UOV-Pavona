#!/usr/bin/env python3
"""
Convert classic format test data to assembly files for RTL testing.
Supports both ov-Is-classic (GF16) and ov-Ip-classic (GF256) formats.

Classic format (3 lines per test case):
  Line 1: pk  - Full uncompressed public key (P1+P2+P3)
  Line 2: sk  - Full secret key (skipped for verify)
  Line 3: sm  - Signed message: message || signature (signature is the tail)

Output: One assembly file per test case with .data section containing:
  - P:          Full public key as little-endian 32-bit words
  - sig:        Signature (x + salt) as little-endian 32-bit words
  - msg:        Message data as little-endian 32-bit words
  - msg_len:    Message length in bytes
  - expect_acc: SHAKE256(message || salt) as expected verification result

Labels match the verify test assembly (ov-*_verify_test.s) so they can
be linked directly without generating a separate harness.

Usage:
  python3 convert_classic_to_asm.py input_file [--format ip|is] [output_dir]
"""

import sys
import os
import re
import argparse
from typing import List, Tuple, Dict, Any
from Crypto.Hash import SHAKE256

CLASSIC_CONFIGS = {
    'is': {
        'name': 'ov-Is-classic (GF16)',
        'pub_n': 160,
        'pub_m': 64,
        'v': 96,
        'o': 64,
        'pub_n_byte': 80,
        'pub_m_byte': 32,
        'salt_bytes': 16,
        'pk_size': 412160,      # N*(N+1)/2 * pub_m_byte = 12880 * 32
        'signature_bytes': 96,  # pub_n_byte + salt = 80 + 16
        'prefix': 'Is-classic',
    },
    'ip': {
        'name': 'ov-Ip-classic (GF256)',
        'pub_n': 112,
        'pub_m': 44,
        'v': 68,
        'o': 44,
        'pub_n_byte': 112,
        'pub_m_byte': 44,
        'salt_bytes': 16,
        'pk_size': 278432,      # N*(N+1)/2 * pub_m_byte = 6328 * 44
        'signature_bytes': 128, # pub_n_byte + salt = 112 + 16
        'prefix': 'Ip-classic',
    }
}


def hex_string_to_bytes(hex_str: str) -> bytearray:
    s = re.sub(r'\s+', '', hex_str)
    if len(s) % 2 != 0:
        raise ValueError('Odd-length hex string')
    return bytearray(int(s[i:i+2], 16) for i in range(0, len(s), 2))


def detect_format(filepath: str) -> str:
    with open(filepath, 'r') as f:
        first_line = f.readline().strip()
    pk = hex_string_to_bytes(first_line)
    pk_size = len(pk)
    if pk_size == CLASSIC_CONFIGS['is']['pk_size']:
        print(f"  Detected ov-Is-classic (PK size: {pk_size:,} bytes)")
        return 'is'
    elif pk_size == CLASSIC_CONFIGS['ip']['pk_size']:
        print(f"  Detected ov-Ip-classic (PK size: {pk_size:,} bytes)")
        return 'ip'
    else:
        raise ValueError(f'Unknown format - PK size {pk_size:,} bytes')


def bytes_to_words_le(data: bytearray) -> List[int]:
    words = []
    for i in range(0, len(data), 4):
        chunk = data[i:i+4]
        while len(chunk) < 4:
            chunk.append(0)
        words.append(int.from_bytes(chunk, 'little'))
    return words


def parse_file(filepath: str, config: Dict[str, Any]) -> List[Tuple[bytearray, bytearray, bytearray, bytearray]]:
    print(f"Parsing: {filepath} ({config['name']})")
    with open(filepath, 'r') as f:
        lines = [line.strip() for line in f if line.strip()]
    if len(lines) % 3 != 0:
        raise ValueError(f'Expected groups of 3 lines, got {len(lines)}')

    test_cases = []
    for i in range(len(lines) // 3):
        pk = hex_string_to_bytes(lines[i * 3])
        sm = hex_string_to_bytes(lines[i * 3 + 2])

        if len(pk) != config['pk_size']:
            raise ValueError(f'Case {i+1}: PK size {len(pk):,} != {config["pk_size"]:,}')

        signature = sm[-config['signature_bytes']:]
        message = sm[:-config['signature_bytes']] if len(sm) > config['signature_bytes'] else bytearray()

        salt = signature[-config['salt_bytes']:]
        hash_input = (message + salt) if message else salt
        expected_hash = bytearray(SHAKE256.new(data=hash_input).read(config['pub_m_byte']))

        # Pad Ip hash from 44B to 64B for 32-byte alignment
        if config['prefix'] == 'Ip-classic' and len(expected_hash) == 44:
            expected_hash = expected_hash + bytearray(20)

        msg_info = f"msg={len(message)}B" if message else "null msg"
        print(f"  Case {i+1}: pk={len(pk):,}B, sig={len(signature)}B, {msg_info}")
        test_cases.append((pk, signature, expected_hash, message))

    print(f"Parsed {len(test_cases)} test cases")
    return test_cases


def generate_asm(pk: bytearray, sig: bytearray, expected_hash: bytearray,
                 message: bytearray, output_path: str, config: Dict[str, Any],
                 case_num: int) -> None:
    pk_words = bytes_to_words_le(pk)
    sig_words = bytes_to_words_le(sig)
    hash_words = bytes_to_words_le(expected_hash)

    with open(output_path, 'w') as f:
        f.write(f"/* Classic format test data - {config['name']} - msglen {len(message)} */\n")
        f.write("/* Generated from convert_classic_to_asm.py */\n\n")
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
                line = msg_words[i:i+8]
                f.write(f"    .word {', '.join(f'0x{w:08x}' for w in line)}\n")
        msg_bytes_written = ((len(message) + 3) // 4) * 4
        padding = 1024 - msg_bytes_written
        if padding > 0:
            f.write(f"    .zero {padding}\n")
        f.write(f"/* Message buffer: {len(message)} bytes data + {padding} bytes padding = 1024B total */\n\n")

        # PK
        f.write("/* Full Public Key (uncompressed P1+P2+P3) */\n")
        f.write(f"/* Size: {len(pk):,} bytes = N*(N+1)/2 * pub_m_byte */\n")
        f.write(f"/* Parameters: n={config['pub_n']}, m={config['pub_m']}, v={config['v']}, o={config['o']} */\n")
        f.write(".balign 32\n")
        f.write(".global P\n")
        f.write("P:\n")
        for i in range(0, len(pk_words), 8):
            line = pk_words[i:i+8]
            f.write(f"    .word {', '.join(f'0x{w:08x}' for w in line)}\n")
        f.write(f"/* PK size: {len(pk):,} bytes ({len(pk_words)} words) */\n\n")

        # Signature
        f.write("/* Signature data */\n")
        f.write(f"/* Format: x ({config['pub_n_byte']}B) + salt ({config['salt_bytes']}B) = {config['signature_bytes']}B total */\n")
        f.write(".balign 32\n")
        f.write(".global sig\n")
        f.write("sig:\n")
        for i in range(0, len(sig_words), 8):
            line = sig_words[i:i+8]
            f.write(f"    .word {', '.join(f'0x{w:08x}' for w in line)}\n")
        f.write(f"/* Signature size: {len(sig)} bytes ({len(sig_words)} words) */\n\n")

        # Expected hash
        f.write("/* Expected Hash (SHAKE256 result) */\n")
        f.write(f"/* SHAKE256(message || salt) = {len(expected_hash)} bytes */\n")
        f.write(".balign 32\n")
        f.write(".global expect_acc\n")
        f.write("expect_acc:\n")
        for i in range(0, len(hash_words), 8):
            line = hash_words[i:i+8]
            f.write(f"    .word {', '.join(f'0x{w:08x}' for w in line)}\n")
        f.write(f"/* Expected hash size: {len(expected_hash)} bytes ({len(hash_words)} words) */\n")


def main():
    parser = argparse.ArgumentParser(description='Convert classic test data to assembly')
    parser.add_argument('input_file', help='Classic format file (pk,sk,sm groups)')
    parser.add_argument('--format', choices=['ip', 'is'],
                        help='Format: ip=ov-Ip (GF256), is=ov-Is (GF16). Auto-detected if omitted.')
    parser.add_argument('output_dir', nargs='?', default='.', help='Output directory')
    args = parser.parse_args()

    if not os.path.exists(args.input_file):
        print(f"Error: '{args.input_file}' not found")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    fmt = args.format or detect_format(args.input_file)
    config = CLASSIC_CONFIGS[fmt]
    test_cases = parse_file(args.input_file, config)

    print(f"\nGenerating assembly files...")
    for i, (pk, sig, expected_hash, message) in enumerate(test_cases):
        msg_len = len(message)
        out = os.path.join(args.output_dir, f"testvectors-{config['prefix']}_msglen{msg_len}.s")
        generate_asm(pk, sig, expected_hash, message, out, config, i + 1)
        print(f"  Generated: {out}")

    print(f"\nDone: {len(test_cases)} files in {args.output_dir}/")


if __name__ == '__main__':
    main()
