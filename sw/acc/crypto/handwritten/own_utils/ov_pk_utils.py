"""
OV public-key helpers: the KAT vector files (cpk / sk / sm per case), the P1 || P2 expansion from pk_seed, the
expanded public key and the SHAKE256 target of a verification.
"""

from typing import List, Tuple

from Crypto.Cipher import AES
from Crypto.Hash import SHAKE256

from ov_params import OVParams


def hex_string_to_bytes(hex_str: str) -> bytearray:
    """Convert hex string to bytearray, stripping whitespace."""
    return bytearray.fromhex(''.join(hex_str.split()))


def parse_pkc_test_data_file(
    filename: str,
    params: OVParams,
) -> List[Tuple[bytearray, bytearray, bytearray, bytearray]]:
    """
    Parse PKC test data file with format: cpk, sk, sm (3 lines per test case).

    Returns list of (cpk, sk, message, signature) tuples.
    """
    print(f"Parsing test data from: {filename}")

    with open(filename, 'r') as f:
        lines = [line.strip() for line in f.readlines() if line.strip()]

    if not lines or len(lines) % 3 != 0:
        raise ValueError(f"File should have groups of 3 lines, found {len(lines)} lines")

    test_cases = []
    num_cases = len(lines) // 3

    for i in range(num_cases):
        cpk = hex_string_to_bytes(lines[i * 3])
        sk = hex_string_to_bytes(lines[i * 3 + 1])
        sm = hex_string_to_bytes(lines[i * 3 + 2])

        # Validate CPK size
        if len(cpk) != params.cpk_size:
            raise ValueError(f"Case {i+1}: CPK size {len(cpk)} != {params.cpk_size}")

        # Extract message and signature from sm
        sig_bytes = params.signature_bytes
        if len(sm) == sig_bytes:
            message = bytearray(0)
            signature = sm
            print(f"  Case {i+1}: Null message (sm length = signature length)")
        elif len(sm) > sig_bytes:
            message = sm[:-sig_bytes]
            signature = sm[-sig_bytes:]
            print(f"  Case {i+1}: Message length = {len(message)} bytes")
        else:
            raise ValueError(
                f"Case {i+1}: sm too short ({len(sm)} < {sig_bytes})"
            )

        if len(signature) != sig_bytes:
            raise ValueError(
                f"Case {i+1}: Signature size {len(signature)} != {sig_bytes}"
            )

        test_cases.append((cpk, sk, message, signature))
        print(f"  cpk={len(cpk)}B, sk={len(sk)}B, msg={len(message)}B, sig={len(signature)}B")

    print(f"Successfully parsed {num_cases} test case(s)")
    return test_cases


def expand_p1p2_from_pkseed(
    pk_seed: bytearray,
    params: OVParams,
) -> bytearray:
    """
    Expand P1 and P2 matrices using AES-128-CTR from a 16-byte pk_seed.

    The AES-CTR cipher encrypts an all-zero plaintext of length
    (P1_SIZE + P2_SIZE) to produce the concatenated P1||P2 stream.

    P1: Upper triangular, V*(V+1)/2 monomials x pub_m_byte bytes each.
        Stored ROW-MAJOR: [Row 0: V elements][Row 1: V-1 elements]...
    P2: Full V*PUB_M = V*O monomials x pub_m_byte bytes each.
        Stored ROW-MAJOR by AES-CTR.

    Args:
        pk_seed: 16-byte AES-128 key (public key seed)
        params: OV parameter set (provides p1_size, p2_size)

    Returns:
        Concatenated P1||P2 as bytearray
    """
    p1p2_size = params.p1_size + params.p2_size
    cipher = AES.new(bytes(pk_seed), AES.MODE_CTR, nonce=b'\x00' * 12)
    zero_plaintext = b'\x00' * p1p2_size
    expanded_stream = cipher.encrypt(zero_plaintext)
    return bytearray(expanded_stream)


def expand_compressed_pk(cpk: bytearray, params: OVParams) -> bytearray:
    """cpk = seed (16 B) || P3  ->  P1 || P2 || P3, with P1 || P2 expanded from the seed by AES-128-CTR."""
    if len(cpk) != params.cpk_size:
        raise ValueError(f"CPK size mismatch: got {len(cpk)}, expected {params.cpk_size}")
    seed, p3 = cpk[:params.pkc_seed_size], cpk[params.pkc_seed_size:]
    if len(p3) != params.p3_size:
        raise ValueError(f"P3 size mismatch: got {len(p3)}, expected {params.p3_size}")
    full_trimat = expand_p1p2_from_pkseed(seed, params) + p3
    if len(full_trimat) != params.trimat_size:
        raise ValueError(f"Trimat size mismatch: got {len(full_trimat)}, expected {params.trimat_size}")
    return full_trimat


def compute_shake256_hash(message: bytearray, salt: bytearray, params: OVParams) -> bytearray:
    """SHAKE256(message || salt), pub_m_byte bytes: the target a valid signature maps to."""
    if len(salt) != params.salt_bytes:
        raise ValueError(f"Salt size mismatch: got {len(salt)}, expected {params.salt_bytes}")
    return bytearray(SHAKE256.new(data=bytes(message) + bytes(salt)).read(params.pub_m_byte))
