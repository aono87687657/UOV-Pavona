#!/usr/bin/env python3
"""Check packed AES round keys, in-place blocks, bounds, and preserved registers."""

import argparse
from pathlib import Path
import random
import sys

from Crypto.Cipher import AES
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[6]
sys.path[:0] = [str(ROOT), str(ROOT / "sw/acc/crypto/handwritten/own_utils")]
from acc_sim_utils import run_acc_test
from dmem_utils import bytes_to_dmem_words

ROUND_KEYS = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "d6aa74fdd2af72fadaa678f1d6ab76fe"
    "b692cf0b643dbdf1be9bc5006830b3fe"
    "b6ff744ed2c2c9bf6c590cbf0469bf41"
    "47f7f7bc95353e03f96c32bcfd058dfd"
    "3caaa3e8a99f9deb50f3af57adf622aa"
    "5e390f7df7a69296a7553dc10aa31f6b"
    "14f9701ae35fe28c440adf4d4ea9c026"
    "47438735a41c65b9e016baf4aebf7ad2"
    "549932d1f08557681093ed9cbe2c974e"
    "13111d7fe3944a17f307a78b4d2b30c5"
)
SENTINEL = bytes.fromhex(
    "67452301efcdab8998badcfe10325476a5a5a5a55a5a5a5adf9b5713e0ac6824"
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, default=ROOT / (
        "bazel-bin/sw/acc/crypto/handwritten/AES_ext/aes128_mem_test.elf"))
    args = parser.parse_args()
    assert args.elf.is_file(), f"Build {args.elf.name} first"
    with args.elf.open("rb") as stream:
        symbols = {s.name: s["st_value"] for s in ELFFile(stream).get_section_by_name(".symtab").iter_symbols()}
    rng = random.Random(0xA128)
    cases = [(bytes(range(16)), bytes.fromhex("00112233445566778899aabbccddeeff")),
             (bytes(16), bytes(16))]
    cases += [(rng.randbytes(16), rng.randbytes(16)) for _ in range(4)]
    for case, (key, plain) in enumerate(cases):
        for inplace in (0, 1):
            words = {}
            for name, value in (("key", key), ("plaintext", plain),
                                ("mode", inplace.to_bytes(4, "little"))):
                words.update(bytes_to_dmem_words(value, symbols[name]))
            ok, data, sim = run_acc_test(str(args.elf), dmem_words=words)
            assert ok, f"case {case}, in-place {inplace}: simulator failed"
            def read(name, size):
                return data[symbols[name]:symbols[name] + size]
            output = "plaintext" if inplace else "ciphertext"
            assert read(output, 16) == AES.new(key, AES.MODE_ECB).encrypt(plain), "ciphertext"
            if case == 0:
                assert read("round_keys", 176) == ROUND_KEYS, "packed round keys"
            for name, value in (("ct_guard_lo", 0x12345678), ("ct_guard_hi", 0x87654321),
                                ("rk_guard_lo", 0x11223344), ("rk_guard_hi", 0x44332211)):
                assert read(name, 4) == value.to_bytes(4, "little"), name
            state = read("ks_state", 80)
            assert state[:64] == SENTINEL * 2, "key schedule WDR preservation"
            assert int.from_bytes(state[64:68], "little") == symbols["key"], "key pointer"
            assert int.from_bytes(state[68:72], "little") == symbols["round_keys"] + 160, "round-key end"
            assert int.from_bytes(state[72:76], "little") == 0xa5, "key schedule flags"
            for reg in range(32):
                assert sim.state.wdrs.get_reg(reg).read_unsigned() == int.from_bytes(SENTINEL, "little"), f"w{reg}"
            for reg in (2, 3, 4, 9, 17, 18, 23, 24, 25, 26, 27, 28, 30):
                assert sim.state.gprs.get_reg(reg).read_unsigned() == 0x44556677, f"x{reg}"
            assert sim.state.gprs.get_reg(10).read_unsigned() == symbols["round_keys"] + 160, "encrypt key end"
            assert sim.state.gprs.get_reg(11).read_unsigned() == symbols["plaintext"], "input pointer"
            assert sim.state.gprs.get_reg(12).read_unsigned() == symbols[output], "output pointer"
            assert int.from_bytes(state[76:80], "little") == 0xa5, "encrypt flags"
    print("PASS: 12 AES cases; full round-key fixture, guards, in-place output, and preserved state")


if __name__ == "__main__":
    main()
