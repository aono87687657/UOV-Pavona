#!/usr/bin/env python3
"""Check chained AES columns, counter carries, scratch guards and saved state."""

import argparse
import hashlib
import io
from pathlib import Path
import random
import sys

from Crypto.Cipher import AES
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[9]
sys.path[:0] = [str(ROOT), str(ROOT / "sw/acc/crypto/handwritten/own_utils")]
from acc_sim_utils import run_acc_test
from dmem_utils import bytes_to_dmem_words


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, default=ROOT / (
        "bazel-bin/sw/acc/crypto/handwritten/uov/shared/verify/ov-Is-pkc/"
        "aes128hw_col_is_test.elf"))
    args = parser.parse_args()
    with args.elf.open("rb") as stream:
        table = ELFFile(stream).get_section_by_name(".symtab")
        symbols = {s.name: s["st_value"] for s in table.iter_symbols()}
        leaf = table.get_symbol_by_name("aes128hw_col_is")[0]
        start, end = leaf["st_value"], leaf["st_value"] + leaf["st_size"]
    assert end > start, "missing column function size"
    counters = (0, 2, 254, 256, 9310, 9312, 21598, 65534, 65536,
                0xfffffffe, 0xffffffff)
    keys = (bytes(range(16)), bytes(16), random.Random(0xa128).randbytes(16))
    checked = 0
    for key in keys:
        aes = AES.new(key, AES.MODE_ECB)
        for counter, calls in ((counter, calls) for counter in counters for calls in (1, 2)):
            words = bytes_to_dmem_words(key, symbols["key"])
            words.update(bytes_to_dmem_words(counter.to_bytes(4, "little"), symbols["counter"]))
            words.update(bytes_to_dmem_words((calls - 1).to_bytes(4, "little"), symbols["repeat_call"]))
            ok, data, sim = run_acc_test(str(args.elf), dmem_words=words,
                                         dump_stats_file=io.StringIO() if checked == 0 else None)
            assert ok, f"counter {counter:#x}: simulator error"

            def read(name, size):
                return data[symbols[name]:symbols[name] + size]

            ivs = b"".join(bytes(12) + ((counter + i) & 0xffffffff).to_bytes(4, "big")
                           for i in range(2 * calls))
            assert read("output", 64) == aes.encrypt(ivs) + bytes(32 * (2 - calls)), f"counter {counter:#x}: lanes"
            for reg in range(2, 32):
                if reg in (5, 6):
                    continue
                expected = {3: symbols["frame"], 13: (counter + 2 * calls) & 0xffffffff,
                            18: symbols["round_keys"]}.get(reg, 0x44556677)
                assert sim.state.gprs.get_reg(reg).read_unsigned() == expected, f"x{reg}"
            for reg in range(32):
                if reg == 13:
                    continue  # Fixture uses the output register to snapshot WSRs.
                expected = 0 if reg == 31 else int.from_bytes(read("sentinels", 1024)[reg * 32:reg * 32 + 32], "little")
                assert sim.state.wdrs.get_reg(reg).read_unsigned() == expected, f"w{reg}"
            assert read("flags_output", 4) == bytes.fromhex("a5000000"), "flags"
            assert read("wsr_output", 96) == read("sentinels", 96), "MOD/ACC/ACCH"
            assert read("guard_lo", 32) == bytes.fromhex("78563412") * 8, "low guard"
            assert read("guard_hi", 32) == bytes.fromhex("21436587") * 8, "high guard"
            assert read("round_keys", 192) == read("rk_before", 192), "key buffer"
            assert read("frame", 32) == bytes(20) + symbols["scratch"].to_bytes(4, "little") + bytes(8), "frame"
            if checked == 0:
                counts = [v for pc, row in sim.stats.func_instrs.items()
                          if start <= pc < end for v in row.values()]
                insns = sum(v[0] for v in counts)
                cycles = sum(sum(v) for v in counts)
                print(f"{calls} column call: {insns} instructions / {cycles} cycles, including return")
            checked += 1
    print(f"PASS: {checked} key/counter/call-count cases; lanes, saved state, keys, frame and guards")
    print(f"ELF SHA-256: {hashlib.sha256(args.elf.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
