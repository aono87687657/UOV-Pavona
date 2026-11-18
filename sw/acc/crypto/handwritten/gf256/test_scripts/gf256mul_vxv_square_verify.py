#!/usr/bin/env python3
"""
Verify gf256mul_vxv_square (parallel 32-byte GF(256) squaring) on ACC ISS.

Reference: gf_arithmetic.gf256_mul_reference (wraps galois with AES poly).
For each byte b in input, expected = gf256_mul_reference(b, b).

Usage:
  ./bazelisk.sh build \\
      //sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square_test
  python3 sw/acc/crypto/handwritten/gf256/test_scripts/gf256mul_vxv_square_verify.py
"""
import os, sys, random, argparse

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, *['..'] * 6))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_HERE, '..', '..', 'own_utils'))

from acc_sim_utils import run_acc_test, read_wdr_register
from dmem_utils import bytes_to_dmem_words
from gf_arithmetic import gf256_mul_reference

ELF = os.path.join(_ROOT,
    "bazel-bin/sw/acc/crypto/handwritten/gf256/gf256mul_vxv_square_test.elf")


def run_once(val_a: bytes) -> bytes:
    """Inject val_a at DMEM[0x000], run, return w0 as 32 bytes (little-endian)."""
    ok, _, sim = run_acc_test(ELF, pqc=False, verbose=False,
                              dmem_words=bytes_to_dmem_words(bytearray(val_a), 0))
    assert ok, "simulation failed"
    return read_wdr_register(sim, 0).to_bytes(32, "little")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-n', '--iterations', type=int, default=10)
    ap.add_argument('-s', '--seed', type=int, default=0)
    args = ap.parse_args()

    random.seed(args.seed)
    fails = 0
    for i in range(1, args.iterations + 1):
        val_a = bytes(random.getrandbits(8) for _ in range(32))
        expected = bytes(gf256_mul_reference(b, b) for b in val_a)
        got = run_once(val_a)
        ok = got == expected
        print(f"[{i:3d}/{args.iterations}] {'PASS' if ok else 'FAIL'}  "
              f"a={val_a.hex()}  y={got.hex()}")
        if not ok:
            print(f"       expected={expected.hex()}")
            fails += 1

    print(f"\n{args.iterations - fails}/{args.iterations} passed")
    sys.exit(0 if fails == 0 else 1)


if __name__ == "__main__":
    main()
