# gf16/test_scripts: python/sage checkers for the GF(16) kernels

Last updated: 2026-10-04: plain python3 commands.

Reference-model checkers for `../gf16_mul.s` and the HW `bn.gfmul.4` path. They
drive the `*_rand_test` / `*_extmul_test` ELFs on the ISS and compare against a
`galois` (or SageMath) model. Nothing here is linked into a kernel.

## Files
| file | role |
|---|---|
| `gf16_mul_verify.py` | random-operand check of `gf16_mul` vs the `galois` reference; drives `gf16_mul_rand_test.elf`, injects operands at DMEM 0x000/0x020/0x040 |
| `gf16_tester.py` | sweeps scalar b = 0x0..0xf through the `gf16_extmul_test` bazel test |
| `expected_output.txt` | reference (b, w0) table, 16 pairs, consumed by `gf16_tester.py` |
| `gf16_mul_expectgenerator.ipynb` | GF(16) model the table above was derived from |
| `sage_gf16.sage` | SageMath cross-check of GF(16) matrix-vector JSON test data |

## Test
```
./bazelisk.sh build //sw/acc/crypto/handwritten/gf16:all
python3 \
  sw/acc/crypto/handwritten/gf16/test_scripts/gf16_mul_verify.py \
  --iterations 100 --seed 42
```

## Notes
- `gf16_tester.py` rewrites the tracked sources `../gf16_extmul_test.s` and
  `../gf16_extmul_test.exp` in place while sweeping (it keeps `.backup` copies).
  Don't sweep on a dirty tree; the committed contents are the b = 0xb case.
- `sage_gf16.sage` needs SageMath, which is not in the `pavona` env.
- The ELF must be built before the checker runs: `standalone.py` silently uses
  whatever stale `bazel-bin` ELF is present.
