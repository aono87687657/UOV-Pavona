# gf256/test_scripts: python/sage checkers and expect generator for the GF(256) kernels

Last updated: 2026-10-04: plain python3 commands.

Reference-model checkers for the kernels in `../`, plus the generator for
`../gf256_acch_test.exp`. They inject operands into DMEM, run the matching
`*_rand_test` / `*_vxv_test` ELF on the ISS, and compare against `galois`
(or SageMath). Nothing here is linked into a kernel.

## Files
| file | role |
|---|---|
| `gf256_mul_verify.py` | random-operand check of `gf256_mul` and `gf256_mul_pqc` vs `galois`, plus a cross-check that both agree |
| `gf256mul_vxv_verify.py` | randomized checker for `gf256mul_vxv` (`-n` iterations, `-s` seed) |
| `gf256mul_vxv_square_verify.py` | randomized checker for `gf256mul_vxv_square` |
| `gf256_acch_expectgen.py` | GENERATES `../gf256_acch_test.exp` (prints to stdout); mirrors the ISS BNGFMUL semantics |
| `gf256_tester.py` + `expected_output.txt` | older sweep tooling: patches `../gf256_extmul_test.s`/`.exp` per scalar and re-runs the bazel test |
| `gf256_mul_expectgenerator.ipynb`, `sage_gf256.sage` | GF(256) models used to derive the tables |

## Test
```
./bazelisk.sh build //sw/acc/crypto/handwritten/gf256:all
python3 \
  sw/acc/crypto/handwritten/gf256/test_scripts/gf256_mul_verify.py
python3 \
  sw/acc/crypto/handwritten/gf256/test_scripts/gf256mul_vxv_verify.py -n 10
python3 \
  sw/acc/crypto/handwritten/gf256/test_scripts/gf256mul_vxv_square_verify.py -n 10
```

## Notes
- `gf256_tester.py` rewrites tracked sources (`../gf256_extmul_test.s`/`.exp`)
  in place while sweeping; it keeps `.backup` copies. Don't sweep on a dirty tree.
- `../gf256_acch_test.exp` is generated: regenerate with `gf256_acch_expectgen.py`,
  never hand-edit.
- `sage_gf256.sage` needs SageMath, which is not in the `pavona` env.
- Build the ELFs first; `standalone.py` silently runs a stale `bazel-bin` ELF.
