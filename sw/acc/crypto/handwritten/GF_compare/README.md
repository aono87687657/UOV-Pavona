# GF_compare: HW bn.gfmul vs software GF-multiply cycle comparison

Last updated: 2026-10-04: plain python3 commands.

Measurement rig only: no BUILD, no `.s`. It orchestrates the isolation drivers
that live in `gf16/` and `gf256/` to quantify what `bn.gfmul.4` / `bn.gfmul.8`
buy over software Galois-field multiply. Companion to `AES_compare/`.

## Files
| file | role |
|---|---|
| `run_gf_compare.py` | the rig: builds the nine drivers, runs each on ACCSim (`--pqc 1`), subtracts, prints, writes the CSV |
| `gf_compare.csv` | GENERATED: regenerate with the runner, never hand-edit |

## Test
```
python3 \
  sw/acc/crypto/handwritten/GF_compare/run_gf_compare.py
```
One cell by hand (build the ELF first):
```
python3 hw/ip/acc/dv/accsim/standalone.py \
  bazel-bin/sw/acc/crypto/handwritten/gf256/gf256_mul_op_test.elf --pqc 1
```

## Measured (ACCSim cycles, 2026-07-22, CSV anchor `6382387d78-dirty`)
| field | impl | elems/op | op cyc |
|---|---|---:|---:|
| GF16 | `bn.gfmul.4` | 64 | 1 |
| GF16 | `gf16_mul` | 64 | 42 |
| GF256 | `bn.gfmul.8` | 32 | 1 |
| GF256 | `gf256_mul` | 32 | 100 |
| GF256 | `gf256_mul_pqc` | 32 | 79 |

## Notes
- Op cost is a subtraction: `op = <variant>_op_test - <field>_setup_{hw,sw}_test`.
  Each op driver is its baseline plus exactly one multiply. Setup is a fixed
  16-18 cyc per call site: report it separately, not per element.
- `--pqc 1` is required by the three drivers carrying `bn.gfmul` / `bn.mulv.l`;
  the `mod0`/`mod1` writes are not gated. The runner passes it uniformly.
- No KAT cell covers these drivers. `gf16_mul` is production (Is sw-tier verify);
  `gf256_mul` has no kernel consumer: its only coverage is the gf256 sim tests.
