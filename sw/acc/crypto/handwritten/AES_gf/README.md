# AES_gf: compute-AES-128 over GF(256) via `bn.gfmul.8`

Last updated: 2026-10-20: the KAT check runs `tools/gather_kat_stats.py` (`kat_check.sh` left tools/).

AES-128 with no AES instruction and no lookup table: SubBytes is an Itoh-Tsujii
`x^254` inverse plus the affine map, MixColumns is a GF(256) multiply, both on
`bn.gfmul.8`. Dual-block (32 B = one WDR) per call. Standalone reference and the
compute-GF arm of `AES_compare/`; the bngf-tier kernels link their own fused
copies under `ov-*/…/AES_bngf/`.

## Files
| file | role |
|---|---|
| `aes128.s` | library `aes128`: one dual-block encrypt. Round keys in `w28` + `w5..w14`, constants `w23`/`w24`/`w25`, IV `w29`, ciphertext out `w27` |
| `KeySchedule.s` | library `KeySchedule`: one AES-128 key-expansion round (`w28` in/out, rcon stream in `w26`); callers loop it 10x |
| `aes128_test.s` | fused demo: 10 key-schedule rounds then one `aes128` call |
| `aes128_fullks_test.s` | measurement driver: 10 `KeySchedule` calls, no encryption |
| `aes128_encrypt_only_test.s` | measurement driver: one `aes128` call, round keys zeroed |
| `aes128_fullks_setup_test.s`, `aes128_encrypt_only_setup_test.s` | matching baselines: same driver minus exactly the measured op |

## Test
No check of its own: comments aside, `aes128.s` and `KeySchedule.s` are the code of
`uov/shared/verify/ov-Is-pkc/AES_bngf/`, which every Is verify bngfonly kernel links, so its KATs run them:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/...
python3 tools/gather_kat_stats.py --ops verify --params Is --cases 0,11 --tiers bngfonly
```
No bazel test target in this package. Cycles:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/AES_gf:all
python3 hw/ip/acc/dv/accsim/standalone.py \
  bazel-bin/sw/acc/crypto/handwritten/AES_gf/aes128_encrypt_only_test.elf --pqc 1
```

## Notes
- `--pqc 1` is required for the three ELFs that link `aes128`/`KeySchedule` (they hold the `bn.gfmul`); the two baselines link neither, so it is a no-op there: pass it anyway and keep one command shape.
- Op cost is a subtraction. Measured 2026-07-22 on ACCSim: key schedule 731 cyc (baseline 26), encrypt 923 cyc for 32 B (baseline 40). Modelled cycles: `bn.gfmul.8` is 1 cycle in the simulator, not RTL-timed.
- The fused `aes128_test` has no baseline; its whole run bundles harness setup + KS + encrypt. Quote the two op rows, not its total, and ignore the `1664 cycles` in the BUILD comment.
- The encrypt driver's ciphertext is garbage on purpose (zeroed round keys). Correctness: the Is verify bngfonly KATs (Test). An edit here does not reach the kernels' copy: keep the two in step.
- `bazel-bin` may still hold an orphan `aes128_keyschedule_only_test.elf` from a removed target: do not measure it.
