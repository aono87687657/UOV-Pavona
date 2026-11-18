# ov-Is-skc: UOV-Is signing (GF(16), v=96 o=64)

Last updated: 2026-10-20: how to run one parameter set and one tier.

## TL;DR
The Is sign kernels and their unit harnesses; the cycles and memory of every tier are in
`../README.md` (Numbers).

## How to run
From the repository root, at the 32 KiB DMEM profile:
```
# One parameter set and one tier: Is at bngfaes.
# Tiers: bngfaes, bngfonly, bnaesonly, sw.
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Is-skc:ov-Is-sign_ldirect_testvec_bngfaes
python3 tools/gather_kat_stats.py --ops sign --params Is --tiers bngfaes --variants ldirect --cases 0,11
```
For another tier, change it in the build label and in `--tiers`. It prints PASS and the cycles.

The three default tiers at once (bngfaes, bngfonly, sw), and the cycles of one case:
```bash
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Is-skc:ov-Is-sign_ldirect_testvec_{bngfaes,bngfonly,sw}
python3 tools/gather_kat_stats.py --ops sign --params Is
# cycles for one case: statistics_0.txt in --output-dir
python3 \
  sw/acc/crypto/handwritten/own_utils/run_test.py sign --param Is --tier bngfaes \
  --test-data-file sw/acc/crypto/handwritten/test_data/testvectors-Is-pkc-skc \
  --case-start 0 --iterations 1 --output-dir /tmp/is_sign
```
- `gather_kat_stats.py` runs prebuilt ELFs: `ov-Is-sign_ldirect_testvec_<tier>` (not `ov-Is-sign_ldirect_<tier>`,
  not the `_msglen_*` targets). Build first, or a stale binary passes.

## Files
| file | role |
|---|---|
| `ov-Is-skc-sign.s` | the ldirect sign body (`in: x10 sig, x11 csk, x12 msg, x13 msglen`; the `_sprec` bodies are in `../../../dmem_large/sign_sprec/`) |
| `gf16_ldirect_96_64.s` | per-attempt L from the streamed P1 and P2, with y fused in on every tier |
| `gf16trimat_2trimat_madd_96_48_64_32.s`, `gf16_matvec_2048_96.s` | S build and L = v x S (precompute-S layout only) |
| `batch_quad_trimat_eval_gf16.s` | y = vin^T·P1·vin (precompute-S layout only) |
| `gaussian_elimination_64x64.s`, `back_substitution_64x64.s` | the 64x64 solve of [L \| y ^ target] |
| `gf16mat_prod_48_64.s`, `gf16_transpose_64_64.s`, `hash_salted_msg.s`, `expandv.s` | u = O·o, transpose, target hash, vinegar KMAC |
| `*_test.s` | unit harnesses |
| `AES_bngf/`, `AES_ttable/` | software AES over `bn.gfmul` (bngfonly) and T-table AES (sw) |

## Notes
- KAT case 11 takes a second elimination attempt (a GF(16) system is singular with a chance of
  about 1/16). The ranges in `../README.md` leave it out; the retry table there shows it. ldirect
  streams all of P again for the new attempt.
- The precompute-S layout trades DMEM for cheap retries: S is 196,608 B and its raw-P1 cache
  148,992 B, so it needs the 512 KiB profile and is measured on the ISS only
  (`../../../dmem_large/sign_sprec/`).
