# AES_bngf: AES-128 computed with `bn.gfmul`, for the Ip sign bngfonly tier

Last updated: 2026-10-20: the KAT check runs `tools/gather_kat_stats.py` (`kat_check.sh` left tools/).

## TL;DR
AES without an S-box table: SubBytes as the Itoh-Tsujii inverse (x^254) plus the affine map, then
ShiftRows, MixColumns and AddRoundKey, all in WDRs on top of `bn.gfmul`. Only the `bngfonly` sign
binaries link it; `bngfaes` uses `bn.aes128` instead. The register layout is chosen so that it does
not collide with the sign kernels' WDR map.

## How to run
There is no simulator test target in this package. Build the harness ELFs, run one on the ISS and
compare the dumped DMEM with the expected bytes in the harness header:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:all
python3 hw/ip/acc/dv/accsim/standalone.py \
  bazel-bin/sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf/aes128_sign_test.elf --pqc 1
```
Inside the sign kernel this backend is covered by `python3 tools/gather_kat_stats.py --ops sign --params Ip` (bngfonly tier).
`--pqc 1` is required: every routine here uses `bn.gfmul`, which traps as an illegal instruction
without it.

## Files
| file | role |
|---|---|
| `aes128_sign.s` | dual-block AES-128 encrypt. The caller loads the constants into w7, w8, w9, RK1..RK10 into w20..w29, RK0 into w30, the IV into w18 and 0 into w31; the 32 B ciphertext comes back in w2 |
| `KeySchedule_sign.s` | one key-schedule round, in and out in w17; the caller runs all 10 back to back |
| `aes_constants_sign.s` | `.data` constants: byte_swap_mask, affine_value, msb_mask, shiftrow_mask, rcon |
| `aes128_sign_test.s`, `aes128_sign_zerokey_test.s`, `aes128_sign_nistkey_sign_iv.s` | encrypt harnesses; the expected ciphertext is in each file header |
| `KeySchedule_sign_test.s`, `KeySchedule_sign_all10_test.s` | RK1, and RK1..RK10, against NIST FIPS-197 |

## Notes
- CSR contract: both routines set `mod0 = 0x11B` and do not restore it. That is fine for Ip, whose
  whole pipeline is GF(256). `mod1` is 0 on exit.
- `aes128_sign` pushes 8 B (x5, x6) and pops them at exit: those two registers are the caller's
  P1+P1^T row cursor and base pointer and must survive the call.
- The vectors are NIST FIPS-197 Appendix B plus two CTR cases with the sign kernel's IV placement
  (counter low half at byte 12, high half at byte 28).
