# AES_bngf: AES-128 computed with `bn.gfmul`, for the Is sign bngfonly tier

Last updated: 2026-10-20: the KAT check runs `tools/gather_kat_stats.py` (`kat_check.sh` left tools/).

## TL;DR
AES without an S-box table: SubBytes as the Itoh-Tsujii inverse (x^254) plus the affine map, then
ShiftRows, MixColumns and AddRoundKey, all in WDRs on top of `bn.gfmul`. Only the `bngfonly` sign
binaries link it; `bngfaes` uses `bn.aes128` instead. The register layout is chosen so that it does
not collide with the sign kernels' WDR map.

## How to run
The harness ELFs are those of the Ip package (the key schedule and the constants are the same files;
`aes128_sign.s` differs from Ip's only in a comment). Build them, run one on the ISS and compare the
dumped DMEM with the expected bytes in the harness header:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:all
python3 hw/ip/acc/dv/accsim/standalone.py \
  bazel-bin/sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf/aes128_sign_test.elf --pqc 1
```
Inside the sign kernel this backend is covered by `python3 tools/gather_kat_stats.py --ops sign --params Is` (bngfonly tier).
`--pqc 1` is required: every routine here uses `bn.gfmul`, which traps as an illegal instruction
without it.

## Files
Files shown as links are one shared source file each: this package's target of the same name is an alias of the target that builds it (the copies here were byte-identical).

| file | role |
|---|---|
| `aes128_sign.s` | dual-block AES-128 encrypt. The caller loads the constants into w7, w8, w9, RK1..RK10 into w20..w29, RK0 into w30, the IV into w18 and 0 into w31; the 32 B ciphertext comes back in w2 |
| [`KeySchedule_sign.s`](../../ov-Ip-skc/AES_bngf/KeySchedule_sign.s) | one key-schedule round, in and out in w17; the caller runs all 10 back to back |
| [`aes_constants_sign.s`](../../ov-Ip-skc/AES_bngf/aes_constants_sign.s) | `.data` constants: byte_swap_mask, affine_value, msb_mask, shiftrow_mask, rcon |
| the harnesses | in [`../../ov-Ip-skc/AES_bngf/`](../../ov-Ip-skc/AES_bngf/README.md): the same tests of the same code |

## Notes
- CSR contract: both routines set `mod0 = 0x11B` for the AES body and do not restore it. An Is
  caller must set `mod0 = 0x13` again before the next `bn.gfmul.4`. `mod1` is 0 on exit.
- The sign kernel runs all 10 `KeySchedule_sign` calls in a row, then sets `mod0 = 0x13` once.
- `aes128_sign.s` is the Ip package's file except for that CSR note in its header: keep the two in
  step when either changes. The other sources are Ip's files.
