# ov-Is-pkc+skc: UOV-Is keygen full (GF(16))

Last updated: 2026-10-07: new directory and target names.

## TL;DR
The Is package of keygen full: one EXECUTE, everything resident, `sk_seed` in, `cpk` and
`csk` out. Pipeline (V=96, O=64, M=64, `mod0 = 0x13`): expandsk -> `P1O_P2` (B = P1*O + P2,
196,608 B) -> `P3_cal` (P3 = Upper(O^T*B), 2,080 x 32 B) -> `cpk_pack` (cpk = pk_seed || P3 =
66,576 B); `csk` is `sk_seed`, never copied. How to run it and its numbers: `../README.md`.

## How to run
`../README.md` (How to run) builds and runs Ip and Is at the 512 KiB profile. The ELF with the
seed built in, on its own on the ISS at that profile (it produces the key pair of KAT case 0;
`_rtl_test` is a name only, there is no RTL run at 512 KiB):
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem_large/keygen_full/ov-Is-pkc+skc:ov-Is-keygen_full_test_bngfaes
python3 hw/ip/acc/dv/accsim/standalone.py --pqc 1 --dump-stats /dev/stdout \
  bazel-bin/sw/acc/crypto/handwritten/uov/dmem_large/keygen_full/ov-Is-pkc+skc/ov-Is-keygen_full_test_bngfaes.elf
```

## Files
| file | role |
|---|---|
| `ov-Is-keygen.s` | the `ov_keygen` orchestrator: the stack layout and the four calls; the same for every tier |
| `expandsk_ret_O_pkseed.s` | seed -> pk_seed and O (KMAC/SHAKE256), 3,104 B on the stack |
| `P1O_P2.s` | B = P1*O + P2. Three cpp arms: none = software gf16 and T-table AES, `-DGF_INSTRUCTIONS`, and `-DAES_INSTRUCTIONS` on top |
| `P3_cal.s` | P3 = Upper(O^T*B). The hardware arm folds at write time (32 B frame); the sw arm keeps the dense P3_full (131,104 B) |
| `cpk_pack.s` | pk_seed \|\| P3 word copy; GPRs only, the same for every tier |
| `ov-Is-keygen_test.s` | the ISS harness: `.data` holds `sk_seed`/`csk`/`cpk`/`stack`; the driver writes the KAT seed |
| `ov-Is-keygen_rtl_test.s` | the seed of KAT case 0 built in, entry in `.text.start`; ISS only (the name is historical) |
| `AES_bngf/`, `AES_ttable/` | the AES helpers of the bngfonly and sw tiers (their own READMEs) |

## Notes
- A reference that fits no shipped part: about 453 KiB of linked `.data`, so it runs at the 512 KiB
  profile, which we ran on the ISS only.
- Stack peaks, the lowest stack pointer over one run below `stack_end`: hardware-GF tiers 269,408 B,
  sw 397,408 B, no guard (`tools/measure_stack.py`, in git history at eb076dd3ed, on
  `ov-Is-keygen_full_test_{bngfaes,bngfonly,sw}.elf` at the 512 KiB profile; it follows x2, not every memory
  access). Both test harnesses reserve the sw maximum in every tier's ELF: there is one harness source
  per parameter set.
- `expandsk_ret_O_pkseed` and the two AES packages are also linked by the stream, one-shot and
  stream-uniform keygens, and the streamed Is kernel takes `p1op2_rows1_94_setup` from `P1O_P2.s`:
  after an edit to those, run the stream KAT again.
- ELF suffix per tier: bngfaes none, bngfonly `_bngfonly`, sw `_sw`; `--pqc 1` is required.
