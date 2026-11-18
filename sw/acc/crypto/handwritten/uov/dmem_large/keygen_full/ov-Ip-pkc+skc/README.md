# ov-Ip-pkc+skc: UOV-Ip keygen full (GF(256))

Last updated: 2026-10-07: new directory and target names.

## TL;DR
The Ip package of keygen full: `sk_seed -> expandsk -> P1O_P2 -> P3_cal -> cpk_pack ->
cpk`, with `csk = sk_seed` left in place. Ip is V 68 / O 44 / M 44 over GF(256);
`cpk = pk_seed (16 B) || 990 x 44 B = 43,576 B`. How to run it and its numbers: `../README.md`.

## How to run
`../README.md` (How to run) builds and runs Ip and Is at the 512 KiB profile. One built ELF on its
own, at that profile (the cycle count does not depend on the seed, so the harness's zero seed costs
the same):
```
./bazelisk.sh build "//sw/acc/crypto/handwritten/uov/dmem_large/keygen_full/ov-Ip-pkc+skc:ov-Ip-keygen_full_bngfaes"
python3 hw/ip/acc/dv/accsim/standalone.py --pqc 1 --dump-stats /dev/stdout \
  bazel-bin/sw/acc/crypto/handwritten/uov/dmem_large/keygen_full/ov-Ip-pkc+skc/ov-Ip-keygen_full_bngfaes.elf
```
`--pqc 1` is needed on every tier (the sw tier uses `bn.mulv.l` in the GF reduction).

## Files
| file | role |
|---|---|
| `ov-Ip-keygen.s` | the `ov_keygen` orchestrator; its header carries the stack contract |
| `expandsk_ret_O_pkseed.s` | KMAC/SHAKE256 expansion `sk_seed -> pk_seed \|\| O`; also linked by the stream, one-shot and stream-uniform families |
| `P1O_P2.s` | `B = P1*O + P2`, 68x44 entries of 64 B. One cpp-guarded source with three arms (none = sw, `-DGF_INSTRUCTIONS`, and `-DAES_INSTRUCTIONS` on top) |
| `P3_cal.s` | `P3 = Upper(O^T x B)`, 990 x 64 B. Both arms build the dense 44x44 `P3_full` and extract the packed upper triangle; the hardware arm does four output rows per pass |
| `cpk_pack.s` | compacts the 64 B-padded P3 entries to 44 B and prepends `pk_seed`; the same for every tier |
| `ov-Ip-keygen_test.s` | the ISS harness; `.data` = sk_seed 32 B, cpk 43,584 B, stack 386,080 B, `stack_end = 429,696` |
| `ov-Ip-keygen_rtl_test.s` | the same kernels with the seed of KAT case 0 built in; ISS only (the name is historical) |
| `AES_bngf/`, `AES_ttable/` | AES computed with `bn.gfmul` (bngfonly) and T-table AES with its 4 KiB table (sw) |

## Notes
- There is no simulator test target in this package; the check is the KAT.
- The bngfaes ELF needs 429,696 B of DMEM (`B` alone is 191,488 B), so its smallest profile is
  512 KiB, measured on the ISS only.
  The 32 KiB path is `../../../dmem32k/keygen_stream`; the smallest one-EXECUTE keygen is
  `../../keygen_min`. All produce the same cpk and csk bytes.
- The 32 KiB stream and stream-uniform kernels carry copies of `expand_batch` and
  `phase4_row_setup` (`P1O_P2.s`) and of the O-alignment block (`P3_cal.s`, phase 1): an edit to
  those parts means running the KAT of those families again.
- `cpk_pack` is a forward copy, not a memmove: it requires `src >= dst + 16`.
