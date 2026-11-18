# sign_sprec: UOV signing with a precomputed S (512 KiB DMEM)

Last updated: 2026-11-02: every table from the rerun iss-2026-10j; Ip3 added at 512 KiB; all other numbers are unchanged.

## TL;DR
- The Ip, Is and Ip3 sign that builds S once per signature and keeps the raw P1 in a cache below S
  (Ip and Is with `-DP1_CACHE`, Ip3 always), so that a retry of the elimination only evaluates and
  solves again. Ip3 is built with both extensions only.
- S and the P1 cache need 351,264 B (Ip) and 353,568 B (Is) of linked DMEM, more than the 128 KiB
  profile holds (130,048 B on the bus): the smallest profile is 512 KiB, measured on the ISS only,
  and only the bngfaes tier is published.
- The shipping sign is `../../dmem32k/sign_ldirect/` (L-direct), which is faster when no retry is needed:
  the tables below divide the two (sprec measured at 512 KiB, ldirect at 32 KiB) and hold the one KAT
  case with a retry.
- Cycles and memory: [Numbers](#numbers).
- Fixed on 2026-10-19: earlier versions of the Ip solver it links searched only the rows up to 31 for the pivot of
  rows 1 to 30, so some solvable systems were taken as unsolvable and signing retried.

## How to run
In a clone of its own (the profile switch rewrites 17 generated files under `hw/`, never committed),
from its root:
```
python3 tools/uov.py profile --profile 512
# One parameter set and one tier: Ip at bngfaes.
# Parameter sets: Ip, Is, Ip3. Tiers built: bngfaes, bngfonly, sw (Ip3: bngfaes); only bngfaes is checked at 512 KiB.
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem_large/sign_sprec/ov-Ip-skc:ov-Ip-sign_sprec_testvec_bngfaes
python3 tools/gather_kat_stats.py --ops sign --params Ip --tiers bngfaes --variants sprec --cases 0,11
```
For another choice, change the parameter set (twice in the build label, once in `--params`) and the
tier (in the label and in `--tiers`). It prints PASS and the cycles.

All three sets at once, after the profile line, and back to the committed 32 KiB files:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem_large/sign_sprec/ov-Ip-skc:ov-Ip-sign_sprec_testvec_bngfaes \
    //sw/acc/crypto/handwritten/uov/dmem_large/sign_sprec/ov-Is-skc:ov-Is-sign_sprec_testvec_bngfaes \
    //sw/acc/crypto/handwritten/uov/dmem_large/sign_sprec/ov-Ip3-skc:ov-Ip3-sign_sprec_testvec_bngfaes
python3 tools/gather_kat_stats.py --ops sign --params Ip,Is,Ip3 --cases 0,11 --tiers bngfaes --variants sprec
python3 tools/uov.py profile --profile 32
```
- `profile --profile 512` switches that clone to the 512 KiB profile (ISS only), `--profile 32` back to
  the committed 32 KiB files.
- `gather_kat_stats.py` runs cases 0 and 11 (message lengths 0 and 1024) on the built ELFs,
  `bazel-bin/sw/acc/crypto/handwritten/uov/dmem_large/sign_sprec/ov-<P>-skc/ov-<P>-sign_sprec_testvec_bngfaes.elf`,
  and prints PASS and the cycles per cell.

## Numbers
Written by `python3 tools/uov.py tables` from the records in `../../results/`; do not edit.

<!-- table:iss:sign/sprec@512 -->
| DMEM | tier | Ip | Is | Ip3 |
|---|---|---:|---:|---:|
| 512 KiB | bngfaes | 1,569,471-1,571,279 | 2,157,658-2,158,570 | 1,877,336-1,879,144 |

ISS cycles of one signature (a single EXECUTE), 512 KiB DMEM profile (ISS only: no chip test runs at this profile); a range is the lowest and the highest of the 12 KAT cases (11 where a case in which signing needed a retry is left out; it is in the retry table of `sw/acc/crypto/handwritten/uov/results/README.md`).
Every case passed. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss:sign/sprec@512 -->

<!-- table:iss-retries:all -->
KAT cases in which signing needed a retry

| DMEM | op | kernel | param | tier | KAT case | retries | ISS cycles | times faster than sw, same case |
|---|---|---|---|---|---:|---:|---:|---:|
| 32 KiB | sign | ldirect | Is | bngfonly | 11 | 1 | 20,477,208 | 2.61x |
| 32 KiB | sign | ldirect | Is | bnaesonly | 11 | 1 | 3,094,440 | 17.3x |
| 32 KiB | sign | ldirect | Is | bngfaes | 11 | 1 | 560,527 | 95.4x |
| 32 KiB | sign | ldirect | Is | sw | 11 | 1 | 53,487,848 | - |
| 512 KiB | sign | sprec | Is | bngfaes | 11 | 1 | 2,254,048 | - |

retries: the attempts after the first, from the sign loop's counter (x8) in the driver output. The tables without retries leave these cases out.
ISS. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-retries:all -->

<!-- table:iss-ratio:sign/sprec@512/ldirect@32 -->
sprec / ldirect (ISS cycles of sprec divided by those of ldirect; above 1.00x, ldirect is faster)

| DMEM | op | param | bngfaes |
|---|---|---|---:|
| sprec 512 KiB, ldirect 32 KiB | sign | Ip | 5.82x |
| sprec 512 KiB, ldirect 32 KiB | sign | Is | 7.60x |
| sprec 512 KiB, ldirect 32 KiB | sign | Ip3 | 5.53x |

The cycles of the KAT cases added up per row; a case in which signing needed a retry is left out; it is in the retry table of `sw/acc/crypto/handwritten/uov/results/README.md`. Two decimals: 1.00x is within half a percent, not necessarily equal.
ISS. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-ratio:sign/sprec@512/ldirect@32 -->

<!-- table:mem:sign/sprec@512 -->
| DMEM | tier | Ip | Is | Ip3 |
|---|---|---:|---:|---:|
| 512 KiB | bngfaes | 13,724 / 351,264 / 349,856 | 5,924 / 353,568 / 352,128 | 10,004 / 409,152 / 407,712 |

Bytes of the ELFs the ISS ran at the 512 KiB DMEM profile (ISS only: no chip test runs at this profile): code / `_dmem_bss_end` (the end of the linked data and bss) / the stack block
reserved inside it (`stack_end - stack`; a reservation, not a measured peak).
Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:mem:sign/sprec@512 -->

## Files
| file | role |
|---|---|
| `ov-Ip-skc/ov-Ip-skc-sign_sprec.s`, `ov-Is-skc/ov-Is-skc-sign_sprec.s` | the sign bodies; the tier comes from the linked helper libraries |
| `ov-Ip-skc/ov-Ip-skc-sign_sprec_test.s`, `ov-Is-skc/ov-Is-skc-sign_sprec_test.s` | the ISS harnesses; `.data` holds S (Ip 68x44x64 B, Is 96x64x32 B), the stack and the P1 cache; the comments in the harness describe the stack reservations |
| `ov-Ip3-skc/` | the Ip3 sign body, its harness, the S builder (`sprec_build_S_74_45.s`), L = v^T S (`gf256_matvec_2880_74.s`) and the cached quadratic (`batch_quad_cached_74.s`); bngfaes only |
| `ov-<P>-skc/BUILD` | the targets per tier; the leaf kernels come from `../../shared/sign/ov-<P>-skc/` and `../../dmem32k/sign_ldirect/ov-<P>-skc/` |

`ov-<P>-sign_sprec_testvec_<tier>` reads the KAT salt (`-DUSE_TESTVEC_SALT`) and is what the KAT
driver runs; `ov-<P>-sign_sprec_<tier>` takes its salt from `RND`. Every sign number is from the testvec
build; where the salt comes from and what a product build needs:
[`../../dmem32k/sign_ldirect/README.md#salt`](../../dmem32k/sign_ldirect/README.md#salt).
