# sign_ldirect: UOV signing in 32 KiB of DMEM

Last updated: 2026-11-17: chip tables from the rerun rtl-2026-11b; the chip tests copy their data faster.

## TL;DR
- The signing path that fits the 32 KiB DMEM, for Ip and Is at four tiers each. Ip3 is in
  `ov-Ip3-skc/`. This directory is the family index: the code is in the parameter
  subfolders.
- One EXECUTE signs one message (the `ldirect` layout: L is built from one streamed pass over P1,
  no stored S).
- Cycles, speed-ups and memory: [Numbers](#numbers).
- Fixed on 2026-10-19: earlier versions of the Ip solver searched only the rows up to 31 for the pivot of rows 1 to
  30, so some solvable systems were taken as unsolvable and signing retried.

## How to run
From the repository root, at the 32 KiB DMEM profile:
```
# One parameter set and one tier: Ip at bngfaes.
# Parameter sets: Ip, Is, Ip3. Tiers: bngfaes, bngfonly, bnaesonly, sw.
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip-skc:ov-Ip-sign_ldirect_testvec_bngfaes
python3 tools/gather_kat_stats.py --ops sign --params Ip --tiers bngfaes --variants ldirect --cases 0,11
```
For another choice, change the parameter set (twice in the build label, once in `--params`) and the
tier (in the label and in `--tiers`). It prints PASS and the cycles.

Ip and Is at every tier at once:
```bash
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip-skc:ov-Ip-sign_ldirect_testvec_{bngfaes,bngfonly,bnaesonly,sw}
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Is-skc:ov-Is-sign_ldirect_testvec_{bngfaes,bngfonly,bnaesonly,sw}
python3 tools/gather_kat_stats.py --ops sign --params Ip,Is --cases 0,11 --tiers bngfaes,bngfonly,bnaesonly,sw
```
One case with its cycles (`statistics_0.txt` in the output directory):
```
python3 \
  sw/acc/crypto/handwritten/own_utils/run_test.py sign --param Ip \
  --tier bngfaes \
  --test-data-file sw/acc/crypto/handwritten/test_data/testvectors-Ip-pkc-skc \
  --case-start 0 --iterations 1 --output-dir /tmp/sign_ip
```
- `gather_kat_stats.py` runs prebuilt ELFs: build first, or it passes on stale binaries at stale cycles.
  The binaries it loads are `ov-<P>-sign_ldirect_testvec_<tier>`, not `ov-<P>-sign_ldirect_<tier>`
  and not the `_msglen_*` targets.
- Cases 0 and 11 (message length 0 and 1024) are the quick check: the message length enters sign
  through the KMAC. A full run takes all 12 cases.
- The fairness gates of the tier comparison: `tools/stream_uniform_gates.sh sign Ip` (and `Is`).
- The Ip solver alone, against a reference solver on matrices whose pivots come from every part of the matrix:
  `./bazelisk.sh test //sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:solve_44x44_test //sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:solve_44x44_sw_test`.
- The Is solver alone, the same way (eight matrices, three with far-row pivots):
  `./bazelisk.sh test //sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:solve_64x64_test //sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:solve_64x64_sw_test`.
- On the chip model and in block-level RTL: `../sign_rtl/` and `sw/device/tests/acc_uov/README.md`.

## What it does
`ldirect` derives the linear system per attempt from one streamed pass over P1 (with y fused into
the same pass), solves it by Gaussian elimination and back-substitution, and retries with a new
vinegar vector when the system is singular. A retry costs about one more attempt; a singular system
has a chance of about 1/256 for Ip (GF(256)) and 1/16 for Is (GF(16)).

The other layout, `sprec`, precomputes S once per signature and needs far more DMEM: it is in
`../../dmem_large/sign_sprec/`, needs the 512 KiB profile and is measured on the ISS only.

Tiers: `bngfaes` uses `bn.gfmul` and `bn.aes128`; `bngfonly` uses `bn.gfmul` with AES computed in
software (`ov-<P>-skc/AES_bngf/`); `bnaesonly` uses `bn.aes128` with software GF (the batched leaf of `../../shared/aes_hw`: both lanes, keys in registers; before 2026-10-13 it was the single-block memory-key leaf `AES_ext:aes128_mem`, which for Ip still provides the key schedule that the L-direct kernel `gf256_ldirect_68_44.s` calls); `sw` uses neither
(`ov-<P>-skc/AES_ttable/`). The orchestrator is the same object in every tier. Ratios measure the
whole-kernel effect of changing the backend, including the common orchestrator cost.

## Salt
- A signature reads its 16-byte salt once, before the first attempt, and keeps it on retries.
- `ov-<P>-sign_ldirect_<tier>` reads it from `RND`, the entropy register fed by the EDN. On the ISS,
  `RND` returns fixed test values (`hw/ip/acc/dv/accsim/sim/standalonesim.py`), so this build signs
  there with one of two fixed salts. It has not been run on the chip RTL.
- `ov-<P>-sign_ldirect_testvec_<tier>` (`-DUSE_TESTVEC_SALT`) reads it from `salt_input` in DMEM,
  written by the test driver: a known-answer test passes its own salt, so the signatures compare
  byte for byte. Every number here, every KAT and every chip sign test uses this build.
- `run_test.py sign` without `--test-data-file` loads the plain build, with the fixed ISS salt.
- For deployment, the host must: link the plain build and check that the linked ELF has no `salt_input`;
  start the entropy source, CSRNG and EDN before it signs; bound the wait for the ACC (an `RND` read waits
  for the EDN with no timeout of its own) and treat a timeout as a failure; check `ERR_BITS`, where
  `RND_REP_CHK_FAIL` and `RND_FIPS_CHK_FAIL` stop the ACC; release no signature from a failed run.
  The plain build on the chip is still to be tested. Feeding the salt from the host instead (the
  testvec build) is just as valid only if the host draws a fresh, uniformly random 16-byte salt for
  every signature.
- The same holds for `ov-Ip3-skc/` (Ip3) and `../../dmem_large/sign_sprec/`.

## Numbers
Written by `python3 tools/uov.py tables` from the records in `../../results/`; do not edit.
Every sign number is from the testvec build (salt from DMEM, see [Salt](#salt)).

<!-- table:iss:sign/ldirect@32:Ip,Is -->
| DMEM | tier | Ip | Is |
|---|---|---:|---:|
| 32 KiB | bngfaes | 269,284-271,092 | 283,859-284,771 |
| 32 KiB | bngfonly | 7,101,107-7,102,915 | 10,242,199-10,243,111 |
| 32 KiB | bnaesonly | 2,244,573-2,246,381 | 1,556,017-1,556,929 |
| 32 KiB | sw | 19,284,259-19,286,067 | 26,752,721-26,753,633 |

ISS cycles of one signature (a single EXECUTE), 32 KiB DMEM profile; a range is the lowest and the highest of the 12 KAT cases (11 where a case in which signing needed a retry is left out; it is in the retry table of `sw/acc/crypto/handwritten/uov/results/README.md`).
Every case passed. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss:sign/ldirect@32:Ip,Is -->

Is KAT case 11 needs a second elimination attempt; the tables leave it out and the retry table
below shows it. The ISS counts `bn.gfmul` and `bn.aes128` as one cycle each.

<!-- table:iss-speedup:sign/ldirect@32:Ip,Is -->
Times faster than sw (sw cycles / tier cycles), ISS

| DMEM | tier | Ip | Is |
|---|---|---:|---:|
| 32 KiB | bngfonly | 2.72x | 2.61x |
| 32 KiB | bnaesonly | 8.59x | 17.2x |
| 32 KiB | bngfaes | 71.5x | 94.2x |

The cycles of the KAT cases added up per row, sw divided by the tier; a case in which signing needed a retry is left out; it is in the retry table of `sw/acc/crypto/handwritten/uov/results/README.md`. -: no run of that tier.
ISS, 32 KiB DMEM profile. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-speedup:sign/ldirect@32:Ip,Is -->

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

On the chip model, exec+wait of one test per cell, KAT case 0 (every meter of these tests:
`sw/acc/crypto/handwritten/uov/results/CHIP-MATRIX.md`):

<!-- table:rtl-cycles:sign/ldirect@32:Ip,Is -->
| DMEM | tier | Ip | Is |
|---|---|---:|---:|
| 32 KiB | bngfaes | 270,381 | 284,865 |
| 32 KiB | bngfonly | 7,102,205 | 10,243,193 |
| 32 KiB | bnaesonly | 2,245,645 | 1,557,009 |
| 32 KiB | sw | 19,285,357 | 26,753,729 |

exec+wait in Ibex cycles. Chip RTL under Verilator, 32 KiB DMEM profile, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-cycles:sign/ldirect@32:Ip,Is -->

<!-- table:rtl-speedup:sign/ldirect@32:Ip,Is -->
Times faster than sw (sw cycles / tier cycles), chip, exec+wait

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | sign | ldirect | Ip | 2.72x | 8.59x | 71.3x |
| 32 KiB | sign | ldirect | Is | 2.61x | 17.2x | 93.9x |

exec+wait: Ibex cycles over EXECUTE and the wait for the ACC to finish, summed over the phases. -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-speedup:sign/ldirect@32:Ip,Is -->

<!-- table:rtl-speedup-op:sign/ldirect@32:Ip,Is -->
Times faster than sw (sw cycles / tier cycles), chip, whole operation

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | sign | ldirect | Ip | 2.72x | 8.59x | 71.1x |
| 32 KiB | sign | ldirect | Is | 2.61x | 17.2x | 93.7x |

The whole operation: from the first input write to the last result read, the host's transfers included (for the stream keygens, tuned and stream_uniform, also the host's fold; in the verify full tests this run also installs the key). -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-speedup-op:sign/ldirect@32:Ip,Is -->

<!-- table:mem:sign/ldirect@32:Ip,Is -->
| DMEM | tier | Ip | Is |
|---|---|---:|---:|
| 32 KiB | bngfaes | 13,524 / 13,952 / 12,544 | 5,108 / 10,176 / 8,736 |
| 32 KiB | bngfonly | 14,660 / 14,432 / 12,544 | 6,148 / 10,336 / 8,736 |
| 32 KiB | bnaesonly | 14,776 / 14,592 / 12,544 | 6,568 / 10,208 / 8,736 |
| 32 KiB | sw | 14,720 / 18,080 / 12,544 | 7,300 / 14,272 / 8,736 |

Bytes of the ELFs the ISS ran at the 32 KiB DMEM profile: code / `_dmem_bss_end` (the end of the linked data and bss) / the stack block
reserved inside it (`stack_end - stack`; a reservation, not a measured peak).
Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:mem:sign/ldirect@32:Ip,Is -->

## Files
| file | role |
|---|---|
| `ov-Ip-skc/` | GF(256), v=68 o=44: sources, BUILD, AES backends, its own README |
| `ov-Is-skc/` | GF(16), v=96 o=64: the same |
| `../../../own_utils/run_test.py sign` | the sign KAT and cycle driver (`--param Ip|Is|Ip3`) |
| `../../../own_utils/run_test.py <kernel>` | the tests of the single kernels (ge, backsub, matvec_small, matvec_large, trimat_eval, transpose, p1p1to, hash, expandsk); `run_test.py` alone lists them |
