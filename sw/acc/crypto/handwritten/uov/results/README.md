# results: the published UOV measurements

Last updated: 2026-11-17: chip tables from the reruns rtl-2026-11 (128 KiB) and rtl-2026-11b (32 KiB); the chip tests copy their data faster, so host I/O is lower.

## TL;DR
- The one place for UOV numbers: every published ISS run and chip-RTL run, with what it was measured
  on. Written only by `python3 tools/uov.py`; do not edit by hand.
- Three pages: this one (every ISS cycle count, the speed-ups over sw on the ISS and the chip, the
  KAT case with a retry, kernel against kernel), `CHIP-MATRIX.md` (every chip test with meters) and
  `COMPARISONS.md` (the same ratios alone, without cycle counts). They and the tables in the READMEs
  of the kernel directories are generated from these records by `python3 tools/uov.py tables`.
- How measurements get here: `tools/README.md`.

## How to run
`python3 tools/uov.py tables`, from the repository root, checks every record listed here and
rewrites the tables of all READMEs from them (`--check` only reports what would change). Recording
a new measurement is described in `tools/README.md` (Recorded measurements).

## Numbers
The ISS cycles of every kernel family; `tuned` is the shipping streamed kernel
(`../dmem32k/keygen_stream/`, `../dmem32k/verify_stream/`). Chip tests exist at 32 and 128 KiB
only (`CHIP-MATRIX.md`); keygen full and sign sprec need the 512 KiB profile and have ISS
numbers only.

<!-- table:iss:all@32 -->
| DMEM | op | kernel | tier | Ip | Is | Ip3 |
|---|---|---|---|---:|---:|---:|
| 32 KiB | keygen | stream_uniform | bngfaes | 2,424,823 | 2,648,528 | 2,794,907 |
| 32 KiB | keygen | stream_uniform | bngfonly | 43,856,494 | 38,024,332 | 55,068,553 |
| 32 KiB | keygen | stream_uniform | bnaesonly | 35,768,933 | 35,167,152 | 41,209,195 |
| 32 KiB | keygen | stream_uniform | sw | 140,068,839 | 124,802,512 | 172,448,040 |
| 32 KiB | keygen | tuned | bngfaes | 2,018,084 | 2,356,745 | 2,566,680 |
| 32 KiB | keygen | tuned | bngfonly | 34,888,302 | 33,483,143 | 49,545,021 |
| 32 KiB | keygen | tuned | bnaesonly | 35,449,206 | 34,682,399 | 41,096,086 |
| 32 KiB | keygen | tuned | sw | 139,749,112 | 124,317,759 | 172,344,351 |
| 32 KiB | sign | ldirect | bngfaes | 269,284-271,092 | 283,859-284,771 | 339,400-341,208 |
| 32 KiB | sign | ldirect | bngfonly | 7,101,107-7,102,915 | 10,242,199-10,243,111 | 8,859,108-8,860,916 |
| 32 KiB | sign | ldirect | bnaesonly | 2,244,573-2,246,381 | 1,556,017-1,556,929 | 2,398,655-2,400,463 |
| 32 KiB | sign | ldirect | sw | 19,284,259-19,286,067 | 26,752,721-26,753,633 | 23,766,364-23,768,172 |
| 32 KiB | verify | stream_uniform | bngfaes | 193,960-194,863 | 165,717-166,620 | 239,475-240,378 |
| 32 KiB | verify | stream_uniform | bngfonly | 7,363,326-7,364,229 | 10,037,683-10,038,586 | 8,125,534-8,126,437 |
| 32 KiB | verify | stream_uniform | bnaesonly | 1,288,803-1,289,706 | 877,675-878,578 | 1,468,107-1,469,010 |
| 32 KiB | verify | stream_uniform | sw | 18,347,346-18,348,249 | 25,998,779-25,999,682 | 22,752,878-22,753,781 |
| 32 KiB | verify | tuned | bngfaes | 154,873-155,776 | 165,603-166,506 | 194,959-195,862 |
| 32 KiB | verify | tuned | bngfonly | 7,357,869-7,358,772 | 10,037,675-10,038,578 | 8,073,946-8,074,849 |
| 32 KiB | verify | tuned | bnaesonly | 1,247,404-1,248,307 | 877,641-878,544 | 1,468,075-1,468,978 |
| 32 KiB | verify | tuned | sw | 18,331,999-18,332,902 | 25,998,745-25,999,648 | 22,752,846-22,753,749 |

ISS cycles of one operation per kernel family, 32 KiB DMEM profile; a range is the lowest and the highest of the 12 KAT cases (11 where a case in which signing needed a retry is left out; it is in the retry table of `sw/acc/crypto/handwritten/uov/results/README.md`).
Every case passed. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss:all@32 -->

<!-- table:iss:all@128 -->
| DMEM | op | kernel | tier | Ip | Is | Ip3 |
|---|---|---|---|---:|---:|---:|
| 128 KiB | keygen | min | bngfaes | 3,556,610 | 4,387,367 | 6,803,420 |
| 128 KiB | keygen | min | bngfonly | 97,267,260 | 146,014,215 | 249,596,240 |
| 128 KiB | keygen | min | bnaesonly | 37,928,618 | 36,667,175 | 46,034,420 |
| 128 KiB | keygen | min | sw | 273,832,014 | 398,599,767 | 655,628,991 |
| 128 KiB | keygen | sp | bngfaes | 1,652,219 | 2,227,917 | 2,079,442 |
| 128 KiB | keygen | sp | bngfonly | 9,695,178 | 12,105,812 | 12,013,022 |
| 128 KiB | keygen | sp | bnaesonly | 34,490,226 | 33,701,433 | 40,381,198 |
| 128 KiB | keygen | sp | sw | 54,739,132 | 58,898,137 | 65,324,077 |
| 128 KiB | verify | full | bngfaes | 154,871-155,774 | 165,544-166,447 | 194,908-195,811 |
| 128 KiB | verify | full | bngfonly | 7,357,790-7,358,693 | 10,037,509-10,038,412 | 8,073,818-8,074,721 |
| 128 KiB | verify | full | bnaesonly | 1,247,297-1,248,200 | 877,465-878,368 | 1,467,969-1,468,872 |
| 128 KiB | verify | full | sw | 18,331,892-18,332,795 | 25,998,569-25,999,472 | 22,752,740-22,753,643 |

ISS cycles of one operation per kernel family, 128 KiB DMEM profile; a range is the lowest and the highest of the 12 KAT cases.
Every case passed. Measured 2026-11-01 to 2026-11-02 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss:all@128 -->

<!-- table:iss:all@512 -->
| DMEM | op | kernel | tier | Ip | Is | Ip3 |
|---|---|---|---|---:|---:|---:|
| 512 KiB | keygen | full | bngfaes | 1,574,091 | 1,733,439 | 1,929,762 |
| 512 KiB | sign | sprec | bngfaes | 1,569,471-1,571,279 | 2,157,658-2,158,570 | 1,877,336-1,879,144 |

ISS cycles of one operation per kernel family, 512 KiB DMEM profile (ISS only: no chip test runs at this profile); a range is the lowest and the highest of the 12 KAT cases (11 where a case in which signing needed a retry is left out; it is in the retry table of `sw/acc/crypto/handwritten/uov/results/README.md`).
Every case passed. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss:all@512 -->

### Speed-up over sw

<!-- table:iss-speedup:all -->
Times faster than sw (sw cycles / tier cycles), ISS

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | keygen | stream_uniform | Ip | 3.19x | 3.92x | 57.8x |
| 32 KiB | keygen | stream_uniform | Is | 3.28x | 3.55x | 47.1x |
| 32 KiB | keygen | stream_uniform | Ip3 | 3.13x | 4.18x | 61.7x |
| 32 KiB | keygen | tuned | Ip | 4.01x | 3.94x | 69.2x |
| 32 KiB | keygen | tuned | Is | 3.71x | 3.58x | 52.7x |
| 32 KiB | keygen | tuned | Ip3 | 3.48x | 4.19x | 67.1x |
| 32 KiB | sign | ldirect | Ip | 2.72x | 8.59x | 71.5x |
| 32 KiB | sign | ldirect | Is | 2.61x | 17.2x | 94.2x |
| 32 KiB | sign | ldirect | Ip3 | 2.68x | 9.91x | 70x |
| 32 KiB | verify | stream_uniform | Ip | 2.49x | 14.2x | 94.5x |
| 32 KiB | verify | stream_uniform | Is | 2.59x | 29.6x | 157x |
| 32 KiB | verify | stream_uniform | Ip3 | 2.8x | 15.5x | 95x |
| 32 KiB | verify | tuned | Ip | 2.49x | 14.7x | 118x |
| 32 KiB | verify | tuned | Is | 2.59x | 29.6x | 157x |
| 32 KiB | verify | tuned | Ip3 | 2.82x | 15.5x | 117x |
| 128 KiB | keygen | min | Ip | 2.82x | 7.22x | 77x |
| 128 KiB | keygen | min | Is | 2.73x | 10.9x | 90.9x |
| 128 KiB | keygen | min | Ip3 | 2.63x | 14.2x | 96.4x |
| 128 KiB | keygen | sp | Ip | 5.65x | 1.59x | 33.1x |
| 128 KiB | keygen | sp | Is | 4.87x | 1.75x | 26.4x |
| 128 KiB | keygen | sp | Ip3 | 5.44x | 1.62x | 31.4x |
| 128 KiB | verify | full | Ip | 2.49x | 14.7x | 118x |
| 128 KiB | verify | full | Is | 2.59x | 29.6x | 157x |
| 128 KiB | verify | full | Ip3 | 2.82x | 15.5x | 117x |

The cycles of the KAT cases added up per row, sw divided by the tier; a case in which signing needed a retry is left out; it is in the retry table of `sw/acc/crypto/handwritten/uov/results/README.md`. -: no run of that tier.
ISS. Measured 2026-11-01 to 2026-11-02 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-speedup:all -->

<!-- table:rtl-speedup:all -->
Times faster than sw (sw cycles / tier cycles), chip, exec+wait

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | keygen | stream_uniform | Ip | 3.19x | 3.92x | 57.6x |
| 32 KiB | keygen | stream_uniform | Is | 3.28x | 3.55x | 47x |
| 32 KiB | keygen | stream_uniform | Ip3 | 3.13x | 4.18x | 61.6x |
| 32 KiB | keygen | tuned | Ip | 4.01x | 3.94x | 69.1x |
| 32 KiB | keygen | tuned | Is | 3.71x | 3.58x | 52.7x |
| 32 KiB | keygen | tuned | Ip3 | 3.48x | 4.19x | 67x |
| 32 KiB | sign | ldirect | Ip | 2.72x | 8.59x | 71.3x |
| 32 KiB | sign | ldirect | Is | 2.61x | 17.2x | 93.9x |
| 32 KiB | sign | ldirect | Ip3 | 2.68x | 9.9x | 69.8x |
| 32 KiB | verify | stream_uniform | Ip | 2.49x | 14.2x | 93.1x |
| 32 KiB | verify | stream_uniform | Is | 2.59x | 29.5x | 154x |
| 32 KiB | verify | stream_uniform | Ip3 | 2.8x | 15.5x | 93.8x |
| 32 KiB | verify | tuned | Ip | 2.49x | 14.7x | 116x |
| 32 KiB | verify | tuned | Is | 2.59x | 29.5x | 154x |
| 32 KiB | verify | tuned | Ip3 | 2.82x | 15.5x | 115x |
| 128 KiB | keygen | min | Ip | 2.82x | 7.22x | 77x |
| 128 KiB | keygen | min | Is | 2.73x | 10.9x | 90.8x |
| 128 KiB | keygen | min | Ip3 | 2.63x | 14.2x | 96.4x |
| 128 KiB | keygen | sp | Ip | 5.65x | 1.59x | 33.1x |
| 128 KiB | keygen | sp | Is | 4.87x | 1.75x | 26.4x |
| 128 KiB | keygen | sp | Ip3 | 5.44x | 1.62x | 31.4x |
| 128 KiB | verify | full | Ip | 2.49x | 14.7x | 117x |
| 128 KiB | verify | full | Is | 2.59x | 29.6x | 156x |
| 128 KiB | verify | full | Ip3 | 2.82x | 15.5x | 116x |

exec+wait: Ibex cycles over EXECUTE and the wait for the ACC to finish, summed over the phases. -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-15 to 2026-11-17 at `9fe0ccdd8c`, `de52799642` (rtl-2026-11, rtl-2026-11b).
<!-- /table:rtl-speedup:all -->

<!-- table:rtl-speedup-op:all -->
Times faster than sw (sw cycles / tier cycles), chip, whole operation

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | keygen | stream_uniform | Ip | 3.18x | 3.9x | 52.8x |
| 32 KiB | keygen | stream_uniform | Is | 3.26x | 3.52x | 41.7x |
| 32 KiB | keygen | stream_uniform | Ip3 | 3.12x | 4.16x | 55.5x |
| 32 KiB | keygen | tuned | Ip | 3.99x | 3.92x | 62.3x |
| 32 KiB | keygen | tuned | Is | 3.68x | 3.56x | 46.1x |
| 32 KiB | keygen | tuned | Ip3 | 3.46x | 4.17x | 59.9x |
| 32 KiB | sign | ldirect | Ip | 2.72x | 8.59x | 71.1x |
| 32 KiB | sign | ldirect | Is | 2.61x | 17.2x | 93.7x |
| 32 KiB | sign | ldirect | Ip3 | 2.68x | 9.9x | 69.6x |
| 32 KiB | verify | stream_uniform | Ip | 2.48x | 13.6x | 71x |
| 32 KiB | verify | stream_uniform | Is | 2.58x | 26.8x | 100x |
| 32 KiB | verify | stream_uniform | Ip3 | 2.78x | 14.8x | 73.8x |
| 32 KiB | verify | tuned | Ip | 2.48x | 14x | 83.6x |
| 32 KiB | verify | tuned | Is | 2.58x | 26.8x | 100x |
| 32 KiB | verify | tuned | Ip3 | 2.8x | 14.8x | 86.2x |
| 128 KiB | keygen | min | Ip | 2.81x | 7.21x | 75.8x |
| 128 KiB | keygen | min | Is | 2.73x | 10.8x | 89.1x |
| 128 KiB | keygen | min | Ip3 | 2.63x | 14.2x | 95.5x |
| 128 KiB | keygen | sp | Ip | 5.62x | 1.59x | 32x |
| 128 KiB | keygen | sp | Is | 4.84x | 1.75x | 25.5x |
| 128 KiB | keygen | sp | Ip3 | 5.41x | 1.62x | 30.5x |
| 128 KiB | verify | full | Ip | 2.48x | 14.1x | 85.2x |
| 128 KiB | verify | full | Is | 2.58x | 26.9x | 102x |
| 128 KiB | verify | full | Ip3 | 2.8x | 14.9x | 87.8x |

The whole operation: from the first input write to the last result read, the host's transfers included (for the stream keygens, tuned and stream_uniform, also the host's fold; in the verify full tests this run also installs the key). -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-15 to 2026-11-17 at `9fe0ccdd8c`, `de52799642` (rtl-2026-11, rtl-2026-11b).
<!-- /table:rtl-speedup-op:all -->

### KAT cases with a retry

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

### Kernel against kernel

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

<!-- table:iss-ratio:keygen/stream_uniform@32/stream@32 -->
stream_uniform / tuned (ISS cycles of stream_uniform divided by those of tuned; above 1.00x, tuned is faster)

| DMEM | op | param | bngfonly | bnaesonly | bngfaes | sw |
|---|---|---|---:|---:|---:|---:|
| 32 KiB | keygen | Ip | 1.26x | 1.01x | 1.20x | 1.00x |
| 32 KiB | keygen | Is | 1.14x | 1.01x | 1.12x | 1.00x |
| 32 KiB | keygen | Ip3 | 1.11x | 1.00x | 1.09x | 1.00x |

The cycles of the KAT cases added up per row. Two decimals: 1.00x is within half a percent, not necessarily equal.
ISS. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-ratio:keygen/stream_uniform@32/stream@32 -->

<!-- table:iss-ratio:verify/stream_uniform@32/stream@32 -->
stream_uniform / tuned (ISS cycles of stream_uniform divided by those of tuned; above 1.00x, tuned is faster)

| DMEM | op | param | bngfonly | bnaesonly | bngfaes | sw |
|---|---|---|---:|---:|---:|---:|
| 32 KiB | verify | Ip | 1.00x | 1.03x | 1.25x | 1.00x |
| 32 KiB | verify | Is | 1.00x | 1.00x | 1.00x | 1.00x |
| 32 KiB | verify | Ip3 | 1.01x | 1.00x | 1.23x | 1.00x |

The cycles of the KAT cases added up per row. Two decimals: 1.00x is within half a percent, not necessarily equal.
ISS. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-ratio:verify/stream_uniform@32/stream@32 -->

## Files
- `campaigns/NAME.json`: the plan of an ISS campaign (`uov.py campaign-init`): its groups (op,
  variant, tier, param, cases, measurement protocol, driver scripts), the tooling commit, each DMEM
  profile's overlay and the local Bazel configuration, by hash. Committed before its runs; each run
  binds to its hash.
- `campaigns/NAME.completed.json`: the groups published under `NAME` and the run behind each.
  A group is published once under that name.
- `iss-<profile>-<stamp>-<id>/` (schema 2), one group: `manifest.json` (the campaign and the hash
  of its plan, the group and its protocol, the source: commit, overlay, configuration, input and
  vector hashes, the ISS memory layout, the frozen ELF with its load segments, `_dmem_bss_end` and
  stack reservation, the collector's workers and timeout, completion), `results.csv` (one row per
  case, from `tools/gather_kat_stats.py`) and `cells/` (each case's ISS statistics and the driver's
  KAT output).
- `campaigns/NAME.json` with `"engine": "rtl"` (`uov.py rtl-init`): chip-RTL measurements made by
  `tools/rtl_campaign.sh`, registered after they were started (the runs did not bind this file):
  the commit they ran at, each profile's DMEM overlay, the local Bazel configuration and the
  baseline ledger, by hash, and every test of the collector's catalog with its protocol (60 at
  32 KiB, 36 at 128 KiB). Its `NAME.completed.json` lists each published test with its run; a
  profile is listed only with all its tests, each from one run.
- `rtl-<32|128>k-<stamp>/` (`uov.py rtl-import`), one finished run directory: `results.csv`, the
  collector's rows as read again from the run's logs at import (per timed run of a test:
  `acc_insn`, `exec_wait`, `host_io_fold`, `op_total_v2`, `app_load`; whole-test cycles and wall
  time on the accepting run), and `manifest.json` (schema 2, engine `rtl`): the hash of the
  registration, the tests, the measuring commit, overlay and configuration, the hashes of the
  measuring tools, the Bazel flags, the run's `DONE` line and `archive.inventory`, the sha256 of the
  run's `evidence.sha256`. Logs and binaries are not copied here: the checkout records their identities
  and hashes. Rechecking the archived evidence and rederiving its numbers requires the run directory
  that `archive.inventory` identifies.

- `observe-<kind>-<stamp>/` (schema 1, engine `observe`), `uov.py observe-import`: one finished ISS observer
  run (`uov.py observe-run`), published whole. `kind` trace: the sign-kernel trace comparisons of
  `tools/ct_trace.py`, one row per signing run (whole and per-attempt trace hashes, cycles, attempts, DMEM span);
  `kind` span: case 0 of every cell in the observer clone's catalog under `tools/dmem_span.py` (lowest and highest
  DMEM byte, bytes touched in 32-byte blocks; the two Ip3 cells at 512 KiB came later and have no span row). Every
  job ran a copy of its ELF, hashed before the run: `results.csv` carries that
  hash and the copy's load image, `manifest.json` the clones' commit and overlay, the hashes of the observer's
  files and the run directory's name. The hardware tiers' traces must be equal; the sw tier (T-table AES) is
  published with its distinct-trace counts. Neither observer establishes constant-time behavior or a worst-case
  memory bound. The observers left `tools/`; they run from a clone at 7aa5580180 (tools/README.md).

## Notes
- Published text is tidied (LF line ends, no trailing blanks, no blank first or last line); the
  collector's raw files stay under the ignored `chip-matrix/<run>/` of the tree that ran them.
- An ISS run is published only when every case passed, every count can be derived again from its
  evidence, and no input, overlay, configuration, HEAD or frozen ELF changed during the run. The
  record is finalised in `chip-matrix/<run>/record` first; publication then copies it here under
  `chip-matrix/.uov-results.lock` of this checkout and adds it to the completion list. If that
  last step fails, `python3 tools/uov.py publish --run chip-matrix/<run> --publish-to CHECKOUT`
  finishes it without running anything again.
- A chip-RTL run directory is imported only if `tools/rtl_campaign.sh --verify-only` passes (one
  clean `DONE` line, the inventory complete and unchanged), it was measured at the registered
  commit with exactly that profile's overlay, no untracked file and the registered configuration,
  its recorded sources are the ones the runner records and equal that commit's files, every test
  passed in that very Bazel invocation (not from a cache) with its timed runs in order, the 32 KiB
  baseline gate is identical, and its own csv equals what its logs read to. One `rtl-import` call
  brings every run of a profile; nothing of a profile is published otherwise.
- `python3 tools/uov.py tables` validates every listed record before it writes a table; where two
  campaigns hold the same cell, the one whose plan was created later is shown.
