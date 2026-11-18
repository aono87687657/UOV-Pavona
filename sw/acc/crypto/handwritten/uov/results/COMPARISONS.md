# UOV comparisons: speed-up over sw, kernel against kernel

Last updated: 2026-11-17: chip tables from the reruns rtl-2026-11 (128 KiB) and rtl-2026-11b (32 KiB); the chip tests copy their data faster, so host I/O is lower.

Every ratio of the published UOV measurements, from the records in this directory; the cycle counts behind them are in `README.md` (ISS) and `CHIP-MATRIX.md` (chip). Written by `python3 tools/uov.py tables`; do not edit.

- Speed-up over sw: the cycles of sw divided by those of the tier, so 67.5x means the tier needs
  1/67.5 of the cycles of sw. In the speed-up tables sw is the baseline and has no column. The
  512 KiB kernels have no sw run, so no speed-up.
- Every row names its DMEM profile. An ISS row adds up the cycles of the KAT cases; a chip row is one
  test (keygen and sign KAT case 0, verify case 11).
- A KAT case in which signing needed a retry is left out of every table; its speed-ups are in
  [the last table](#kat-cases-with-a-retry), its cycles in `README.md`.
- `tuned` is the shipping streamed kernel (`../dmem32k/keygen_stream/`,
  `../dmem32k/verify_stream/`; the chip tests call it `stream`). `stream_uniform` runs one outer
  for all four tiers and swaps only the backend, so its tier ratios are whole-kernel speed-ups from
  changing the backend with the outer held fixed.

## Speed-up over sw on the ISS

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

## Speed-up over sw on the chip
exec+wait covers EXECUTE and the wait for the ACC; the whole operation adds the host's transfers
(for the streamed keygens also the host's fold), which no ACC instruction speeds up.

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

## sign: sprec against ldirect
sprec builds S once per signature in 512 KiB of DMEM, so that a retry only evaluates and solves
again; ldirect, the shipping sign, fits 32 KiB and derives the linear system per attempt. Each is
measured at its own profile.

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

## stream_uniform against tuned
The uniform keygen runs the window count of the sw arm in every tier; the tuned bngfaes verify
unrolls its fold by 8.

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

## KAT cases with a retry

<!-- table:iss-retries-speedup:all -->
Times faster than sw (sw cycles / tier cycles), ISS, the KAT cases in which signing needed a retry

| DMEM | op | kernel | param | KAT case | retries | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|---:|---:|
| 32 KiB | sign | ldirect | Is | 11 | 1 | 2.61x | 17.3x | 95.4x |

sw divided by the tier in that one case; its cycles are in the retry table of `sw/acc/crypto/handwritten/uov/results/README.md`. retries: - where the tiers' counts differ. In a tier column, -: no run of that tier.
ISS. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-retries-speedup:all -->
