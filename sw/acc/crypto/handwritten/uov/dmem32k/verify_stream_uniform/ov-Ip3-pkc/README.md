# verify_stream_uniform/ov-Ip3-pkc: streamed Ip3 verification with a swappable backend

Last updated: 2026-11-17: chip tables from the rerun rtl-2026-11b; the chip tests copy their data faster.

## TL;DR
- A measurement rig for the Round-3 parameter set Ip3 (v=74, o=m=45), not a shipping kernel: one
  outer kernel, four backends swapped behind `backend_verify_p1p2` and `backend_verify_p3_rows` by a
  Bazel dependency. The idea is that of `../`.
- Ratios between arms compare whole-kernel cycles with the outer kernel held fixed; they include its
  common cost.
- Cycles and speed-ups: [Numbers](#numbers). The shipping Ip3 verify is `../../verify_stream/ov-Ip3-pkc/`.

## How to run
From the repository root, at the 32 KiB DMEM profile:
```
# One parameter set and one tier: Ip3 at bngfaes.
# Tiers: bngfaes, bngfonly, bnaesonly, sw.
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream_uniform/ov-Ip3-pkc:ov-Ip3-verify_stream_uniform_bngfaes
python3 tools/gather_kat_stats.py --ops verify --params Ip3 --tiers bngfaes --variants stream_uniform --cases 0,11
```
For another tier, change it in the build label and in `--tiers`. It prints PASS and the cycles.

Every arm at once, the gate script and the rejection check:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream_uniform/ov-Ip3-pkc:all
python3 tools/gather_kat_stats.py --ops verify --params Ip3 --cases 0,11 --tiers sw,bnaesonly,bngfonly,bngfaes --variants stream_uniform
tools/stream_uniform_gates.sh verify Ip3
python3 sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/tests/measure_cycles.py --param Ip3 --negative \
  --elf bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k/verify_stream_uniform/ov-Ip3-pkc/ov-Ip3-verify_stream_uniform_bngfaes.elf
```
- `gather_kat_stats.py` takes the parameter sets by name (`Ip3` here); `0-11` runs all 12 cases.
- The gate script checks that the outer is identical in every arm (bytes, relocations, shared
  symbol addresses) and that each arm uses only the instructions of its tier.
- `--negative` flips one signature byte per case; every case must reject with status -1. The other
  arms are `ov-Ip3-verify_stream_uniform_{bngfonly,bnaesonly,sw}.elf`.
- A PASS of the `gather_kat_stats.py` line means each selected signature is accepted; with `--negative`,
  that each case rejects its signature with one byte flipped. The `init_done` and capacity rejections
  below are not run by these commands. The separate Round-3 reference check and its limits are in
  [test-data provenance](../../../../test_data/README.md#notes).
- On the chip model: `acc_uov_verify_stream_uniform_ip3_<tier>_test`
  (`sw/device/tests/acc_uov/README.md`).

## What it does
The streamed protocol of `../../verify_stream/ov-Ip3-pkc/` (INIT, UPDATE, FINAL), plus an `init_done`
word (FINAL and UPDATE reject with -3 before a completed INIT) and a capacity table per `row_start`
(`caprows`, uniform cap of 528 entries) that rejects an UPDATE whose fold would read past the
message and P3 window.

| arm | AES | GF(256) fold |
|---|---|---|
| bngfaes | `bn.aes128` (`aes128_360`) | `bn.gfmul` |
| bngfonly | computed with `bn.gfmul` | `bn.gfmul` |
| bnaesonly | `bn.aes128` (`aes128hw_384`) | software (`bn.mulv` reduction) |
| sw | T-table | software (`bn.mulv` reduction) |

## Numbers
Written by `python3 tools/uov.py tables` from the records in `../../../results/`; do not edit.

<!-- table:iss:verify/stream_uniform@32:Ip3 -->
| DMEM | tier | Ip3 |
|---|---|---:|
| 32 KiB | bngfaes | 239,475-240,378 |
| 32 KiB | bngfonly | 8,125,534-8,126,437 |
| 32 KiB | bnaesonly | 1,468,107-1,469,010 |
| 32 KiB | sw | 22,752,878-22,753,781 |

ISS cycles of one accepting verification (INIT, the updates and FINAL, summed), 32 KiB DMEM profile; a range is the lowest and the highest of the 12 KAT cases.
Every case passed. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss:verify/stream_uniform@32:Ip3 -->

<!-- table:iss-speedup:verify/stream_uniform@32:Ip3 -->
Times faster than sw (sw cycles / tier cycles), ISS

| DMEM | tier | Ip3 |
|---|---|---:|
| 32 KiB | bngfonly | 2.8x |
| 32 KiB | bnaesonly | 15.5x |
| 32 KiB | bngfaes | 95x |

The cycles of the KAT cases added up per row, sw divided by the tier. -: no run of that tier.
ISS, 32 KiB DMEM profile. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-speedup:verify/stream_uniform@32:Ip3 -->

<!-- table:iss-ratio:verify/stream_uniform@32/stream@32:Ip3 -->
stream_uniform / tuned (ISS cycles of stream_uniform divided by those of tuned; above 1.00x, tuned is faster)

| DMEM | op | param | bngfonly | bnaesonly | bngfaes | sw |
|---|---|---|---:|---:|---:|---:|
| 32 KiB | verify | Ip3 | 1.01x | 1.00x | 1.23x | 1.00x |

The cycles of the KAT cases added up per row. Two decimals: 1.00x is within half a percent, not necessarily equal.
ISS. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-ratio:verify/stream_uniform@32/stream@32:Ip3 -->

These are whole-kernel backend comparisons. sw to bnaesonly changes only the AES leaf and its key
setup; the GF code is the same text. bngfonly to bngfaes keeps the `bn.gfmul.8` fold, but each arm
has its own copy, and the bngfonly copy runs one more instruction per folded entry. bnaesonly to
bngfaes changes the GF path and the AES leaf (`aes128hw_384` to `aes128_360`); sw to bngfonly also
changes T-table AES to computed AES. Neither of these two steps isolates the GF instruction gain.
Keep this rig's absolute cycles separate from those of the tuned kernel in `../../verify_stream/ov-Ip3-pkc/`.

On the chip model, exec+wait of one test per cell (every meter of these tests:
`sw/acc/crypto/handwritten/uov/results/CHIP-MATRIX.md`):

<!-- table:rtl-cycles:verify/stream_uniform@32:Ip3 -->
| DMEM | tier | Ip3 |
|---|---|---:|
| 32 KiB | bngfaes | 242,592 |
| 32 KiB | bngfonly | 8,128,623 |
| 32 KiB | bnaesonly | 1,471,193 |
| 32 KiB | sw | 22,755,989 |

exec+wait in Ibex cycles. Chip RTL under Verilator, 32 KiB DMEM profile, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-cycles:verify/stream_uniform@32:Ip3 -->

<!-- table:rtl-speedup:verify/stream_uniform@32:Ip3 -->
Times faster than sw (sw cycles / tier cycles), chip, exec+wait

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | verify | stream_uniform | Ip3 | 2.8x | 15.5x | 93.8x |

exec+wait: Ibex cycles over EXECUTE and the wait for the ACC to finish, summed over the phases. -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-speedup:verify/stream_uniform@32:Ip3 -->

<!-- table:rtl-speedup-op:verify/stream_uniform@32:Ip3 -->
Times faster than sw (sw cycles / tier cycles), chip, whole operation

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | verify | stream_uniform | Ip3 | 2.78x | 14.8x | 73.8x |

The whole operation: from the first input write to the last result read, the host's transfers included (for the stream keygens, tuned and stream_uniform, also the host's fold; in the verify full tests this run also installs the key). -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-speedup-op:verify/stream_uniform@32:Ip3 -->

## Files
| file | role |
|---|---|
| `ov-Ip3-verify_stream_uniform.s` | the outer, shared by all arms |
| `ov-Ip3-verify_backend.s` | one cpp-guarded source with the four arms |
| `BUILD` | 4 backend libraries, 4 ISS binaries `ov-Ip3-verify_stream_uniform_<arm>` and their underscore twins for the chip tests; the hardware AES and P3 leaves come from `../../../shared/verify/ov-Ip3-pkc/`, the computed AES leaf from `../../verify_stream/ov-Ip3-pkc/`; the T-table AES of the sw arm from `../../../shared/keygen/ov-Ip-pkc+skc/AES_ttable` (`aes128table_384`), `../../../shared/verify/ov-Ip-pkc/AES_ttable` and `AES_table`; the bngfonly key schedule from `../../../shared/verify/ov-Ip-pkc/AES_bngf` |
