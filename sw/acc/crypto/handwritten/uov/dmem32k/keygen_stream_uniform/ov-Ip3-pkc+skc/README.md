# keygen_stream_uniform/ov-Ip3-pkc+skc: streamed Ip3 keygen with a swappable backend

Last updated: 2026-11-17: chip tables from the rerun rtl-2026-11b; the chip tests copy their data faster.

## TL;DR
- A measurement rig for the Round-3 parameter set Ip3 (v=74, o=45), not a shipping kernel: one outer
  kernel with a window of 5 columns, four backends swapped behind `backend_*` by a Bazel dependency.
  The idea and the reading of the ratios are those of `../`.
- Cycles and speed-ups: [Numbers](#numbers). The shipping Ip3 keygen is
  `../../keygen_stream/ov-Ip3-pkc+skc/`.

## How to run
From the repository root, at the 32 KiB DMEM profile:
```
# One parameter set and one tier: Ip3 at bngfaes.
# Tiers: bngfaes, bngfonly, bnaesonly, sw.
./bazelisk.sh build "//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream_uniform/ov-Ip3-pkc+skc:ov-Ip3-keygen_stream_uniform_bngfaes"
python3 tools/gather_kat_stats.py --ops keygen --params Ip3 --tiers bngfaes --variants stream_uniform --cases 0
```
For another tier, change it in the build label and in `--tiers`. It prints PASS and the cycles.

Every arm at once, and the gate script (it builds every arm itself):
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream_uniform/ov-Ip3-pkc+skc:all
python3 tools/gather_kat_stats.py --ops keygen --params Ip3 --cases 0 --tiers bngfaes,bngfonly,bnaesonly,sw --variants stream_uniform
tools/stream_uniform_gates.sh keygen Ip3
```
- The KAT driver is `../../keygen_stream/tests/test_stream_keygen.py --param Ip3`, the same as for
  `../../keygen_stream/ov-Ip3-pkc+skc/`.
- The gate script checks that the outer is identical in every arm and that each arm uses only the
  instructions of its tier.
- A PASS means the public key (cpk) that the host packs from the windows matches the fixture cpk of
  each selected case, byte for byte. The secret seed is only an input; no secret key is compared.
  The 12 Ip3 ladder cases share one key pair. The separate Round-3 reference check and its limits
  are in [test-data provenance](../../../../test_data/README.md#notes).
- On the chip model: `acc_uov_keygen_stream_uniform_ip3_<tier>_test`
  (`sw/device/tests/acc_uov/README.md`).

## Numbers
Written by `python3 tools/uov.py tables` from the records in `../../../results/`; do not edit.

<!-- table:iss:keygen/stream_uniform@32:Ip3 -->
| DMEM | tier | Ip3 |
|---|---|---:|
| 32 KiB | bngfaes | 2,794,907 |
| 32 KiB | bngfonly | 55,068,553 |
| 32 KiB | bnaesonly | 41,209,195 |
| 32 KiB | sw | 172,448,040 |

ISS cycles of one key generation (INIT and every window, summed), 32 KiB DMEM profile; the same in all 12 KAT cases.
Every case passed. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss:keygen/stream_uniform@32:Ip3 -->

<!-- table:iss-speedup:keygen/stream_uniform@32:Ip3 -->
Times faster than sw (sw cycles / tier cycles), ISS

| DMEM | tier | Ip3 |
|---|---|---:|
| 32 KiB | bngfonly | 3.13x |
| 32 KiB | bnaesonly | 4.18x |
| 32 KiB | bngfaes | 61.7x |

The cycles of the KAT cases added up per row, sw divided by the tier. -: no run of that tier.
ISS, 32 KiB DMEM profile. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-speedup:keygen/stream_uniform@32:Ip3 -->

<!-- table:iss-ratio:keygen/stream_uniform@32/stream@32:Ip3 -->
stream_uniform / tuned (ISS cycles of stream_uniform divided by those of tuned; above 1.00x, tuned is faster)

| DMEM | op | param | bngfonly | bnaesonly | bngfaes | sw |
|---|---|---|---:|---:|---:|---:|
| 32 KiB | keygen | Ip3 | 1.11x | 1.00x | 1.09x | 1.00x |

The cycles of the KAT cases added up per row. Two decimals: 1.00x is within half a percent, not necessarily equal.
ISS. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-ratio:keygen/stream_uniform@32/stream@32:Ip3 -->

On the chip model, exec+wait of one test per cell (every meter of these tests:
`sw/acc/crypto/handwritten/uov/results/CHIP-MATRIX.md`):

<!-- table:rtl-cycles:keygen/stream_uniform@32:Ip3 -->
| DMEM | tier | Ip3 |
|---|---|---:|
| 32 KiB | bngfaes | 2,800,729 |
| 32 KiB | bngfonly | 55,074,272 |
| 32 KiB | bnaesonly | 41,214,935 |
| 32 KiB | sw | 172,453,779 |

exec+wait in Ibex cycles. Chip RTL under Verilator, 32 KiB DMEM profile, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-cycles:keygen/stream_uniform@32:Ip3 -->

<!-- table:rtl-speedup:keygen/stream_uniform@32:Ip3 -->
Times faster than sw (sw cycles / tier cycles), chip, exec+wait

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | keygen | stream_uniform | Ip3 | 3.13x | 4.18x | 61.6x |

exec+wait: Ibex cycles over EXECUTE and the wait for the ACC to finish, summed over the phases. -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-speedup:keygen/stream_uniform@32:Ip3 -->

<!-- table:rtl-speedup-op:keygen/stream_uniform@32:Ip3 -->
Times faster than sw (sw cycles / tier cycles), chip, whole operation

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | keygen | stream_uniform | Ip3 | 3.12x | 4.16x | 55.5x |

The whole operation: from the first input write to the last result read, the host's transfers included (for the stream keygens, tuned and stream_uniform, also the host's fold; in the verify full tests this run also installs the key). -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-speedup-op:keygen/stream_uniform@32:Ip3 -->

<!-- table:mem:keygen/stream_uniform@32:Ip3 -->
| DMEM | tier | Ip3 |
|---|---|---:|
| 32 KiB | bngfaes | 6,088 / 26,336 |
| 32 KiB | bngfonly | 7,000 / 26,976 |
| 32 KiB | bnaesonly | 7,888 / 26,848 |
| 32 KiB | sw | 8,632 / 31,104 |

Bytes of the ELFs the ISS ran at the 32 KiB DMEM profile: code / `_dmem_bss_end` (the end of the linked data and bss).
Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:mem:keygen/stream_uniform@32:Ip3 -->

## Files
| file | role |
|---|---|
| `ov-Ip3-keygen_stream_uniform.s` | the outer, shared by all arms: INIT (expandsk, then `backend_init_once`) and WINDOW; all AES and GF work goes through the `backend_*` symbols |
| `ov-Ip3-keygen_backend.s` | one cpp-guarded source with the four arms |
| `BUILD` | the backend libraries `ov-Ip3-keygen_backend_<arm>`, the ISS binaries `ov-Ip3-keygen_stream_uniform_<arm>` and their underscore twins for the chip tests |
