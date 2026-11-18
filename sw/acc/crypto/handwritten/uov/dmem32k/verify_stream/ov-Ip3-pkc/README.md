# verify_stream/ov-Ip3-pkc: streamed Ip3 verification in 32 KiB of DMEM

Last updated: 2026-11-17: chip tables from the rerun rtl-2026-11b; the chip tests copy their data faster.

## TL;DR
- The streamed verify of `../` for the Round-3 parameter set Ip3 (v=74, o=m=45,
  n=119, a 135-byte signature), at four tiers: INIT, UPDATE per P3 window, FINAL.
- Cycles and memory: [Numbers](#numbers).

## How to run
From the repository root, at the 32 KiB DMEM profile:
```
# One parameter set and one tier: Ip3 at bngfaes.
# Tiers: bngfaes, bngfonly, bnaesonly, sw.
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/ov-Ip3-pkc:ov-Ip3-verify_stream_bngfaes
python3 tools/gather_kat_stats.py --ops verify --params Ip3 --tiers bngfaes --variants stream --cases 0,11
```
For another tier, change it in the build label and in `--tiers`. It prints PASS and the cycles.

Every tier at once, and the rejection check:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/ov-Ip3-pkc:all
python3 tools/gather_kat_stats.py --ops verify --params Ip3 --cases 0,11 --tiers bngfaes,bngfonly,bnaesonly,sw --variants stream
python3 sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/tests/measure_cycles.py --param Ip3 --negative
```
- `gather_kat_stats.py` takes the parameter sets by name (`Ip3` here). It runs prebuilt ELFs: build
  first.
- `../tests/measure_cycles.py --param Ip3`: `--elf PATH` (default the bngfaes ELF), `--cases LIST`
  (default `0,11`), `--phases` (cycles per phase), `--negative` (one signature byte flipped per case; every
  case must reject with status -1), `--dump-stats FILE` (one case), `--vectors FILE`.
- A PASS of the `gather_kat_stats.py` line means each selected signature is accepted. A PASS with
  `--negative` means each selected case rejects its signature with one byte flipped. The separate
  Round-3 reference check and its limits are in [test-data provenance](../../../../test_data/README.md#notes).
- On the chip model: `acc_uov_verify_stream_ip3_<tier>_test` (`sw/device/tests/acc_uov/README.md`).

## Numbers
Written by `python3 tools/uov.py tables` from the records in `../../../results/`; do not edit.

<!-- table:iss:verify/stream@32:Ip3 -->
| DMEM | tier | Ip3 |
|---|---|---:|
| 32 KiB | bngfaes | 194,959-195,862 |
| 32 KiB | bngfonly | 8,073,946-8,074,849 |
| 32 KiB | bnaesonly | 1,468,075-1,468,978 |
| 32 KiB | sw | 22,752,846-22,753,749 |

ISS cycles of one accepting verification (INIT, the updates and FINAL, summed), 32 KiB DMEM profile; a range is the lowest and the highest of the 12 KAT cases.
Every case passed. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss:verify/stream@32:Ip3 -->

<!-- table:iss-speedup:verify/stream@32:Ip3 -->
Times faster than sw (sw cycles / tier cycles), ISS

| DMEM | tier | Ip3 |
|---|---|---:|
| 32 KiB | bngfonly | 2.82x |
| 32 KiB | bnaesonly | 15.5x |
| 32 KiB | bngfaes | 117x |

The cycles of the KAT cases added up per row, sw divided by the tier. -: no run of that tier.
ISS, 32 KiB DMEM profile. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-speedup:verify/stream@32:Ip3 -->

On the chip model, exec+wait of one test per cell (every meter of these tests:
`sw/acc/crypto/handwritten/uov/results/CHIP-MATRIX.md`):

<!-- table:rtl-cycles:verify/stream@32:Ip3 -->
| DMEM | tier | Ip3 |
|---|---|---:|
| 32 KiB | bngfaes | 198,109 |
| 32 KiB | bngfonly | 8,077,028 |
| 32 KiB | bnaesonly | 1,471,202 |
| 32 KiB | sw | 22,755,953 |

exec+wait in Ibex cycles. Chip RTL under Verilator, 32 KiB DMEM profile, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-cycles:verify/stream@32:Ip3 -->

<!-- table:rtl-speedup:verify/stream@32:Ip3 -->
Times faster than sw (sw cycles / tier cycles), chip, exec+wait

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | verify | tuned | Ip3 | 2.82x | 15.5x | 115x |

exec+wait: Ibex cycles over EXECUTE and the wait for the ACC to finish, summed over the phases. -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-speedup:verify/stream@32:Ip3 -->

<!-- table:rtl-speedup-op:verify/stream@32:Ip3 -->
Times faster than sw (sw cycles / tier cycles), chip, whole operation

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | verify | tuned | Ip3 | 2.8x | 14.8x | 86.2x |

The whole operation: from the first input write to the last result read, the host's transfers included (for the stream keygens, tuned and stream_uniform, also the host's fold; in the verify full tests this run also installs the key). -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-speedup-op:verify/stream@32:Ip3 -->

<!-- table:mem:verify/stream@32:Ip3 -->
| DMEM | tier | Ip3 |
|---|---|---:|
| 32 KiB | bngfaes | 11,064 / 0 |
| 32 KiB | bngfonly | 12,136 / 24,736 |
| 32 KiB | bnaesonly | 6,752 / 24,640 |
| 32 KiB | sw | 7,300 / 28,736 |

Bytes of the ELFs the ISS ran at the 32 KiB DMEM profile: code / `_dmem_bss_end` (the end of the linked data and bss).
Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:mem:verify/stream@32:Ip3 -->

## Host contract
- Layout: `ctrl@0 acc@0x20 oil@0x60 target@0xA0 sig@0xE0 seed@0x180 msg/window@0x1A0`. The 135-byte
  signature occupies a 160-byte slot, so the seed and the window sit 32 B above their Ip and Is
  addresses, and the host must zero `sig[135..159]`: INIT's salt read spans the whole slot.
- `oil` is an input of every UPDATE: write it again for each window so that byte 0 is
  `o[row_start]`.
- The message and P3 window is 23,968 B; the host splits the rows 13/32.

## Files
| file | role |
|---|---|
| `ov-Ip3-pkc_verify_stream_gfhw.s` | the hardware-GF kernel: bngfonly without flags, bngfaes with `-DAES_INSTRUCTIONS` |
| `ov-Ip3-pkc_verify_stream_gfsw.s` | the software-GF kernel: sw (T-table AES) without flags, bnaesonly with `-DAES_INSTRUCTIONS`; the same host contract |
| `aes128_360.s`, `aes128_360_bngf.s` | AES-CTR for eight 45-byte entries per call: with `bn.aes128`, and computed with `bn.gfmul` |
| `aes128hw_384.s`, `aes128hw_384_sign.s` | 24 AES-CTR blocks with `bn.aes128`: the drop-in for the T-table generator in the software-GF kernel, and the variant the Ip3 sign links |
| `load_p3_45.s` | loads 8 packed 45-byte P3 columns and aligns each to a WDR pair |
| `window_model.py` | a standalone model of the window schedule (row capacities, refills, the host split, the window size) |
| `../tests/measure_cycles.py` | the KAT, negative and cycle driver (`--param Ip3`), shared with Ip and Is |

ELF names: `ov-Ip3-verify_stream_<tier>`, `<tier>` = `bngfaes`, `bngfonly`, `bnaesonly`, `sw`; each has an
underscore twin for the chip tests. Each source refuses at assembly time the flag combination that
belongs to the other source.
