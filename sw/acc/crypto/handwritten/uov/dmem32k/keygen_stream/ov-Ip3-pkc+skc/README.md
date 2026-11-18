# keygen_stream/ov-Ip3-pkc+skc: streamed Ip3 key generation in 32 KiB of DMEM

Last updated: 2026-11-17: chip tables from the rerun rtl-2026-11b; the chip tests copy their data faster.

## TL;DR
- The streamed keygen of `../` for the Round-3 parameter set Ip3 (v=74, o=45), at
  four tiers: INIT, then one WINDOW call per window of P3 columns; the host folds and packs.
- Cycles and memory: [Numbers](#numbers).

## How to run
From the repository root, at the 32 KiB DMEM profile:
```
# One parameter set and one tier: Ip3 at bngfaes.
# Tiers: bngfaes, bngfonly, bnaesonly, sw.
./bazelisk.sh build "//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Ip3-pkc+skc:ov-Ip3-keygen_stream_bngfaes"
python3 tools/gather_kat_stats.py --ops keygen --params Ip3 --tiers bngfaes --variants stream --cases 0
```
For another tier, change it in the build label and in `--tiers`. It prints PASS and the cycles.

Every tier at once (the sw line is slow: see Numbers), and the cycles of each phase:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Ip3-pkc+skc:all
python3 tools/gather_kat_stats.py --ops keygen --params Ip3 --cases 0 --tiers bngfaes,bngfonly,bnaesonly --variants stream
python3 tools/gather_kat_stats.py --ops keygen --params Ip3 --cases 0 --tiers sw --variants stream          # slow: see Numbers
# per-phase and total cycles, one ELF
python3 sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/tests/test_stream_keygen.py --param Ip3 \
  --elf bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Ip3-pkc+skc/ov-Ip3-keygen_stream_bngfaes.elf \
  --cases 0 --stats
```
- `gather_kat_stats.py` takes the parameter sets by name (`Ip3` here). It runs prebuilt ELFs: build
  first.
- The driver is the one of Ip and Is (`../tests/README.md`) with `--param Ip3`: `--elf`,
  `--cases`, `--stats`, `--dump-stats FILE`, and `--localize`, which compares every folded P3 entry with
  the Python reference and names the first wrong one.
- A PASS means the public key (cpk) that the host packs from the windows matches the fixture cpk of
  each selected case, byte for byte. The secret seed is only an input; no secret key is compared.
  The 12 Ip3 ladder cases share one key pair. The separate Round-3 reference check and its limits
  are in [test-data provenance](../../../../test_data/README.md#notes).
- On the chip model: `acc_uov_keygen_stream_ip3_<tier>_test` (`sw/device/tests/acc_uov/README.md`).

## Numbers
Written by `python3 tools/uov.py tables` from the records in `../../../results/`; do not edit.

<!-- table:iss:keygen/stream@32:Ip3 -->
| DMEM | tier | Ip3 |
|---|---|---:|
| 32 KiB | bngfaes | 2,566,680 |
| 32 KiB | bngfonly | 49,545,021 |
| 32 KiB | bnaesonly | 41,096,086 |
| 32 KiB | sw | 172,344,351 |

ISS cycles of one key generation (INIT and every window, summed), 32 KiB DMEM profile; the same in all 12 KAT cases.
Every case passed. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss:keygen/stream@32:Ip3 -->

<!-- table:iss-speedup:keygen/stream@32:Ip3 -->
Times faster than sw (sw cycles / tier cycles), ISS

| DMEM | tier | Ip3 |
|---|---|---:|
| 32 KiB | bngfonly | 3.48x |
| 32 KiB | bnaesonly | 4.19x |
| 32 KiB | bngfaes | 67.1x |

The cycles of the KAT cases added up per row, sw divided by the tier. -: no run of that tier.
ISS, 32 KiB DMEM profile. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-speedup:keygen/stream@32:Ip3 -->

On the chip model, exec+wait of one test per cell (every meter of these tests:
`sw/acc/crypto/handwritten/uov/results/CHIP-MATRIX.md`):

<!-- table:rtl-cycles:keygen/stream@32:Ip3 -->
| DMEM | tier | Ip3 |
|---|---|---:|
| 32 KiB | bngfaes | 2,571,832 |
| 32 KiB | bngfonly | 49,550,088 |
| 32 KiB | bnaesonly | 41,101,776 |
| 32 KiB | sw | 172,350,132 |

exec+wait in Ibex cycles. Chip RTL under Verilator, 32 KiB DMEM profile, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-cycles:keygen/stream@32:Ip3 -->

<!-- table:rtl-speedup:keygen/stream@32:Ip3 -->
Times faster than sw (sw cycles / tier cycles), chip, exec+wait

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | keygen | tuned | Ip3 | 3.48x | 4.19x | 67x |

exec+wait: Ibex cycles over EXECUTE and the wait for the ACC to finish, summed over the phases. -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-speedup:keygen/stream@32:Ip3 -->

<!-- table:rtl-speedup-op:keygen/stream@32:Ip3 -->
Times faster than sw (sw cycles / tier cycles), chip, whole operation

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | keygen | tuned | Ip3 | 3.46x | 4.17x | 59.9x |

The whole operation: from the first input write to the last result read, the host's transfers included (for the stream keygens, tuned and stream_uniform, also the host's fold; in the verify full tests this run also installs the key). -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-speedup-op:keygen/stream@32:Ip3 -->

<!-- table:mem:keygen/stream@32:Ip3 -->
| DMEM | tier | Ip3 |
|---|---|---:|
| 32 KiB | bngfaes | 8,688 / 29,152 |
| 32 KiB | bngfonly | 9,592 / 29,152 |
| 32 KiB | bnaesonly | 7,636 / 26,752 |
| 32 KiB | sw | 8,380 / 31,040 |

Bytes of the ELFs the ISS ran at the 32 KiB DMEM profile: code / `_dmem_bss_end` (the end of the linked data and bss).
Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:mem:keygen/stream@32:Ip3 -->

## Host contract
- Phase 0 (INIT) runs expandsk on `sk_seed` (0x20) and leaves `pk_seed` (0x40, zero-extended to
  32 B) and the padded O in DMEM. Phase 1 (WINDOW, `arg0 = col_start`, `arg1 = col_count`) needs a
  completed INIT.
- Window width: at most 6 columns in the hardware-GF kernel, at most 5 in the software-GF kernel.
  Slice entry (k, j) is at `slice + k*384 + j*64` in the hardware-GF kernel: 45 valid bytes and
  19 bytes of padding. Derive the geometry from the ELF symbols, as the driver does.

## Files
| file | role |
|---|---|
| `ov-Ip3-keygen_stream.s` | the hardware-GF kernel: bngfaes and bngfonly |
| `ov-Ip3-keygen_stream_gfsw.s` | the software-GF kernel: sw (T-table AES) and, with `-DAES_INSTRUCTIONS`, bnaesonly |
| `expandsk_ret_O_pkseed.s` | the Ip3 seed expansion |
| `../tests/test_stream_keygen.py --param Ip3` | the KAT and cycle driver (one driver for Ip, Is and Ip3) |
| `tests/init_kat.py` | a KAT of the INIT phase alone: `pk_seed` and the padded O against the SHAKE256 reference |

ELF names: `ov-Ip3-keygen_stream_<tier>`, `<tier>` = `bngfaes`, `bngfonly`, `bnaesonly`, `sw`; each has an
underscore twin for the chip tests.
