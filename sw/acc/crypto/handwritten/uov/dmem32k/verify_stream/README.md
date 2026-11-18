# verify_stream: streamed UOV verification in 32 KiB of DMEM

Last updated: 2026-11-17: chip tables from the rerun rtl-2026-11b; the chip tests copy their data faster.

## TL;DR
- The default verify path, for Ip and Is at four tiers each. Ip3 is in `ov-Ip3-pkc/`.
- One phase-dispatch binary per parameter set and tier: the host loads it once and executes it per
  phase, feeding the compressed public key in row-aligned P3 windows, so the whole verification
  fits the 32 KiB DMEM.
- Cycles and memory: [Numbers](#numbers).

## How to run
From the repository root, at the 32 KiB DMEM profile:
```
# One parameter set and one tier: Ip at bngfaes.
# Parameter sets: Ip, Is, Ip3. Tiers: bngfaes, bngfonly, bnaesonly, sw.
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/ov-Ip-pkc:ov-Ip-verify_stream_bngfaes
python3 tools/gather_kat_stats.py --ops verify --params Ip --tiers bngfaes --variants stream --cases 0,11
```
For another choice, change the parameter set (twice in the build label, once in `--params`) and the
tier (in the label and in `--tiers`). It prints PASS and the cycles.

Ip and Is at every tier at once:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/...
python3 tools/gather_kat_stats.py --ops verify --params Ip,Is --cases 0,11 --tiers bngfaes,bngfonly --variants stream
python3 tools/gather_kat_stats.py --ops verify --params Ip,Is --cases 0,11 --tiers sw,bnaesonly --variants stream
```
- `gather_kat_stats.py` runs prebuilt ELFs: build first, or the sweep passes on stale binaries at stale
  cycles.
- Per-phase cycles and the functional tests: `tests/README.md`.
- On the chip model: `sw/device/tests/acc_uov/README.md`. `acc_uov_verify_stream_{ip,is}_<tier>_test`
  runs one arm (an accepting and a rejecting run).

## What it does
```
phase 0 INIT    KMAC(msg||salt) -> target ; P1/P2 (from pk_seed) -> acc
phase 1 UPDATE  fold one row-aligned P3 window into acc  (x K)
phase 2 FINAL   compare acc with target -> ctrl.status (0 accept / -1 reject)
```
The context `{acc, target}` stays in DMEM between the runs.

There are four ELFs per parameter set. The GF engine selects the source file, so the two pairs
built from one source differ in the AES only: bngfaes and bngfonly with the GF in hardware, sw and
bnaesonly with the GF in software. A ratio across the file boundary compares two tuned kernels; the
controlled comparison of the GF engines is `../verify_stream_uniform/`.

## Numbers
Written by `python3 tools/uov.py tables` from the records in `../../results/`; do not edit.

<!-- table:iss:verify/stream@32:Ip,Is -->
| DMEM | tier | Ip | Is |
|---|---|---:|---:|
| 32 KiB | bngfaes | 154,873-155,776 | 165,603-166,506 |
| 32 KiB | bngfonly | 7,357,869-7,358,772 | 10,037,675-10,038,578 |
| 32 KiB | bnaesonly | 1,247,404-1,248,307 | 877,641-878,544 |
| 32 KiB | sw | 18,331,999-18,332,902 | 25,998,745-25,999,648 |

ISS cycles of one accepting verification (INIT, the updates and FINAL, summed), 32 KiB DMEM profile; a range is the lowest and the highest of the 12 KAT cases.
Every case passed. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss:verify/stream@32:Ip,Is -->

<!-- table:iss-speedup:verify/stream@32:Ip,Is -->
Times faster than sw (sw cycles / tier cycles), ISS

| DMEM | tier | Ip | Is |
|---|---|---:|---:|
| 32 KiB | bngfonly | 2.49x | 2.59x |
| 32 KiB | bnaesonly | 14.7x | 29.6x |
| 32 KiB | bngfaes | 118x | 157x |

The cycles of the KAT cases added up per row, sw divided by the tier. -: no run of that tier.
ISS, 32 KiB DMEM profile. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-speedup:verify/stream@32:Ip,Is -->

The ISS counts instructions and stalls, with `bn.aes128` and `bn.gfmul` at one cycle each; the
host's dispatch and its DMEM writes between the phases are not in these numbers.

On the chip model, exec+wait of one test per cell (every meter of these tests:
`sw/acc/crypto/handwritten/uov/results/CHIP-MATRIX.md`):

<!-- table:rtl-cycles:verify/stream@32:Ip,Is -->
| DMEM | tier | Ip | Is |
|---|---|---:|---:|
| 32 KiB | bngfaes | 157,959 | 169,206 |
| 32 KiB | bngfonly | 7,360,928 | 10,041,231 |
| 32 KiB | bnaesonly | 1,250,461 | 881,259 |
| 32 KiB | sw | 18,335,084 | 26,002,373 |

exec+wait in Ibex cycles. Chip RTL under Verilator, 32 KiB DMEM profile, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-cycles:verify/stream@32:Ip,Is -->

<!-- table:rtl-speedup:verify/stream@32:Ip,Is -->
Times faster than sw (sw cycles / tier cycles), chip, exec+wait

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | verify | tuned | Ip | 2.49x | 14.7x | 116x |
| 32 KiB | verify | tuned | Is | 2.59x | 29.5x | 154x |

exec+wait: Ibex cycles over EXECUTE and the wait for the ACC to finish, summed over the phases. -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-speedup:verify/stream@32:Ip,Is -->

<!-- table:rtl-speedup-op:verify/stream@32:Ip,Is -->
Times faster than sw (sw cycles / tier cycles), chip, whole operation

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | verify | tuned | Ip | 2.48x | 14x | 83.6x |
| 32 KiB | verify | tuned | Is | 2.58x | 26.8x | 100x |

The whole operation: from the first input write to the last result read, the host's transfers included (for the stream keygens, tuned and stream_uniform, also the host's fold; in the verify full tests this run also installs the key). -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-speedup-op:verify/stream@32:Ip,Is -->

<!-- table:mem:verify/stream@32:Ip,Is -->
| DMEM | tier | Ip | Is |
|---|---|---:|---:|
| 32 KiB | bngfaes | 3,792 / 0 | 752 / 0 |
| 32 KiB | bngfonly | 2,816 / 23,136 | 2,024 / 31,360 |
| 32 KiB | bnaesonly | 3,496 / 23,008 | 1,776 / 23,072 |
| 32 KiB | sw | 4,268 / 27,104 | 2,404 / 27,136 |

Bytes of the ELFs the ISS ran at the 32 KiB DMEM profile: code / `_dmem_bss_end` (the end of the linked data and bss).
Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:mem:verify/stream@32:Ip,Is -->

A DMEM end of 0 means the ELF links no data: the bngfaes arms address the DMEM by the fixed map
below.

## Host contract
- DMEM map: `ctrl@0 acc@0x20 oil@0x60 target@0xA0 sig@0xE0 seed@0x160 msg/p3_window@0x180` (Is
  differs slightly: see the file header).
- Bus window: 31,744 B of the 32 KiB DMEM are host-visible (the top 1,024 B are ACC-only scratch),
  so `MSG_offset + window_bytes <= 31744`. Is: 0x100 + 30 KiB = 30,976. Ip: the fixed 13/31 row
  split needs at most 22,368 B padded, 0x180 + 22,368 = 22,752.
- `oil` is an input of every UPDATE, not context: write it again before each UPDATE, shifted so that
  element 0 is `o[row_start]`. Forgetting this gives a silently wrong accumulator.
- The bngfonly, bnaesonly and sw arms carry data above the window. They therefore check the UPDATE
  geometry (`caprows`) and the INIT message length (reject -2), and they refuse FINAL or UPDATE
  before a completed INIT (reject -3): the loader's zeroed `.data` would otherwise compare
  acc 0 with target 0 and accept. The bngfaes arms have nothing above the window and keep the
  contract without these checks.

## Files
| file | role |
|---|---|
| `ov-Ip-pkc/ov-Ip-pkc_verify_stream_gfhw.s` | GF(256), v=68 o=44. bngfaes arm: `bn.aes128` and `bn.gfmul.8`, linking `../../shared/verify/ov-Ip-pkc/AES_bngfaes/{aes128_352,load_p3}`; fixed split into 2 windows at row 13. bngfonly arm (`-DGF_INSTRUCTIONS` alone): INIT with computed AES from `AES_bngf/{KeySchedule,aes128_352}` and a 352 B round-key scratch above the bus window; UPDATE and FINAL identical |
| `ov-Is-pkc/ov-Is-pkc_verify_stream_gfhw.s` | GF(16), v=96 o=64. bngfaes arm self-contained (AES-CTR inline with `bn.aes128.kf`); bngfonly arm uses `AES_bngf/{KeySchedule,aes128}` with the round keys in WDRs. Greedy row-aligned windows filled to the maximum |
| `ov-Ip-pkc/ov-Ip-pkc_verify_stream_gfsw.s` | the sw and bnaesonly tiers from one source, GF in software (`gf256_mul`, `bn.mulv`; PQC mode is still required). One fold reads the keystream from 11 WDRs; only how they are filled differs. sw: the T-table AES writes the 352 B buffer and 11 `bn.lid` load it. bnaesonly (`-DAES_INSTRUCTIONS`): `aes128hw_352reg` leaves the blocks in the registers, and the T-table, its key schedule and the 192 B round-key frame drop out. Window 22,368 B |
| `../../shared/verify/ov-Ip-pkc/aes128hw_352reg.s` | the leaf the bnaesonly arm links: returns 11 double blocks in `w7 w8 w9 w10 w13 w14 w15 w18 w19 w20 w30`, no stores |
| `ov-Is-pkc/ov-Is-pkc_verify_stream_gfsw.s` | the Is sw and bnaesonly tiers: software `gf16_mul` with T-table or hardware AES. Window capped at 22,496 B so that `winend` clears the T-table; exports `msgwin` and `winend` |
| `BUILD` | per parameter set: the bngfaes binary (both `-D` flags), `_bngfonly` (`-DGF_INSTRUCTIONS` only) from the same source, `_sw` and `_bnaesonly` (`-DAES_INSTRUCTIONS` only) from the software-GF source |
| `tests/` | the per-phase cycle driver and the functional tests against the Python public map |
