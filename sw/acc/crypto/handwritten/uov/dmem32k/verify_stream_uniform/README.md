# verify_stream_uniform: streamed verification with a swappable backend

Last updated: 2026-11-17: chip tables from the rerun rtl-2026-11b; the chip tests copy their data faster.

## TL;DR
- A measurement rig, not a shipping kernel: one outer kernel per parameter set, four backends
  (bngfaes, bngfonly, bnaesonly, sw) swapped behind `backend_verify_*` by a Bazel dependency.
- It answers "what do the AES and GF instructions buy": everything except the AES and GF work is
  identical in every arm, so a cycle ratio between two arms is the whole-kernel effect of changing
  the backend with the outer held fixed. Every arm fits the 32 KiB DMEM: the public key is streamed
  in windows, not held.
- Cycles, speed-ups and memory: [Numbers](#numbers). The shipping verify is `../verify_stream/`.
- Ip and Is live in `ov-Ip-pkc/` and `ov-Is-pkc/`; Ip3 has its own README in `ov-Ip3-pkc/`.

## How to run
From the repository root, at the 32 KiB DMEM profile:

    # One parameter set and one tier: Ip at bngfaes.
    # Parameter sets: Ip, Is, Ip3. Tiers: bngfaes, bngfonly, bnaesonly, sw.
    ./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream_uniform/ov-Ip-pkc:ov-Ip-verify_stream_uniform_bngfaes
    python3 tools/gather_kat_stats.py --ops verify --params Ip --tiers bngfaes --variants stream_uniform --cases 0,11

For another choice, change the parameter set (twice in the build label, once in `--params`) and the
tier (in the label and in `--tiers`). It prints PASS and the cycles.

Every Ip and Is arm at once, and the fairness gates (they build every arm themselves):

    ./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream_uniform/...
    python3 tools/gather_kat_stats.py --ops verify --params Ip --cases 0,11 --tiers sw,bngfonly,bnaesonly,bngfaes --variants stream_uniform
    python3 tools/gather_kat_stats.py --ops verify --params Is --cases 0,11 --tiers sw,bngfonly,bnaesonly,bngfaes --variants stream_uniform
    tools/stream_uniform_gates.sh verify Ip        # fairness gates; builds the arms itself
    tools/stream_uniform_gates.sh verify Is

- The gates are what make a ratio between two arms quotable. They check that the outer's loaded
  sections and their relocation tables are identical in every arm (a JAL can point at another
  symbol with the same placeholder bytes, so the bytes alone are not enough), that the host-visible
  symbols have the same addresses, that each `backend_*` symbol has exactly one provider, and that
  each arm uses only the instructions of its tier. Run them again after any change to the outer or
  the BUILD file.
- On the chip model: `sw/device/tests/acc_uov/README.md`; the tests are
  `acc_uov_verify_stream_uniform_{ip,is}_<tier>_test`.

## What it does
The host protocol of the shipping kernel (INIT, UPDATE per window, FINAL, with the context kept in
DMEM), plus one `init_done` word so that FINAL cannot accept before INIT has run. The outer holds
the phase dispatch, the KMAC feed, the row bounds and the window capacity check, and no backend
instruction; the backend library supplies the P1/P2 expansion and the P3 row fold.

The uniform geometry leaves out the tuning of the shipping bngfaes kernel (its fold is unrolled by
8; this one walks the elements with a WDR cursor), so the Ip bngfaes arm is slower here than in
`../verify_stream/`. Do not mix the ratios of this rig with the absolute cycles of the shipping
kernel; the two kernels against each other, per tier: `../../results/COMPARISONS.md`.

## Numbers
Written by `python3 tools/uov.py tables` from the records in `../../results/`; do not edit.

<!-- table:iss:verify/stream_uniform@32:Ip,Is -->
| DMEM | tier | Ip | Is |
|---|---|---:|---:|
| 32 KiB | bngfaes | 193,960-194,863 | 165,717-166,620 |
| 32 KiB | bngfonly | 7,363,326-7,364,229 | 10,037,683-10,038,586 |
| 32 KiB | bnaesonly | 1,288,803-1,289,706 | 877,675-878,578 |
| 32 KiB | sw | 18,347,346-18,348,249 | 25,998,779-25,999,682 |

ISS cycles of one accepting verification (INIT, the updates and FINAL, summed), 32 KiB DMEM profile; a range is the lowest and the highest of the 12 KAT cases.
Every case passed. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss:verify/stream_uniform@32:Ip,Is -->

<!-- table:iss-speedup:verify/stream_uniform@32:Ip,Is -->
Times faster than sw (sw cycles / tier cycles), ISS

| DMEM | tier | Ip | Is |
|---|---|---:|---:|
| 32 KiB | bngfonly | 2.49x | 2.59x |
| 32 KiB | bnaesonly | 14.2x | 29.6x |
| 32 KiB | bngfaes | 94.5x | 157x |

The cycles of the KAT cases added up per row, sw divided by the tier. -: no run of that tier.
ISS, 32 KiB DMEM profile. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-speedup:verify/stream_uniform@32:Ip,Is -->

<!-- table:iss-ratio:verify/stream_uniform@32/stream@32:Ip,Is -->
stream_uniform / tuned (ISS cycles of stream_uniform divided by those of tuned; above 1.00x, tuned is faster)

| DMEM | op | param | bngfonly | bnaesonly | bngfaes | sw |
|---|---|---|---:|---:|---:|---:|
| 32 KiB | verify | Ip | 1.00x | 1.03x | 1.25x | 1.00x |
| 32 KiB | verify | Is | 1.00x | 1.00x | 1.00x | 1.00x |

The cycles of the KAT cases added up per row. Two decimals: 1.00x is within half a percent, not necessarily equal.
ISS. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-ratio:verify/stream_uniform@32/stream@32:Ip,Is -->

Reading the steps: bngfonly to bngfaes, and sw to bnaesonly, change the AES only. sw to bngfonly
swaps the GF dot engine and also replaces the T-table AES by computed AES, so it is not a
`bn.gfmul`-only figure. The ISS counts `bn.aes128` and `bn.gfmul` as one cycle each.

On the chip model, exec+wait of one test per cell (every meter of these tests:
`sw/acc/crypto/handwritten/uov/results/CHIP-MATRIX.md`):

<!-- table:rtl-cycles:verify/stream_uniform@32:Ip,Is -->
| DMEM | tier | Ip | Is |
|---|---|---:|---:|
| 32 KiB | bngfaes | 197,081 | 169,322 |
| 32 KiB | bngfonly | 7,366,358 | 10,041,231 |
| 32 KiB | bnaesonly | 1,291,934 | 881,192 |
| 32 KiB | sw | 18,350,460 | 26,002,306 |

exec+wait in Ibex cycles. Chip RTL under Verilator, 32 KiB DMEM profile, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-cycles:verify/stream_uniform@32:Ip,Is -->

<!-- table:rtl-speedup:verify/stream_uniform@32:Ip,Is -->
Times faster than sw (sw cycles / tier cycles), chip, exec+wait

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | verify | stream_uniform | Ip | 2.49x | 14.2x | 93.1x |
| 32 KiB | verify | stream_uniform | Is | 2.59x | 29.5x | 154x |

exec+wait: Ibex cycles over EXECUTE and the wait for the ACC to finish, summed over the phases. -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-speedup:verify/stream_uniform@32:Ip,Is -->

<!-- table:rtl-speedup-op:verify/stream_uniform@32:Ip,Is -->
Times faster than sw (sw cycles / tier cycles), chip, whole operation

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | verify | stream_uniform | Ip | 2.48x | 13.6x | 71x |
| 32 KiB | verify | stream_uniform | Is | 2.58x | 26.8x | 100x |

The whole operation: from the first input write to the last result read, the host's transfers included (for the stream keygens, tuned and stream_uniform, also the host's fold; in the verify full tests this run also installs the key). -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-speedup-op:verify/stream_uniform@32:Ip,Is -->

<!-- table:mem:verify/stream_uniform@32:Ip,Is -->
| DMEM | tier | Ip | Is |
|---|---|---:|---:|
| 32 KiB | bngfaes | 1,940 / 22,944 | 940 / 27,136 |
| 32 KiB | bngfonly | 2,548 / 23,520 | 2,004 / 27,264 |
| 32 KiB | bnaesonly | 3,836 / 23,616 | 1,808 / 27,488 |
| 32 KiB | sw | 4,436 / 27,712 | 2,436 / 31,552 |

Bytes of the ELFs the ISS ran at the 32 KiB DMEM profile: code / `_dmem_bss_end` (the end of the linked data and bss).
Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:mem:verify/stream_uniform@32:Ip,Is -->

## Host contract
- Window of Ip: `msgwin` 0x180..0x58e0, sized for the largest window `caprows` admits: 504 entries
  (rs=5/rc=16, rs=10/rc=21), 63 `load_p3` refills, 192 + 63*352 = 22,368 B, ending exactly at
  `winend`. The 13/31 host split reaches only 0x5780, so the reservation cannot be derived from it.
  Window of Is: 0x100..0x6900, cap 26,624 B.
- The kernel only reads the window, so an oversized `row_count` would be an over-read: it would
  fold `caprows` (which sits at `winend`) and backend `.data` into the accumulator and return a
  wrong verdict. That is what the capacity check in UPDATE prevents.
- A host that writes past `winend` corrupts `caprows`; larger values there admit oversized windows
  instead of rejecting them.
- `measure_cycles.py` takes the cap from `winend - msgwin` for Is; for Ip it uses the fixed 13/31
  split. The cap bounds UPDATE only, not the INIT message written at the same base, and since Ip
  fits exactly, a passing Ip run does not test the bound.

## Files
| file | role |
|---|---|
| `ov-<P>-pkc/ov-<P>-verify_stream_uniform.s` | the outer: phase dispatch, KMAC feed, the `init_done` guard at 0x010, row bounds and window capacity, every `ecall` path. No backend instruction |
| `ov-<P>-pkc/ov-<P>-verify_backend.s` | one cpp-guarded source per parameter set with the four arms. Is P3 is pure `gfmul.4`, so both hardware-GF arms share one `p3_rows`. The Ip `bnaesonly` arm shares the body of the sw arm: the GF engine picks the arm, the AES leaf is an inner `#ifdef` |
| `ov-Ip-pkc/aes128hw_352.s` | hardware-AES leaf with the memory ABI of `aes128table_352` (x10 key, x11 = 352 B out, x13 counter in and out, `+22`); the AES leaf of the Ip `bnaesonly` arm (the stream verify links `aes128hw_352reg` instead) |
| `ov-<P>-pkc/BUILD` | per parameter set: 4 ISS binaries, 4 underscore twins for the chip tests and 4 backend libraries. The outer compiles without copts: its object must be byte-identical in every arm |
