# keygen_stream_uniform: streamed keygen with a swappable backend

Last updated: 2026-11-17: chip tables from the rerun rtl-2026-11b; the chip tests copy their data faster.

## TL;DR
- A measurement rig, not a shipping kernel: one outer kernel per parameter set, four backends
  (bngfaes, bngfonly, bnaesonly, sw) swapped behind `backend_*` by a Bazel dependency.
- It answers "what do the AES and GF instructions buy": the outer is identical in every arm, so a
  cycle ratio between two arms is the whole-kernel effect of changing the backend with the outer
  held fixed.
- Cycles, speed-ups and memory: [Numbers](#numbers). The shipping keygen is `../keygen_stream/`.
- Ip and Is live in `ov-Ip-pkc+skc/` and `ov-Is-pkc+skc/`; Ip3 has its own README in `ov-Ip3-pkc+skc/`.

## How to run
From the repository root, at the 32 KiB DMEM profile:
```
# One parameter set and one tier: Ip at bngfaes.
# Parameter sets: Ip, Is, Ip3. Tiers: bngfaes, bngfonly, bnaesonly, sw.
./bazelisk.sh build "//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream_uniform/ov-Ip-pkc+skc:ov-Ip-keygen_stream_uniform_bngfaes"
python3 tools/gather_kat_stats.py --ops keygen --params Ip --tiers bngfaes --variants stream_uniform --cases 0
```
For another choice, change the parameter set (twice in the build label, once in `--params`) and the
tier (in the label and in `--tiers`). It prints PASS and the cycles.

Every Ip and Is arm at once, and the fairness gates (they build every arm themselves):
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream_uniform/...
python3 tools/gather_kat_stats.py --ops keygen --params Ip,Is --cases 0 --tiers bngfaes,bngfonly,bnaesonly,sw --variants stream_uniform
tools/stream_uniform_gates.sh keygen Ip
tools/stream_uniform_gates.sh keygen Is
```
Cycles for one arm (the stream driver sums all phases and compares the cpk with the KAT; a bare
`standalone.py` run executes one phase, not a keygen):
```
python3 sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/tests/test_stream_keygen.py --param Ip \
  --elf bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream_uniform/ov-Ip-pkc+skc/ov-Ip-keygen_stream_uniform_bngfaes.elf \
  --cases 0 --stats --dump-stats /tmp/kg_fk.txt
```
- The driver's options: `../keygen_stream/tests/README.md`.
- `stream_uniform_gates.sh` builds the arms itself and checks what makes a ratio quotable: the outer
  object is the same in every arm (loaded sections byte for byte, and their relocation tables), the
  host-visible symbols have the same addresses, each `backend_*` symbol has one provider, each arm
  uses only the instructions of its tier, and `check_loop` passes. Run it again after any change to
  the outer or the BUILD file.
- On the chip model: `sw/device/tests/acc_uov/README.md`; the tests are
  `acc_uov_keygen_stream_uniform_{ip,is}_<tier>_test`.

## What it does
The same host protocol as `../keygen_stream/` (INIT, then one WINDOW call per window), with the
geometry of the sw arm fixed for every arm: WJ 5 for Ip and 10 for Is. The outer contains no
`bn.gfmul` and no `bn.aes128`; the backend library supplies the AES stream and the dot products.

Because the geometry is the sw arm's, the hardware arms run more windows than the tuned kernel
(Ip 9 instead of 7, Is 7 instead of 6), and each window streams all of P1 from AES again. So the
absolute cycles here are higher than in `../keygen_stream/`, and the ratios hold for this fixed
geometry (WJ 5 and 10). The two kernels against each other, per tier:
`../../results/COMPARISONS.md`.

## Numbers
Written by `python3 tools/uov.py tables` from the records in `../../results/`; do not edit.

<!-- table:iss:keygen/stream_uniform@32:Ip,Is -->
| DMEM | tier | Ip | Is |
|---|---|---:|---:|
| 32 KiB | bngfaes | 2,424,823 | 2,648,528 |
| 32 KiB | bngfonly | 43,856,494 | 38,024,332 |
| 32 KiB | bnaesonly | 35,768,933 | 35,167,152 |
| 32 KiB | sw | 140,068,839 | 124,802,512 |

ISS cycles of one key generation (INIT and every window, summed), 32 KiB DMEM profile; the same in all 12 KAT cases.
Every case passed. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss:keygen/stream_uniform@32:Ip,Is -->

<!-- table:iss-speedup:keygen/stream_uniform@32:Ip,Is -->
Times faster than sw (sw cycles / tier cycles), ISS

| DMEM | tier | Ip | Is |
|---|---|---:|---:|
| 32 KiB | bngfonly | 3.19x | 3.28x |
| 32 KiB | bnaesonly | 3.92x | 3.55x |
| 32 KiB | bngfaes | 57.8x | 47.1x |

The cycles of the KAT cases added up per row, sw divided by the tier. -: no run of that tier.
ISS, 32 KiB DMEM profile. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-speedup:keygen/stream_uniform@32:Ip,Is -->

<!-- table:iss-ratio:keygen/stream_uniform@32/stream@32:Ip,Is -->
stream_uniform / tuned (ISS cycles of stream_uniform divided by those of tuned; above 1.00x, tuned is faster)

| DMEM | op | param | bngfonly | bnaesonly | bngfaes | sw |
|---|---|---|---:|---:|---:|---:|
| 32 KiB | keygen | Ip | 1.26x | 1.01x | 1.20x | 1.00x |
| 32 KiB | keygen | Is | 1.14x | 1.01x | 1.12x | 1.00x |

The cycles of the KAT cases added up per row. Two decimals: 1.00x is within half a percent, not necessarily equal.
ISS. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-ratio:keygen/stream_uniform@32/stream@32:Ip,Is -->

Reading the steps: bngfonly to bngfaes changes the AES only (the GF engine is the same). sw to
bngfonly swaps the dot engine and also replaces the T-table AES by AES computed with `bn.gfmul`, so
it is the whole software backend, not a `bn.gfmul`-only figure. The ISS counts `bn.gfmul` and
`bn.aes128` as one cycle each.

On the chip model, exec+wait of one test per cell (every meter of these tests:
`sw/acc/crypto/handwritten/uov/results/CHIP-MATRIX.md`):

<!-- table:rtl-cycles:keygen/stream_uniform@32:Ip,Is -->
| DMEM | tier | Ip | Is |
|---|---|---:|---:|
| 32 KiB | bngfaes | 2,430,617 | 2,652,963 |
| 32 KiB | bngfonly | 43,862,338 | 38,028,908 |
| 32 KiB | bnaesonly | 35,774,760 | 35,171,911 |
| 32 KiB | sw | 140,074,450 | 124,807,009 |

exec+wait in Ibex cycles. Chip RTL under Verilator, 32 KiB DMEM profile, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-cycles:keygen/stream_uniform@32:Ip,Is -->

<!-- table:rtl-speedup:keygen/stream_uniform@32:Ip,Is -->
Times faster than sw (sw cycles / tier cycles), chip, exec+wait

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | keygen | stream_uniform | Ip | 3.19x | 3.92x | 57.6x |
| 32 KiB | keygen | stream_uniform | Is | 3.28x | 3.55x | 47x |

exec+wait: Ibex cycles over EXECUTE and the wait for the ACC to finish, summed over the phases. -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-speedup:keygen/stream_uniform@32:Ip,Is -->

<!-- table:rtl-speedup-op:keygen/stream_uniform@32:Ip,Is -->
Times faster than sw (sw cycles / tier cycles), chip, whole operation

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | keygen | stream_uniform | Ip | 3.18x | 3.9x | 52.8x |
| 32 KiB | keygen | stream_uniform | Is | 3.26x | 3.52x | 41.7x |

The whole operation: from the first input write to the last result read, the host's transfers included (for the stream keygens, tuned and stream_uniform, also the host's fold; in the verify full tests this run also installs the key). -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-speedup-op:keygen/stream_uniform@32:Ip,Is -->

<!-- table:mem:keygen/stream_uniform@32:Ip,Is -->
| DMEM | tier | Ip | Is |
|---|---|---:|---:|
| 32 KiB | bngfaes | 3,340 / 25,920 | 1,616 / 27,392 |
| 32 KiB | bngfonly | 4,076 / 26,432 | 2,756 / 27,552 |
| 32 KiB | bnaesonly | 5,896 / 27,136 | 2,528 / 27,488 |
| 32 KiB | sw | 5,840 / 30,624 | 3,284 / 31,456 |

Bytes of the ELFs the ISS ran at the 32 KiB DMEM profile: code / `_dmem_bss_end` (the end of the linked data and bss).
Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:mem:keygen/stream_uniform@32:Ip,Is -->

## Files
| file | role |
|---|---|
| `ov-Ip-pkc+skc/ov-Ip-keygen_stream_uniform.s`, `ov-Is-pkc+skc/ov-Is-keygen_stream_uniform.s` | the outers, shared by all arms |
| `ov-Ip-pkc+skc/ov-Ip-keygen_backend.s`, `ov-Is-pkc+skc/ov-Is-keygen_backend.s` | one cpp-guarded source each with the four arms |
| `BUILD` | per parameter set: 4 backend libraries, 4 ISS binaries and 4 underscore twins for the chip tests; the outer compiles without copts, and the backend library stays first in `deps` |

## Notes
- Every arm links inside the 32 KiB DMEM. In the Is sw arm, which alone carries the 4 KiB AES
  T-table, the outer's `gbuf23` and `frame` and the backend's `rkbuf`, `ivb` and `swframe` sit in
  the 1 KiB ACC-only scratch above the bus window, as absolute `.set` addresses: they are used only
  at run time and never read by the host.
- Only the chip tests in `sw/device/tests/acc_uov` link the underscore twins. A change to a `.s`
  file here means rebuilding and measuring those again.
