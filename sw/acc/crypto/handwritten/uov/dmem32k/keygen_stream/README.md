# keygen_stream: streamed UOV key generation in 32 KiB of DMEM

Last updated: 2026-11-17: chip tables from the rerun rtl-2026-11b; the chip tests copy their data faster.

## TL;DR
- The key generation that fits the 32 KiB DMEM, for Ip and Is at four tiers each. Ip3 is in
  `ov-Ip3-pkc+skc/`.
- The host runs the kernel once for INIT and once per window of P3 columns, then folds and packs the
  public key.
- Cycles and memory: [Numbers](#numbers).

## How to run
From the repository root, at the 32 KiB DMEM profile (the committed one;
`python3 tools/uov.py profile --profile 32` returns to it).
```
# One parameter set and one tier: Ip at bngfaes.
# Parameter sets: Ip, Is, Ip3. Tiers: bngfaes, bngfonly, bnaesonly, sw.
./bazelisk.sh build "//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Ip-pkc+skc:ov-Ip-keygen_stream_bngfaes"
python3 tools/gather_kat_stats.py --ops keygen --params Ip --tiers bngfaes --variants stream --cases 0
```
For another choice, change the parameter set (twice in the build label, once in `--params`) and the
tier (in the label and in `--tiers`). It prints PASS and the cycles.

Ip and Is at several tiers at once (the sw line is slow: see Numbers), and the cycles of each phase:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/...
python3 tools/gather_kat_stats.py --ops keygen --params Ip,Is --cases 0 --tiers bngfaes,bngfonly --variants stream
python3 tools/gather_kat_stats.py --ops keygen --params Ip,Is --cases 0 --tiers sw --variants stream          # slow: see Numbers
# per-phase and total cycles, one ELF
python3 sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/tests/test_stream_keygen.py --param Ip \
  --elf bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Ip-pkc+skc/ov-Ip-keygen_stream_bngfaes.elf \
  --cases 0 --stats
```
- `gather_kat_stats.py --ops keygen --params .. --cases .. --tiers .. --variants ..` runs the KAT on the built ELFs and prints
  PASS and the cycles per cell. It runs prebuilt ELFs: build first, or a stale binary passes at stale
  cycles.
- Case 0 is a quick check: the message length never enters keygen. Each of the 12 Ip and Is KAT cases
  has its own seed and public key, so a full run takes all 12 (the 12 Ip3 ladder cases share one key pair).
- The driver's options are explained in `tests/README.md`.
- On the chip model: `sw/device/tests/acc_uov/README.md`; the tests are
  `acc_uov_keygen_stream_{ip,is}_<tier>_test`.

## What it does
Phase 0 (INIT) derives `pk_seed` and the O context, which stay in DMEM. Phase 1
(WINDOW, with `col_start` and `col_count`) writes one window of P3 columns to `slice`. The host
collects the windows into the full P3, folds the upper triangle (XOR of the j<k entries) and packs
`cpk = pk_seed || P3`.

## Numbers
Written by `python3 tools/uov.py tables` from the records in `../../results/`; do not edit.

<!-- table:iss:keygen/stream@32:Ip,Is -->
| DMEM | tier | Ip | Is |
|---|---|---:|---:|
| 32 KiB | bngfaes | 2,018,084 | 2,356,745 |
| 32 KiB | bngfonly | 34,888,302 | 33,483,143 |
| 32 KiB | bnaesonly | 35,449,206 | 34,682,399 |
| 32 KiB | sw | 139,749,112 | 124,317,759 |

ISS cycles of one key generation (INIT and every window, summed), 32 KiB DMEM profile; the same in all 12 KAT cases.
Every case passed. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss:keygen/stream@32:Ip,Is -->

<!-- table:iss-speedup:keygen/stream@32:Ip,Is -->
Times faster than sw (sw cycles / tier cycles), ISS

| DMEM | tier | Ip | Is |
|---|---|---:|---:|
| 32 KiB | bngfonly | 4.01x | 3.71x |
| 32 KiB | bnaesonly | 3.94x | 3.58x |
| 32 KiB | bngfaes | 69.2x | 52.7x |

The cycles of the KAT cases added up per row, sw divided by the tier. -: no run of that tier.
ISS, 32 KiB DMEM profile. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-speedup:keygen/stream@32:Ip,Is -->

The ISS counts `bn.gfmul` and `bn.aes128` as one cycle each. On the chip model, exec+wait of one test
per cell (every meter of these tests: `sw/acc/crypto/handwritten/uov/results/CHIP-MATRIX.md`):

<!-- table:rtl-cycles:keygen/stream@32:Ip,Is -->
| DMEM | tier | Ip | Is |
|---|---|---:|---:|
| 32 KiB | bngfaes | 2,022,802 | 2,360,831 |
| 32 KiB | bngfonly | 34,892,775 | 33,487,309 |
| 32 KiB | bnaesonly | 35,454,888 | 34,687,166 |
| 32 KiB | sw | 139,755,053 | 124,322,264 |

exec+wait in Ibex cycles. Chip RTL under Verilator, 32 KiB DMEM profile, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-cycles:keygen/stream@32:Ip,Is -->

<!-- table:rtl-speedup:keygen/stream@32:Ip,Is -->
Times faster than sw (sw cycles / tier cycles), chip, exec+wait

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | keygen | tuned | Ip | 4.01x | 3.94x | 69.1x |
| 32 KiB | keygen | tuned | Is | 3.71x | 3.58x | 52.7x |

exec+wait: Ibex cycles over EXECUTE and the wait for the ACC to finish, summed over the phases. -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-speedup:keygen/stream@32:Ip,Is -->

<!-- table:rtl-speedup-op:keygen/stream@32:Ip,Is -->
Times faster than sw (sw cycles / tier cycles), chip, whole operation

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | keygen | tuned | Ip | 3.99x | 3.92x | 62.3x |
| 32 KiB | keygen | tuned | Is | 3.68x | 3.56x | 46.1x |

The whole operation: from the first input write to the last result read, the host's transfers included (for the stream keygens, tuned and stream_uniform, also the host's fold; in the verify full tests this run also installs the key). -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-speedup-op:keygen/stream@32:Ip,Is -->

<!-- table:mem:keygen/stream@32:Ip,Is -->
| DMEM | tier | Ip | Is |
|---|---|---:|---:|
| 32 KiB | bngfaes | 5,912 / 31,744 | 3,192 / 31,744 |
| 32 KiB | bngfonly | 6,632 / 31,744 | 3,984 / 31,744 |
| 32 KiB | bnaesonly | 5,716 / 27,104 | 3,328 / 27,776 |
| 32 KiB | sw | 5,660 / 30,592 | 4,084 / 31,744 |

Bytes of the ELFs the ISS ran at the 32 KiB DMEM profile: code / `_dmem_bss_end` (the end of the linked data and bss).
Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:mem:keygen/stream@32:Ip,Is -->

## Host contract
- A bare `standalone.py` run executes only the one phase `ctrl` selects, not a key generation: use
  the driver.
- Window width WJ: bngfaes and bngfonly Ip 7, Is 12 (even `col_count` only); sw and bnaesonly Ip 5,
  Is 10. The software-GF kernels are separate sources with their own geometry, and bnaesonly keeps
  it although it has no AES table.
- The kernel zeroes `slice` on every call: read a window out before the next call.
- Derive the stride from `slice_end - slice`, never from the tier: a hardcoded stride misreads every
  entry. The chip tests' generators do this.
- DMEM: everything the host reads or writes lies below the 31,744 B bus window; the ACC-only buffers
  (Ip `p2buf` 1,024 B, Is `gbuf23` 768 B) start at 31,744. The drivers refuse a tree at another DMEM
  profile, so the ISS enforces the size.

## Files
| file | role |
|---|---|
| `ov-Ip-pkc+skc/ov-Ip-keygen_stream.s`, `ov-Is-pkc+skc/ov-Is-keygen_stream.s` | kernels of the bngfaes and bngfonly tiers (cpp arms) |
| `ov-Ip-pkc+skc/ov-Ip-keygen_stream_sw.s`, `ov-Is-pkc+skc/ov-Is-keygen_stream_sw.s` | kernels of the sw and bnaesonly tiers (narrower windows) |
| `tests/test_stream_keygen.py` | the Ip and Is driver (`--param`): cpk byte-compared with the KAT, negative controls, geometry read from the ELF symbols |

ELF names: `ov-<P>-keygen_stream_<tier>`, `<tier>` = `bngfaes`, `bngfonly`, `bnaesonly`, `sw`.
