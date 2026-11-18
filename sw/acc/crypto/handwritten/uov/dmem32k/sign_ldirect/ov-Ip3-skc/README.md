# sign_ldirect/ov-Ip3-skc: Ip3 signing in 32 KiB of DMEM

Last updated: 2026-11-17: chip tables from the rerun rtl-2026-11b; the chip tests copy their data faster.

## TL;DR
- The L-direct sign of `../` for the Round-3 parameter set Ip3 (v=74, o=45; a 135-byte
  signature in a 160-byte slot), at four tiers. One EXECUTE signs one message.
- Cycles, speed-ups and memory: [Numbers](#numbers).
- Fixed on 2026-10-19: earlier versions of the solver searched only the rows up to 31 for the pivot of rows 1 to
  30, so some solvable systems were taken as unsolvable and signing retried.

## How to run
From the repository root, at the 32 KiB DMEM profile:
```
# One parameter set and one tier: Ip3 at bngfaes.
# Tiers: bngfaes, bngfonly, bnaesonly, sw.
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip3-skc:ov-Ip3-sign_ldirect_testvec_bngfaes
python3 tools/gather_kat_stats.py --ops sign --params Ip3 --tiers bngfaes --variants ldirect --cases 0,11
```
For another tier, change it in the build label and in `--tiers`. It prints PASS and the cycles.

Every tier at once, and the gate script:
```bash
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip3-skc:ov-Ip3-sign_ldirect_testvec_{bngfaes,bngfonly,bnaesonly,sw}
python3 tools/gather_kat_stats.py --ops sign --params Ip3 --cases 0,11 --tiers bngfaes,bngfonly,bnaesonly,sw
tools/stream_uniform_gates.sh sign Ip3
```
- `gather_kat_stats.py` takes the parameter sets by name (`Ip3` here). It runs the prebuilt
  `ov-Ip3-sign_ldirect_testvec_*` ELFs: build first.
- The driver is `own_utils/run_test.py sign --param Ip3`, with the options of Ip and Is
  (`sw/acc/crypto/handwritten/own_utils/README.md`).
- A PASS of the `gather_kat_stats.py` line (the driver with `--test-data-file`, testvec build) means each
  selected case's signature is byte-identical to the fixture's, made with the fixture's salt.
  Without `--test-data-file` the driver draws a random seed and message, reads the salt the kernel
  used (the fixed ISS value), recomputes the intermediate values and the signature in Python and
  compares them, then checks the signature with the public map; no fixture signature is involved.
  The separate Round-3 reference check and its limits are in
  [test-data provenance](../../../../test_data/README.md#notes).
- The solver alone, against a reference solver on matrices whose pivots come from every part of the matrix:
  `./bazelisk.sh test //sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip3-skc:solve_45x45_test //sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip3-skc:solve_45x45_sw_test`.
- On the chip model: `acc_uov_sign_ip3_<tier>_test`, which runs the harness of `../../sign_rtl/`
  (`sw/device/tests/acc_uov/README.md`).

## Numbers
Written by `python3 tools/uov.py tables` from the records in `../../../results/`; do not edit.
Every sign number is from the testvec build (salt from DMEM); where the salt comes from and what a
product build needs: [`../sign_ldirect/README.md#salt`](../README.md#salt).

<!-- table:iss:sign/ldirect@32:Ip3 -->
| DMEM | tier | Ip3 |
|---|---|---:|
| 32 KiB | bngfaes | 339,400-341,208 |
| 32 KiB | bngfonly | 8,859,108-8,860,916 |
| 32 KiB | bnaesonly | 2,398,655-2,400,463 |
| 32 KiB | sw | 23,766,364-23,768,172 |

ISS cycles of one signature (a single EXECUTE), 32 KiB DMEM profile; a range is the lowest and the highest of the 12 KAT cases.
Every case passed. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss:sign/ldirect@32:Ip3 -->

<!-- table:iss-speedup:sign/ldirect@32:Ip3 -->
Times faster than sw (sw cycles / tier cycles), ISS

| DMEM | tier | Ip3 |
|---|---|---:|
| 32 KiB | bngfonly | 2.68x |
| 32 KiB | bnaesonly | 9.91x |
| 32 KiB | bngfaes | 70x |

The cycles of the KAT cases added up per row, sw divided by the tier. -: no run of that tier.
ISS, 32 KiB DMEM profile. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-speedup:sign/ldirect@32:Ip3 -->

On the chip model, exec+wait of one test per cell, KAT case 0 (every meter of these tests:
`sw/acc/crypto/handwritten/uov/results/CHIP-MATRIX.md`):

<!-- table:rtl-cycles:sign/ldirect@32:Ip3 -->
| DMEM | tier | Ip3 |
|---|---|---:|
| 32 KiB | bngfaes | 340,471 |
| 32 KiB | bngfonly | 8,860,171 |
| 32 KiB | bnaesonly | 2,399,731 |
| 32 KiB | sw | 23,767,441 |

exec+wait in Ibex cycles. Chip RTL under Verilator, 32 KiB DMEM profile, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-cycles:sign/ldirect@32:Ip3 -->

<!-- table:rtl-speedup:sign/ldirect@32:Ip3 -->
Times faster than sw (sw cycles / tier cycles), chip, exec+wait

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | sign | ldirect | Ip3 | 2.68x | 9.9x | 69.8x |

exec+wait: Ibex cycles over EXECUTE and the wait for the ACC to finish, summed over the phases. -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-speedup:sign/ldirect@32:Ip3 -->

<!-- table:rtl-speedup-op:sign/ldirect@32:Ip3 -->
Times faster than sw (sw cycles / tier cycles), chip, whole operation

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 32 KiB | sign | ldirect | Ip3 | 2.68x | 9.9x | 69.6x |

The whole operation: from the first input write to the last result read, the host's transfers included (for the stream keygens, tuned and stream_uniform, also the host's fold; in the verify full tests this run also installs the key). -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl-speedup-op:sign/ldirect@32:Ip3 -->

<!-- table:mem:sign/ldirect@32:Ip3 -->
| DMEM | tier | Ip3 |
|---|---|---:|
| 32 KiB | bngfaes | 10,876 / 15,744 / 14,304 |
| 32 KiB | bngfonly | 11,904 / 16,224 / 14,304 |
| 32 KiB | bnaesonly | 14,492 / 15,776 / 14,304 |
| 32 KiB | sw | 15,228 / 19,872 / 14,304 |

Bytes of the ELFs the ISS ran at the 32 KiB DMEM profile: code / `_dmem_bss_end` (the end of the linked data and bss) / the stack block
reserved inside it (`stack_end - stack`; a reservation, not a measured peak).
Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:mem:sign/ldirect@32:Ip3 -->

## Files
| file | role |
|---|---|
| `ov-Ip3-skc-sign.s` | the sign body (`in: x10 sig, x11 csk, x12 msg, x13 msglen`); each attempt builds L with `gf256_ldirect_74_45`, a retry streams P again |
| `gf256_ldirect_74_45.s`, `gaussian_elimination_45x45.s`, `back_substitution_45x45.s`, `gf256mat_prod_74_45.s`, `row_mul_O.s` | the kernels of one attempt |
| `../../../shared/sign/ov-Ip3-skc/expand_360.s`, `expand_360_table.s` | the AES-CTR P stream in 360 B batches (hardware AES, T-table) |
| `expandv.s`, `hash_salted_msg.s`, `gf256_transpose_45_45.s` | vinegar KMAC, target hash, transpose |
| `*_test.s`, `ldirect_kat_test.s`, `run_ldirect_kats.py` | unit and kernel-KAT harnesses and their runner; `ldirect_test_inputs.s` is generated by `gen_ldirect_test_inputs.py` |
| `../../../../own_utils/run_test.py sign --param Ip3` | the sign KAT and cycle driver |
