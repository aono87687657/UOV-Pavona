# keygen_full: UOV key generation with everything resident (512 KiB DMEM, reference)

Last updated: 2026-11-02: every table from the rerun iss-2026-10j; Ip3 added; the Ip and Is numbers are unchanged.

## TL;DR
- One EXECUTE computes the whole key pair with `B = P1·O + P2` held in DMEM. A reference, not the
  shipping path: it needs the 512 KiB DMEM profile, which we ran on the ISS only, and at this
  profile only the bngfaes tier is tested and documented.
- It is the `full` keygen of the KAT tools and the origin of the phase kernels the smaller
  keygen families reuse. The shipping keygen is `../../dmem32k/keygen_stream/`; the smallest
  one-EXECUTE keygen is `../keygen_min/`.
- Cycles and memory: [Numbers](#numbers).

## How to run
In a clone of its own (the profile switch rewrites 17 generated files under `hw/`, never committed),
from its root:
```
python3 tools/uov.py profile --profile 512
# One parameter set and one tier: Ip at bngfaes.
# Parameter sets: Ip, Is, Ip3. Tiers built: bngfaes, bngfonly, sw (Ip3: bngfaes); only bngfaes is checked at 512 KiB.
./bazelisk.sh build "//sw/acc/crypto/handwritten/uov/dmem_large/keygen_full/ov-Ip-pkc+skc:ov-Ip-keygen_full_bngfaes"
python3 tools/gather_kat_stats.py --ops keygen --params Ip --tiers bngfaes --variants full --cases 0
```
For another choice, change the parameter set (twice in the build label, once in `--params`) and the
tier (in the label and in `--tiers`). It prints PASS and the cycles.

All three sets at once, after the profile line:
```
./bazelisk.sh build "//sw/acc/crypto/handwritten/uov/dmem_large/keygen_full/ov-Ip-pkc+skc:ov-Ip-keygen_full_bngfaes" \
    "//sw/acc/crypto/handwritten/uov/dmem_large/keygen_full/ov-Is-pkc+skc:ov-Is-keygen_full_bngfaes" \
    "//sw/acc/crypto/handwritten/uov/dmem_large/keygen_full/ov-Ip3-pkc+skc:ov-Ip3-keygen_full_bngfaes"
python3 tools/gather_kat_stats.py --ops keygen --params Ip,Is,Ip3 --cases 0 --tiers bngfaes --variants full
```
- `profile --profile 512` switches that clone to the 512 KiB profile: ISS only, no chip test runs at 512 KiB.
- `gather_kat_stats.py` runs the built ELFs on the ISS and prints PASS and the cycles. Case 0 is a
  quick check (the message length never enters keygen); `0-11` runs every recorded key.

One cell through the driver, with the statistics file in `/tmp/kg`, and then back to the committed
32 KiB profile:
```
mkdir -p /tmp/kg
python3 sw/acc/crypto/handwritten/own_utils/run_test.py keygen --param Ip \
  --tier bngfaes --cases 0 --output-dir /tmp/kg \
  --elf bazel-bin/sw/acc/crypto/handwritten/uov/dmem_large/keygen_full/ov-Ip-pkc+skc/ov-Ip-keygen_full_bngfaes.elf
python3 tools/uov.py profile --profile 32
```
The numbers below were recorded through `tools/uov.py` (`tools/README.md`).

## What it does
`sk_seed -> expandsk -> P1O_P2 -> P3_cal -> cpk_pack -> cpk`, with `csk = sk_seed` left in place.
Each parameter package holds the orchestrator, the four phase kernels and both software AES
backends.

## Numbers
Written by `python3 tools/uov.py tables` from the records in `../../results/`; do not edit.

<!-- table:iss:keygen/full@512 -->
| DMEM | tier | Ip | Is | Ip3 |
|---|---|---:|---:|---:|
| 512 KiB | bngfaes | 1,574,091 | 1,733,439 | 1,929,762 |

ISS cycles of one key generation (a single EXECUTE), 512 KiB DMEM profile (ISS only: no chip test runs at this profile); the same in all 12 KAT cases.
Every case passed. Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss:keygen/full@512 -->

<!-- table:mem:keygen/full@512 -->
| DMEM | tier | Ip | Is | Ip3 |
|---|---|---:|---:|---:|
| 512 KiB | bngfaes | 4,116 / 429,696 / 386,080 | 3,136 / 464,032 / 397,408 | 5,444 / 460,000 / 413,376 |

Bytes of the ELFs the ISS ran at the 512 KiB DMEM profile (ISS only: no chip test runs at this profile): code / `_dmem_bss_end` (the end of the linked data and bss) / the stack block
reserved inside it (`stack_end - stack`; a reservation, not a measured peak).
Measured 2026-11-01 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:mem:keygen/full@512 -->

## Files
| file | role |
|---|---|
| `ov-Ip-pkc+skc/`, `ov-Is-pkc+skc/` | one parameter set each: orchestrator, four phase kernels, both AES backends, the ISS harness and a harness with the seed built in (see each README) |
| `ov-Ip3-pkc+skc/` | the Ip3 set, both extensions only: orchestrator, P1O_P2, P3_cal, cpk_pack and the ISS harness (see its README) |
| `../../../own_utils/run_test.py keygen` | the KAT driver (`own_utils/ov_keygen_test_utils.py:keygen_main`; `--param`, `--tier`, `--cases`, `--elf`, `--output-dir`) |

## Notes
- The libraries here are used beyond this directory: `expandsk_ret_O_pkseed` and the AES backends
  are linked by `../../dmem32k/keygen_stream`, `../keygen_min`, `../keygen_sp` and
  `../../dmem32k/keygen_stream_uniform`. The 32 KiB stream kernels also carry copies of
  `expand_batch` and `phase4_row_setup` (`P1O_P2.s`) and of the O-alignment block (`P3_cal.s`,
  phase 1). An edit to any of these means running the KAT of those families again.
- No RTL run at 512 KiB: the `ov-*-keygen_rtl_test*` targets are the same kernels with the seed of KAT
  case 0 built in, run on the ISS only (the name is historical).
