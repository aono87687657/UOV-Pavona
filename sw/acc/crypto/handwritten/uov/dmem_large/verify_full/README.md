# verify_full: UOV verification in one EXECUTE with the public key resident

Last updated: 2026-11-17: chip tables from the rerun rtl-2026-11; the chip tests copy their data faster.

## TL;DR
- One EXECUTE per verification: the host writes the compressed public key once per key, then
  `msg_len`, `msg` and the signature (Ip3 135 B, Ip 128 B, Is 96 B) per verification, starts the ACC
  once and reads a result word. No control block, no P3 windows, no oil transfer (the kernel takes the oil vector
  from the signature).
- Ip and Is (Round 2) here, Ip3 (Round 3) in `ov-Ip3-pkc/`, four tiers each, each with
  its own driver and chip tests. All need more than the 32 KiB DMEM and run at the 128 KiB profile; the
  32 KiB shipping paths are `../../dmem32k/verify_stream/` (Ip, Is) and
  `../../dmem32k/verify_stream/ov-Ip3-pkc/` (Ip3), whose phase bodies these kernels reuse under a one-shot
  shell.
- Cycles and memory: [Numbers](#numbers).

## How to run
In a clone of its own, from its root, at the 128 KiB profile (`python3 tools/uov.py profile
--profile 128`, never committed; back: `--profile 32`):
```
python3 tools/uov.py profile --profile 128
# One parameter set and one tier: Ip at bngfaes.
# Parameter sets: Ip, Is, Ip3. Tiers: bngfaes, bngfonly, bnaesonly, sw.
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem_large/verify_full/ov-Ip-pkc:ov-Ip-verify_full_bngfaes
python3 tools/gather_kat_stats.py --ops verify --params Ip --tiers bngfaes --variants full --cases 0,11
```
For another choice, change the parameter set (twice in the build label, once in `--params`) and the
tier (in the label and in `--tiers`). It prints PASS and the cycles.

Every arm, and the Ip3 driver with its checks, after the profile line:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem_large/verify_full/... \
  //sw/acc/crypto/handwritten/uov/dmem_large/verify_full/ov-Ip3-pkc:all
python3 sw/acc/crypto/handwritten/uov/dmem_large/verify_full/tests/test_full_verify.py --param Ip3 \
  --elf bazel-bin/sw/acc/crypto/handwritten/uov/dmem_large/verify_full/ov-Ip3-pkc/ov-Ip3-verify_full_bngfaes.elf \
  --cases 0,11 --tier bngfaes --poison --stats \
  --vectors2 sw/acc/crypto/handwritten/test_data/testvectors-Ip3-pkc-skc.nistkat
```
- `--elf`: the built app to run; the other arms are
  `ov-Ip3-verify_full_{bngfonly,bnaesonly,sw}.elf`.
- `--cases 0,11`: KAT cases (`0`, `0,11` or `0-11`; default `0,11`, message lengths 0 and 1,024).
- `--tier bngfaes`: refuse unless the ELF's symbol fingerprint is that tier.
- `--poison`: before every run after the first, fill the kernel's scratch with 0xA5 and the cpk
  padding with valid non-zero bytes.
- `--stats`: print instructions and cycles next to the timed accepting runs; `--dump-stats FILE`
  writes the ISS statistics of every run.
- `--vectors FILE` (default `test_data/testvectors-Ip3-pkc-skc`, which signs all twelve cases under
  one key pair) and `--vectors2 FILE` (default `test_data/testvectors-Ip3-pkc-skc.nistkat`; its case 0
  is the second key pair for the cross-key checks).
- `--part I/N`: run every N-th check sequence from the I-th, after the accept; the N parts together
  run every sequence once (splits the slow sw and bngfonly proofs). `--help` lists every option.
- A PASS covers the selected cases and the checks that ran. All check sequences run unless
  `--part I/N` is given; then only that part's sequences run, and all N parts are needed to cover the
  full list. The poisoned-scratch check runs only with `--poison`. `tools/gather_kat_stats.py` passes neither
  option. The separate Ip3 and Is Round-3 reference checks and their limits are in
  [test-data provenance](../../../test_data/README.md#notes); Ip uses the Round-2 parameter set.
- Ip and Is: the same driver with `--param Ip` and `ov-Ip-verify_full_{bngfaes,bngfonly,bnaesonly,sw}.elf`,
  `--param Is` and `ov-Is-verify_full_*.elf` (in `ov-Ip-pkc/` and `ov-Is-pkc/`). Their second key is the next KAT
  case's (each case has its own key pair), so they need no `--vectors2`.
- Chip model: the tests `acc_uov_verify_full_{ip3,ip,is}_<tier>_test`; `tools/rtl_campaign.sh
  --profile 128` runs them with the one-shot keygen tests (`--cells` selects some).

## What it does
The driver's proof: accept; signature bytes corrupted across vinegar, oil and salt and at their
boundaries; length errors; repeated runs; poisoned scratch; a corrupted key; and a second key from
another recording, both ways, then the first key restored. Each sequence ends with an accept on the
same image, and every result other than a length error must equal the Python public map's verdict.
The chip test runs case 11 three times (accept, reject, and accept with the key resident after the
first run), then the negative checks and case 0.

## Numbers
Written by `python3 tools/uov.py tables` from the records in `../../results/`; do not edit.

<!-- table:iss:verify/full@128 -->
| DMEM | tier | Ip | Is | Ip3 |
|---|---|---:|---:|---:|
| 128 KiB | bngfaes | 154,871-155,774 | 165,544-166,447 | 194,908-195,811 |
| 128 KiB | bngfonly | 7,357,790-7,358,693 | 10,037,509-10,038,412 | 8,073,818-8,074,721 |
| 128 KiB | bnaesonly | 1,247,297-1,248,200 | 877,465-878,368 | 1,467,969-1,468,872 |
| 128 KiB | sw | 18,331,892-18,332,795 | 25,998,569-25,999,472 | 22,752,740-22,753,643 |

ISS cycles of one accepting verification with the key already installed, 128 KiB DMEM profile; a range is the lowest and the highest of the 12 KAT cases.
Every case passed. Measured 2026-11-01 to 2026-11-02 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss:verify/full@128 -->

<!-- table:iss-speedup:verify/full@128 -->
Times faster than sw (sw cycles / tier cycles), ISS

| DMEM | tier | Ip | Is | Ip3 |
|---|---|---:|---:|---:|
| 128 KiB | bngfonly | 2.49x | 2.59x | 2.82x |
| 128 KiB | bnaesonly | 14.7x | 29.6x | 15.5x |
| 128 KiB | bngfaes | 118x | 157x | 117x |

The cycles of the KAT cases added up per row, sw divided by the tier. -: no run of that tier.
ISS, 128 KiB DMEM profile. Measured 2026-11-01 to 2026-11-02 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-speedup:verify/full@128 -->

For Ip3, verification with a new key also pays the transfer of the key (46,591 bytes, sent as the
46,816-byte padded `cpk`). On the chip model, the three timed runs of each test:

<!-- table:rtl-runs:verify/full@128 -->
| DMEM | param | tier | accept | reject_resident | accept_resident |
|---|---|---|---:|---:|---:|
| 128 KiB | Ip | bngfaes | 156,362 | 156,305 | 156,305 |
| 128 KiB | Ip | bngfonly | 7,359,272 | 7,359,215 | 7,359,215 |
| 128 KiB | Ip | bnaesonly | 1,248,769 | 1,248,712 | 1,248,712 |
| 128 KiB | Ip | sw | 18,333,377 | 18,333,320 | 18,333,320 |
| 128 KiB | Is | bngfaes | 166,990 | 167,004 | 166,999 |
| 128 KiB | Is | bngfonly | 10,038,958 | 10,038,972 | 10,038,967 |
| 128 KiB | Is | bnaesonly | 878,929 | 878,942 | 878,943 |
| 128 KiB | Is | sw | 26,000,051 | 26,000,049 | 26,000,049 |
| 128 KiB | Ip3 | bngfaes | 196,359 | 196,369 | 196,369 |
| 128 KiB | Ip3 | bngfonly | 8,075,279 | 8,075,289 | 8,075,289 |
| 128 KiB | Ip3 | bnaesonly | 1,469,449 | 1,469,389 | 1,469,389 |
| 128 KiB | Ip3 | sw | 22,754,209 | 22,754,219 | 22,754,219 |

exec+wait in Ibex cycles of every timed run of each test; - where a test does not make that run.
Chip RTL under Verilator, 128 KiB DMEM profile, one loaded image per test. Measured 2026-11-15 to 2026-11-17 at `de52799642` (rtl-2026-11).
<!-- /table:rtl-runs:verify/full@128 -->

<!-- table:rtl-speedup:verify/full@128 -->
Times faster than sw (sw cycles / tier cycles), chip, exec+wait

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 128 KiB | verify | full | Ip | 2.49x | 14.7x | 117x |
| 128 KiB | verify | full | Is | 2.59x | 29.6x | 156x |
| 128 KiB | verify | full | Ip3 | 2.82x | 15.5x | 116x |

exec+wait: Ibex cycles over EXECUTE and the wait for the ACC to finish, summed over the phases. -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-15 to 2026-11-17 at `de52799642` (rtl-2026-11).
<!-- /table:rtl-speedup:verify/full@128 -->

<!-- table:rtl-speedup-op:verify/full@128 -->
Times faster than sw (sw cycles / tier cycles), chip, whole operation

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 128 KiB | verify | full | Ip | 2.48x | 14.1x | 85.2x |
| 128 KiB | verify | full | Is | 2.58x | 26.9x | 102x |
| 128 KiB | verify | full | Ip3 | 2.8x | 14.9x | 87.8x |

The whole operation: from the first input write to the last result read, the host's transfers included (for the stream keygens, tuned and stream_uniform, also the host's fold; in the verify full tests this run also installs the key). -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-15 to 2026-11-17 at `de52799642` (rtl-2026-11).
<!-- /table:rtl-speedup-op:verify/full@128 -->

<!-- table:mem:verify/full@128 -->
| DMEM | tier | Ip | Is | Ip3 |
|---|---|---:|---:|---:|
| 128 KiB | bngfaes | 3,896 / 45,248 | 844 / 67,872 | 11,172 / 48,256 |
| 128 KiB | bngfonly | 2,708 / 45,792 | 1,904 / 68,000 | 12,016 / 49,152 |
| 128 KiB | bnaesonly | 3,400 / 45,696 | 1,668 / 68,192 | 6,648 / 48,736 |
| 128 KiB | sw | 4,172 / 49,984 | 2,296 / 72,256 | 7,196 / 53,024 |

Bytes of the ELFs the ISS ran at the 128 KiB DMEM profile: code / `_dmem_bss_end` (the end of the linked data and bss).
Measured 2026-11-01 to 2026-11-02 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:mem:verify/full@128 -->

The 1 KiB scratch is separate from the DMEM end. The hardware-GF arms use no stack; the
software-GF arms have a private stack in the image (`sfk_stack`).

## Host contract
Ip3's symbols (Ip and Is have the same symbols; their offsets and sizes follow the table):

| symbol | bytes | written by | notes |
|---|---:|---|---|
| `hdr` | 32 | host `+4 msg_len`; kernel `+12 result` | result: 0 accept, -1 reject, -2 `msg_len` > 1,024, -5 while running |
| `sig` | 160 | host | the 135-byte signature and a zero tail (the salt read spans bytes 96..159) |
| `msg` | 1,024 | host | 32-byte granules, zero tail |
| `cpk` | 46,816 | host, once per key | 46,591 bytes of key and 225 bytes of readable padding (the P3 loader reads 65 B past the key in the hardware arms, 225 B in the software arms) |
| `target`, `accctx`, `oil`, `seed` | 64/64/64/32 | kernel | internal; poisoned by the driver before repeated runs |

Ip3 layout: hdr 0, accctx 0x20, oil 0x60, target 0xA0, sig 0xE0, seed 0x180, msg 0x1A0, cpk 0x5A0;
the tier's data after cpk. Ip: sig 128 B at 0xE0, seed 0x160, msg 0x180, cpk 0x580 (43,576 B and 264 B
of padding). Is: oil 0x40, target 0x60, sig 96 B at 0x80, seed 0xE0, msg 0x100, cpk 0x510 (66,576 B, no
padding). The drivers check each ELF's symbols against these maps before the first run. The kernels
keep the absolute low map of the streamed bodies, so `hdr` must stay at 0. The P3 pass runs all rows
in one go: Ip3 45 (129 loader refills in the hardware arms, 130 batches in the software arms), Ip 44,
Is 64.

## Files
| file | role |
|---|---|
| `ov-Ip-pkc/ov-Ip-pkc_verify_full.s`, `ov-Is-pkc/ov-Is-pkc_verify_full.s` | Ip and Is, hardware-GF arms (bngfaes, bngfonly) |
| `ov-Ip-pkc/ov-Ip-pkc_verify_full_sw.s`, `ov-Is-pkc/ov-Is-pkc_verify_full_sw.s` | Ip and Is, software-GF arms (sw, bnaesonly) |
| `ov-Ip3-pkc/ov-Ip3-pkc_verify_full.s` | Ip3 hardware-GF arms: bngfaes (`-DAES_INSTRUCTIONS -DGF_INSTRUCTIONS`) and bngfonly (`-DGF_INSTRUCTIONS`) |
| `ov-Ip3-pkc/ov-Ip3-pkc_verify_full_sw.s` | Ip3 software-GF arms: sw (no flags, T-table AES) and bnaesonly (`-DAES_INSTRUCTIONS`, `aes128hw_384`) |
| `ov-Ip3-pkc/aes128_360_bngf_full.s` | the streamed computed-AES leaf with its staging buffer taken from the kernel's `blkbuf` label instead of a fixed address |
| `tests/test_full_verify.py` | the proof driver of Ip, Is and Ip3 (`--param`) |
