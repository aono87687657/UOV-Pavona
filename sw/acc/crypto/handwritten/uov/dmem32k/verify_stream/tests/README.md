# verify_stream/tests: the driver of the streamed verification

Last updated: 2026-11-17: `--reject` added.

## TL;DR
The host driver of the phase-dispatch binaries in the parent directory (Ip, Is, Ip3). It loads the ELF
once into the ISS and changes only `ctrl`, `oil` and the P3 window between the phases, so the DMEM
context persists as it does on hardware.

## How to run
From the repository root, at the 32 KiB DMEM profile:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/...
BB=bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k/verify_stream
T=sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/tests

python3 $T/measure_cycles.py --mode functional --param Ip --elf $BB/ov-Ip-pkc/ov-Ip-verify_stream_bngfaes.elf
python3 $T/measure_cycles.py --mode functional --param Is --elf $BB/ov-Is-pkc/ov-Is-verify_stream_bngfaes.elf
python3 $T/measure_cycles.py --param both --cases 0,11
python3 $T/measure_cycles.py --param Ip3 --negative
```
- `--mode functional` (Ip, Is; `--elf` required): the accumulator against the Python public map over
  `--cases` (default `0-11`), then the reject (status -1) of a corrupted signature on case 0.
- `--mode measure` (default): `--param Ip|Is|Ip3|both` (default both = Ip and Is); `--cases LIST` as
  `0`, `0,11` or `0-11` (default 11; Ip3 `0,11`); `--elf PATH` and `--vectors FILE` (single `--param`;
  default the bngfaes streamed ELF and the KAT file); `--dump-stats FILE` writes the summed count and
  the lines per phase (single parameter set and case). Ip3 only: `--phases` (lines per phase) and
  `--negative` (one signature byte flipped per case; every case must reject with status -1).
- `--reject` (single `--param`, `--elf` required): flipped signature bits, a signature under another
  key and a corrupted key must reject.
- The driver refuses a tree that is not at the 32 KiB DMEM profile
  (`python3 tools/uov.py profile --profile 32`). `--help` lists the options.

## Files
| file | role |
|---|---|
| `measure_cycles.py` | the driver of Ip, Is and Ip3: instructions and cycles per phase, the Ip3 rejection run (`--negative`), and the Ip and Is functional test (`--mode functional`: the same host sequence, Ip: INIT, 2 UPDATE windows, FINAL; Is: the windows filled to the maximum; then the accumulator compared bit for bit with the Python public map, all 12 KAT cases and a reject with a corrupted signature); also the driver of the KAT sweep for the `stream` and `stream_uniform` verify variants |
| `../../../shared/verify/ov-Is-pkc/tests/verify_aes128hw_col_is.py` | the hardware-AES column leaf of the Is verify (`//sw/acc/crypto/handwritten/uov/shared/verify/ov-Is-pkc:aes128hw_col_is_test`): chained columns, counter carries, scratch guards and saved state |

## Notes
- Is windows: `winend - msgwin` when the ELF exports them (`msgwin` must be the window base), else
  the 30 KiB host contract, which is granted only to the bngfaes arm, which links nothing in DMEM. A
  window that would leave the bus window, or a row that does not fit, is refused.
- `--mode measure`: Ip and Is print one row per phase (`INIT`, one `UPD r<row_start>` per window,
  `FINAL`) and `TOTAL`; Ip3 prints one line per case (the phases with `--phases`).
  Each phase is its own ISS run, so nothing is subtracted; the cost of the fold alone is the sum of
  the `UPD r*` rows.
- `--mode measure`: every case must end with `ctrl.status == 0` (with `--negative`: -1, the reject; -2
  and -3 are errors); otherwise the run fails and exits nonzero. INIT and UPDATE write only an error,
  which FINAL would overwrite, so the driver clears the status before INIT, reads it after INIT and every
  UPDATE, and a nonzero one ends the case with it. `--mode functional` prints one line per case and then the reject.
- The ISS DMEM is the profile's 32 KiB (31,744 B bus + 1,024 B scratch); a phase that overflows it
  fails.
- A bare `standalone.py <elf> --pqc 1` does not measure a verification here: `ctrl = 0` from a cold
  DMEM dispatches INIT over a zero message, and no window is ever folded.
