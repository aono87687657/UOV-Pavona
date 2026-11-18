# keygen_stream/tests: the driver for the streamed keygen ELFs

Last updated: 2026-11-17: `--vectors` added.

## TL;DR
The host-side driver for the phase-dispatch keygen in the parent directory. It runs every tier's ELF
of Ip, Is and Ip3, compares the public key with the KAT and prints the cycles.

## How to run
From the repository root, at the 32 KiB DMEM profile:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/...
python3 sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/tests/test_stream_keygen.py --param Ip \
  --elf bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Ip-pkc+skc/ov-Ip-keygen_stream_bngfaes.elf \
  --cases 0 --stats
```
- `--param Ip|Is|Ip3`: the parameter set of the ELF (required).
- `--elf PATH`: the ELF to run (required).
- `--cases LIST`: KAT cases (seeds) as `0`, `0,11` or `0-11`, default 0; each runs on a fresh
  simulator.
- `--vectors FILE`: the vector file (default `test_data/testvectors-<param>-pkc-skc`).
- `--stats`: print the cycles per phase and the `streamed total:` line.
- `--dump-stats FILE`: write `executed N instructions in M cycles`, summed over the phases (one case
  only).

## What it does
The driver runs INIT and every WINDOW call on the ISS, assembles the full P3 from the window slices,
folds the upper triangle (XOR of the j<k entries), packs `cpk = pk_seed || P3` and compares it byte
for byte with the KAT. Each run also makes two negative controls: one real byte corrupted in window
0 and one in the short last window must both give a mismatch.

## Files
| file | role |
|---|---|
| `test_stream_keygen.py` | Ip (GF(256), O_DIM 44, 44 B valid per 64 B slice entry), Ip3 (O_DIM 45, 45 B valid per 64 B entry; `--localize`) and Is (GF(16), O_DIM 64, 32 B slice entries) |

## Notes
- WJ, the strides and the window list come from the ELF symbols (`ctrl`, `sk_seed`, `pk_seed`,
  `slice`, `slice_end`), so the driver runs every tier's ELF unchanged.
- The driver refuses a tree that is not at the 32 KiB DMEM profile (31,744 B bus + 1,024 B scratch;
  `python3 tools/uov.py profile --profile 32`), so the ISS enforces the real size.
- A bare `standalone.py` run on a streamed ELF executes only the one phase `ctrl` selects, not a key
  generation. Use the driver for cycles.
