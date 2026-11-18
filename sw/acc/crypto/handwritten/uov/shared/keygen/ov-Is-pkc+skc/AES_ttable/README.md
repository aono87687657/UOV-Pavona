# AES_ttable: T-table AES-128 in general-purpose registers (Is keygen, sw tier)

Last updated: 2026-10-20: the KAT check runs `tools/gather_kat_stats.py` (`kat_check.sh` left tools/).

## TL;DR
The AES key schedule and single-block encryption use GPRs only, without PQC instructions. One
interleaved 4 KiB T-table serves the rounds and the S-box of the final round. `aes128_dual_table` is
the entry point for Is: it wraps two `AES_128_encrypt` calls into the dual-block shape (w18 in, w2
out) the GF(16) kernels expect, moving the WDRs through a 32 B stack frame.
Libraries only: they are tested through the keygen binaries that link them.

## How to run
The streamed 32 KiB keygen of this tier links these libraries. From the repository root, at the
32 KiB DMEM profile:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Is-pkc+skc:ov-Is-keygen_stream_sw
python3 tools/gather_kat_stats.py --ops keygen --params Is --cases 0 --tiers sw --variants stream
```
Case 0 checks one key pair, and it takes minutes: the sw keygen is the slowest cell (see the Numbers of
`../../../../dmem32k/keygen_stream/README.md`). The one-shot and stream-uniform keygens link
these libraries too.

## Files
Files shown as links are one shared source file each: this package's target of the same name is an alias of the target that builds it (the copies here were byte-identical).

| file | role |
|---|---|
| [`aes128_table.s`](../../../../../AES_table/aes128_table.s) | `AES128_TABLE`: 256 entries of 16 B = 4 KiB of `.data`, the four byte rotations per S-box input |
| [`key_schedule.s`](../../ov-Ip-pkc+skc/AES_ttable/key_schedule.s) | `AES_128_keyschedule`: 16 B key to 11 round keys (176 B), SubWord from the low byte of the table |
| [`aes_encrypt.s`](../../ov-Ip-pkc+skc/AES_ttable/aes_encrypt.s) | `AES_128_encrypt`: one 16 B block, round keys from DMEM |
| `aes128_dual_table.s` | the dual-block wrapper: w18 = double IV, x18 = base of the round keys in DMEM, out w2 = 32 B ciphertext; a 32 B scratch frame |
| `BUILD` | the aliases of the three shared files and the `acc_library` of the wrapper |

## Notes
- The table loads depend on the data: a functional reference, not equivalent to the `bngfonly` and
  `bngfaes` tiers for side channels.
- The 4 KiB table is what forces the narrower window of the streamed sw keygen (Is WJ=10).
  `ov-Is-keygen_stream_sw` carries the table in its own source, to place it on the bus side, and
  does not link `:aes128_table`.
- `aes128_dual_table` preserves x1..x4, x9, x17, x18, x23..x28, x30 and every WDR except w2; the
  caller saves its own x11 and x12 around each call.
- The three shared files are linked by other kernels too (the Ip keygen among them): an edit there
  changes all of them.
