# AES_ttable: T-table AES-128 in general-purpose registers (Ip keygen, sw tier)

Last updated: 2026-10-20: the KAT check runs `tools/gather_kat_stats.py` (`kat_check.sh` left tools/).

## TL;DR
AES-128 for the `sw` tier: GPRs only, no WDR, WSR or CSR, no PQC instruction. One interleaved 4 KiB
T-table serves the rounds and the S-box of the final round, and `aes128table_352` wraps it into the
AES-CTR generator that expands pk_seed into P1 and P2. Libraries only: they are tested through the
keygen binaries that link them.

## How to run
The streamed 32 KiB keygen of this tier links these libraries. From the repository root, at the
32 KiB DMEM profile:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Ip-pkc+skc:ov-Ip-keygen_stream_sw
python3 tools/gather_kat_stats.py --ops keygen --params Ip --cases 0 --tiers sw --variants stream
```
Case 0 checks one key pair, and it takes minutes: the sw keygen is the slowest cell (see the Numbers of
`../../../../dmem32k/keygen_stream/README.md`). The one-shot and stream-uniform keygens and
`sign_rtl` link these libraries too.

## Files
Files shown as links are one shared source file each: this package's target of the same name is an alias of the target that builds it (the copies here were byte-identical).

| file | role |
|---|---|
| [`aes128_table.s`](../../../../../AES_table/aes128_table.s) | `AES128_TABLE`: 256 entries of 16 B = 4 KiB of `.data`, the four byte rotations per S-box input |
| `key_schedule.s` | `AES_128_keyschedule`: 16 B key to 11 round keys (176 B), SubWord from the low byte of the table |
| `aes_encrypt.s` | `AES_128_encrypt`: one 16 B block, round keys from DMEM |
| `aes128table_352.s` | AES-128-CTR generator, 22 blocks = 352 B of keystream; little-endian counter in and out through x13, so calls can be chained |
| `aes128table_384.s` | AES-128-CTR generator, 24 blocks = 384 B of keystream, the Ip3 counterpart of `aes128table_352` (counter chained through x13); linked by the Ip3 sw kernels |
| `BUILD` | the alias of the shared table and one `acc_library` per source kept here |

## Notes
- The table loads depend on the data: a functional reference, not equivalent to the `bngfonly` and
  `bngfaes` tiers for side channels.
- The 4 KiB table is what forces the narrower window of the streamed sw keygen (Ip WJ=5).
- `AES_128_encrypt` preserves all WDR, WSR and CSR state; it clobbers x5..x8, x13..x16, x19..x22,
  x29 and x31. Derive the `clob:` lines of callers from these headers.
- Byte-identical to the four files of the same names in `../../ov-Is-pkc+skc/AES_ttable/` (which
  adds a dual-block wrapper). Edit both or neither.
