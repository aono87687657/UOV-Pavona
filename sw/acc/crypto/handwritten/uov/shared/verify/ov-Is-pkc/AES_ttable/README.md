# AES_ttable: T-table AES-128 for the Is verify sw tier

Last updated: 2026-10-20: the KAT check runs `tools/gather_kat_stats.py` (`kat_check.sh` left tools/).

## TL;DR
AES-128 in GPRs (key schedule and single-block encrypt) on one interleaved 4 KiB T-table, used by
the `sw` arms of the stream verify (`../../../../dmem32k/verify_stream/`) and of verify full. `aes128_col_is` wraps it into the CTR call the public
map makes: one 32 B column of P is two AES blocks. Libraries only.

## How to run
No test of its own: the sw arm of the Is stream verify KAT exercises it. From the repository root, at
the shipped 32 KiB profile:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/ov-Is-pkc:ov-Is-verify_stream_sw
python3 tools/gather_kat_stats.py --ops verify --params Is --cases 0,11 --tiers sw
```

## Files
Files shown as links are one shared source file each: this package's target of the same name is an alias of the target that builds it (the copies here were byte-identical).

| file | role |
|---|---|
| [`aes128_table.s`](../../../../../AES_table/aes128_table.s) | `AES128_TABLE`: 256 entries of 16 B = 4 KiB. The 4 little-endian words of an entry are the 4 byte rotations of `{2S, S, S, 3S}`; offset +0 is Te2, whose low byte is `S[x]`, so an S-box byte of the final round is one `lw` and an `andi 0xff`, with no separate table |
| [`key_schedule.s`](../../ov-Ip-pkc/AES_ttable/key_schedule.s) | `AES_128_keyschedule`: 16 B key to 176 B (11 round keys). in `x10` key, `x11` round-key buffer; clob `x5..x8`, `x12..x18`, `x29..x31` |
| [`aes_encrypt.s`](../../ov-Ip-pkc/AES_ttable/aes_encrypt.s) | `AES_128_encrypt`: one 16 B block. in `x10` round keys, `x11` plaintext, `x12` ciphertext; clob `x5..x8`, `x13..x16`, `x19..x22`, `x29`, `x31` |
| `aes128_col_is.s` | `aes128_col_is`: 2 CTR blocks in a row into `w13` = 32 B = 64 GF(16) nibbles = one column of P. The IV is built in registers; `x13` is the little-endian counter chained across calls, `x18` the base of the round keys, `20(x3)` a 32 B scratch |
| `BUILD` | the aliases of the three shared files and the `acc_library` of `aes128_col_is` |

## Notes
- `sw` tier only. `bngfonly` uses `../AES_bngf/`; `bngfaes` has `bn.aes128` inline in the public map
  and links nothing here.
- The 4 KiB table is in `.data` and its loads depend on key and data: this path is not equivalent
  to the hardware-AES tiers for side channels.
- `aes128_col_is` is specific to Is (32 B columns). `AES_128_encrypt` is single-block, so a column
  takes 2 calls.
