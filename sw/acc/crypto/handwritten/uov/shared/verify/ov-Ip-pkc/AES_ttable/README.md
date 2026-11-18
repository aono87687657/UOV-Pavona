# AES_ttable: T-table AES-128 for the Ip verify sw tier

Last updated: 2026-10-20: the KAT check runs `tools/gather_kat_stats.py` (`kat_check.sh` left tools/).

## TL;DR
AES-128 in GPRs only (no WDR, WSR or CSR) on a 4 KiB interleaved T-table. Used by the `sw` arms of
the stream verify (`../../../../dmem32k/verify_stream/` and the Round-3 stream and uniform
directories) and of verify full: the baseline the
`bn.gfmul` and `bn.aes128` tiers are measured against. Libraries only.

## How to run
No test of its own: the sw arm of the Ip stream verify KAT exercises it. From the repository root, at
the shipped 32 KiB profile:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/ov-Ip-pkc:ov-Ip-verify_stream_sw
python3 tools/gather_kat_stats.py --ops verify --params Ip --cases 0,11 --tiers sw
```

## Files
Files shown as links are one shared source file each: this package's target of the same name is an alias of the target that builds it (the copies here were byte-identical).

| file | role |
|---|---|
| [`aes128_table.s`](../../../../../AES_table/aes128_table.s) | the 4 KiB table, 256 entries of 16 B; each entry holds the 4 byte rotations of {2S, S, S, 3S}, and offset +0 (Te2) has S[x] in its low byte, so the final round needs no separate S-box |
| `key_schedule.s` | expands a 16 B key to 11 round keys (176 B); x10 key, x11 buffer (advanced to base+160). clob x5-x8, x12-x18, x29-x31 |
| `aes_encrypt.s` | one-block encrypt; x10 round keys, x11 plaintext, x12 ciphertext. clob x5-x8, x13-x16, x19-x22, x29, x31 |
| `aes128table_352.s` | AES-128-CTR generator, fixed 22 blocks = 352 B; x10 round keys, x11 out, x13 little-endian counter in and out (chained by the caller) |
| `BUILD` | the alias of the shared table and one `acc_library` per source kept here |

## Notes
- The table loads depend on the data: a performance baseline, not an implementation equivalent to
  the other tiers for side channels. The table costs 4 KiB of DMEM.
- The code is identical to the standalone `../../../../../AES_table` sources (comments aside). They
  are separate copies: a fix in one has to be made in the other by hand.
