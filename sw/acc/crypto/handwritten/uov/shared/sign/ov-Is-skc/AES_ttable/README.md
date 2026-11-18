# AES_ttable: T-table AES-128 for the Is sign sw tier

Last updated: 2026-10-20: the KAT check runs `tools/gather_kat_stats.py` (`kat_check.sh` left tools/).

## TL;DR
AES-128 in GPRs on a 4 KiB interleaved T-table, plus the two CTR wrappers the Is sign kernel calls.
Only the `sw` tier of the parent package links it (`bngfaes` uses `bn.aes128`, `bngfonly` links
`../AES_bngf/`). Libraries only: the test is the sw sign binary.

## How to run
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Is-skc:ov-Is-sign_ldirect_testvec_sw
python3 tools/gather_kat_stats.py --ops sign --params Is --cases 0,11 --tiers sw
```
`gather_kat_stats.py` runs prebuilt ELFs: build first, or it passes on a stale binary. The sw sign cells
are the slow ones of a sweep.

## Files
Files shown as links are one shared source file each: this package's target of the same name is an alias of the target that builds it (the copies here were byte-identical).

| file | role |
|---|---|
| [`aes128_table.s`](../../../../../AES_table/aes128_table.s) | `AES128_TABLE`, 256 entries of 16 B. Entry +0 is Te2, whose low byte is S[x], so the final round and the key schedule need no separate S-box table |
| [`key_schedule.s`](../../ov-Ip-skc/AES_ttable/key_schedule.s) | `AES_128_keyschedule`: 16 B key to 11 round keys (176 B). in: x10 key, x11 round-key buffer |
| [`aes_encrypt.s`](../../../../../AES_table/aes_encrypt.s) | `AES_128_encrypt`: one 16 B block. in: x10 round keys, x11 plaintext, x12 ciphertext. GPRs only |
| `aes128_dual_table.s` | `aes128_dual_table`: two CTR blocks into w2 (32 B); the drop-in for `aes128_sign` in the sw trimat kernel. 32 B of stack |
| `aes128_col_is.s` | `aes128_col_is`: one 32 B P column = 2 CTR blocks into w13; the little-endian counter is chained in and out through x13 |
| `BUILD` | the aliases of the three shared files and one `acc_library` per source kept here |

## Notes
- Each `.s` header carries the exact clobber and preserve map. The two wrappers rely on
  `AES_128_encrypt` preserving x1..x4, x9, x17, x18, x23..x28 and x30: check those before changing
  its register use.
- The table loads depend on the data: a functional baseline without instruction extensions, not
  equivalent to the other tiers for side channels, at a cost of 4 KiB of `.data`.
