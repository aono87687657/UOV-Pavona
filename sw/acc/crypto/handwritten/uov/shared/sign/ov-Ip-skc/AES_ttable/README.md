# AES_ttable: T-table AES-128 in general-purpose registers, for the Ip sign sw tier

Last updated: 2026-10-20: the KAT check runs `tools/gather_kat_stats.py` (`kat_check.sh` left tools/).

## TL;DR
AES-128 with GPRs only (no WDR, no WSR or CSR, no PQC instruction), used by the `sw` sign tier as
the baseline without instruction extensions. Libraries only, no test binaries: the test is the sw
sign binary.

## How to run
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip-skc:ov-Ip-sign_ldirect_testvec_sw
python3 tools/gather_kat_stats.py --ops sign --params Ip --cases 0,11 --tiers sw
```

## Files
Files shown as links are one shared source file each: this package's target of the same name is an alias of the target that builds it (the copies here were byte-identical).

| file | role |
|---|---|
| [`aes128_table.s`](../../../../../AES_table/aes128_table.s) | 4 KiB interleaved T-table, 256 entries of 16 B `[Te2, Te0, Te3, Te1]`; the low byte of entry +0 is S[x], so a final-round byte is one `lw` and an `andi 0xff` |
| `key_schedule.s` | `AES_128_keyschedule`: 16 B key to 176 B round keys. clob x5-x8, x12-x18, x29-x31 |
| [`aes_encrypt.s`](../../../../../AES_table/aes_encrypt.s) | `AES_128_encrypt`: one 16 B block from 11 expanded round keys. clob x5-x8, x13-x16, x19-x22, x29, x31 |
| [`aes128table_352.s`](../../../../../AES_table/aes128table_352.s) | AES-128-CTR generator, fixed 22 blocks = 352 B, for the P1/P2 expansion from pk_seed |

## Notes
- The table loads depend on the data: this tier is not equivalent to `bngfonly` and `bngfaes` for
  side channels. It is a functional baseline, not a shipping configuration.
- The 4 KiB table is the largest `.data` item of every sw sign ELF.
- `aes128table_352` is the T-table counterpart of the bngfonly `expand352`; the sign KAT on this
  tier compares the whole signature with the fixture's.
- The block count of `aes128table_352` is fixed at 22 by the routine; it takes no count argument.
