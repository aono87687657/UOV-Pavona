# AES_bngf: AES-128 computed with `bn.gfmul`, for the Ip verify bngfonly tier

Last updated: 2026-10-20: the KAT check runs `tools/gather_kat_stats.py` (`kat_check.sh` left tools/).

## TL;DR
AES-128 without `bn.aes128`: SubBytes is an Itoh-Tsujii `a^254` inverse built from `bn.gfmul.8.vv`;
everything else is shifts, masks and XORs on WDRs. Linked by the `bngfonly` arms of
the stream verify (`../../../../dmem32k/verify_stream/` and the Round-3 stream and uniform
directories) and of verify full. Libraries only.

## How to run
No test of its own: the bngfonly arm of the Ip stream verify KAT exercises it. From the repository root, at
the shipped 32 KiB profile:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/ov-Ip-pkc:ov-Ip-verify_stream_bngfonly
python3 tools/gather_kat_stats.py --ops verify --params Ip --cases 0,11 --tiers bngfonly
```

## Files
| file | role |
|---|---|
| `aes128_352.s` | dual-block AES-128-CTR, 11 double blocks = 352 B of keystream; Sub, Shift, Mix and the counter increment in one nested `loopi`. clob x6, x24-x27, x30, w9-w26, w30, FG0; no stack |
| `KeySchedule.s` | one key-schedule round (RotWord, SubBytes, affine map, rcon). in/out w30 round key, w26 rcon carrier; clob w20-w25, FG0 |
| `load_p3.s` | loads 8 packed 44 B P3 columns (352 B) and aligns each to a 32 B WDR with `bn.rshi`. in x12 (advanced by 352); clob w9-w24 |
| `BUILD` | one `acc_library` per source |

## Notes
- The caller sets `mod0 = 0x11b` beforehand; w27 (affine_value), w28 (msb_mask), w31 (zero) and the
  base of the round keys in x2 belong to the caller and are preserved.
- `load_p3.s` exports the same symbol as `../AES_bngfaes/load_p3.s` but uses another WDR layout
  (w9-w24 instead of w8-w23). They are not interchangeable: do not merge them.
- `aes128_352.s` reuses w19 as shiftrow mask, byte-swap mask and column mask; the last `bn.movr`
  overwrites it, and the unpack after the loop depends on that.
