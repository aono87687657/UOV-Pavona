# AES_bngf: AES-128 computed with `bn.gfmul`, for the Is verify bngfonly tier

Last updated: 2026-10-20: the KAT check runs `tools/gather_kat_stats.py` (`kat_check.sh` left tools/).

## TL;DR
AES-128 without `bn.aes128`: SubBytes is an Itoh-Tsujii `a^254` inverse built from `bn.gfmul.8.vv`;
everything else is shifts, masks and XORs on WDRs. Linked by the `bngfonly` arms of
the stream verify (`../../../../dmem32k/verify_stream/`) and of verify full. Libraries only.

## How to run
No test of its own: the bngfonly arm of the Is stream verify KAT exercises it. From the repository root, at
the shipped 32 KiB profile:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/ov-Is-pkc:ov-Is-verify_stream_bngfonly
python3 tools/gather_kat_stats.py --ops verify --params Is --cases 0,11 --tiers bngfonly
```

## Files
| file | role |
|---|---|
| `aes128.s` | one dual-block encrypt (32 B out in w27): round 0, `loopi 9` for rounds 1-9, the final round. clob x5, x6, w16-w22, w25, w26, w31, FG0; sets mod0=0x11b, mod1=0; no stack |
| `KeySchedule.s` | one key-schedule round (RotWord, SubBytes, affine map, rcon). in/out w28 round key, w26 rcon carrier; clob w17-w22, w31, x23, FG0 |
| `BUILD` | one `acc_library` per source |

## Notes
- The round keys stay in WDRs for the whole public map, with no stack buffer: w28 = round 0,
  w5..w14 = rounds 1..10, each stored twice (`K | K<<128`).
- The caller owns w23 (affine_value), w24 (msb_mask), w29 (the IV: counter at bytes 12 and 28,
  little-endian, advanced by 2 per call) and w30 (byte-swap mask).
- Both routines leave `mod0 = 0x11b`; the caller must restore `0x13` before the next `bn.gfmul.4`.
