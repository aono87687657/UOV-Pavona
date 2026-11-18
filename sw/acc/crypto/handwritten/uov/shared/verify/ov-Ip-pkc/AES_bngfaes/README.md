# AES_bngfaes: hardware-AES helpers for the Ip verify bngfaes tier

Last updated: 2026-10-20: the KAT check runs `tools/gather_kat_stats.py` (`kat_check.sh` left tools/).

## TL;DR
AES-128-CTR on `bn.aes128.kf/encz.swap/encm/encf`, with the key schedule carried on the fly in
w28. Linked by the `bngfaes` arms of the shipping stream verify
(`//sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/ov-Ip-pkc:ov-Ip-verify_stream_bngfaes`) and of verify full
(`../../../../dmem_large/verify_full/`).
Libraries only.

## How to run
No test of its own. The shipping streamed verify links it, so from the repository root at the
32 KiB DMEM profile:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/ov-Ip-pkc:ov-Ip-verify_stream_bngfaes
python3 tools/gather_kat_stats.py --ops verify --params Ip --cases 0,11 --tiers bngfaes
```
After an edit here, also run the verify full KAT (`../../../../dmem_large/verify_full/README.md`): both binaries
change.

## Files
| file | role |
|---|---|
| `aes128_352.s` | one batch of 11 dual-block CTR operations = 352 B of keystream, aligned to 44 B columns in w9-w23. in w27 counter increment, w30 base key, w31 zero; in/out w29 IV base; clob w8-w23, w28, FG0; no stack |
| `load_p3.s` | loads 8 packed 44 B P3 columns (352 B) and aligns each to a 32 B WDR with `bn.rshi`. in x12 (advanced by 352); clob w8-w23 |
| `BUILD` | one `acc_library` per source |

## Notes
- Both files are leaf routines: no stack frame, and no GPR, WSR or CSR write other than x12 in
  `load_p3`.
- `load_p3.s` exports the same symbol as `../AES_bngf/load_p3.s` with another WDR layout (w8-w23
  instead of w9-w24). Keep them separate.
