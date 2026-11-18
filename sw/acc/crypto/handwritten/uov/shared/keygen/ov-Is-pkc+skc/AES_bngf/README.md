# AES_bngf: AES-128 computed with `bn.gfmul` (Is keygen, bngfonly tier)

Last updated: 2026-10-20: the KAT check runs `tools/gather_kat_stats.py` (`kat_check.sh` left tools/).

## TL;DR
AES-128 for the `bngfonly` tier: no `bn.aes128`; SubBytes is an Itoh-Tsujii GF(256) inverse chain
on `bn.gfmul.8.vv`. Two CTR blocks per call, to match the 32 B entries of the keygen's AES-CTR
stream. Libraries only: they are tested through the keygen binaries that link them.

## How to run
The streamed 32 KiB keygen of this tier links these libraries. From the repository root, at the
32 KiB DMEM profile:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Is-pkc+skc:ov-Is-keygen_stream_bngfonly
python3 tools/gather_kat_stats.py --ops keygen --params Is --cases 0 --tiers bngfonly --variants stream
```
Case 0 checks one key pair; more cases check more keys.
`gather_kat_stats.py` runs the prebuilt ELF, so build first. The one-shot and stream-uniform keygens link the same libraries.

## Files
Files shown as links are one shared source file each: this package's target of the same name is an alias of the target that builds it (the copies here were byte-identical).

| file | role |
|---|---|
| [`aes128_keygen.s`](../../ov-Ip-pkc+skc/AES_bngf/aes128_keygen.s) | dual-block AES-128 encrypt; in: w30 = RK0, w20..w29 = RK1..RK10 (each stored twice), w18 = IV; out: w2 = 32 B ciphertext |
| [`KeySchedule_keygen.s`](../../ov-Ip-pkc+skc/AES_bngf/KeySchedule_keygen.s) | one key-schedule round (RotWord, Itoh-Tsujii SubBytes, affine map, rcon); RK1..RK10 land in w29..w20 |
| [`aes_constants_keygen.s`](../../../../dmem_large/keygen_full/ov-Ip-pkc+skc/AES_bngf/aes_constants_keygen.s) | `.data`: `byte_swap_mask`, `affine_value`, `msb_mask`, `shiftrow_mask`, `rcon`; it lives with keygen full, the streamed kernels define their own |
| `BUILD` | the aliases of the two shared files |

## Notes
- Both helpers set `mod0 = 0x11B` and do not restore it: Is callers work in GF(16), so they must set `mod0 = 0x13` again after each group of calls. `mod1` is 0 on exit; both are leaves.
- `aes128_keygen` needs the round keys loaded into the WDRs by the caller; it does not run the key
  schedule itself.
- Byte-identical to `../../ov-Ip-pkc+skc/AES_bngf/`; separate copies so that each parameter set
  links its own package. Edit both or neither.
- `aes_constants_keygen` is linked by keygen full only. The stream kernels carry these constants
  in their own source, to control where they are placed inside the 32 KiB.
