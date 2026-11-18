# ov-Ip3-pkc+skc: UOV-Ip3 keygen full (GF(256))

Last updated: 2026-10-28: new package.

## TL;DR
The Ip3 package of keygen full: `sk_seed -> expandsk -> P1O_P2 -> P3_cal -> cpk_pack -> cpk`, with
`csk = sk_seed` left in place. Ip3 is V 74 / O 45 / M 45 over GF(256);
`cpk = pk_seed (16 B) || 1,035 x 45 B = 46,591 B`. One tier, bngfaes, at the 512 KiB DMEM profile,
run on the ISS only.

## How to run
At the 512 KiB profile (`python3 tools/uov.py profile --profile 512`, see `../README.md`), from the
repository root:
```
./bazelisk.sh build "//sw/acc/crypto/handwritten/uov/dmem_large/keygen_full/ov-Ip3-pkc+skc:ov-Ip3-keygen_full_bngfaes"
python3 tools/gather_kat_stats.py --ops keygen --params Ip3 --tiers bngfaes --variants full --cases 0
```
It prints PASS and the cycles. The Ip3 KAT file repeats one key pair, so a second key comes from the
NIST-format file (12 distinct keys; `--cases all` runs every one):
```
python3 sw/acc/crypto/handwritten/own_utils/run_test.py keygen --param Ip3 --tier bngfaes --cases 0,11 \
  --test-data-file sw/acc/crypto/handwritten/test_data/testvectors-Ip3-pkc-skc.nistkat \
  --elf bazel-bin/sw/acc/crypto/handwritten/uov/dmem_large/keygen_full/ov-Ip3-pkc+skc/ov-Ip3-keygen_full_bngfaes.elf
```

## Files
| file | role |
|---|---|
| `ov-Ip3-keygen.s` | the `ov_keygen` orchestrator; its header carries the stack contract |
| `P1O_P2.s` | `B = P1*O + P2`, 74x45 cells of 64 B: P2 streamed straight into B, then each P1 row folded in place |
| `P3_cal.s` | dense `O^T x B` (eleven four-row passes and one row for k = 44), folded into the 1,035-cell upper triangle |
| `cpk_pack.s` | 64 B cells to 45 B slots through the masked slot writer, after the `pk_seed` prefix |
| `ov-Ip3-keygen_test.s` | the ISS harness; `.data` = sk_seed 32 B, cpk 46,592 B, stack 413,376 B, `stack_end = 460,000` |

Linked from `../../../shared/`: `keygen/ov-Ip3-pkc+skc:expandsk_ret_O_pkseed` (`sk_seed -> pk_seed || O`,
O padded to 96 B per column) and `sign/ov-Ip3-skc:expand_360` (8 P1/P2 entries per call).

## Notes
- The ELF needs 460,000 B of DMEM (`B` alone is 213,120 B), so its smallest profile is 512 KiB.
  The stack block is the exact peak (during `P3_cal`), no guard.
- `expand_batch`, `phase4_row_setup` (`P1O_P2.s`) and `_slot_write` (`cpk_pack.s`) are copies of the
  routines in `../../keygen_sp/ov-Ip3-pkc+skc/ov-Ip3-keygen_sp.s`: an edit to them means running the
  KAT of both packages again.
- There is no simulator test target in this package; the check is the KAT.
