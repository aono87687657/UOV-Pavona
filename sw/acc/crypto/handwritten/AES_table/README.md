# AES_table: software T-table AES-128 (32-bit GPR path)

Last updated: 2026-10-20: the KAT check runs `tools/gather_kat_stats.py` (`kat_check.sh` left tools/).

The T-table AES primitives and the T-table arm of `AES_compare/`. Every sw-tier kernel links `aes128_table` from here,
and the sw sign kernels link `aes_encrypt` (the Round-2 Ip ones also `aes128table_352`) through the aliases in
`uov/shared/sign/*/AES_ttable/`. The keygen and verify kernels keep their own key-schedule and encrypt copies in
`uov/shared/*/AES_ttable/`; `key_schedule.s` here is linked by no kernel.

## Files
| file | role |
|---|---|
| `aes128_table.s` | 4 KiB constant table, 256 x 16 B, interleaved `[Te2, Te0, Te3, Te1]`; byte 0 of `Te2` is `S[x]`, so the final round needs no separate S-box. Symbol `AES128_TABLE` |
| `key_schedule.s` | `AES_128_keyschedule`: 16 B key -> 176 B round keys, SubWord through `AES128_TABLE` |
| `aes_encrypt.s` | `AES_128_encrypt`: one 16 B block from resident round keys. Pure GPR, no WDR/WSR/CSR |
| `aes128table_352.s` | `aes128table_352`: AES-CTR PRG, fixed 22 blocks = 352 B keystream (zero nonce, 32-bit BE counter); counter enters and leaves in `x13` so calls chain |
| `aes128_table_test.s`, `aes_ctr_test.s` | functional drivers (KS + encrypt; KS + N x 352 B expansion, `num_rounds` a DMEM word) |
| `aes_keyschedule_test.s`, `aes_encrypt_only_test.s` + their `*_setup_test.s` | measurement drivers and their baselines: one op each, baseline = driver minus exactly that op |
| `test_scripts/verify_aes128_table.py` | static check of the table source: all 256 entries and their order (see below) |

## Test
```
python3 sw/acc/crypto/handwritten/AES_table/test_scripts/verify_aes128_table.py
```
No bazel test target in this package.

## Notes
- The table check needs no build and no toolchain. The other primitives have no check of their own: the sw-tier KATs run
  their code (`python3 tools/gather_kat_stats.py --ops verify --params Ip,Is --cases 0,11 --tiers sw`, likewise keygen and sign).
- Isolated op cost = op-driver run - setup-only run. Keep each baseline in lockstep with its driver or the subtraction stops meaning anything. `AES_compare/aes_compare.csv` records 492 op cyc for the key schedule (7 setup) and 1147 op cyc per 16 B block (9 setup), ACCSim, 2026-07-22.
- Pure GPR code: no `bn.gfmul`/`bn.aes128`, so `--pqc 1` is harmless but unnecessary.
- 4 KiB of constant table on top of the code, and data-dependent loads: not side-channel-equivalent to the ISE or compute-GF paths. Publish the footprint next to any cycle number.
- `aes_ctr_test.s` is the in-tree exhibit for "a loop body must not end on a jump" (the trailing `nop`): keep it.
- An edit to `aes128_table.s`, `aes_encrypt.s` or `aes128table_352.s` reaches the sw kernels that link them: re-run their
  KATs. The per-op copies in `uov/shared/*/AES_ttable/` are separate files: a fix to one is not a fix to the others.
