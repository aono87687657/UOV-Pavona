# gf16: GF(2^4) software multiply + the GF(16) half of the HW-vs-SW rig

Last updated: 2026-10-28: `gf16_macc_sw` tests each scalar bit with one instruction; its unit test `gf16_macc_sw_test`.

Software GF(16) multiply/MAC/inverse routines, plus the measurement drivers that
feed `GF_compare/`. Both libraries are production: the shipping OV-Is kernels
link them at the **sw** tier (`gf16_sw_helpers` by keygen + sign, `gf16_mul` by
verify). The `bngfonly`/`bngfaes` tiers emit `bn.gfmul.4` inline and link
neither.

## Files
| file | role |
|---|---|
| `gf16_mul.s` | `gf16_mul`: `w0 = w1 x w2`, 64 nibbles by one scalar, Russian-peasant shift/xor. Needs `w3` = msb_mask `0x88..88`; destroys `w1` |
| `gf16_sw_helpers.s` | `gf16_macc_sw` (`w20 ^= w0 x` next nibble of `w19`) and `gf16_scalar_inv_sw` (inverse via `a^14`). Need `w16` = `0x88..`/nibble, `w31` = 0 |
| `gf16_mul_test.s` / `.exp` | bazel sim test for `gf16_mul`, fixed operands, scalar `b = 0x9` |
| `gf16_macc_sw_test.s` / `.dexp` | bazel sim test of `gf16_macc_sw` on every scalar 0..15, values of a reference GF(2^4) multiply |
| `gf16_extmul_test.s` / `.exp` | bazel sim test for the HW `bn.gfmul.4` path, scalar `b = 0xb` (`pqc = True`) |
| `gf16_mul_rand_test.s` | harness with DMEM-injected operands (`val_a` @ 0x000, `val_b` @ 0x020, msb_mask @ 0x040); faults if run bare |
| `gf16_gfmul_op_test.s`, `gf16_mul_op_test.s` | measurement drivers: setup + exactly one HW / SW multiply |
| `gf16_setup_hw_test.s`, `gf16_setup_sw_test.s` | matching baselines: same loads (and mod0/mod1 writes on the HW side), no op |
| `test_scripts/` | random-operand verifier, HW `b`-sweep tester, expected-value table and its generators |

## Test
```
./bazelisk.sh test //sw/acc/crypto/handwritten/gf16:gf16_mul_test
./bazelisk.sh test //sw/acc/crypto/handwritten/gf16:gf16_extmul_test
./bazelisk.sh test //sw/acc/crypto/handwritten/gf16:gf16_macc_sw_test

./bazelisk.sh build //sw/acc/crypto/handwritten/gf16:gf16_mul_rand_test
python3 \
  sw/acc/crypto/handwritten/gf16/test_scripts/gf16_mul_verify.py --iterations 100 --seed 42
```
End to end, this code is what the OV-Is sw-tier kernels compute with:
`python3 tools/gather_kat_stats.py --ops verify --params Is --cases 0,11 --tiers sw` (build the sw ELFs first).

## Notes
- HW path is `bn.gfmul.4`, mod0 = `0x13`, 64 nibbles per op. Cost is a subtraction (`op driver - setup baseline`): 1 cyc HW vs 42 cyc SW for 64 elements, setup 16/18 cyc, ACCSim 2026-07-22. Modelled: `bn.gfmul` is 1 cycle in the simulator, so this is an instruction-count argument, not timing closure.
- `--pqc 1` is required on any ELF containing `bn.gfmul`, otherwise it traps ILLEGAL_INSN.
- Preconditions are the caller's job: skipping the mask preload gives silently wrong results, not a fault.
- `test_scripts/gf16_tester.py` rewrites the tracked `gf16_extmul_test.s`/`.exp` while sweeping `b` (keeps `.backup` copies): do not run it on a dirty tree.
- Both software paths are data-independent: fixed shift/xor schedule, no table lookups, no data-dependent branches.
