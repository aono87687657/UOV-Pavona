# AES_ext: AES-128 instruction-extension reference + cycle-isolation drivers

Last updated: 2026-10-18: the check is `test_scripts/verify_aes128_mem.py`; the demo's Python check was dropped (every
bngfaes and bnaesonly KAT runs the same instructions with real keys).

Standalone reference for the AES ISE (`bn.aes128.kf`, `.encz[.swap]`, `.encm`,
`.encf`): one functional demo plus the key-schedule / encrypt cycle drivers that
`AES_compare/` consumes as its ISE arm. The demo and the cycle drivers are standalone; the library
`aes128_mem` (round keys packed in memory) is linked by the `bnaesonly` arms of several UOV kernels
(`git grep 'AES_ext:aes128_mem'` lists them).

## Files
| file | role |
|---|---|
| `aes128_ext_test.s` | functional demo: three dual-block encryptions under key = 0, `kf`/`encm` interleaved; results in `w1`..`w3`; no check of its own (every bngfaes and bnaesonly KAT runs these instructions) |
| `aes128_ext_ks_test.s` | cycle driver, key schedule only: `bn.aes128.kf` x10 into `w1`..`w10` (rk0 = `w0`) |
| `aes128_ext_enc_test.s` | cycle driver, encrypt only: `encz.swap` + `encm` x9 + `encf`, round keys resident in `w20`..`w30` |
| `aes128_ext_setup_test.s` | shared baseline for both drivers: same load scaffold, no AES op |
| `aes128_mem.s` | library `aes128_mem`: hardware AES-128 with packed memory keys; preserves WDRs, WSRs and flags; 96 B private scratch, not reentrant |
| `aes128_mem_test.s` | test of the memory ABI (packed round keys, unaligned blocks, saved state): `aes128_mem_test` links `aes128_mem`, `aes128_mem_baseline_test` the T-table AES of `AES_table/` |
| `test_scripts/verify_aes128_mem.py` | the check of `aes128_mem`: all 11 round keys, guard words, in-place output, returned pointers, preserved registers and flags (see below) |

## Test
```
./bazelisk.sh build //sw/acc/crypto/handwritten/AES_ext:all
python3 sw/acc/crypto/handwritten/AES_ext/test_scripts/verify_aes128_mem.py
```
No bazel test target in this package. Cycles:
```
python3 hw/ip/acc/dv/accsim/standalone.py \
  bazel-bin/sw/acc/crypto/handwritten/AES_ext/aes128_ext_ks_test.elf --pqc 1
```

## Notes
- `--pqc 1` is required: `bn.aes128` traps ILLEGAL_INSN without it.
- Op cost is a subtraction: `op = driver run - aes128_ext_setup_test run`. Measured 2026-07-22 on ACCSim at `2f0fbc81fb`: key schedule 10 cyc, encrypt 11 cyc (32 B dual-block), setup 8 cyc. Those equal the instruction counts; the simulator models each AES instruction at 1 cycle, so they are modelled, not RTL-timed.
- Separate key-schedule and encryption ELFs isolate their costs. The encryption driver starts
  with resident round keys; UOV kernels use different key-schedule strategies.
- The three cycle drivers have no functional check: zero key, zero message; only their cycle counts mean anything.
