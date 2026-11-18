# AES_ext/test_scripts: the check of the memory AES library

Last updated: 2026-10-18: `verify_aes128_mem.py` is the one check; the demo's script `verify_aes128_ext.py` was
dropped (every bngfaes and bnaesonly KAT runs the same instructions with real keys).

`verify_aes128_mem.py` runs the Bazel-built `aes128_mem_test` on the ACC simulator, 12 cases (six key and plaintext pairs,
each with a separate and an in-place output), and checks what the UOV KATs cannot see: the 176 round-key bytes of the
FIPS-197 Appendix C.1 key (`000102…0f`), the guard words around the ciphertext and the round keys, the returned pointers, the flags, and that all
32 WDRs and 13 GPRs keep their values. The kernels' hardware AES leaves read only round key 0 and derive the others, and no
kernel calls `aes128_mem`'s own encrypt, so wrong stored round keys 1 to 10 would pass every KAT.

## Test
```
./bazelisk.sh build //sw/acc/crypto/handwritten/AES_ext:aes128_mem_test
python3 sw/acc/crypto/handwritten/AES_ext/test_scripts/verify_aes128_mem.py
```
`--elf FILE` checks another build. Prints `PASS: 12 AES cases; ...`, or stops at the first failed check with its name.

## Notes
- Needs pycryptodome and pyelftools; imports `own_utils/` from the repo; writes nothing.
