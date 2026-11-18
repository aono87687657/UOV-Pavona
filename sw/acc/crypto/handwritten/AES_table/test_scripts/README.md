# AES_table/test_scripts: the static check of the T-table

Last updated: 2026-10-18: `verify_aes128_table.py` is the one script kept; the key-schedule, encrypt and CTR checkers
were dropped.

`verify_aes128_table.py` parses `../aes128_table.s` and checks all 256 entries, four words each in the order
`[Te2, Te0, Te3, Te1]`, against a Python `xtime` reference. No build, no simulator, no toolchain; it writes nothing.

## Test
```
python3 sw/acc/crypto/handwritten/AES_table/test_scripts/verify_aes128_table.py
```
Prints `PASS: all 256 entries match ...`, or the first five mismatching entries and the total count.
