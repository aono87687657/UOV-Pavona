# keygen_sp/ov-Ip3-pkc+skc: single-pass Ip3 key generation in one EXECUTE (128 KiB DMEM)

Last updated: 2026-10-21: one restart driver for keygen_min and keygen_sp (`../../tests/test_oneshot_keygen.py`).

The `_sp` family for the Round-3 parameter set Ip3. Documented with both one-shot families in
[../keygen_min/README.md](../../keygen_min/README.md); driver `../../tests/test_oneshot_keygen.py --variant sp --param Ip3` (`--vectors2`: its
case 0 is the second key pair B). A PASS means that after each run of A -> B -> A the cpk matches the
fixture byte for byte and the 32-byte seed at `csk` is unchanged.
The separate Round-3 reference check and its limits are in
[test-data provenance](../../../../test_data/README.md#notes).
