# verify_full/ov-Ip3-pkc: Ip3 verification in one EXECUTE with the public key resident (128 KiB DMEM)

Last updated: 2026-10-19: paths after the folder reorg (one subfolder per parameter set).

The verify-full kernels for the Round-3 parameter set Ip3, documented with Ip and Is in
[../README.md](../README.md): how to run, numbers, host contract, files. Driver:
`../tests/test_full_verify.py --param Ip3`. A PASS covers the selected cases and the checks
that ran: with `--part I/N` only that part's sequences, and the poisoned-scratch check only with
`--poison` (the list: [../README.md](../README.md#what-it-does)). The separate
Round-3 reference check and its limits are in [test-data provenance](../../../../test_data/README.md#notes).
