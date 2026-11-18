# keygen_sp: single-pass UOV key generation in one EXECUTE (128 KiB DMEM)

Last updated: 2026-11-17: the chip numbers in [../keygen_min/README.md](../keygen_min/README.md) come from the rerun rtl-2026-11.

## TL;DR
- The `_sp` family for Ip and Is: one EXECUTE per key, a single pass over P1. Ip3 is in
  `ov-Ip3-pkc+skc/`. Its numbers, host contract and files are documented together with the `_min`
  family in [../keygen_min/README.md](../keygen_min/README.md).

## How to run
In a clone of its own (the profile switch rewrites generated files under `hw/`, never
committed), from its root:
```
python3 tools/uov.py profile --profile 128
# One parameter set and one tier: Ip at bngfaes.
# Parameter sets: Ip, Is, Ip3. Tiers: bngfaes, bngfonly, bnaesonly, sw.
./bazelisk.sh build "//sw/acc/crypto/handwritten/uov/dmem_large/keygen_sp/ov-Ip-pkc+skc:ov-Ip-keygen_sp_bngfaes"
python3 tools/gather_kat_stats.py --ops keygen --params Ip --tiers bngfaes --variants sp --cases 0
```
For another choice, change the parameter set (twice in the build label, once in `--params`) and the
tier (in the label and in `--tiers`). It prints PASS and the cycles.
`python3 tools/uov.py profile --profile 32` switches back. Every arm and the restart driver:
[../keygen_min/README.md](../keygen_min/README.md#how-to-run).

## Files

- Kernels: `ov-<P>-keygen_sp.s` (bngfaes, bngfonly) and `ov-<P>-keygen_sp_sw.s` (sw, bnaesonly).
- Driver: `../tests/test_oneshot_keygen.py --variant sp` with `--param Ip`, `Is` or `Ip3`.
