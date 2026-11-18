# own_utils: shared Python support layer for the OV/UOV test drivers

Last updated: 2026-10-20: the KAT check runs `tools/gather_kat_stats.py` (`kat_check.sh` left tools/).

## TL;DR
- `run_test.py TEST --param Ip|Is|Ip3 [options]` runs one ISS test: the keygen and sign KAT drivers the
  collector uses, and the tests of the single sign kernels. `run_test.py` alone lists the tests and the
  parameter sets each has; `run_test.py TEST --param P --help` lists a test's options.
- The stream and one-shot drivers under `sw/acc/crypto/handwritten/uov/` (`tests/`) take their reference
  implementations, KAT parsing and DMEM helpers from here. These modules own the DMEM injection, the ISS run,
  the Python reference implementations and the validation.
- Every test runs a prebuilt ELF from `bazel-bin/`: build it first. The harnesses ship a zeroed `.data`, so a
  bare `standalone.py` run measures nothing useful.

## How to run
From the repository root. The sign KAT at the 32 KiB profile; cycles are the line
`ACC executed N instructions in M cycles` in `/tmp/sign_ip/statistics_*.txt`:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip-skc:ov-Ip-sign_ldirect_testvec_bngfaes
python3 sw/acc/crypto/handwritten/own_utils/run_test.py sign --param Ip --tier bngfaes \
  --test-data-file sw/acc/crypto/handwritten/test_data/testvectors-Ip-pkc-skc \
  --cases 0,11 --output-dir /tmp/sign_ip
```
- `--tier {bngfaes,bngfonly,bnaesonly,sw}` picks the ELF name (with `--precompute` the ELFs of
  `../uov/dmem_large/sign_sprec/`: 512 KiB profile, ISS only); `--elf` overrides it; `--debug` adds the 14
  intermediate checkpoints. Case numbers count from 0: message length 0 is case 0, 1024 is case 11. The sweep
  over tiers and parameter sets is `python3 tools/gather_kat_stats.py --ops sign --params Ip,Is,Ip3`.

The keygen KAT of the large families, in a clone of its own at the 128 KiB profile
(`python3 tools/uov.py profile --profile 128`, never committed; keygen full needs `--profile 512`):
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem_large/keygen_min/ov-Ip-pkc+skc:ov-Ip-keygen_min_bngfaes
python3 sw/acc/crypto/handwritten/own_utils/run_test.py keygen --param Ip \
  --elf bazel-bin/sw/acc/crypto/handwritten/uov/dmem_large/keygen_min/ov-Ip-pkc+skc/ov-Ip-keygen_min_bngfaes.elf \
  --tier bngfaes --cases 0 --output-dir /tmp/kg_ip
```
- `--elf` is required: `keygen_<min|sp>/ov-<P>-pkc+skc/ov-<P>-keygen_<min|sp>_<tier>.elf` or
  `keygen_full/ov-<P>-pkc+skc/ov-<P>-keygen_full_bngfaes.elf`. `--tier` refuses an ELF whose symbol fingerprint is
  another tier. Case 0 checks one key pair; more cases check more keys, except for Ip3, whose 12 ladder cases share
  one key pair.

The single sign kernels, Ip and Is: `run_test.py ge|backsub|transpose|matvec_small|expandsk|hash|trimat_eval
--param Ip|Is` at the 32 KiB profile; `matvec_large` and `p1p1to` run the precompute-S kernels of
`../uov/dmem_large/sign_sprec/` (512 KiB profile). Each takes its default ELF from `ov_params.py` (build it
first) and `--iterations`, `--seed`, `--output-dir`.

## Files
| file | role |
|---|---|
| `run_test.py` | the entry point: test name and parameter set to one `*_main()` here |
| `ov_params.py` | `OVParams` dataclass + the `OV_IS` (GF16 v=96 o=64) / `OV_IP` (GF256 v=68 o=44) / `OV_IP3` (Round 3, GF256 v=74 o=45) instances: all sizes, DMEM addresses, default ELF paths |
| `acc_sim_utils.py` | ISS driver (`run_acc_test`), common argparser, `run_test_suite` |
| `dmem_utils.py` | bytes <-> 32-bit DMEM word conversion, injection, extraction, validation |
| `gf_arithmetic.py` | GF(16)/GF(256) reference arithmetic + `ov_publicmap_reference` |
| `ov_pk_utils.py` | KAT vector files (`parse_pkc_test_data_file`), P1\|\|P2 from pk_seed (AES-128-CTR), `expand_compressed_pk`, `compute_shake256_hash` |
| `ov_sign_test_utils.py` | full sign flow (`sign_main`) with `--debug` |
| `ov_keygen_test_utils.py` | keygen sub-ops: P1\*O+P2 and P3 |
| `ov_ge_test_utils.py` | Gaussian elimination + back-substitution (`ge_main`, `backsub_main`) |
| `ov_p1_test_utils.py` | (P1+P1^T)\*O+P2 (`p1p1to_main`) |
| `ov_matvec_test_utils.py` | mat-vec products (`small_matvec_main`, `large_matvec_main`) |
| `ov_hash_test_utils.py` | SHAKE256 / salted message hash |
| `ov_expandsk_test_utils.py` | secret-key expansion sk_seed -> pk_seed + O |
| `ov_transpose_test_utils.py` | matrix transpose |
| `ov_trimat_eval_test_utils.py` | batch quad trimat evaluation |

## Test
No test of its own; exercised via the drivers under `sw/acc/crypto/handwritten/uov/`, e.g. `python3 tools/gather_kat_stats.py --ops verify --params Ip,Is,Ip3`, and `tools/tests/test_kat_drivers.py`.

## Notes
- Injection contract: `build_*_words()` returns a sparse `dict[byte_addr] -> 32-bit word`; keys must come from `OVParams` fields, never hardcoded. To retarget a variant ELF use `dataclasses.replace(OV_IS, default_sign_elf=...)` and override only what differs.
- GF16 is nibble-packed little-endian within each byte (low nibble = element 2k). Report mismatches per element (nibble), so a failure names the element and not just the byte.
- Sign KAT mode shifts every `sign_*_addr` that lives after the message by `params.sign_testvec_offset` (32 B). When debugging a `*_testvec_*.elf`, read addresses from `acc_objdump.py -t <elf>`, not from `ov_params.py`.
- Parallel sweeps must pass an explicit per-cell `--output-dir`: the auto-name is second-granular, so concurrent cells sharing a `test_name` collide and `statistics_0.txt` becomes last-writer-wins (KAT pass/fail still per-cell in the `.log`). Identical cycle counts across different tiers = suspect a collision.
- The `_test_utils` vs `_utils` suffix is naming drift, not a semantic signal.
