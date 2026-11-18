# uov: UOV keygen, sign and verify in ACC assembly

Last updated: 2026-11-02: `dmem_large/keygen_full/` and `dmem_large/sign_sprec/` cover Ip3.

## TL;DR
- The UOV signature scheme in hand-written ACC assembly for three parameter sets (Ip, Is and the
  Round-3 Ip3), with the GF and AES primitives underneath and the shared Python drivers.
- Each operation exists in several kernel families that trade DMEM for cycles, and each family
  builds at up to four tiers, so that the contribution of the instruction extensions can be
  measured. In the KAT sweep (`tools/gather_kat_stats.py`), keygen compares the public key with the fixture
  (the one-run kernels also check that the secret-key seed is unchanged) and sign compares the whole
  signature, made with the fixture's salt. The streamed verify that the sweep runs only checks that
  the selected signatures are accepted. Rejection is tested by
  `dmem32k/verify_stream/tests/measure_cycles.py` (`--mode functional`, Ip and Is: one flipped signature
  byte on case 0; `--param Ip3 --negative`: one flipped byte per case) and by the full verify. A PASS
  applies to those inputs and
  options. The Round-3 reference checks and their limits are in
  [test-data provenance](../test_data/README.md#notes).
- Check a family: its README. A quick keygen check: the block below.
- Numbers: `results/README.md` (ISS), `results/CHIP-MATRIX.md` (chip model) and
  `results/COMPARISONS.md` (speed-up over sw, kernel against kernel).

## How to run
The host KAT drivers that `tools/gather_kat_stats.py` runs need `numpy` and `galois` on top of
pavona's `python-requirements.txt` (`pip3 install numpy galois`); without them they stop at import.

From the repository root, at the 32 KiB DMEM profile (the committed one):
```
# One parameter set and one tier: Ip at bngfaes.
# Parameter sets: Ip, Is, Ip3. Tiers: bngfaes, bngfonly, bnaesonly, sw.
./bazelisk.sh build "//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Ip-pkc+skc:ov-Ip-keygen_stream_bngfaes"
python3 tools/gather_kat_stats.py --ops keygen --params Ip --tiers bngfaes --variants stream --cases 0
```
For another choice, change the parameter set (twice in the build label, once in `--params`) and the
tier (in the label and in `--tiers`). It prints PASS and the cycles.
Every family README starts its How to run with one parameter set and one tier of its own kernel.

`python3 tools/gather_kat_stats.py --ops OPS --params PARAMS [--cases ..] [--tiers ..] [--variants ..]` runs the KAT of any family on the ISS
(`tools/README.md`); it runs prebuilt ELFs, so build the ELFs it loads first. Without the tier argument it
also runs bngfonly and sw; the sw keygen of Ip and Is takes about 40 minutes on the ISS. The kernels of
`dmem_large/` need a larger DMEM profile, set in a clone of its own (it rewrites 17 generated
files under `hw/`, never committed): `python3 tools/uov.py profile --profile 128`, or `512` (ISS
only), and `--profile 32` to return.

Of the three operations, only sign has `bazel test` targets on the ISS: 12 tests (Ip, Is, Ip3 at four
tiers, message length 0),
`./bazelisk.sh test //sw/acc/crypto/handwritten/uov/dmem32k/sign_rtl/...` (`dmem32k/sign_rtl/README.md`).
Keygen and verify at 32 KiB are streamed: a host driver runs them phase by phase and moves the
public key between the host and DMEM, so one ELF run is one phase; their check is `gather_kat_stats.py`.

## What it does
The UOV families are split by the DMEM they need: `dmem32k/` holds everything that runs in the
32 KiB DMEM, `dmem_large/` the families that need more. The GF, AES and Python support code beside
them sits one level up, in `../`. Every family folder holds one subfolder per parameter set, `ov-<P>-pkc+skc` (keygen),
`ov-<P>-skc` (sign) or `ov-<P>-pkc` (verify), with that set's sources, test vectors and one BUILD for all its tiers,
so a label reads `//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Ip-pkc+skc:ov-Ip-keygen_stream_bngfaes`
and `//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/...` builds the family. The family's README and the test
scripts that serve every parameter set sit on top.

| directory | what |
|---|---|
| `dmem32k/keygen_stream/` | streamed keygen in phases; the shipping keygen (Ip, Is, Ip3) |
| `dmem32k/keygen_stream_uniform/` | one outer kernel with swapped backends, for the tier comparison |
| `dmem32k/sign_ldirect/` | the shipping sign (L-direct) |
| `dmem32k/sign_rtl/` | self-contained sign ELFs for RTL simulation and the chip tests, and their ISS tests |
| `dmem32k/verify_stream/` | streamed verify (INIT, UPDATE per window, FINAL); the shipping verify |
| `dmem32k/verify_stream_uniform/` | the verify counterpart of the tier comparison |
| `dmem_large/keygen_full/` | keygen in one pass over the whole key (512 KiB, ISS only), the reference (Ip, Is, Ip3) |
| `dmem_large/keygen_min/`, `keygen_sp/` | keygen in one EXECUTE (128 KiB): smallest footprint, single pass |
| `dmem_large/verify_full/` | verify in one EXECUTE with the key resident (128 KiB) |
| `dmem_large/sign_sprec/` | sign with a precomputed S (512 KiB, ISS only; Ip, Is, Ip3) |
| `shared/` | kernels and AES/GF leaves used by both the 32 KiB and the large families; `shared/aes_hw/` holds the AES-unit leaves that several operations link |
| `results/` | every published measurement |
| `../gf16/`, `../gf256/` | GF(16) and GF(256) software helpers of the sw-tier kernels, and the GF comparison drivers |
| `../AES_ext/`, `../AES_gf/`, `../AES_table/` | standalone AES-128 references: the `bn.aes128` instructions, `bn.gfmul.8`, T-table |
| `../AES_compare/`, `../GF_compare/` | cycle comparisons of those: a Python runner and its CSV |
| `../own_utils/` | the shared Python layer: ISS driver, DMEM marshalling, GF reference arithmetic, `OVParams`, validators, ELF lookup |
| `../test_data/` | KAT vectors and converters to linkable `.s` data |

## Notes
- Tiers: `bngfaes` uses `bn.gfmul` and `bn.aes128`; `bngfonly` uses `bn.gfmul` with AES in software;
  `bnaesonly` uses `bn.aes128` with GF in software; `sw` uses neither.
- Parameter sets: Ip is GF(256) with v=68, o=44; Is is GF(16) with v=96, o=64; Ip3 is GF(256) with
  v=74, o=45. The 32 KiB DMEM is 31,744 B visible on the bus and 1,024 B of ACC-only scratch.
- Streamed kernels are driven by the host phase by phase and link little or no data of their own;
  a bare simulator run of one executes a single phase.
