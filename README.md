# UOV on Pavona

UOV (Unbalanced Oil and Vinegar) on the ACC coprocessor: 
Supporting ov-Ip and ov-Is key generation, signing, and verification.

For Pavona itself, see the [upstream README](https://github.com/pavona/pavona).

This repository is the artifact of the paper "UOV on ACC: Hardware/Software Co-Design for Post-Quantum
Signatures". It is based on Pavona at commit `285e653a0b` and adds:

- two instruction-set extensions (ISEs) for ACC, `bn.gfmul` and `bn.aes128`,
- implementations of UOV key generation, signing, and verification in ACC assembly,
- tests on the instruction-set simulator (ISS), in an RTL simulation of Egret, and on an FPGA,
- the measurements of the paper and the scripts to repeat them (`tools/`).

The UOV code is in `sw/acc/crypto/handwritten/uov/`: `dmem32k/` for 32 KiB of data memory, which this README
covers first, `dmem_large/` for 128 and 512 KiB, `shared/` for the routines both use, and `consttime/` for the
constant-time checks. Field arithmetic and AES are in `sw/acc/crypto/handwritten/{gf16,gf256,AES_*}/`.

## Names

Names that differ between the paper and the repository:

| Paper | Repository |
|---|---|
| uov-Ip-r2, uov-Is, uov-Ip | `Ip`, `Is`, `Ip3` |
| the baseline (`sw`) and the configurations `bngfonly`, `bnaesonly`, and `bngfaes` (both extensions) | the same four names; the scripts call them tiers |
| key generation, signing, verification for 32 KiB | `keygen_stream`, `sign_ldirect`, `verify_stream`; the result tables call the first and the last `tuned` |
| key generation and verification with shared high-level code | `keygen_stream_uniform`, `verify_stream_uniform` |

## Hardware configurations

Both ISEs work on the 256-bit wide data registers (WDRs) of ACC:

- `bn.gfmul` multiplies in the binary fields GF(16) and GF(256). One WDR holds 64 elements of GF(16)
  (`bn.gfmul.4`) or 32 elements of GF(256) (`bn.gfmul.8`). Every element of the first operand is multiplied by
  one element of the second operand, which the register `mod1` selects, or by the element at the same position
  (`.vv`). With `.acc` or `.acch` the products are added to one of two 256-bit accumulators; `.z` clears the
  accumulator first, and `.inc` increments `mod1` afterwards.
- `bn.aes128` is a group of four instructions that process two 128-bit blocks of AES-128 in one WDR:
  `bn.aes128.encz` adds the key (with `.swap` it first reverses the bytes of the 32-bit counter of each block),
  `bn.aes128.encm` is a middle round, `bn.aes128.encf` is the final round, and `bn.aes128.kf` computes the next
  round key.

Three build flags select the hardware:

| Flag | Effect |
|---|---|
| `gfmacc_bignum` | adds the hardware of `bn.gfmul` |
| `mod_reg_poly` | `bn.gfmul` takes the reduction polynomial from the register `mod0` (`configurable` in the paper). Without this flag the polynomial is fixed (`fixed` in the paper): x^8 + x^4 + x^3 + x + 1 for GF(256) and x^4 + x + 1 for GF(16). |
| `aes_bignum` | adds the hardware of `bn.aes128` |

The UOV code writes the polynomial to `mod0` in either case, so it runs unchanged with and without
`mod_reg_poly`.

The four configurations of the paper differ in the instructions that the software uses:

| Configuration | New instructions used | Flags needed |
|---|---|---|
| `sw` | none | none |
| `bngfonly` | `bn.gfmul` | `gfmacc_bignum` |
| `bnaesonly` | `bn.aes128` | `aes_bignum` |
| `bngfaes` | `bn.gfmul` and `bn.aes128` | `gfmacc_bignum`, `aes_bignum` |

The ISS implements both ISEs, and the RTL simulation of Egret is built with all three flags (`verilator_real`
in `hw/BUILD`), so all four configurations run on both. The bitstreams for the FPGA are listed in the section
"Running testvectors on FPGA".

| File | Content |
|---|---|
| `hw/ip/acc/data/bignum-insns.yml` | definition of the new instructions |
| `hw/ip/acc/rtl/gfmacc.sv` | hardware of `bn.gfmul` |
| `hw/ip/acc/rtl/acc_aes_bignum.sv`, `hw/ip/acc/rtl/aes/` | hardware of `bn.aes128` |
| `hw/ip/acc/acc.core` | build flags `gfmacc_bignum`, `aes_bignum`, `mod_reg_poly` |

## Setup

We used Ubuntu 24.04 on x86-64 with 32 cores and 62 GiB of memory. The system packages are those of Pavona,
see `doc/getting_started/README.md`.

Get the repository with `git clone`, not as a zip file: `tools/uov.py` needs the git repository.

All builds and tests run through `./bazelisk.sh`. The first build downloads Bazel and the LLVM toolchain.

The scripts in the section on reproducing the results also need a Python environment with the packages of
`python-requirements.txt` (we used Python 3.12) and an objdump for RISC-V:

```sh
python3 -m venv .venv && source .venv/bin/activate
pip3 install -r python-requirements.txt --require-hashes
export RV32_TOOL_OBJDUMP="$(./bazelisk.sh info output_base)/external/toolchains_llvm++llvm+llvm_toolchain_llvm/bin/llvm-objdump"
```

## Tests on the instruction-set simulator (ISS)

The ISS is in `hw/ip/acc/dv/accsim/`, the test vectors in `sw/acc/crypto/handwritten/test_data/`.

### Known-answer tests

To check the setup, run known-answer test 0 and the `reject` tests with both extensions:

```sh
./bazelisk.sh test \
  //sw/acc/crypto:uov_nistkat_keygen_stream_bngfaes_{Ip,Is,Ip3}_0 \
  //sw/acc/crypto:uov_nistkat_sign_ldirect_bngfaes_{Ip,Is,Ip3}_0 \
  //sw/acc/crypto:uov_nistkat_verify_stream_bngfaes_{Ip,Is,Ip3}_{0,reject}
```

A test is named `uov_nistkat_<operation>_<implementation>_<configuration>_<parameter set>_<n>`:

| Part of the name | Values |
|---|---|
| `<operation>_<implementation>` | `keygen_stream`, `sign_ldirect`, `verify_stream`, `keygen_stream_uniform`, `verify_stream_uniform` |
| `<configuration>` | `sw`, `bngfonly`, `bnaesonly`, `bngfaes` |
| `<parameter set>` | `Ip`, `Is`, `Ip3` |
| `<n>` | `0` to `11`: number of the known-answer test |
| | `reject` (verification only): signatures with a single bit flipped, under a different public key, and under a corrupted public key must be rejected |

#### Full suite

The full suite has 744 tests and needs about 200 core-hours on our machine. Some tests run for more than
2 hours, so the command raises the time limit that Bazel sets per test:

```sh
./bazelisk.sh test --test_timeout=172800 //sw/acc/crypto:uov_nistkat_dmem32
```

Bazel prints one line with `PASSED` for every test, and its last line ends with `744 tests pass.`

## Reproducing the results

### On the ISS

#### Cycle counts

Build the implementations, then run the measuring script with the operations, parameter sets, test vectors,
and configurations you want:

```sh
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/... \
  //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/... \
  //sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/...
python3 tools/gather_kat_stats.py --ops keygen,sign,verify --params Ip,Is,Ip3 --cases 6 \
  --tiers sw,bngfonly,bnaesonly,bngfaes
```

The script checks every result against the known-answer test and prints one line per run with the cycle
count.

```
sign Ip3 bngfaes ldirect case6: PASS cycles=339472
```

The baseline is slow on the ISS: one key generation takes about 45 minutes.

#### Settings for the results of the paper

| Result | Settings |
|---|---|
| baseline and both extensions, slowest of the 12 test vectors | `--params Is,Ip3 --tiers sw,bngfaes --cases 0-11`. The paper leaves out case 11 of `Is`, which needs two signing attempts. |
| all configurations with 32 KiB for a 32-byte message | the command above. Case 6 is the test vector with a 32-byte message. |
| different sizes of the data memory | the command above with `--tiers bngfaes` for 32 KiB. For 128 and 512 KiB, see below; the paper shows key generation `sp` and `full` with `--tiers bngfaes`. |
| signing with one, two, and three attempts | `--ops sign --tiers bngfaes --vectors retrygrid --cases 0-35`. The 36 cases are 4 keys, messages of 0, 32, and 1024 bytes, and one, two, or three attempts; `sw/acc/crypto/handwritten/test_data/testvectors-retrygrid-index.csv` lists them. With precomputation, switch to 512 KiB (see below) and add `--variants sprec`. |

#### AES-128 comparison

The script measures the key schedule and the encryption of three implementations:

| Name in the output | Implementation |
|---|---|
| `ISE` | with `bn.aes128` |
| `compute-GF` | with `bn.gfmul` |
| `T-table` | in software with lookup tables |

```sh
python3 sw/acc/crypto/handwritten/AES_compare/run_aes_compare.py
```

#### Memory usage

The scripts need two more implementations built. They run every implementation once and record the memory it
uses, which takes a few hours:

```sh
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream_uniform/... \
  //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream_uniform/...
python3 tools/dmem_usage.py run --elf-root bazel-bin --out /tmp/dmem-usage
python3 tools/uov.py mem-usage --elf-root bazel-bin --observed /tmp/dmem-usage
```

The result is `sw/acc/crypto/handwritten/uov/mem-usage/usage.csv`. Its columns `dmem_fixed`, `dmem_stream`,
and `imem` are Fixed, Stream, and IMEM in the paper, which shows the rows with variant `stream` and `ldirect`.

### On the ISS with 128 or 512 KiB of data memory

The implementations for 128 and 512 KiB need an ACC with a larger data memory. `tools/uov.py profile` changes
the size in the hardware files under `hw/`, and `--profile 32` changes it back.

| Data memory | Implementation | Description |
|---|---|---|
| 128 KiB | key generation `min` | single invocation of ACC; processes the columns of O in blocks and regenerates P1 for every block |
| 128 KiB | key generation `sp` | single invocation of ACC; generates P1 once |
| 128 KiB | verification `full` | single invocation of ACC with the whole public key in memory |
| 512 KiB | key generation `full` | as `sp`, and also keeps the matrices P1 O + P2 in memory |
| 512 KiB | signing `sprec` | precomputes the matrices S once per signature |

#### 128 KiB

```sh
# change the data memory of ACC to 128 KiB
python3 tools/uov.py profile --profile 128
# build the implementations for 128 KiB
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem_large/keygen_min/... \
  //sw/acc/crypto/handwritten/uov/dmem_large/keygen_sp/... \
  //sw/acc/crypto/handwritten/uov/dmem_large/verify_full/...
# measure key generation (min and sp) and verification
python3 tools/gather_kat_stats.py --params Ip,Is,Ip3 --tiers sw,bngfonly,bnaesonly,bngfaes --ops keygen \
  --variants min,sp --cases 6
python3 tools/gather_kat_stats.py --params Ip,Is,Ip3 --tiers bngfaes --ops verify --variants full --cases 6
```

#### 512 KiB

```sh
# change the data memory of ACC to 512 KiB
python3 tools/uov.py profile --profile 512
# build the implementations for 512 KiB
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem_large/keygen_full/... \
  //sw/acc/crypto/handwritten/uov/dmem_large/sign_sprec/...
# measure key generation and signing with precomputation
python3 tools/gather_kat_stats.py --params Ip,Is,Ip3 --tiers bngfaes --ops keygen --variants full --cases 6
python3 tools/gather_kat_stats.py --params Ip,Is,Ip3 --tiers bngfaes --ops sign --variants sprec --cases 6
```

### In the RTL simulation

Every test runs one operation in an RTL simulation of Egret with Verilator, driven by a C program on the Ibex
core (`sw/device/tests/acc_uov/`). For example, signing for uov-Is with both extensions:

```sh
./bazelisk.sh test --test_output=streamed --test_timeout=604800 --//hw:make_options=-j,8 \
  --//hw:verilator_options=--threads,4 --test_arg=--verilator-args=+ibex_tracer_enable=0 \
  //sw/device/tests/acc_uov:acc_uov_sign_is_bngfaes_test_sim_verilator
```

A test is named `acc_uov_<operation>_<set>_<configuration>_test_sim_verilator`:

| Part of the name | Values |
|---|---|
| `<operation>` | `keygen_stream`, `sign`, `verify_stream` |
| `<set>` | `ip`, `is`, `ip3` |
| `<configuration>` | `sw`, `bngfonly`, `bnaesonly`, `bngfaes` |

The tests sign the empty message and verify a 1024-byte message. A test prints its cycle counters:

```
meters v2 protocol=accept_negative op=sign param=is family=ldirect tier=bngfaes run=accept acc_insn=256577 exec_wait=284865 host_io_fold=716 op_total_v2=285613 app_load=238536
```

`protocol` names what a test runs. The counters cover the measured runs only; the further checks run after
them and print no counters.

| `protocol` | Measured runs | Further checks |
|---|---|---|
| `accept_only` | one key generation, compared with the expected key | none |
| `accept_negative` | one signature, compared with the expected one | signing with a changed secret seed and with a changed salt must give a different signature |
| `accept_reject` | one verification of a valid signature | a changed signature must be rejected |
| `aba` (128 KiB) | three key generations: seed A, seed B, seed A again | none |
| `verify_oneshot` (128 KiB) | three verifications: a valid signature, a changed one, and the valid one again with the public key still in memory | none |

A test with several measured runs prints one line per run; `run` names the run.

| Counter | Description |
|---|---|
| `op_total_v2` | cycles of the entire operation |
| `exec_wait` | cycles of the execution on ACC |
| `host_io_fold` | cycles the Ibex core spends on transfers and, in key generation, on computing Upper |
| `acc_insn` | instructions executed by ACC, the same number as on the ISS |

| Run | Time |
|---|---|
| first run: download of Verilator and compilation of the simulation model | about 10 minutes |
| the test above | about 4 minutes |
| key generation with the baseline | 3 to 6 hours; the command therefore raises the limit of 2 hours that Bazel sets per test |

#### With 128 KiB of data memory

The tests for 128 KiB need the larger data memory, as on the ISS. They are named
`acc_uov_keygen_sp_<set>_<configuration>_test_sim_verilator` (also `keygen_min`) and
`acc_uov_verify_full_<set>_<configuration>_test_sim_verilator`. For example, key generation and verification
for uov-Ip with both extensions:

```sh
# change the data memory of ACC to 128 KiB
python3 tools/uov.py profile --profile 128
./bazelisk.sh test --test_output=streamed --test_timeout=604800 --//hw:make_options=-j,8 \
  --//hw:verilator_options=--threads,4 --test_arg=--verilator-args=+ibex_tracer_enable=0 \
  //sw/device/tests/acc_uov:acc_uov_keygen_sp_ip3_bngfaes_test_sim_verilator \
  //sw/device/tests/acc_uov:acc_uov_verify_full_ip3_bngfaes_test_sim_verilator
```

The simulation model is compiled again for the new size of the data memory.

### Stored measurements

The cycle counts measured with `gather_kat_stats.py` are stored in `sw/acc/crypto/handwritten/uov/results/`.
`results/README.md` lists the cycle counts of every implementation as the lowest and the highest of the 12
known-answer tests.

## Synthesis results

The reports of the FPGA synthesis with Vivado and of the ASIC synthesis with Genus are stored in `reports/`.
To print the two synthesis tables of the paper from them, in the Python environment of the section "Setup":

```sh
python3 util/gen_synth.py --latex-tables
```

The script also prints the results of one group of modules, or runs the synthesis again.

The group of modules can be selected as one of:

| Option | Description |
|---|---|
| `--aes` | the AES unit of `bn.aes128` alone (`acc_aes_bignum`) |
| `--mul` | the multiplier of `bn.gfmul` alone (`gfmacc`), with the fixed (`mul`) and with the configurable (`mul_reg`) reduction polynomial |
| `--mac` | `acc_mac_bignum` without the multiplier and with each of its two variants |
| `--acc` | `acc_core` without the ISEs, with each variant of the multiplier, with AES, and with AES and each variant of the multiplier |

Further options are:

| Option | Description |
|---|---|
| `--pqc` | with `--mac` or `--acc`: the same modules with the PQC extensions of Pavona enabled |
| `--tool Vivado`, `Genus`, `all` | the results of the FPGA synthesis (`Vivado`, the default), of the ASIC synthesis (`Genus`), or of both |
| `--run_synthesis` | run the synthesis again. This replaces the stored reports in `reports/`, which `--latex-tables` reads. It needs `fusesoc` and the tool. For Genus the script uses `csh` and `tcsh`; first set the path of the Genus setup file in `util/gen_synth.py` and the path of the ASAP7 libraries in `hw/ip/acc/sta/genus_synth.tcl` and `genus_timing.tcl`. |

For example, the results of `acc_mac_bignum` with the PQC extensions of Pavona for both tools, and the same
synthesis run again with Genus:

```sh
python3 util/gen_synth.py --mac --pqc --tool all
python3 util/gen_synth.py --mac --pqc --tool Genus --run_synthesis
```

## Running testvectors on FPGA

This repository provides Bazel targets for building CW340 bitstreams implementing the different hardware configurations explained above:

| `//hw/bitstream/vivado:<name>_test_rom` | `gfmacc_bignum` | `aes_bignum` | `mod_reg_poly` | supports |
|---|---|---|---|---|
| `fpga_cw340` | yes | yes | yes | every backend |
| `fpga_cw340_fixed_poly` | yes | yes | no | every backend |
| `fpga_cw340_gfmacc_only` | yes | no | yes | bngfonly, sw |
| `fpga_cw340_no_ise` | no | no | — | sw |

These bitstreams can be used to test the various UOV implementation variants against the official UOV testvectors.
The software side is one target per variant, parameter set, and operation, each running the 100 pqov KAT cases of that operation (verification: 100 accepts and 100 one-bit rejects):

`//sw/device/tests/crypto/cryptotest:uov_kat_<variant>_<parameter set>_<operation>_fpga_cw340_test_rom`

| `<variant>` | requires |
|---|---|
| `bngfaes` | `gfmacc_bignum`, `aes_bignum` |
| `bngfonly` | `gfmacc_bignum` |
| `bnaesonly` | `aes_bignum` |
| `sw` | — |

`<parameter set>` is `Ip`, `Is`, or `Ip3`; `<operation>` is `keygen`, `sign`, or `verify`.

To run a test, follow these steps, replacing the bitstream and the test target with the pair you want from the tables above:

```sh
BITSTREAM=fpga_cw340   # or fpga_cw340_fixed_poly, fpga_cw340_gfmacc_only, fpga_cw340_no_ise
TEST=uov_kat_bngfaes_Ip_verify   # uov_kat_<variant>_<parameter set>_<operation>

./bazelisk.sh build //hw/bitstream/vivado:${BITSTREAM}_test_rom
./bazelisk.sh run //sw/host/opentitantool -- --interface=cw340 fpga load-bitstream \
  "$PWD/bazel-bin/hw/bitstream/vivado/build.${BITSTREAM}/lowrisc_systems_chip_egret_cw340_0.1/synth-vivado/lowrisc_systems_chip_egret_cw340_0.1.bit"
./bazelisk.sh test --define bitstream=skip --test_output=streamed \
  //sw/device/tests/crypto/cryptotest:${TEST}_fpga_cw340_test_rom
```

## License

Unless otherwise stated, everything in this repository is covered by the
[Apache License, Version 2.0](./LICENSE).
