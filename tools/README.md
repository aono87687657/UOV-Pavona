# tools: UOV KAT, measurement and table scripts

Last updated: 2026-11-11: the paper tabulars that print `uov-` names, and `claim:gain:what`, name the sets as the paper does: `uov-Ip` is the Round-3 set (`Ip3`), `uov-Ip-r2` the Round-2 set (`Ip`); the variable names keep `Ip` and `Ip3`. Earlier: 2026-11-05: kernel names in `tab-cycles.tex`, `tab-rtl-cycles.tex`, `tab-retrygrid.tex` and `tab-retrymodel.tex` as `\kernel{...}`. Earlier: 2026-11-04: `tab-rtl-cycles.tex` (chip exec+wait beside the ISS table); the 32-byte case is taken only from the vector file the records ran. Earlier: 2026-11-04: `tab-cycles.tex` shows the KAT case with a 32-byte message (`iss:...:m32`), not a range, in millions. Earlier: 2026-11-03: `uov.py paper` writes `tab-contrib.tex`, `tab-cycles.tex` and the checked `claim:` variables. Earlier: 2026-11-02: `uov.py retry` (sign on the retry grid), `gather_kat_stats.py --vectors`, three paper tables.

## TL;DR
| to do | command |
|---|---|
| check kernels against the KAT on the ISS, a few cells, in parallel | `python3 tools/gather_kat_stats.py --ops OPS --params PARAMS [--cases ..] [--tiers ..]` |
| run the chip tests of a DMEM profile under Verilator | `tools/rtl_campaign.sh --profile 32` (or `128`) |
| the fairness gates of a tier comparison | `tools/stream_uniform_gates.sh <op> <param>` |
| record measurements and publish them | `python3 tools/uov.py` (below) |
| rewrite the README tables from the published records | `python3 tools/uov.py tables` |
| write the paper's number file and tabulars from the published records | `python3 tools/uov.py paper --out DIR` (`DIR`: your output directory, relative to where you run the command or absolute; point the paper's LaTeX inputs there; it gets `vars.tex`, one `\DefineVar` per published number, and the generated tabulars) |
| run the tool tests, one file at a time | `python3 tools/tests/test_uov.py` (likewise the other `tools/tests/test_*.py`) |
| measure a sign kernel on the retry grid and publish the record | `python3 tools/uov.py retry --kernel ldirect --publish-to CHECKOUT` (`sprec` in a 512 KiB clone; section below) |
| switch the DMEM profile, only in a clone of its own (it rewrites 17 generated files under `hw/`; never commit them) | `python3 tools/uov.py profile --profile 128` (`512`: ISS only; `32` restores the committed files) |

UOV campaign numbers live in `sw/acc/crypto/handwritten/uov/results/`; their README tables are generated.

`util/acc_build.py` is pavona's and carries one change of ours: an app with `.data` above the
15-bit load-checksum index (only possible above 128 KiB, so ISS only) builds without a load
checksum; every 32 and 128 KiB app gets the same checksum as before.

Tools that left the repo stay in its history; one runs again once restored into `tools/` (it finds
the simulator from there), e.g. `git show eb076dd3ed:tools/measure_stack.py > tools/measure_stack.py`.
The ISS trace and DMEM span observers (`ct_trace.py`, `dmem_span.py`, `trace_equality.py`, `uov.py observe-run`
and `observe-import`) run from a clone at 7aa5580180; `--at` takes a later commit once fetched there. The catalog
and the trace check's simulator and drivers are then those of 7aa5580180; the span check runs each lane clone's
own. Their published records stay in `uov/results/`;
`paper` refuses one that observed other binaries than the newest ISS records, so after a kernel change observe it again.

## What each tool is
| tool | what it is |
|---|---|
| `uov.py` | the one entry point for measurement rounds: plans an ISS round, runs and publishes it, registers and imports chip runs, writes the README tables and the paper's numbers (section below) |
| `gather_kat_stats.py` | runs keygen, sign and verify on the ISS for the chosen parameter sets, tiers, variants and cases; every run must match its KAT; collects instructions and cycles; by default the shortest and the longest case, into a new temporary folder |
| `rtl_campaign.sh` | runs the chip tests of one DMEM profile on the Verilator chip model in the background and archives logs, evidence hashes and a `DONE` line (section below) |
| `gather_chip_matrix.py` | what `rtl_campaign.sh` runs: the chip tests and their `meters v2` lines into CSV; with the expected counts and `--strict`, which `rtl_campaign.sh` passes, a 32 KiB run fails when an instruction count differs; `gather_chip_matrix.py firmware` checks before a chip run that each test firmware embeds exactly its ACC programs, byte for byte |
| `stream_uniform_gates.sh` | the fairness gates of a tier comparison: the outer code identical across the tiers, each tier with only its own instructions (section below) |
| `acc_disasm.py` | disassembles an ACC object or ELF with the instruction database, custom instructions included, whatever the installed objdump prints |

## How to run
`python3 tools/gather_kat_stats.py --ops OPS --params PARAMS [--cases ..] [--tiers ..] [--variants ..]` (PARAMS required: Ip, Is, Ip3 or a comma list),
from the repository root, at the 32 KiB DMEM profile:
```bash
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/... \
    //sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/...
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Is-skc:ov-Is-sign_ldirect_testvec_{bngfaes,bngfonly,sw}
python3 tools/gather_kat_stats.py --ops verify --params Ip,Is            # cases 0,11; tiers sw, bngfonly, bngfaes
python3 tools/gather_kat_stats.py --ops keygen --params Ip --cases 0 --tiers bngfaes   # one cell
python3 tools/gather_kat_stats.py --ops sign --params Is --cases 0,11 --tiers sw,bngfonly
```
- `gather_kat_stats.py` runs prebuilt `bazel-bin` ELFs. Build first: without the
  build the sweep passes on stale binaries at stale cycles (the sign: cycles equal to those before
  an edit). The READMEs of the kernel directories give the build line for each family.
- Cases `0,11` (the shortest and the longest message) are the quick check; `0-11` is everything.
  For keygen, case 0 is the quick check (the message length does not enter keygen); the other cases
  check other keys for Ip and Is, while the 12 Ip3 ladder cases share one key pair.
- One op per line when a variant is named: `variants` applies to the op it belongs to, and the
  other ops would run nothing.
- The `sw` tier is slow: a stream or one-shot keygen at sw is the slowest cell by far (the
  Numbers of the keygen READMEs).
- Unknown tiers, parameter sets and variants are errors; a combination a variant does not have is
  printed as skipped.

The grid:
- ops: `keygen`, `sign`, `verify`
- parameter sets (required): `Ip` (GF(256)), `Is` (GF(16)), `Ip3` (Round 3), or a comma list of them
- tiers: `bngfaes` (`bn.gfmul` and `bn.aes128`), `bngfonly` (`bn.gfmul`, AES in software),
  `bnaesonly` (`bn.aes128`, GF in software; not in the default tier set), `sw` (neither; the
  GF(256) software helpers use `bn.mulv.l`)
- variants (the first is the default):

  | op | at 32 KiB | named, at a larger DMEM profile |
  |---|---|---|
  | `keygen` | `stream`, `stream_uniform` | `min`, `sp` (128 KiB), `full` (512 KiB) |
  | `sign` | `ldirect` | `sprec` (512 KiB) |
  | `verify` | `stream`, `stream_uniform` | `full` (128 KiB) |

The ELFs the drivers load:

| op | ELF name |
|---|---|
| keygen | `ov-<P>-keygen_<stream|stream_uniform|min|sp|full>_<tier>` |
| sign | `ov-<P>-sign_<ldirect|sprec>_testvec_<tier>` (not `ov-<P>-sign_ldirect_<tier>`, which draws a random salt) |
| verify | `ov-<P>-verify_<stream|stream_uniform|full>_<tier>` |

`tools/gather_kat_stats.py` (`elf_of`) gives each one's path.

## Measurement rounds: `tools/uov.py`
Commands run from a repository root with `python3` and the repository's Python requirements. CHECKOUT is the absolute path
of the checkout that receives the records (`sw/acc/crypto/handwritten/uov/results/`), never the tree the command runs in.
COMMIT is the commit the round measures. An ISS plan and a chip registration of one round share a letter by convention
(`iss-YYYY-MMx`, `rtl-YYYY-MMx`); the tools do not tie them together. Every subcommand has `--help`.

```bash
# 1. in a clone at COMMIT with no tracked changes: plan and register, then commit both files in CHECKOUT
python3 tools/uov.py campaign-init --name iss-YYYY-MMx --profiles 32,128,512 --publish-to CHECKOUT
python3 tools/uov.py rtl-init --name rtl-YYYY-MMx --measured-at COMMIT --bazelrc-site FILE --publish-to CHECKOUT
# 2. ISS, one clone per profile at COMMIT (committing in CHECKOUT must not move them)
python3 tools/uov.py profile --profile 128              # 128 and 512 KiB clones only; never commit this
python3 tools/uov.py campaign-run --campaign iss-YYYY-MMx --profile 128 --publish-to CHECKOUT
# 3. chip tests, one clone per profile (32, 128) at COMMIT
tools/rtl_campaign.sh --profile 128
# 4. in a clone at COMMIT with no tracked changes: import each chip profile whole
python3 tools/uov.py rtl-import --campaign rtl-YYYY-MMx --archive /CLONE/chip-matrix/rtl-128k-STAMP --publish-to CHECKOUT
# 5. in CHECKOUT: rewrite the README tables from the records
python3 tools/uov.py tables
```
FILE is the local `.bazelrc-site` the measuring trees used. A record is published once it is listed in the round's
`results/campaigns/NAME.completed.json`; nothing is pushed.
An ISS record holds the sha256 of every input it measured, among them the second-key file of the Ip3 one-shot
verify (`sw/acc/crypto/handwritten/test_data/testvectors-Ip3-pkc-skc.nistkat`).

Refusals (exit 2, the reason printed):
- the plan or registration is not committed in CHECKOUT;
- `campaign-run`, `iss`: HEAD is not the commit `campaign-init` ran at, the tracked changes are not exactly the profile's
  overlay, `.bazelrc-site` differs, or an untracked file sits among the inputs;
- `campaign-init`, `rtl-init`, `rtl-import`: any tracked change; `rtl-import` also at another commit than `rtl-init` ran at;
- a chip run made in a tree with an untracked file, at another commit or `.bazelrc-site`, changed since it finished, or whose
  `DONE` is not `collector_exit=0 postcheck_exit=0 archive_exit=0`;
- a chip profile that is not whole in one call: all 60 tests at 32 KiB or all 36 at 128 KiB, each from exactly one run
  (repeat `--archive`).

`campaign-run` exits 0 when all is published, 1 when a group failed (running it again retries the group as a new run),
2 when stopped. An interrupted publication: ISS, `python3 tools/uov.py publish --run chip-matrix/RUN --publish-to CHECKOUT`
in the clone that ran it; chip, the same `rtl-import` again. Stop a running `campaign-run` with SIGTERM to its process
group: `ps -o pid,pgid,user,args -p PID` shows it; check that the line is your `campaign-run` and that PGID is not 0 or 1,
then `kill -TERM -- -PGID` with that number. Keep the `chip-matrix/` run directories: re-reading a chip record's numbers
needs its run directory.

Rerun only some tests. A group (ISS) is published once under its plan name and a profile (chip) once under its registration name, so re-measuring one needs a new name:
- ISS, one group (one kernel family, tier and parameter set, 12 cases): a new plan with only its profile, committed, then
  `python3 tools/uov.py iss --campaign iss-YYYY-MMy --cohort OP/VARIANT/TIER/PARAM --publish-to CHECKOUT` in that profile's
  clone.
- Chip, some tests: `tools/rtl_campaign.sh --profile 32 --cells "acc_uov_..._test ..."`, a new `rtl-init`, and one
  `rtl-import` whose runs (all at COMMIT and one `.bazelrc-site`) hold every test of the profile exactly once.
Tables take each cell from the round created last that has it. An ISS speed-up or ratio table is left as it is (exit 2)
until every tier of each parameter set it shows comes from one round.

`paper --out DIR` also uses the newest observe record of each kind and refuses one that observed other binaries than
the cycle records next to it.

Retry records: `retry` runs one sign kernel at bngfaes on a vector set whose cases have a known number of retries
(default `retrygrid`: `test_data/testvectors-<P>-pkc-skc.retrygrid`, index `test_data/testvectors-retrygrid-index.csv`),
in this tree, which must be a commit plus exactly the kernel's profile overlay (`ldirect`: 32 KiB, the committed files;
`sprec`: 512 KiB, a clone switched with `profile --profile 512`):
```
python3 tools/uov.py retry --kernel ldirect --publish-to CHECKOUT                # 32 KiB clone
python3 tools/uov.py retry --kernel sprec --publish-to CHECKOUT                  # 512 KiB clone
```
`--params` (default `Ip,Ip3,Is`), `--vectors` (default `retrygrid`), `--workers` (default 12) and `--timeout` (seconds per
case, default 7200) are optional. It builds and freezes the three ELFs, runs `gather_kat_stats.py --vectors` on them and
publishes `results/retry-<profile>-<stamp>-<id>` only if every case passes, every count re-derives from its evidence, the
harness's attempt counter equals the index and no input or frozen ELF changed (exit 0; 1: a case failed; 2: stopped). A
retry record is not part of any round, so it never replaces a published KAT cell. `paper` reads the one record of each
kernel (two are refused) and refuses it unless its ELFs are the images of the published ISS records of the same cells: `tab-retrygrid.tex`
(cycles at 0, 1 and 2 retries, one count over all keys, and what each retry adds, refused unless every retry adds the
same), and with both kernels `tab-retrymodel.tex` (model figures at 32 B: the chance an attempt fails for a uniform
random matrix, average cycles, sprec / ldirect, the fewest retries in one signature from which sprec is cheaper and the
chance of that many). `paper` also writes `tab-uniform-tuned.tex` (stream_uniform and tuned cycles at 32 KiB and their
ratio) and `tab-contrib.tex` (for keygen and verify stream_uniform and sign ldirect at 32 KiB: each backend over sw, and
bngfaes over bngfonly and over bnaesonly, the `both:` variables) and `tab-cycles.tex` (ISS cycles of every kernel,
parameter set and backend at each DMEM size, in millions to 3 figures, for the KAT case with a 32-byte message, the
`m32` variables; `paper` writes nothing if that case is missing or retried, or if the vector file is not the one the
records ran) and `tab-rtl-cycles.tex` (the same layout for the chip RTL's exec+wait at 32 and 128 KiB); both mark
the streamed kernels with a dagger (`uniform`, `tuned`). Kernel names in these two tables, `tab-retrygrid.tex` and
`tab-retrymodel.tex` are written `\kernel{...}`, a macro the paper defines; the other tabulars keep plain names. The tabulars that print `uov-` names call the Round-3 set `uov-Ip` and the Round-2 set `uov-Ip-r2` (`Ip3` and `Ip` in the variable names and everywhere else). The `claim:` variables are the numbers the paper's comparisons quote (the largest uniform / tuned
ratio, the S-buffer sizes and ratios, from `own_utils/ov_params.py` for the parameters); `paper` writes nothing if one
of the comparisons `paper_claims` checks (listed in its docstring) no longer holds.
`tables --check` reports what `tables` would change and changes no file; it only takes the lock
`chip-matrix/.uov-results.lock` (exit 1 if a file would change).

Tables: a tracked Markdown file marks one with `<!-- table:NAME -->` and `<!-- /table:NAME -->` on lines of their own.
NAME is mostly `KIND:OP/FAMILY@PROFILE[:PARAM,...]`, families as in `gather_kat_stats.py` and `gather_chip_matrix.py`
(`keygen/stream@32`, `keygen/min@128`, `sign/ldirect@32`); `iss:all@PROFILE`, `iss-speedup:all`, `iss-retries:all` and
the ratio form `iss-ratio:OP/A@P/B@P` are the other forms. A table whose cells are not all published stays as it is and is
reported (exit 2).

| kind | table |
|---|---|
| `iss`, `iss-speedup` | ISS cycles of a family (row per tier, column per parameter set), or times faster than sw |
| `iss-ratio` | cycles of family A divided by family B |
| `iss-retries`, `iss-retries-speedup` | the KAT cases where signing retried, with cycles or speed-up only |
| `mem` | code bytes, `_dmem_bss_end` and the stack reservation of the measured ELFs |
| `rtl`, `rtl-cycles`, `rtl-runs` | chip meters of each test's accepting run; `exec_wait` alone; every timed run |
| `rtl-speedup`, `rtl-speedup-op` | times faster than sw on the chip: `exec_wait`, or the whole operation |
| `rtl-iss` | each chip test's ACC instruction count against the ISS cases of the same kernel |

## Chip tests: `tools/rtl_campaign.sh`
It checks the DMEM profile, the firmware images and the generated headers, records every hash, then
runs the tests of the profile detached through `gather_chip_matrix.py` (one `meters v2`
line per timed run, results bound to the Bazel event log of that run). At 32 KiB, every test's
ACC instruction counts must equal `sw/device/tests/acc_uov/expected_insn_counts_32k.csv`; a difference
fails the run. Before it starts, `gather_chip_matrix.py firmware` checks that each firmware embeds
exactly its ACC kernels.
`tools/rtl_campaign.sh --verify-only DIR` checks a finished run directory (one clean `DONE` line,
`evidence.sha256` complete and unchanged) and writes nothing; `--help` lists every option.
`gather_chip_matrix.py --dmem32k --collect DIR` (or `--dmem128k`) re-reads a finished collection instead of running:
DIR is its `--out` directory, `RUN/results` in a run of `rtl_campaign.sh` (logs, event log, selection and Bazel exit), and
it rewrites the results csv and `status.json` there. The tests and their meters: `sw/device/tests/acc_uov/README.md`.

## Fairness gates: `tools/stream_uniform_gates.sh`
A KAT that passes is necessary but not sufficient for the tier comparisons: those also need the
proof that the outer kernel is identical in the four arms.
```bash
tools/stream_uniform_gates.sh keygen Ip
tools/stream_uniform_gates.sh verify Is
tools/stream_uniform_gates.sh sign Ip
```
Arguments: the operation (`keygen`, `verify`, `sign`) and the parameter set (`Ip`, `Is`, `Ip3`);
the script builds the four arms itself. It first reads each arm's ELF and outer object once
(instructions, the outer's relocations, the ELF's symbols) and stops if a word has no decoding or
a tool fails. Gates on what was read: the outer's loaded sections identical (name, type, flags,
address, size, alignment, bytes), the relocation tables of those sections identical (and not
empty), shared symbol addresses identical, exactly one provider per `backend_*` symbol, the
instructions allowed per arm, and `check_loop`.

The instructions come from `tools/acc_disasm.py`, which decodes the words of a file with the
instruction database (`hw/ip/acc/data/`), whatever the installed objdump makes of the ACC opcodes.
On its own, for one object or linked ELF (`--elf`):
```bash
python3 tools/acc_disasm.py --elf bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream_uniform/ov-Ip-pkc+skc/ov-Ip-keygen_stream_uniform_bngfaes.elf
```
It prints each executable section word by word (address, word, instruction; symbol names on their
own lines; in an object the operands as stored, before relocation) and the other loaded sections
as hex. Exit status 1 if a word has no decoding, the file holds no instructions, or it is not a
32-bit little-endian RISC-V object or executable whose executable sections are the instruction
memory the loader takes.

## One kernel on its own
```bash
python3 hw/ip/acc/dv/accsim/standalone.py \
    <elf> --pqc 1 --dump-stats /tmp/stats.txt
```
Read `executed N instructions in M cycles` from the statistics file. Use `--pqc 1` for these UOV
ELFs; without it, instructions that need gated PQC registers can trap as `ILLEGAL_INSN`. The flag
takes a value and is true for any non-empty one, so `--pqc 0` also enables PQC. This works for self-contained ELFs. Full kernels and phase-dispatch kernels need their KAT
driver: the harness writes the inputs and, for streamed kernels, sums the runs of the phases.
