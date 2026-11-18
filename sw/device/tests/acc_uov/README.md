# acc_uov: UOV on the chip model

Last updated: 2026-10-20: the KAT check runs `tools/gather_kat_stats.py` (`kat_check.sh` left tools/).

## TL;DR
- Chip-level tests for UOV keygen, verify and sign: Ibex boots from ROM, drives the ACC over TL-UL
  and checks the result against reference vectors held in Ibex memory (KAT vectors for Ip and Is;
  for Ip3, vectors recorded with a pre-release Round-3 reference implementation and confirmed by
  the Round-3 reference implementation). They run under Verilator.
- 96 tests: 60 at the 32 KiB DMEM profile and 36 one-shot tests at the 128 KiB profile.
- One test: the `bazelisk.sh test` line below. All of a profile: `tools/rtl_campaign.sh --profile 32`.
- Numbers: `sw/acc/crypto/handwritten/uov/results/CHIP-MATRIX.md`, the speed-ups in `COMPARISONS.md`
  next to it, and the Numbers section of each kernel directory's README.

## How to run
One test:

    ./bazelisk.sh test --test_output=streamed --//hw:make_options=-j,8 \
      //sw/device/tests/acc_uov:acc_uov_sign_is_bngfaes_test_sim_verilator

All tests of a profile:

    tools/rtl_campaign.sh --profile 32          # the 60 tests at 32 KiB
    tools/rtl_campaign.sh --profile 128         # the 36 one-shot tests (the tree must be at the 128 KiB profile)

- `--profile 128` runs in a clone of its own switched with `python3 tools/uov.py profile --profile 128`
  (it rewrites 17 generated files under `hw/`; never commit them). There are no chip tests at 512 KiB.
- The targets are tagged `manual`, so a `:all` wildcard matches nothing ("Found 0 test targets"):
  name them, or use `rtl_campaign.sh`, which builds, checks and runs the tests of a profile detached
  and keeps each result with the event log of its build in `chip-matrix/rtl-<32|128>k-<stamp>/`.
  `--cells "<test> ..."` selects some, `--jobs N` and `--threads T` set the parallelism,
  `--dry-run` stops after the checks, `--help` lists every option. The parallelism changes the wall
  time and resource use; simulated counts should be compared for the same build, inputs and protocol.
  A run has finished cleanly when its `DONE` file reads
  `collector_exit=0 postcheck_exit=0 archive_exit=0`; `--verify-only <run directory>` checks that
  and the file inventory, and `--collect-only <run directory>` reads the results of a finished run
  again.
- Verilator is fetched by Bazel at a pinned version (`third_party/verilator/extensions.bzl`), so the
  installed one does not matter, but the first build needs network access.
- Keep `--//hw:make_options` the same between runs: changing it switches Bazel's configuration,
  which points `bazel-testlogs` at another directory and makes measured tests look as if they had
  never run.
- Time limit: the repository's `.bazelrc` ends a test after 7200 s, and the software-GF tests run
  longer (`rtl_campaign.sh` sets its own limit). By hand, pass `--test_timeout=<seconds>` above the
  expected run time. A single number applies to every size class; four numbers are
  `short,moderate,long,eternal`, with `-1` keeping a class's default. A bare `-1` does not mean
  "no limit": it replaces the repository's 7200 s by Bazel's built-in 3600 s.
- From a finished run to the tables: `python3 tools/uov.py rtl-import` publishes the run
  directories into `sw/acc/crypto/handwritten/uov/results/`, and `python3 tools/uov.py tables`
  rewrites the chip matrix there and the README tables (`tools/README.md`).

## The tests
Each is `//sw/device/tests/acc_uov:<name>_sim_verilator`, named
`acc_uov_<op>_<family>_<param>_<tier>_test`; sign has no family part
(`acc_uov_sign_ip_bngfaes_test`). Parameter sets `ip`, `is`, `ip3`; tiers `bngfaes` (GF-multiply
and AES instructions), `bngfonly` (GF-multiply instruction, AES in software), `bnaesonly` (AES
instructions, GF in software), `sw` (neither).

| profile | op | family | tests |
|---|---|---|---:|
| 32 KiB | keygen | `stream` (the shipping kernel) | 12 |
| 32 KiB | keygen | `stream_uniform` (one outer, swapped backends) | 12 |
| 32 KiB | verify | `stream` (the shipping kernel) | 12 |
| 32 KiB | verify | `stream_uniform` | 12 |
| 32 KiB | sign | (none; printed `ldirect`) | 12 |
| 128 KiB | keygen | `sp` (single pass) | 12 |
| 128 KiB | keygen | `min` (smallest footprint) | 12 |
| 128 KiB | verify | `full` (the whole key resident) | 12 |

Round 3 (`ip3`): the same three drivers; the generated headers carry the Round-3 geometry and host
map. The keygen headers are named by window width, not by tier:
`keygen_stream_ip3_wj6_testvec.h` for the hardware-GF arms (bngfaes, bngfonly) and `_wj5` for the
software-GF arms (bnaesonly, sw) and every uniform arm. `verify_ip3_testvec.h` is case 11 (a
1024 B message); its two windows are exactly the kernel's 23,968 B `msgwin` (read-ahead slack past
it would run into the bngfonly arm's data), and the 135 B signature goes into a 160 B slot. `sign_ip3_testvec.h` is case 0; the sign app is
`//sw/acc/crypto/handwritten/uov/dmem32k/sign_rtl/ov-Ip3-skc:ov_Ip3_sign_rtl_<tier>_0`, whose test-vector
library holds the salt in `salt_input` (the driver writes it too). Regenerate with
`gen_*_testvec.py --param Ip3` (keygen and verify need `--elf`; see each script's docstring).

## What each number is
One `meters v2` line per timed run; `tools/gather_chip_matrix.py` reads them. At 32 KiB the ACC
instruction counts (total and per phase) must equal `expected_insn_counts_32k.csv`, or the run fails. The KAT
comparisons and the test's own log output come after the meters stop, so console time is in none of
them.

| column | meaning |
|---|---|
| `acc_insn` | the ACC's `INSN_CNT`, read by the host: the instructions the ACC retired. A count, not a timing model |
| `exec_wait` | Ibex `mcycle` over EXECUTE and the done poll, summed over the phases: how long the chip spends in the accelerated operation |
| `host_io_fold` | the host's transfers (inputs, windows, control and status words, results read back) and, for the streamed keygen, its fold; inputs are staged in RAM before the meters and copied a word at a time (`acc_dmem_copy.h`) |
| `op_total_v2` | from the first input write to the last result read: the whole operation |
| `app_load` | the push of the ACC image |
| `whole_test_cycles` | Verilator's "Executed cycles" for the whole test, with ROM boot, UART output and the untimed negative runs: context only |

Compare within a column, never across. The speed-up of a keygen depends on where the boundary is
drawn (the host's fold is an Ibex cost no accelerator touches), so
`sw/acc/crypto/handwritten/uov/results/COMPARISONS.md` gives it for `exec_wait` and for the whole
operation, one table each. Ratios of cycles and of
instructions differ by the cycles per instruction of each tier: memory operations cost 2 cycles,
and the tiers have different instruction mixes.

## Cross-checks
**ISS against chip.** For the keygen and verify tests the ACC's instruction count on the chip must
equal that of the ISS run of the same ELF and case; the chip matrix (Against the ISS) shows it per
test, with the cycles by which `exec_wait` lies above the ISS. That difference includes host command
and polling overhead per ACC invocation (INIT and one per window); the measured gap is specific to
the test and timing boundaries. To repeat the ISS side by hand, build first: the ISS runs prebuilt
ELFs, and a stale one passes at stale cycles:

    ./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/... \
                        //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream_uniform/...
    python3 tools/gather_kat_stats.py --ops keygen --params Ip,Is --cases 0                                   # quick check: one key pair
    python3 tools/gather_kat_stats.py --ops verify --params Ip,Is --cases 0,11 --tiers sw,bngfonly,bngfaes --variants stream_uniform

Name the variant: the default verify variant of `gather_kat_stats.py` is `stream`, another kernel than the
`stream_uniform` tests run.

A single ELF directly (`--pqc` takes a value):

    python3 hw/ip/acc/dv/accsim/standalone.py <elf> --pqc 1 --dump-stats /tmp/s

For the `ov-*-sign_rtl*` harnesses `standalone.py` exits 1 with `Run stopped at PC <n+4>, but
_expected_end_addr was <n>` and writes no statistics. That is a mismatch of the checker, not a
failure of the kernel: the harness symbol marks the address of the `ecall`, while the ISS reports
the next PC. Confirm with `--dump-regs` (`STOP_PC == _expected_end_addr`, `x5 == 0`); for
statistics, strip the symbol from a copy: `llvm-objcopy -N _expected_end_addr copy.elf`.

**Fairness gates.** A ratio between two arms measures the backend only if the outer kernel is
identical in every arm (its loaded sections byte for byte, relocations, symbol addresses, the
instructions allowed per tier):

    tools/stream_uniform_gates.sh verify Ip
    tools/stream_uniform_gates.sh verify Is

**Block-level RTL** (sign only) runs the self-contained `sign_rtl` cells on the standalone
simulator:

    ./bazelisk.sh build //hw/ip/acc/dv/smoke_pqc:verilator_acc
    SIM=$(./bazelisk.sh cquery --output=files //hw/ip/acc/dv/smoke_pqc:verilator_acc)
    $SIM --load-elf=bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k/sign_rtl/ov-Ip-skc/ov-Ip-sign_rtl_bngfaes_0.elf

**Negative control.** The tests arrived after the hardware gates, so there is no earlier commit to
check out. The same firmware, run on the Verilator chip model without the two PQC gates that
`ebc8e12438` adds (`AccPQCEn` in `top_egret.hjson` and the fusesoc PQC compile flags in `hw/BUILD`),
failed at INIT with `acc_recov`. This records failure of that configuration; removing both gates
in one experiment does not isolate the effect of either gate alone.

## Correctness oracle
Every driver compares against reference vectors, not against another run of our own code. Keygen checks
`pk_seed` and every packed P3 slot as it becomes final. Verify checks accept on a good signature
and reject (`-1`) on a corrupted one. Sign compares the signature with a value held in Ibex memory,
never read back from the device, and checks a poisoned stack guard.

The negative runs differ by driver, and only keygen runs the full set: keygen exercises a bad
phase, a window geometry out of range and a flipped seed; sign runs a flipped seed and a probe of
the window edge; the streamed verify checks acceptance and rejection for its selected valid and
corrupted signatures, not sensitivity to every input. The one-shot verify also checks signature
flips, length errors, non-zero key padding, a corrupted resident key and a second key (both ways
for Ip and Is).

The `gen_*_testvec.py` scripts here do not generate vectors: they reformat the checked-in
`sw/acc/crypto/handwritten/test_data/testvectors-{Ip,Is,Ip3}-pkc-skc` into C headers (for Ip3 the
second key of the one-shot tests is case 0 of `testvectors-Ip3-pkc-skc.nistkat`). The Ip and Is files come
from the pqm4 reference C implementation built for the host; pqm4 ships only Ip, and the Is vectors
come from the same sources with `params.h` switched to `_OV16_160_64`. Keygen and sign also
reproduce the published KAT case of the pqov project byte for byte on the ISS, and verify accepts
and rejects it correctly on that case. The official Round-3 package was published on 2026-09-28. The recorded
Ip3 and Is reference checks and their exact case coverage are described in
[test-data provenance](../../../acc/crypto/handwritten/test_data/README.md#notes).

## Gotchas
| symptom | cause |
|---|---|
| a `sw` test dies at exactly 3600 s | `--test_timeout=-1` means "Bazel's default", not "no limit"; pass a real number |
| a keygen `sw` test dies at exactly 7200 s | Bazel driven by hand without `--test_timeout`; `rtl_campaign.sh` sets its own limit |
| console lines missing | they are in `test.xml`, not in `test.log` |
| the ISS trapped `ILLEGAL_INSN`: the run ends in tens of cycles, `rc=0`, no message | Use `--pqc 1`; `--pqc 0` also enables PQC because any non-empty value is true. Missing PQC support can trap when an instruction accesses a gated register. Check error registers and expected outputs as well as the exit code; a short run alone is not a PASS |
| the KAT passes but the cycles equal the old ones | a stale prebuilt ELF; rebuild before the ISS run |
| the first assemble that is not cached fails: `acc_as failed ... clang: error: unable to execute command` | the LLVM 22.1.2 `ld.lld` Bazel fetches is linked against `libxml2.so.2`; distributions with libxml2 2.14 or later (`.so.16`, e.g. Ubuntu 26.04) have to provide that soname on the toolchain's `lib/` path |
