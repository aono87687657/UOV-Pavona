# sign_rtl: self-contained sign ELFs for RTL simulation

Last updated: 2026-11-17: Ip3 has the cryptotest binaries too.

## TL;DR
- Sign harnesses that carry their test vector, the compare and the verdict inside the binary:
  `acc_top_sim` loads one ELF and runs it once, with no host to inject inputs or grade the output.
- They fit inside the 31,744 B bus-visible DMEM window at every tier. The chip tests
  (`sw/device/tests/acc_uov`) link the underscore twins.
- ISS tests: 12 `acc_sim_test` targets `ov_{Ip,Is,Ip3}_sign_test_<tier>`, message length 0, built from the
  same harnesses. A test passes when the harness's own compare leaves `x5 = 0`.
- Numbers of the chip tests: `../sign_ldirect/README.md` (Numbers) and,
  for Ip3, `sw/acc/crypto/handwritten/uov/results/CHIP-MATRIX.md`.

## How to run
From the repository root, at the 32 KiB DMEM profile, one test on the ISS (it builds what it needs):

    # One parameter set and one tier: Ip at bngfaes.
    # Parameter sets: Ip, Is, Ip3. Tiers: bngfaes, bngfonly, bnaesonly, sw.
    ./bazelisk.sh test //sw/acc/crypto/handwritten/uov/dmem32k/sign_rtl/ov-Ip-skc:ov_Ip_sign_test_bngfaes

For another choice, change the parameter set (twice in the label) and the tier. All 12 tests, and the
ELFs alone:

    ./bazelisk.sh test //sw/acc/crypto/handwritten/uov/dmem32k/sign_rtl/...
    ./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/sign_rtl/...

Block-level RTL (the simulator needs the PQC build, or every `bn.gfmul.*.acch` is illegal):

    ./bazelisk.sh build //hw/ip/acc/dv/smoke_pqc:verilator_acc
    SIM=$(./bazelisk.sh cquery --output=files //hw/ip/acc/dv/smoke_pqc:verilator_acc)
    $SIM --load-elf=<repo>/bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k/sign_rtl/ov-Is-skc/ov-Is-sign_rtl_bngfaes_0.elf

The simulator forks the ISS for cosimulation, so the `python3` it finds must have the ISS packages
(`semantic_version`, `pyelftools`, `mako`, `hjson`). Without them the run aborts with
`Failed to run command 'initial_secure_wipe': EOF from ISS` and a core dump, which looks like an
RTL failure and is not one.

The verdict of one run, computed on the host:

    python3 sw/acc/crypto/handwritten/uov/dmem32k/sign_rtl/check_sign_run.py \
      --log run.log --rc rc.txt --expected-sig <hex> --param Is --tier bngfaes --msglen 0

On the chip model: `sw/device/tests/acc_uov/README.md` (`acc_uov_sign_{ip,is,ip3}_<tier>_test`).

## What it does
The harness stages the salt of the test vector, calls sign, checks the stack canary, compares the
signature and publishes it in `w0..`. A run gives four signals:
- `x5`: the compare inside the binary (0 pass, -1 signature, -2 stack guard);
- the signature rebuilt on the host from the `w0..` dump;
- the simulator's exit status (the RTL against the ISS in cosimulation);
- the cycle difference to an ISS run.

Only the two byte compares are functional oracles. The cosimulation replays the RTL's own memory
image, so a wrong result that is consistent in both models still matches. The exit status is
meaningful through the stop-PC check: `_expected_end_addr` sits on the PASS `ecall`, so a signature
mismatch ends on the `ecall` of `sign_fail` and the run exits 1.

## Files
| file | role |
|---|---|
| `ov-{Ip,Is,Ip3}-skc/` | one parameter set each: its harness, its `testvectors/` and its BUILD |
| `ov-{Ip,Is}-skc/ov-<P>-skc_sign_rtl.s` | the harness: stage the salt, call sign, check the canary, compare the signature, publish it in `w0..` |
| `ov-Ip3-skc/ov-Ip3-skc_sign_rtl.s` | the Round-3 harness: the same checks for the 135 B signature in a 160 B slot (33 words and a 3-byte tail); no salt staging, the Ip3 vector library defines `salt_input` filled in (the salt sits at byte 119, which no word copy can stage) |
| `ov-<P>-skc/testvectors/` | generated sign-only vectors (cpk and expect_acc removed; [Test vectors](#test-vectors)) |
| `tests/sign_pass.exp`, `BUILD` | the expected registers of the ISS tests, `x5 = 0`, and the BUILD that exports it to the three parameter BUILDs |
| `gen_sign_testvec.py`, `check_sign_run.py` | the vector generator (it stops unless msg_len, msg, sk_seed and sig survive) and the host-side verdict of one run |
| `ov-{Ip,Is}-skc/BUILD` | 48 cells each ({sw,bngfonly,bnaesonly,bngfaes} x 12 message lengths, 0..1024), the chip twins `ov_<P>_sign_rtl_<tier>_0` (message length 0), the cryptotest binaries `ov_<P>_sign_rtl_<tier>_hostfed` and the ISS tests `ov_<P>_sign_test_<tier>` |
| `ov-Ip3-skc/BUILD` | the chip twins `ov_Ip3_sign_rtl_<tier>_0`, the cryptotest binaries `ov_Ip3_sign_rtl_<tier>_hostfed` and the ISS tests `ov_Ip3_sign_test_<tier>` |

## Test vectors
`ov-<P>-skc/testvectors/` holds copies of the shared KAT vectors with `cpk` and `expect_acc` removed. Sign reads only
`msg_len`, `msg`, `sk_seed` and `sig`; the dropped cpk (Ip 43,576 B, Is 66,576 B) is what kept the RTL harness ELF from
fitting the 31,744 B bus-visible DMEM window. Generated files: never edit them by hand. Each parameter folder's BUILD
wraps each file in an `acc_library` named `testvectors-<P>-sign_msglen<N>`.

To regenerate, from the repository root. With no option the generator writes all 25 vector files in place (24 for Ip
and Is, 12 message lengths each, and the Ip3 one, with `salt_input` filled in); from the committed KAT files they come
out identical to the committed vectors:

    python3 sw/acc/crypto/handwritten/uov/dmem32k/sign_rtl/gen_sign_testvec.py

One file: `--param` (`Ip`, `Is` or `Ip3`), `--msglen` (the KAT case's message length) and `--out` (the `.s` file to
write), all three together:

    python3 sw/acc/crypto/handwritten/uov/dmem32k/sign_rtl/gen_sign_testvec.py \
        --param Ip --msglen 0 --out /tmp/testvectors-Ip-sign_msglen0.s

- Derived from `sw/acc/crypto/handwritten/test_data/testvectors-<P>-pkc-skc` through `convert_pkc_to_asm.py`; the
  generator stops if a needed symbol is lost or a dropped one survives.
- KAT case numbers: message length 0 is case 0, 1024 is case 11.
- `sig` is x followed by the salt: Is 80 + 16 = 96 B, Ip 112 + 16 = 128 B. The harness stages the salt from `sig+80`
  (Is) or `sig+112` (Ip), so sign reproduces the KAT signature.

## Notes
- The stack reservation is the measured peak of the sw tier: the lowest stack pointer over one KAT
  run, Is 8,736 B and Ip 12,544 B below `stack_end` (`tools/measure_stack.py`, in git history at
  eb076dd3ed, on the 32 KiB ELFs `ov-I{s,p}-skc-sign_testvec_test_sw`; it follows x2, not every
  memory access). A 32 B `0xdeadbeef` canary below `stack:` is checked before the signature
  compare, because the kernel rewrites the output buffer at the end and would otherwise hide an
  overflow.
- `_expected_end_addr` must stay on the PASS `ecall`, not on the instruction after it:
  `acc_core_get_stop_pc()` reports the address of the `ecall`. A real cosimulation mismatch returns
  the same status 1; the two differ only in that a stop-PC failure prints a message, while
  `acc_err_get()` returns earlier and silently. Quote `x5` or the verdict of `check_sign_run.py`
  when the byte compare itself has to be stated.
- The ISS stops 4 B past the `ecall`, so the ISS tests build with `-DISS_SIM_TEST`, which leaves the
  label out; a test passes on `x5 = 0` with no error bits set. Without the define the ELFs load the same code and data as before.
- The chip test `acc_uov_sign_ip_bngfaes_test` also probes the edge of the bus window: the last word
  of the 31,744 B window must read back and one word past it must be refused. Block-level RTL
  cannot cover that: `acc_top_sim` loads all 32 KiB through the back door and has no host bus.
- Run in block-level RTL so far (2026-07-29 and 2026-08-01): message lengths 0 and 1024 of the
  bngfaes, bngfonly and sw cells of Ip and Is, each with exit status 0 and, for bngfaes, the
  signature rebuilt from `w0..` equal to the KAT. The other ten message lengths build and have not
  been run.
