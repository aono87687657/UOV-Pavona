# keygen_min and keygen_sp: UOV key generation in one EXECUTE (128 KiB DMEM)

Last updated: 2026-11-17: chip tables from the rerun rtl-2026-11; the chip tests copy their data faster.

## TL;DR
- One EXECUTE produces the whole public key: the host writes `sk_seed`, executes, and reads `cpk`
  and `csk`. No control block, no windows for the host to assemble. For Ip, Is and Ip3, four tiers.
- Two families: `_min`, the smallest footprint under this contract, and `_sp`, a single pass over
  P1, which is faster and larger.
- They need more than the 32 KiB DMEM and are measured at the 128 KiB profile; the 32 KiB shipping
  keygen is `../../dmem32k/keygen_stream/`.
- Cycles and memory: [Numbers](#numbers).

## How to run
In a clone of its own, from its root:
```
python3 tools/uov.py profile --profile 128
# One parameter set, one tier and one family: Ip at bngfaes, keygen_min.
# Parameter sets: Ip, Is, Ip3. Tiers: bngfaes, bngfonly, bnaesonly, sw. Families: min, sp.
./bazelisk.sh build "//sw/acc/crypto/handwritten/uov/dmem_large/keygen_min/ov-Ip-pkc+skc:ov-Ip-keygen_min_bngfaes"
python3 tools/gather_kat_stats.py --ops keygen --params Ip --tiers bngfaes --variants min --cases 0
```
For another choice, change the parameter set (twice in the build label, once in `--params`), the tier
(in the label and in `--tiers`) and the family (`keygen_min` twice in the label and `--variants min`, or
`keygen_sp` and `sp`). It prints PASS and the cycles.

Every arm, step by step:

1. Profile: `python3 tools/uov.py profile --profile 128` (back: `--profile 32`). It switches the
   clone (never commit the switch) to the 128 KiB DMEM profile (130,048 B bus-visible and 1 KiB
   of scratch) and regenerates every derived file.
2. Build:
   ```
   ./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem_large/keygen_min/... \
       //sw/acc/crypto/handwritten/uov/dmem_large/keygen_sp/... \
       //sw/acc/crypto/handwritten/uov/dmem_large/keygen_min/ov-Ip3-pkc+skc:all \
       //sw/acc/crypto/handwritten/uov/dmem_large/keygen_sp/ov-Ip3-pkc+skc:all
   ```
3. ISS, one arm (the driver is `../tests/test_oneshot_keygen.py`; the ELF is `ov-<P>-keygen_<min|sp>_<tier>.elf` in
   `keygen_min` or `keygen_sp`, each parameter set in its `ov-<P>-pkc+skc/` subfolder):
   ```
   python3 sw/acc/crypto/handwritten/uov/dmem_large/tests/test_oneshot_keygen.py --variant sp --param Ip \
     --elf bazel-bin/sw/acc/crypto/handwritten/uov/dmem_large/keygen_sp/ov-Ip-pkc+skc/ov-Ip-keygen_sp_bngfaes.elf \
     --cases 0 --tier bngfaes --poison --stats
   ```
   - `--elf`: the built app to run.
   - `--cases 0`: the KAT case (`0`, `0,11` or `0-11`, default 0). Case 0 checks one key pair; for Ip3 all
     12 ladder cases share one key pair. The driver then runs a second key B on the same simulator,
     with no reload: `_min` for Ip and Is runs A -> B, `_sp` runs A -> B -> A, and the Ip3 `_min` runs
     A -> A -> B -> A (its second run is the next ladder case, the same key). B is the next case of the
     file for Ip and Is, and case 0 of `--vectors2` for Ip3. `tools/gather_kat_stats.py` runs each case once,
     without B.
   - `--tier bngfaes`: refuse unless the ELF's symbol fingerprint is that tier.
   - `--poison`: fill the working buffers with 0xA5 before the first run; `--poison-return` (`_sp`)
     poisons them again before the last A.
   - `--stats`: print instructions and cycles per run; `--dump-stats FILE` writes the ISS
     statistics, one labelled record per run.
   - `--vectors2 FILE` (Ip3): its case 0 is the second key pair B (default
     `testvectors-Ip3-pkc-skc.nistkat`).

   Or the Ip and Is `_min` cells of a tier through the KAT tool: `python3 tools/gather_kat_stats.py --ops keygen --params Ip,Is --cases 0 --tiers bngfaes --variants min`
   (`sp` for the single-pass family).
4. Chip model (Verilator): `tools/rtl_campaign.sh --profile 128` runs the 36 one-shot tests (24
   keygen, 12 verify full); `--cells "acc_uov_keygen_sp_is_bngfaes_test ..."` selects some,
   `--help` lists every option, and `sw/device/tests/acc_uov/README.md` describes the run. The
   software-GF tests take many hours each.

## What it does
- `_min` processes the oil columns in the narrowest window (2 for Ip and Is, 1 for Ip3) and expands
  the P1 stream from `pk_seed` again for every window: 22, 32 and 45 passes.
- `_sp` expands every row once and folds it into all oil columns. The P3 accumulator is the upper
  triangle in 64 B cells (`tri`, overlaying the payload), packed in place into the 44 B or 45 B
  slots at the end (Ip, Ip3), or the payload of 32 B slots itself (Is). It saves the repeated
  expansions, with their key schedules and folds; on bngfonly those were most of `_min`'s cycles.

Neither is a proven optimum: `_sp` is the fastest and `_min` the smallest of the implementations
measured here.

## Numbers
Written by `python3 tools/uov.py tables` from the records in `../../results/`; do not edit.

<!-- table:iss:keygen/sp@128 -->
| DMEM | tier | Ip | Is | Ip3 |
|---|---|---:|---:|---:|
| 128 KiB | bngfaes | 1,652,219 | 2,227,917 | 2,079,442 |
| 128 KiB | bngfonly | 9,695,178 | 12,105,812 | 12,013,022 |
| 128 KiB | bnaesonly | 34,490,226 | 33,701,433 | 40,381,198 |
| 128 KiB | sw | 54,739,132 | 58,898,137 | 65,324,077 |

ISS cycles of one key generation (a single EXECUTE), 128 KiB DMEM profile; the same in all 12 KAT cases.
Every case passed. Measured 2026-11-01 to 2026-11-02 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss:keygen/sp@128 -->

<!-- table:iss-speedup:keygen/sp@128 -->
Times faster than sw (sw cycles / tier cycles), ISS

| DMEM | tier | Ip | Is | Ip3 |
|---|---|---:|---:|---:|
| 128 KiB | bngfonly | 5.65x | 4.87x | 5.44x |
| 128 KiB | bnaesonly | 1.59x | 1.75x | 1.62x |
| 128 KiB | bngfaes | 33.1x | 26.4x | 31.4x |

The cycles of the KAT cases added up per row, sw divided by the tier. -: no run of that tier.
ISS, 128 KiB DMEM profile. Measured 2026-11-01 to 2026-11-02 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-speedup:keygen/sp@128 -->

<!-- table:iss:keygen/min@128 -->
| DMEM | tier | Ip | Is | Ip3 |
|---|---|---:|---:|---:|
| 128 KiB | bngfaes | 3,556,610 | 4,387,367 | 6,803,420 |
| 128 KiB | bngfonly | 97,267,260 | 146,014,215 | 249,596,240 |
| 128 KiB | bnaesonly | 37,928,618 | 36,667,175 | 46,034,420 |
| 128 KiB | sw | 273,832,014 | 398,599,767 | 655,628,991 |

ISS cycles of one key generation (a single EXECUTE), 128 KiB DMEM profile; the same in all 12 KAT cases.
Every case passed. Measured 2026-11-01 to 2026-11-02 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss:keygen/min@128 -->

<!-- table:iss-speedup:keygen/min@128 -->
Times faster than sw (sw cycles / tier cycles), ISS

| DMEM | tier | Ip | Is | Ip3 |
|---|---|---:|---:|---:|
| 128 KiB | bngfonly | 2.82x | 2.73x | 2.63x |
| 128 KiB | bnaesonly | 7.22x | 10.9x | 14.2x |
| 128 KiB | bngfaes | 77x | 90.9x | 96.4x |

The cycles of the KAT cases added up per row, sw divided by the tier. -: no run of that tier.
ISS, 128 KiB DMEM profile. Measured 2026-11-01 to 2026-11-02 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:iss-speedup:keygen/min@128 -->

On the chip model, exec+wait of one test per cell (every meter and every timed run:
`sw/acc/crypto/handwritten/uov/results/CHIP-MATRIX.md`):

<!-- table:rtl-cycles:keygen/sp@128 -->
| DMEM | tier | Ip | Is | Ip3 |
|---|---|---:|---:|---:|
| 128 KiB | bngfaes | 1,652,759 | 2,228,489 | 2,080,056 |
| 128 KiB | bngfonly | 9,695,746 | 12,106,400 | 12,013,616 |
| 128 KiB | bnaesonly | 34,490,780 | 33,702,027 | 40,381,785 |
| 128 KiB | sw | 54,739,684 | 58,898,684 | 65,324,623 |

exec+wait in Ibex cycles. Chip RTL under Verilator, 128 KiB DMEM profile, the accepting run of each test. Measured 2026-11-15 to 2026-11-17 at `de52799642` (rtl-2026-11).
<!-- /table:rtl-cycles:keygen/sp@128 -->

<!-- table:rtl-speedup:keygen/sp@128 -->
Times faster than sw (sw cycles / tier cycles), chip, exec+wait

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 128 KiB | keygen | sp | Ip | 5.65x | 1.59x | 33.1x |
| 128 KiB | keygen | sp | Is | 4.87x | 1.75x | 26.4x |
| 128 KiB | keygen | sp | Ip3 | 5.44x | 1.62x | 31.4x |

exec+wait: Ibex cycles over EXECUTE and the wait for the ACC to finish, summed over the phases. -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-15 to 2026-11-17 at `de52799642` (rtl-2026-11).
<!-- /table:rtl-speedup:keygen/sp@128 -->

<!-- table:rtl-speedup-op:keygen/sp@128 -->
Times faster than sw (sw cycles / tier cycles), chip, whole operation

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 128 KiB | keygen | sp | Ip | 5.62x | 1.59x | 32x |
| 128 KiB | keygen | sp | Is | 4.84x | 1.75x | 25.5x |
| 128 KiB | keygen | sp | Ip3 | 5.41x | 1.62x | 30.5x |

The whole operation: from the first input write to the last result read, the host's transfers included (for the stream keygens, tuned and stream_uniform, also the host's fold; in the verify full tests this run also installs the key). -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-15 to 2026-11-17 at `de52799642` (rtl-2026-11).
<!-- /table:rtl-speedup-op:keygen/sp@128 -->

<!-- table:rtl-cycles:keygen/min@128 -->
| DMEM | tier | Ip | Is | Ip3 |
|---|---|---:|---:|---:|
| 128 KiB | bngfaes | 3,557,153 | 4,387,913 | 6,804,005 |
| 128 KiB | bngfonly | 97,267,853 | 146,014,768 | 249,596,848 |
| 128 KiB | bnaesonly | 37,929,188 | 36,667,714 | 46,034,993 |
| 128 KiB | sw | 273,832,619 | 398,600,301 | 655,629,584 |

exec+wait in Ibex cycles. Chip RTL under Verilator, 128 KiB DMEM profile, the accepting run of each test. Measured 2026-11-15 to 2026-11-17 at `de52799642` (rtl-2026-11).
<!-- /table:rtl-cycles:keygen/min@128 -->

<!-- table:rtl-speedup:keygen/min@128 -->
Times faster than sw (sw cycles / tier cycles), chip, exec+wait

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 128 KiB | keygen | min | Ip | 2.82x | 7.22x | 77x |
| 128 KiB | keygen | min | Is | 2.73x | 10.9x | 90.8x |
| 128 KiB | keygen | min | Ip3 | 2.63x | 14.2x | 96.4x |

exec+wait: Ibex cycles over EXECUTE and the wait for the ACC to finish, summed over the phases. -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-15 to 2026-11-17 at `de52799642` (rtl-2026-11).
<!-- /table:rtl-speedup:keygen/min@128 -->

<!-- table:rtl-speedup-op:keygen/min@128 -->
Times faster than sw (sw cycles / tier cycles), chip, whole operation

| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |
|---|---|---|---|---:|---:|---:|
| 128 KiB | keygen | min | Ip | 2.81x | 7.21x | 75.8x |
| 128 KiB | keygen | min | Is | 2.73x | 10.8x | 89.1x |
| 128 KiB | keygen | min | Ip3 | 2.63x | 14.2x | 95.5x |

The whole operation: from the first input write to the last result read, the host's transfers included (for the stream keygens, tuned and stream_uniform, also the host's fold; in the verify full tests this run also installs the key). -: no test of that tier.
Chip RTL under Verilator, the accepting run of each test. Measured 2026-11-15 to 2026-11-17 at `de52799642` (rtl-2026-11).
<!-- /table:rtl-speedup-op:keygen/min@128 -->

<!-- table:mem:keygen/sp@128 -->
| DMEM | tier | Ip | Is | Ip3 |
|---|---|---:|---:|---:|
| 128 KiB | bngfaes | 6,144 / 87,776 | 3,596 / 81,088 | 9,148 / 91,008 |
| 128 KiB | bngfonly | 6,880 / 88,544 | 4,416 / 81,248 | 10,060 / 91,776 |
| 128 KiB | bnaesonly | 5,980 / 89,024 | 3,936 / 81,344 | 8,132 / 91,488 |
| 128 KiB | sw | 5,924 / 92,512 | 4,668 / 85,408 | 8,876 / 95,776 |

Bytes of the ELFs the ISS ran at the 128 KiB DMEM profile: code / `_dmem_bss_end` (the end of the linked data and bss).
Measured 2026-11-01 to 2026-11-02 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:mem:keygen/sp@128 -->

<!-- table:mem:keygen/min@128 -->
| DMEM | tier | Ip | Is | Ip3 |
|---|---|---:|---:|---:|
| 128 KiB | bngfaes | 6,188 / 60,224 | 3,376 / 77,248 | 9,044 / 60,352 |
| 128 KiB | bngfonly | 6,924 / 60,992 | 4,188 / 77,408 | 9,956 / 61,120 |
| 128 KiB | bnaesonly | 6,088 / 61,472 | 3,732 / 77,504 | 8,064 / 60,832 |
| 128 KiB | sw | 6,032 / 64,960 | 4,464 / 81,568 | 8,808 / 65,120 |

Bytes of the ELFs the ISS ran at the 128 KiB DMEM profile: code / `_dmem_bss_end` (the end of the linked data and bss).
Measured 2026-11-01 to 2026-11-02 at `7ca6de3b2e` (iss-2026-10j).
<!-- /table:mem:keygen/min@128 -->

The 1 KiB scratch is separate from the DMEM end; the stack and every working frame lie inside it.
INIT's key-expansion frame overlays a buffer that is idle in that phase (`slice` for Ip and Is
`_min`, `tri` for Ip `_sp`, the end of the payload for Is `_sp`, `p1buf` for Ip3); the later phases
use the fixed `frame`. The software-GF arms add a private stack in the image (`swstack`,
`swframe`), and the Ip3 bngfonly arms keep the stack of the software-AES leaf in the image below
`kg_stack_top`. Is cannot go below 64 KiB under this contract: its cpk alone is 66,576 B. For
comparison, a 64 KiB DMEM has 64,512 B visible on the bus; these kernels were run at the 128 KiB
profile only.

## Host contract
For a C caller (chip test, cryptotest firmware). Every arm speaks the same contract; only the app
name changes.

1. Load the app (`acc_testutils_load_app`).
2. Write the 32-byte secret seed at `sk_seed`.
3. One EXECUTE; wait for done; `ERR_BITS` must be 0.
4. Read `cpk_len` bytes from `cpk`: the 16-byte `pk_seed` followed by the packed upper-triangular
   P3. `csk` is the same buffer as `sk_seed`: the unchanged 32-byte seed, not an expanded secret
   key.

| param | `cpk_len` | seed |
|---|---:|---:|
| Ip | 43,576 | 32 |
| Is | 66,576 | 32 |
| Ip3 | 46,591 | 32 |

- Addresses come from the exported symbols: `ACC_DECLARE_SYMBOL_ADDR(<app>, sk_seed)`,
  `(<app>, csk)`, `(<app>, cpk)` with `ACC_ADDR_T_INIT`. These are ACC DMEM addresses (what
  `acc_testutils_write_data` and `read_data` take), not offsets into the bus window. `sk_seed` (and
  `csk`) is at ACC address 0, a valid offset: pass the symbol addresses through as they are.
- There is no control block and no window protocol: this is not a drop-in replacement for a
  handler of the streamed keygen (INIT and WINDOW phases, host fold).
- The same loaded image can run again with another seed. The chip tests of the hardware-GF arms
  (bngfaes, bngfonly) run A -> B -> A on one image; those of the software-GF arms make the
  accepting run only.
- A digest of the public key covers exactly these `cpk_len` bytes, `pk_seed` included, and nothing
  past the end (Ip and Ip3 keep a zero guard behind `cpk`). Ip3 is not a whole number of words:
  read `ceil(cpk_len / 4)` words and use `cpk_len` bytes.
- The cryptotest wire path supports Ip and Is; Ip3 is for other C callers.

App names (underscore twins of the hyphenated targets, the same image): `ov_<P>_keygen_<min|sp>_<tier>`,
with `<P>` = `Ip`, `Is`, `Ip3` and `<tier>` = `bngfaes`, `bngfonly`, `bnaesonly`, `sw`.

## Files
| file | role |
|---|---|
| `ov-<P>-pkc+skc/ov-<P>-keygen_min.s` | `_min`, hardware-GF arms: bngfaes (`-DAES_INSTRUCTIONS -DGF_INSTRUCTIONS`), bngfonly (`-DGF_INSTRUCTIONS`) |
| `ov-<P>-pkc+skc/ov-<P>-keygen_min_sw.s` | `_min`, software-GF arms: sw (T-table AES) and bnaesonly (hardware AES through the batched `uov/shared/aes_hw` leaf since 2026-10-13, before that the single-block memory-key leaf; software GF); Ip and Is select the arm by the linked AES leaf, Ip3 also passes `-DAES_INSTRUCTIONS` |
| `../keygen_sp/ov-<P>-pkc+skc/ov-<P>-keygen_sp.s` | single pass, bngfaes and bngfonly arms (Is: the payload of 32 B slots is the accumulator, no pack) |
| `../keygen_sp/ov-<P>-pkc+skc/ov-<P>-keygen_sp_sw.s` | single pass, sw and bnaesonly arms (arm by the linked AES leaf; Ip3 also passes `-DAES_INSTRUCTIONS`) |
| `ov-<P>-pkc+skc/BUILD` (each family) | the `acc_binary` targets; the AES backends and `expandsk_ret_O_pkseed` come from `../../shared/keygen/` and `../../shared/keygen/ov-Ip3-pkc+skc/` |
| `../tests/test_oneshot_keygen.py` | the restart driver of `_min` and `_sp` (`--variant`, `--param`): tier fingerprint, ELF hash, poison, restarts without reload (`_min` A -> B, Ip3 A -> A -> B -> A; `_sp` A -> B -> A with distinct seeds, the last A a natural restart), the 8 B guard after cpk (Ip, Ip3; Is has none) |

Ip3 has its own README in `ov-Ip3-pkc+skc/` and `../keygen_sp/ov-Ip3-pkc+skc/`.

## Notes
- In `_sp` on Ip and Ip3, stage 2 keeps `_min`'s visiting order (T column c resident, k over all O
  columns); the destination cell is tri(min(k,c), max(k,c)), so each off-diagonal slot receives its
  two terms from two visits and the diagonal one. The guard bytes after cpk lie inside `tri` and
  are zeroed again after the pack; Is writes its payload directly.
- `gather_kat_stats.py` runs prebuilt ELFs: build first, or it passes on stale binaries at stale cycles.
- A PASS means that after every run the driver makes, the cpk matches the fixture byte for byte and
  the 32-byte seed at `csk` (the `sk_seed` buffer) is unchanged. The separate Round-3 reference check
  (Ip3) and its limits are in [test-data provenance](../../../test_data/README.md#notes).
