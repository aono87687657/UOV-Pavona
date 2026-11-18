# testvectors-Ip3-pkc-skc*: provenance

Last updated: 2026-11-02: the reference code signs the ladder, `.nistkat` and retry cases again byte for byte.

Generated 2026-08-19 with **a pre-release Round-3 UOV reference implementation** in which
OV(256,119,45) is a natively supported parameter set (v=74, o=m=45, n=119;
cpk 46,591 B, signature 135 B). At generation, that tree's own KAT output was checked against
the checksum list it ships (recorded here then; the list is not in this repository). It
replaces an earlier provisional set from a Round-2 codebase with the parameters substituted.

| file | cases | message lengths | purpose |
|---|---|---|---|
| `testvectors-Ip3-pkc-skc` | 12 | 0, 1, 2, 4 … 1024 | the default KAT: msglen 0 and the power-of-two ladder; one key pair for all 12 cases |
| `testvectors-Ip3-pkc-skc.nistkat` | 12 of 100 | 33 … 396 (33·i) | the NIST KAT cases 0..11 in this directory's three-line format, byte-exact against the Round-3 known-answer tests of the submission package |
| `testvectors-Ip3-pkc-skc.retry2` | 1 | 32 | a seed whose first vinegar draw yields a singular L: one retry |
| `testvectors-Ip3-pkc-skc.retry3` | 1 | 32 | two retries |
| `testvectors-Ip3-pkc-skc.retryctrl` | 1 | 32 | matched control, no retry: the subtraction baseline |

The `Ip` siblings (`testvectors-Ip-pkc-skc.nistkat`, `.retry2/3`, `.retryctrl`)
are the Round-2 equivalents from the same generation run, so retry cost is
measurable on both parameter sets with one method.

## What a PASS here means, and what it does not

- **Kernel PASS in the KAT sweep (`tools/gather_kat_stats.py`):** keygen compares the public key with the
  fixture (the one-run kernels also check that the secret-key seed is unchanged); sign compares the
  whole signature, made with the fixture's salt; the streamed verify checks that each selected
  signature is accepted. `measure_cycles.py --param Ip3 --negative` is a separate run in which each case must
  reject its signature with one byte flipped; the full verify also runs its rejection and
  key-preservation sequences. A PASS is limited to the selected cases, ELF and driver options.
- **Round-3 package checks** (package hash and source: [README.md](README.md#notes)):
  - 2026-10-12: the `.nistkat` cases are byte-exact against the Round-3 known-answer tests of the
    submission package: pk, sk and sm match counts 0..11 (12 of 100 cases) of the Ip_pkc_skc KAT
    the package's reference generates (`make PROJ=Ip_pkc_skc KAT=1`, then `PQCgenKAT_sign`).
  - 2026-10-12: the 12-case Ip3 and Is ladders are confirmed by the Round-3 reference
    implementation: it regenerates the compressed public key of each case from the seed and accepts
    each signature. That check did not compare the signatures byte for byte; the one of 2026-11-02
    below does.
  - 2026-10-17: the KAT archive the package links was compared as well. Its Ip-pkc-skc and
    Is-pkc-skc files equal the generated ones byte for byte, so the 12 `.nistkat` cases also equal
    its counts 0..11.
  - The retry vectors are recordings: the reference drew their salts from OS randomness, so the
    salts cannot be regenerated from the seeds. These package checks did not cover them.
- **Reference re-signing, 2026-11-02:** the reference code signed each case of the Ip3 and Is ladders,
  the `.nistkat` file and the three retry files again from its secret key, with the salt of the
  recorded signature (its last 16 bytes) as the random input. Each result equals the recorded signed
  message byte for byte; the reference verify accepts it and rejects it with one byte flipped. The
  retry files need 1, 2 and 3 attempts (`.retryctrl`, `.retry2`, `.retry3`), counted at the Gaussian
  elimination, which runs once per attempt. Reference: pqov
  ([github.com/pqov/pqov](https://github.com/pqov/pqov), main at `fac2ec1fe6`, Round 3), not the
  submission package. The Round-2 Ip files had the same check on pqm4
  (`testvectors-Ip-pkc-skc.nistkat.PROVENANCE.md`).
- **Limit:** these checks cover the tested inputs only. They do not prove conformance with the whole
  specification, nor constant time. A matching checksum shows a file is intact, not that the
  reference was right.

## Cross-tree control

- 2026-08-19: built for the Round-2 Is parameters, the same pre-release tree reproduced the
  committed Round-2 Is vectors byte for byte. A domain-separation or hash-prefix difference between
  the two trees would have shown up here.
- 2026-10-12: for the 12-case Is ladder, the official Round-3 reference regenerated the compressed
  public keys from the seeds and accepted the recorded signatures (signatures not compared byte for
  byte then; the re-signing of 2026-11-02 matched them byte for byte).

Neither check establishes agreement for Ip3 on its own, or for other keys.

## Integrity

`SHA256SUMS-r3-2026-08-19` (beside these files) covers the listed Ip and Ip3 files; it does not cover every file in this directory. `sha256sum -c`
detects corruption, merge damage or an accidental regeneration without running a kernel. It shows
agreement with the listed hashes, not that the reference was right.

## Reproducing the checks

The `.nistkat` check can be repeated from the public KAT archive alone: compare its 12 cases with
counts 0..11 of `KAT/Ip-pkc-skc/PQCsignKAT_32.rsp`. The other 88 cases are not in this file. The
ladder check needs the package's reference implementation, which is not part of this repository;
nothing in the build depends on it, the drivers read these files. The re-signing needs the pqov
reference (pqm4 for Ip) built with a `randombytes()` that returns the recorded salt; that harness
is not part of this repository either. The original generation of 2026-08-19 cannot be repeated
from what is here.
