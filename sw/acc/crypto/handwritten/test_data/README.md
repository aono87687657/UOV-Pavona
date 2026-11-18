# test_data: UOV known-answer test vectors

Last updated: 2026-11-02: the retry grid (`.retrygrid`) and the re-signing check (`refcheck/`) added.

## TL;DR
The KAT files of all six Round-2 UOV variants (Ip and Is, each classic, pkc and pkc-skc), the Ip3
vectors with their provenance notes, and two converters that turn vectors into linkable `.s` data.
The KAT sweep (`tools/gather_kat_stats.py`) and the UOV KAT drivers read `testvectors-<P>-pkc-skc` from here.

## How to run
A quick check for Ip, Is and Ip3 at 32 KiB on the bngfaes tier, from the repository root (about 3 minutes
once built):
```bash
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/... \
                    //sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Ip3-pkc+skc:all \
                    //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/... \
                    //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/ov-Ip3-pkc:all
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip-skc:ov-Ip-sign_ldirect_testvec_{bngfaes,bngfonly,sw}
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Is-skc:ov-Is-sign_ldirect_testvec_{bngfaes,bngfonly,sw}
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip3-skc:ov-Ip3-sign_ldirect_testvec_{bngfaes,bngfonly,sw}
python3 tools/gather_kat_stats.py --ops keygen --params Ip,Is,Ip3 --cases 0 --tiers bngfaes
python3 tools/gather_kat_stats.py --ops sign,verify --params Ip,Is,Ip3 --cases 0,11 --tiers bngfaes
```
`--tiers` picks the tiers, comma-separated: `sw`, `bngfonly`, `bngfaes`, `bnaesonly`. Without
it the sweep runs sw, bngfonly and bngfaes, which the build lines above cover (`bnaesonly` also needs the
`_testvec_bnaesonly` sign builds): for Ip and Is on 2026-10-19 (at 0b9306c645) the keygen
line then took 42 minutes and the sign,verify line 17 minutes (32-core machine, up to 12 cells at a time),
almost all of it in the sw tier.
The sweep runs prebuilt ELFs: without the build lines it fails on missing ELFs, or passes on stale
ones.

To write a directory of linkable assembly (a `<dir>` whose name ends in `-pkc-skc` selects the
-skc file name prefix):
```
python3 sw/acc/crypto/handwritten/test_data/convert_pkc_to_asm.py --format ip \
    sw/acc/crypto/handwritten/test_data/testvectors-Ip-pkc-skc <dir>
```

## Files
| file | role |
|---|---|
| `testvectors-{Ip,Is}-pkc-skc` | the KAT source the Ip and Is keygen, sign and verify drivers read |
| `testvectors-{Ip,Is}-pkc` | reference vectors: compressed public key, full secret key |
| `testvectors-{Ip,Is}-classic` | reference vectors: uncompressed public key, full secret key |
| `testvectors-Ip3-pkc-skc` | the Ip3 vectors: 12 cases, message lengths 0 to 1024, one key pair for all 12; recorded with a pre-release Round-3 reference implementation and confirmed by the Round-3 reference implementation (`testvectors-Ip3-pkc-skc.PROVENANCE.md`) |
| `testvectors-Ip3-pkc-skc.nistkat` | counts 0..11 of the package's 100 KAT cases (message lengths 33 to 396 B), in the three-line format of this directory; byte-exact against the Round-3 known-answer tests of the submission package |
| `testvectors-Ip-pkc-skc.nistkat` | the same 12 counts for Round-2 Ip (`testvectors-Ip-pkc-skc.nistkat.PROVENANCE.md`) |
| `testvectors-Is-pkc-skc.nistkat` | the same 12 counts for Is, from the Round-3 KAT archive (`testvectors-Is-pkc-skc.nistkat.PROVENANCE.md`) |
| `testvectors-{Ip3,Ip}-pkc-skc.{retry2,retry3,retryctrl}` | one recorded case each: a seed that needs one retry, one that needs two, and the matched control without a retry |
| `testvectors-{Ip,Ip3,Is}-pkc-skc.retrygrid` | the retry grid: 36 cases each, 4 keys x message lengths 0, 32, 1024 B x 0, 1, 2 retries (`testvectors-retrygrid.PROVENANCE.md`) |
| `testvectors-retrygrid-index.csv` | per retry-grid case: key and its source, message length, attempts |
| `SHA256SUMS-retrygrid-2026-11-02` | checksums of the three retry-grid files and the index (`sha256sum -c`) |
| `refcheck/` | re-signs the `-pkc-skc` files with the UOV reference code (not part of the build; [refcheck/README.md](refcheck/README.md)) |
| `SHA256SUMS-r3-2026-08-19` | checksums of the Ip and Ip3 vector files listed in that snapshot (`sha256sum -c`) |
| `convert_pkc_to_asm.py` | pkc and pkc-skc hex to one `.s` per message length in `asm/<variant>/` |
| `convert_classic_to_asm.py` | classic hex to one `.s` per message length in `asm/<variant>/` |

## Notes
- Format: 3 lines per case (public key, secret key, signed message), hex, so a 12-case file has 36
  lines. Ladders: message length 0, 1, 2, 4, ..., 1024 B for cases 0..11, so `--cases 0,11` covers both
  ends; `.nistkat`: 33, 66, ..., 396 B; retry files: one case, 32 B. A signed message is the message
  followed by the signature, which ends with the 16-byte salt.
- Sign checks load the `_testvec_` builds, which read the salt from the vector, so the signature
  compares byte for byte. The plain builds read it from `RND` (fixed values on the ISS) and cannot
  match these files ([sign_ldirect README, Salt](../uov/dmem32k/sign_ldirect/README.md#salt)).
- Sizes. Ip: public key 278,432 B (classic) or 43,576 B (pkc), secret key 237,896 B (classic) or
  32 B (pkc-skc), signature 128 B. Is: public key 412,160 B or 66,576 B, secret key 348,704 B or
  32 B, signature 96 B.
- The Ip and Is files without a suffix (classic, pkc, pkc-skc) were generated from the pqm4
  reference C implementation built for the host (`testvectors.py` and `bin-host`). pqm4 ships only
  Ip; the Is vectors come from the same sources with `params.h` switched to `_OV16_160_64`.
- The Ip3 vectors were recorded with a pre-release Round-3 reference implementation. Since
  2026-09-28 the [official Round-3 page](https://csrc.nist.gov/projects/pqc-dig-sig/round-3-additional-signatures)
  provides the specification and the submission package (UOV-R3.zip, sha256
  `13a1c0e9b3c17022c79e611f27e1210471d7ee0a65b4df6cccb872e8b115c7b9`). Checks against it:
  - `testvectors-Ip3-pkc-skc.nistkat` is byte-exact against the Round-3 known-answer tests of the
    submission package: pk, sk and signed message match counts 0..11, 12 of the 100 cases. Checked
    on 2026-10-12 against the KAT the package's reference generates, and on 2026-10-17 against the
    KAT archive the package links (its Ip-pkc-skc and Is-pkc-skc files equal the generated ones byte
    for byte).
  - The 12-case Ip3 and Is message-length ladders are confirmed by the Round-3 reference
    implementation (2026-10-12): it regenerates each case's public key from the seed and accepts
    each signature. The Ip3 ladder uses one key pair for all 12 cases; the Ip and Is ladders have
    12 different keys.
  - The retry vectors are recordings: their salts came from OS randomness, so a salt cannot be
    regenerated from the seed. The package checks did not cover them.
  These checks cover the listed vectors only: they do not prove conformance with the whole
  specification, nor constant time. Round-2 Ip remains a separate parameter set. See
  [the provenance record](testvectors-Ip3-pkc-skc.PROVENANCE.md) for the details and for what
  cannot be reproduced.
- 2026-11-02: the reference code signed every case of the Ip, Ip3 and Is ladders, both `.nistkat`
  files, all six retry files and the three retry grids again from the case's secret key, with the
  salt of the recorded signature (its last 16 bytes) as the random input. Each result equals the recorded signed message
  byte for byte, the reference verify accepts it and rejects it with one byte flipped, and the retry
  files need 1, 2 and 3 attempts (`.retryctrl`, `.retry2`, `.retry3`; counted at the Gaussian
  elimination, which runs once per attempt). Ip3 and Is used the pqov reference
  ([github.com/pqov/pqov](https://github.com/pqov/pqov), main at `fac2ec1fe6`, Round 3); Ip used the
  pqm4 Round-2 reference (pqm4 `cc2c1b9` with mupq `ddccced`,
  `mupq/crypto_sign/ov-Ip-pkc-skc/ref`). `refcheck/` repeats it; the reference code itself is not in this
  repository. The limits above apply.
- The classic and pkc (not -skc) files are kept as reference: no driver in the tree reads them.
