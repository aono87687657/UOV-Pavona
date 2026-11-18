# refcheck: re-sign the test vectors with the UOV reference code

Last updated: 2026-11-02: first version.

## TL;DR
- Signs every case of the `-pkc-skc` vector files in `test_data/` again
  with the UOV reference code, from the case's secret key and the salt of the recorded
  signature, and compares the result byte for byte.
- Also counts the signing attempts (retries) the reference needs, and checks that its verify accepts each
  signature and rejects it with one byte flipped.
- Not part of the build: nothing in Bazel or the KAT tests uses it. It needs the reference code, which is not in
  this repository.

## How to run
From the repository root, with gcc, GNU ld (for `--wrap`) and OpenSSL's libcrypto (pqov's default build takes AES
and SHAKE from it):
```
git clone https://github.com/pqov/pqov /tmp/pqov
git -C /tmp/pqov checkout fac2ec1fe6
git clone https://github.com/mupq/pqm4 /tmp/pqm4
git -C /tmp/pqm4 checkout cc2c1b9
git -C /tmp/pqm4 submodule update --init --recursive mupq
bash sw/acc/crypto/handwritten/test_data/refcheck/build.sh /tmp/pqov /tmp/pqm4/mupq /tmp/refcheck && \
  bash sw/acc/crypto/handwritten/test_data/refcheck/run.sh /tmp/refcheck
```
`build.sh PQOV_DIR MUPQ_DIR OUT_DIR` makes `refcheck-Ip`, `refcheck-Ip3` and `refcheck-Is` in `OUT_DIR`; it stops
unless both reference trees are clean checkouts of these commits (mupq's own pqclean submodule included).
`run.sh BUILD_DIR` prints one line per file and exits 0 only if every case passes and every file has exactly the
expected cases (under 10 seconds). One file by hand: `refcheck-<P> FILE ATTEMPTS`, `ATTEMPTS` a comma list with one
expected attempt count per case.

## Result
2026-11-02, test_data at c5b5973234 plus the retry grid: 14 files, 174 cases, 0 failed.

| file | cases | attempts |
|---|---:|---|
| `testvectors-{Ip,Ip3,Is}-pkc-skc` | 12 each | 1, except Is case 11: 2 |
| `testvectors-{Ip,Ip3}-pkc-skc.nistkat` | 12 each | 1 |
| `testvectors-{Ip,Ip3}-pkc-skc.{retryctrl,retry2,retry3}` | 1 each | 1, 2, 3 |
| `testvectors-{Ip,Ip3,Is}-pkc-skc.retrygrid` | 36 each | as `testvectors-retrygrid-index.csv` |

## What it uses
| set | reference | build |
|---|---|---|
| Ip3 (OV(256,119,45)) | pqov main `fac2ec1fe6` (Round 3), `src/ref` | `-D_OV256_119_45 -D_OV_PKC_SKC` |
| Is (OV(16,160,64)) | pqov main `fac2ec1fe6`, `src/ref` | `-D_OV16_160_64 -D_OV_PKC_SKC` |
| Ip (Round 2, OV(256,112,44)) | pqm4 `cc2c1b9`, mupq `ddccced`, `crypto_sign/ov-Ip-pkc-skc/ref` | `-DPQM4`, pqm4's host FIPS 202 and PQClean AES |

## How it works
- `refcheck.c` provides `randombytes()`: it returns the 16-byte salt at the end of the recorded signature and fails
  if it is asked for anything else or more than once. The reference sources are compiled unchanged.
- The signer's Gaussian elimination runs once per attempt. It is linked with `-Wl,--wrap`, so each call is counted:
  every call but the last must fail, and the number of calls is the number of attempts.
- A file must hold whole 3-line records; an incomplete last record fails the run.
