# testvectors-*-pkc-skc.retrygrid: provenance

Last updated: 2026-11-02: first version.

Signing vectors with a known number of retries, for Ip, Ip3 and Is, so that the retry cost of each signing kernel can
be measured on the same inputs. Each file holds 36 cases in this directory's three-line format: 4 keys, message
lengths 0, 32 and 1024 B, and 1, 2 or 3 signing attempts (0, 1 or 2 retries) for each length.
`testvectors-retrygrid-index.csv` lists, per case, the key and its source, the message length and the attempts.
`SHA256SUMS-retrygrid-2026-11-02` holds the file checksums (`sha256sum -c`).

## How they were made (2026-11-02)
- Keys: cases 0 to 3 of `testvectors-Ip-pkc-skc`, `testvectors-Is-pkc-skc` and `testvectors-Ip3-pkc-skc.nistkat`
  (the Ip3 keys are written here in lower-case hex; `.nistkat` uses upper case).
- Messages: fixed pseudo-random bytes per case (Python `random.Random("<set>-<key>-<length>-<attempts>").randbytes(length)`).
- Salts: searched with the signing chain of `own_utils` (vinegar from SHAKE256 over message, salt, secret seed and
  counter; retry while the linear system is singular) until a salt needed exactly the wanted number of attempts. The
  search tool is not in this repository; the files are the record.
- Signatures: made by the same chain and checked against the committed public key.

## Checks
- 2026-11-02: the UOV reference code signed every case again from its secret key and recorded salt and got the same
  signed message byte for byte, with the attempt count of the index; its verify accepted each signature and rejected
  it with one byte flipped. Ip3 and Is: pqov main `fac2ec1fe6`; Ip: pqm4 `cc2c1b9` (mupq `ddccced`). How to repeat:
  [refcheck/README.md](refcheck/README.md).
- These checks cover these inputs only; the salts were chosen for their retry count and are not a random sample.
