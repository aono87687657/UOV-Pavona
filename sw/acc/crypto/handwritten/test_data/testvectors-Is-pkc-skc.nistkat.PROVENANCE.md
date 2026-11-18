# testvectors-Is-pkc-skc.nistkat: provenance

Counts 0..11 of the 100 NIST KAT cases of uov-Is pkc-skc (v=96, o=m=64, n=160; cpk 66,576 B,
signature 96 B; message lengths 33 … 396 B) in this directory's three-line format, taken
2026-11-14 from the KAT archive the Round-3 submission package links.

- `UOV-R3.zip` from the [NIST Round-3 page](https://csrc.nist.gov/projects/pqc-dig-sig/round-3-additional-signatures),
  sha256 `13a1c0e9b3c17022c79e611f27e1210471d7ee0a65b4df6cccb872e8b115c7b9`; its
  `UOV-R3/KAT/KAT_download_link.txt` links the archive
  https://drive.google.com/file/d/1mwf6Rj2TdQmLRLj04T6MkESF_D-GwyCt (`UOV-KAT-round3.zip`), sha256
  `8c876ecfc688ba920cb4688f634c98017436ce271b4be498996368bec0418410`.
- `KAT/Is-pkc-skc/PQCsignKAT_32.rsp` in it, sha256
  `461679a78490f47c7b5b91024868828274946a798d55d52718166ab882155ed4`.
- This file: pk, sk and sm of counts 0..11 as upper-case hex, one line each, sha256
  `9f1f08f5a301903c29fbcd7efa35709cfd16a5eedc8e6df8adc40547f87a4371`.

The Is parameters are the same in Rounds 2 and 3. The long-standing `testvectors-Is-pkc-skc` (no
suffix) is unrelated to this file and unchanged.
