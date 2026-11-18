# testvectors-Ip-pkc-skc.nistkat / .retry2 / .retry3 / .retryctrl: provenance

Last updated: 2026-11-02: the reference code signs the ladder, `.nistkat` and retry cases again byte for byte.

Generated 2026-08-19 in the same run as the Ip3 sets, for Round-2 Ip
(v=68, o=m=44, n=112; cpk 43,576 B, signature 128 B). They exist so retry cost
is measurable on both parameter sets by one method. The retry vectors are recordings: their salts came
from OS randomness, so a salt cannot be regenerated from the seed. The Round-3 package has no set with
these parameters, so its checks do not cover these files.

On 2026-11-02 the pqm4 Round-2 reference (pqm4 `cc2c1b9` with mupq `ddccced`,
`mupq/crypto_sign/ov-Ip-pkc-skc/ref`, built for the host) signed each `.nistkat` and retry case
again with the salt of the recorded signature and matched it byte for byte, with 1, 2 and 3
attempts for `.retryctrl`, `.retry2` and `.retry3`; its verify accepted each signature and rejected
it with one byte flipped. The same check passed on `testvectors-Ip-pkc-skc`.

| file | cases | message lengths | purpose |
|---|---|---|---|
| `.nistkat` | 12 of 100 | 33 … 396 (33*i) | the NIST KAT cases 0..11 in this directory's three-line format; at generation the reference's full KAT output was checked against the checksum list it ships (recorded then; the list is not in this repository) |
| `.retry2` | 1 | 32 | a seed whose first vinegar draw yields a singular L: one retry |
| `.retry3` | 1 | 32 | two retries |
| `.retryctrl` | 1 | 32 | matched control, no retry: the subtraction baseline |

The long-standing `testvectors-Ip-pkc-skc` (no suffix) is unrelated to this run
and unchanged.

Full detail, including what a PASS does and does not mean and the integrity
file: `testvectors-Ip3-pkc-skc.PROVENANCE.md` beside this one.
