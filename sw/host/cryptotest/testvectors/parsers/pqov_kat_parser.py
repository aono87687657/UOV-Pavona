#!/usr/bin/env python3
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
"""Convert a pqov PQCsignKAT .rsp (optionally xz) to cryptotest JSON. sm is message || signature."""

import argparse
import hashlib
import json
import lzma
import re
import sys

import jsonschema


def sha3_256(data):
    return list(hashlib.sha3_256(data).digest())


def read_text(path):
    if path.endswith(".xz"):
        with lzma.open(path, "rt") as f:
            return f.read()
    with open(path) as f:
        return f.read()


def read_cases(text):
    """Yield (count, sk, pk, msg, sig) per KAT case."""
    for block in text.split("count = ")[1:]:
        def field(k):
            m = re.search(rf"^{k} = (.*)$", block, re.M)
            if m is None:
                raise SystemExit(f"case is missing field {k!r}")
            return m.group(1).strip()

        count = int(block.split("\n", 1)[0])
        mlen, smlen = int(field("mlen")), int(field("smlen"))
        sm = bytes.fromhex(field("sm"))
        if len(sm) != smlen:
            raise SystemExit(f"case {count}: sm is {len(sm)} B, smlen says {smlen}")
        if smlen <= mlen:
            raise SystemExit(f"case {count}: smlen {smlen} <= mlen {mlen}")
        yield (count, bytes.fromhex(field("sk")), bytes.fromhex(field("pk")),
               sm[:mlen], sm[mlen:])


# (cpk, signature) bytes; catches a KAT file of the wrong set or round.
SIZES = {"Ip": (43576, 128), "Is": (66576, 96), "Ip3": (46591, 135)}


def parse(text, param, test_type, salt_bytes, limit):
    out = []
    for count, sk, pk, msg, sig in read_cases(text):
        if limit is not None and count >= limit:
            break
        if (len(pk), len(sig)) != SIZES[param]:
            raise SystemExit(f"case {count}: pk {len(pk)} B, sig {len(sig)} B; "
                             f"{param} has {SIZES[param]}")
        base = {"vendor": "pqov", "test_case_id": count, "parameter_set": param}
        if test_type == "keygen":
            out.append({**base, "operation": "keygen", "sk_seed": list(sk),
                        "expected_hash": sha3_256(pk), "result": True})
        elif test_type == "sign":
            out.append({**base, "operation": "sign", "sk_seed": list(sk),
                        "message": list(msg), "salt": list(sig[-salt_bytes:]),
                        "expected_hash": sha3_256(sig), "result": True})
        else:
            out.append({**base, "operation": "verify", "pk": list(pk),
                        "message": list(msg), "signature": list(sig),
                        "result": True})
            bad = bytearray(sig)
            bad[0] ^= 1
            out.append({**base, "operation": "verify", "pk": list(pk),
                        "message": list(msg), "signature": list(bad),
                        "result": False})
    return out


def main():
    p = argparse.ArgumentParser(description="Parse pqov PQCsignKAT testvectors.")
    p.add_argument("--src", required=True, help="PQCsignKAT_*.rsp or .rsp.xz")
    p.add_argument("--dst", type=argparse.FileType("w"), required=True)
    p.add_argument("--schema", required=True)
    p.add_argument("--parameter-set", choices=sorted(SIZES), required=True)
    p.add_argument("--test-type", choices=["keygen", "sign", "verify"], required=True)
    p.add_argument("--salt-bytes", type=int, default=16)
    p.add_argument("--cases", type=int, default=None,
                   help="keep only the first N cases (default: all)")
    a = p.parse_args()

    vectors = parse(read_text(a.src), a.parameter_set, a.test_type, a.salt_bytes,
                    a.cases)
    with open(a.schema) as f:
        jsonschema.validate(vectors, json.load(f))
    # Compact: indent would put each public key byte on its own line.
    json.dump(vectors, a.dst, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
