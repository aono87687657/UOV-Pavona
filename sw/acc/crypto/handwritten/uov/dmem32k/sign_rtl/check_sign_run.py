#!/usr/bin/env python3
# Verdict for one sign RTL/ISS run. Fail-closed: anything unproven is FAIL.
#
# Two INDEPENDENT oracles:
#   external  signature bytes recovered from the w0.. dump, compared here on the
#             host against the testvector. Does not trust the DUT's own compare.
#   x5        the harness's in-DUT compare (0 pass / -1 sig mismatch / -2 guard).
# Plus liveness/health: sim exit code (cosim verdict), exactly one register dump,
# exactly one cycle line, no error text, and an optional ISS cycle baseline.
#
#   usage: check_sign_run.py --log F --rc F --expected-sig HEX [--iss-cycles N]
#                            --param Ip|Is --tier T --msglen N
import argparse
import re
import sys

SIG_BYTES = {"Ip": 128, "Is": 96}
BAD_TEXT = re.compile(r"^(ERROR:|%Error)|Mismatch|Simulation timeout of|Received stop request",
                      re.MULTILINE)


def wdr_bytes(log: str, idx: int) -> bytes:
    """w<idx> from the dump -> 32 bytes, little-endian within each 32-bit word.
    Dump prints 8 words MS-word first: w0 | 0xAAAAAAAA_..._HHHHHHHH."""
    m = re.search(rf"^w{idx}\s+\|\s+0x([0-9a-fA-F_]+)\s*$", log, re.MULTILINE)
    if not m:
        return b""
    words = m.group(1).split("_")
    if len(words) != 8:
        return b""
    out = b""
    for w in reversed(words):                      # low word first
        out += int(w, 16).to_bytes(4, "little")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Verdict for one sign RTL or ISS run; anything unproven is FAIL.")
    ap.add_argument("--log", required=True)
    ap.add_argument("--rc")
    ap.add_argument("--expected-sig", required=True, help="hex, full signature")
    ap.add_argument("--iss-cycles", type=int)
    ap.add_argument("--param", required=True, choices=("Ip", "Is"))
    ap.add_argument("--tier", required=True)
    ap.add_argument("--msglen", required=True)
    ap.add_argument("--max-delta", type=int, default=1024)
    a = ap.parse_args()

    fields = {"param": a.param, "tier": a.tier, "msglen": a.msglen,
              "verdict": "FAIL", "external": "-", "x5": "-", "cosim": "-",
              "cycles": "-", "delta": "-", "reason": "-"}

    def emit(reason=None):
        if reason:
            fields["reason"] = reason
        print("RESULT " + " ".join(f"{k}={v}" for k, v in fields.items()))
        return 0 if fields["verdict"] == "PASS" else 1

    try:
        log = open(a.log, encoding="utf-8", errors="replace").read()
    except OSError:
        return emit("log-missing")
    if not log.strip():
        return emit("log-empty")

    # sim exit code = the cosim (RTL vs ISS) verdict; missing file fails closed
    if a.rc:
        try:
            rc = open(a.rc).read().strip()
        except OSError:
            return emit("rc-missing")
        if not re.fullmatch(r"\d+", rc):
            return emit("rc-garbage")
        fields["cosim"] = rc
    else:
        rc = "0"
        fields["cosim"] = "NA"

    cyc = re.findall(r"^Executed cycles:\s+(\d+)\s*$", log, re.MULTILINE)
    if len(cyc) != 1:
        return emit(f"cycles-count={len(cyc)}")
    fields["cycles"] = cyc[0]

    x5 = re.findall(r"^x5\s+\|\s+(0x[0-9a-fA-F]{8})\s*$", log, re.MULTILINE)
    if len(x5) != 1:
        return emit(f"dump-count={len(x5)}")
    fields["x5"] = x5[0]

    if BAD_TEXT.search(log):
        return emit("sim-error-text")
    if rc != "0":
        return emit(f"cosim-rc={rc}")

    # --- external oracle: rebuild the signature from the WDR dump ---
    want = bytes.fromhex(a.expected_sig)
    n = SIG_BYTES[a.param]
    if len(want) < n:
        return emit(f"expected-sig-short={len(want)}")
    got = b""
    for i in range((n + 31) // 32):
        b = wdr_bytes(log, i)
        if len(b) != 32:
            return emit(f"wdr{i}-missing")
        got += b
    got = got[:n]
    fields["external"] = "PASS" if got == want[:n] else "FAIL"
    if got != want[:n]:
        off = next(i for i in range(n) if got[i] != want[i])
        return emit(f"sig-mismatch@byte{off}")

    # --- DUT's own oracle ---
    if x5[0] == "0xfffffffe":
        return emit("stack-guard-clobbered")
    if x5[0] != "0x00000000":
        return emit(f"x5={x5[0]}")

    # --- cycle sanity: catches "terminated early, identically, in both models" ---
    if a.iss_cycles:
        d = int(cyc[0]) - a.iss_cycles
        fields["delta"] = f"{d:+d}"
        if not (0 <= d <= a.max_delta):
            return emit(f"cycle-delta={d}")

    fields["verdict"] = "PASS"
    return emit()


if __name__ == "__main__":
    sys.exit(main())
