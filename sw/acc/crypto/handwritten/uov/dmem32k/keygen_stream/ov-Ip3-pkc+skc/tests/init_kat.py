#!/usr/bin/env python3
"""INIT-phase KAT for ov-Ip3-keygen_stream_bngfaes: expandsk -> pk_seed@0x40 + padded O@o_aligned.
Injects sk_seed@0x20, ctrl[0]=0 (INIT), runs the built ELF, checks pk_seed and the
45x96 padded O against the SHAKE256 oracle (slack bytes must be zero)."""
import hashlib, io, os, random, sys
_SD = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(_SD, *['..'] * 9))
sys.path[:0] = [REPO, f"{REPO}/sw/acc/crypto/handwritten/own_utils", f"{REPO}/hw/ip/acc/dv/accsim"]
from acc_sim_utils import run_acc_test
from dmem_utils import bytes_to_dmem_words, extract_bytes_from_dmem

V, O = 74, 45
ELF = f"{REPO}/bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Ip3-pkc+skc/ov-Ip3-keygen_stream_bngfaes.elf"
PK_ADDR, O_ADDR = 0x40, 0x43E0
rnd = random.Random(0x1173)
bad = []
for trial in range(3):
    seed = bytes(rnd.randrange(256) for _ in range(32))
    dig = hashlib.shake_256(seed).digest(16 + V * O)
    pk, o_cols = dig[:16], dig[16:]           # o_cols: column-major, V bytes per column
    words = bytes_to_dmem_words(seed, 0x20)   # sk_seed
    words.update(bytes_to_dmem_words(bytes(4), 0))  # ctrl[0]=0 -> INIT
    ok, dmem, _ = run_acc_test(ELF, dmem_words=words, dump_stats_file=io.StringIO())
    if not ok:
        bad.append((trial, "sim")); continue
    if extract_bytes_from_dmem(dmem, PK_ADDR, 16) != pk:
        bad.append((trial, "pk_seed"))
    if extract_bytes_from_dmem(dmem, PK_ADDR + 16, 16) != bytes(16):
        bad.append((trial, "pk_seed not zero-extended"))
    for c in range(O):
        slot = extract_bytes_from_dmem(dmem, O_ADDR + c * 96, 96)
        if slot[:V] != o_cols[c * V:(c + 1) * V]:
            bad.append((trial, f"O col {c}")); break
        if slot[V:] != bytes(96 - V):
            bad.append((trial, f"O col {c} slack nonzero")); break
print("INIT KAT:", "PASS - pk_seed zero-ext + 45 padded O columns match oracle + slack zero (3 seeds)"
      if not bad else f"FAIL {bad}")
sys.exit(1 if bad else 0)
