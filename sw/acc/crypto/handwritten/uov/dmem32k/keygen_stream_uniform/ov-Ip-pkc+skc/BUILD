load("//rules:acc.bzl", "acc_binary", "acc_library")

package(default_visibility = ["//visibility:public"])

# Stream-uniform keygen (Ip): ONE backend-neutral outer kernel (WJ=5), one
# cpp-guarded backend source, so arm-vs-arm ratios isolate the AES/GF
# instruction contribution (the bnaesonly arm is the sw arm with the AES
# leaf exchanged for the batched hardware one of uov/shared/aes_hw). Same VARIANTS convention as ov-verify/ov-*-pkc.
# The OUTER compiles with NO copts (its object must be byte-identical across
# arms). Backend lib stays FIRST in deps: its private .data lands directly
# after the outer's, keeping shared symbol addresses identical across arms
# (gated: address assert + outer-object hash).

VARIANTS = [
    ("sw", []),
    ("bngfonly", ["-DGF_INSTRUCTIONS"]),
    ("bngfaes", ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"]),
    ("bnaesonly", ["-DAES_INSTRUCTIONS"]),
]

_KG = "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc"

DEPS_PER_VARIANT = {
    "bnaesonly": [
        "//sw/acc/crypto/handwritten/AES_ext:aes128_mem",
        "//sw/acc/crypto/handwritten/uov/shared/aes_hw:aes128hw_table_352",
        "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
        "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
    ],
    # sw tier: T-table AES + gf256 SW dots (bn.mulv.l reduce, repo sw baseline).
    "sw": [
        _KG + "/AES_ttable:key_schedule",
        _KG + "/AES_ttable:aes_encrypt",
        _KG + "/AES_ttable:aes128table_352",
        "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
        _KG + "/AES_ttable:aes128_table",
        "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
    ],
    # bngfonly tier: compute-AES helpers + HW bn.gfmul.
    "bngfonly": [
        _KG + "/AES_bngf:KeySchedule_keygen",
        _KG + "/AES_bngf:aes128_keygen",
    ],
    # bngfaes tier: HW bn.aes128 + HW bn.gfmul (AES inline in the arm).
    "bngfaes": [],
}

# ── backend libraries (one per variant; same source, diff copts) ─────────
[
    acc_library(
        name = "ov-Ip-keygen_backend_" + suffix,
        srcs = ["ov-Ip-keygen_backend.s"],
        copts = copts,
    )
    for suffix, copts in VARIANTS
]

# ── stream_uniform binaries (shared outer + backend swap; outer copts-free) ──
[
    acc_binary(
        name = "ov-Ip-keygen_stream_uniform_" + suffix,
        srcs = ["ov-Ip-keygen_stream_uniform.s"],
        deps = [":ov-Ip-keygen_backend_" + suffix, _KG + ":expandsk_ret_O_pkseed"] + DEPS_PER_VARIANT[suffix],
    )
    for suffix, copts in VARIANTS
]

# Chip-level C driver twins. ACC_SYMBOL_PTR token-pastes the app name, so it
# must be underscore-only; same sources and deps as the hyphenated binaries,
# generated from the same VARIANTS list so the two cannot drift.
[
    acc_binary(
        name = "ov_Ip_keygen_stream_uniform_" + suffix,
        srcs = ["ov-Ip-keygen_stream_uniform.s"],
        deps = [":ov-Ip-keygen_backend_" + suffix, _KG + ":expandsk_ret_O_pkseed"] + DEPS_PER_VARIANT[suffix],
    )
    for suffix, copts in VARIANTS
]
