load("//rules:acc.bzl", "acc_binary", "acc_library")

package(default_visibility = ["//visibility:public"])

# Stream-uniform keygen (Is): ONE backend-neutral outer kernel (WJ=10), one
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

_KGS = "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc"

DEPS_IS_PER_VARIANT = {
    "bnaesonly": [
        "//sw/acc/crypto/handwritten/AES_ext:aes128_mem",
        "//sw/acc/crypto/handwritten/uov/shared/aes_hw:aes128hw_dual_table",
        "//sw/acc/crypto/handwritten/gf16:gf16_sw_helpers",
    ],
    # sw tier: T-table AES (4KiB table as a lib; lands after the outer .data)
    # + gf16 SW dots.
    "sw": [
        _KGS + "/AES_ttable:key_schedule",
        _KGS + "/AES_ttable:aes_encrypt",
        _KGS + "/AES_ttable:aes128_dual_table",
        _KGS + "/AES_ttable:aes128_table",
        "//sw/acc/crypto/handwritten/gf16:gf16_sw_helpers",
    ],
    # bngfonly tier: compute-AES helpers + HW bn.gfmul.
    "bngfonly": [
        _KGS + "/AES_bngf:KeySchedule_keygen",
        _KGS + "/AES_bngf:aes128_keygen",
    ],
    # bngfaes tier: HW bn.aes128 + HW bn.gfmul (AES inline in the arm).
    "bngfaes": [],
}

# ── Is keygen stream_uniform (WJ=10) ────────────────────────────────────────
[
    acc_library(
        name = "ov-Is-keygen_backend_" + suffix,
        srcs = ["ov-Is-keygen_backend.s"],
        copts = copts,
    )
    for suffix, copts in VARIANTS
]

[
    acc_binary(
        name = "ov-Is-keygen_stream_uniform_" + suffix,
        srcs = ["ov-Is-keygen_stream_uniform.s"],
        deps = [":ov-Is-keygen_backend_" + suffix, _KGS + ":expandsk_ret_O_pkseed"] + DEPS_IS_PER_VARIANT[suffix],
    )
    for suffix, copts in VARIANTS
]

[
    acc_binary(
        name = "ov_Is_keygen_stream_uniform_" + suffix,
        srcs = ["ov-Is-keygen_stream_uniform.s"],
        deps = [":ov-Is-keygen_backend_" + suffix, _KGS + ":expandsk_ret_O_pkseed"] + DEPS_IS_PER_VARIANT[suffix],
    )
    for suffix, copts in VARIANTS
]
