load("//rules:acc.bzl", "acc_binary", "acc_library")

package(default_visibility = ["//visibility:public"])

# Stream-uniform verify (Ip + Is): ONE backend-neutral outer per param (streamed
# host contract + init_done guard), one cpp-guarded backend source per param.
# Same VARIANTS convention as ov-verify/ov-{Ip,Is}-pkc. The OUTER compiles
# with NO copts (its object must be byte-identical across arms - that is what
# makes the comparison fair); only the backend library gets the tier flags. Backend
# lib is FIRST in deps (shared-address rule: outer .data links first, adapter
# private .data appends after the window reservation).

# Both parameters provide all four AES/GF combinations.
VARIANTS = [
    ("sw", []),
    ("bngfonly", ["-DGF_INSTRUCTIONS"]),
    ("bngfaes", ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"]),
    ("bnaesonly", ["-DAES_INSTRUCTIONS"]),
]
_VF_IS = "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Is-pkc"

IS_DEPS_PER_VARIANT = {
    "bnaesonly": [
        "//sw/acc/crypto/handwritten/uov/shared/aes_hw:aes128hw_bank_verify",
        "//sw/acc/crypto/handwritten/gf16:gf16_mul",
    ],
    # sw tier: SW T-table AES + SW gf16_mul (mulv-free).
    "sw": [
        _VF_IS + "/AES_ttable:aes128_table",
        _VF_IS + "/AES_ttable:key_schedule",
        _VF_IS + "/AES_ttable:aes_encrypt",
        _VF_IS + "/AES_ttable:aes128_col_is",
        "//sw/acc/crypto/handwritten/gf16:gf16_mul",
    ],
    # bngfonly tier: compute-AES (AES_bngf) + HW bn.gfmul.4.
    "bngfonly": [
        _VF_IS + "/AES_bngf:aes128",
        _VF_IS + "/AES_bngf:KeySchedule",
    ],
    # bngfaes tier: AES inlined in the arm (bn.aes128.kf keys) - no helper deps.
    "bngfaes": [],
}

[
    acc_library(
        name = "ov-Is-verify_backend_" + suffix,
        srcs = ["ov-Is-verify_backend.s"],
        copts = copts,
    )
    for suffix, copts in VARIANTS
    if suffix in IS_DEPS_PER_VARIANT
]

[
    acc_binary(
        name = "ov-Is-verify_stream_uniform_" + suffix,
        srcs = ["ov-Is-verify_stream_uniform.s"],
        deps = [":ov-Is-verify_backend_" + suffix] + IS_DEPS_PER_VARIANT[suffix],
    )
    for suffix, copts in VARIANTS
    if suffix in IS_DEPS_PER_VARIANT
]

[
    acc_binary(
        name = "ov_Is_verify_stream_uniform_" + suffix,
        srcs = ["ov-Is-verify_stream_uniform.s"],
        deps = [":ov-Is-verify_backend_" + suffix] + IS_DEPS_PER_VARIANT[suffix],
    )
    for suffix, copts in VARIANTS
    if suffix in IS_DEPS_PER_VARIANT
]
