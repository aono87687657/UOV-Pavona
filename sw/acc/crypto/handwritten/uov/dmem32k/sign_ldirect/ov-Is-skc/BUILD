load("//rules:acc.bzl", "acc_library", "acc_binary")
package(default_visibility = ["//visibility:public"])

acc_library(
    name = "gf16_ldirect_96_64",
    srcs = ["gf16_ldirect_96_64.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_binary(
    name = "ov-Is-sign_ldirect_bngfaes",
    srcs = ["ov-Is-skc-sign_test.s"],
    deps = [":ov-Is-skc-sign","//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:hash_salted_msg","//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:expandv",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:expandsk_ret_O_pkseed",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:gf16_transpose_64_64",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:gaussian_elimination_64x64",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:gf16mat_prod_48_64",
            ":gf16_ldirect_96_64",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:back_substitution_64x64"
            ]
)

acc_library(
    name = "ov-Is-skc-sign",
    srcs = ["ov-Is-skc-sign.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "ov-Is-skc-sign_testvec",
    srcs = ["ov-Is-skc-sign.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS", "-DUSE_TESTVEC_SALT"],
)

acc_binary(
    name = "ov-Is-sign_ldirect_testvec_bngfaes",
    srcs = ["ov-Is-skc-sign_test.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
    deps = [":ov-Is-skc-sign_testvec","//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:hash_salted_msg","//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:expandv",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:expandsk_ret_O_pkseed",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:gf16_transpose_64_64",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:gaussian_elimination_64x64",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:gf16mat_prod_48_64",
            ":gf16_ldirect_96_64",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:back_substitution_64x64"
            ]
)

# --- bngfaes tier (HW inline bn.aes128.*, no AES helper deps) ---

# Default sign path is L-direct (no S precompute): acch MAC kernels + gf16_ldirect_96_64.
IS_SIGN_BNGFAES_DEPS = [
    ":hash_salted_msg", ":expandv", ":expandsk_ret_O_pkseed", ":gf16_transpose_64_64",
    ":gaussian_elimination_64x64",
    ":gf16mat_prod_48_64",
    ":gf16_ldirect_96_64",
    ":back_substitution_64x64",
]

acc_library(
    name = "ov-Is-skc-sign_bngfonly",
    srcs = ["ov-Is-skc-sign.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

# AES implementation bundles, shared across the tier dep lists below (same style as
# the keygen BUILD). bngf = SW AES built from bn.gfmul; ttable = pure-SW T-table AES.
_AES_BNGF = [
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc/AES_bngf:KeySchedule_sign",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc/AES_bngf:aes128_sign",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc/AES_bngf:aes_constants_sign",
]

_AES_TTABLE = [
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc/AES_ttable:aes128_dual_table",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc/AES_ttable:aes128_col_is",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc/AES_ttable:aes_encrypt",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc/AES_ttable:key_schedule",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc/AES_ttable:aes128_table",
]

IS_SIGN_BNGFONLY_DEPS = [
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:hash_salted_msg", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:expandv", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:expandsk_ret_O_pkseed", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:gf16_transpose_64_64",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:gaussian_elimination_64x64_bngfonly",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:gf16mat_prod_48_64_bngfonly",
    ":gf16_ldirect_96_64_bngfonly",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:back_substitution_64x64",
] + _AES_BNGF

acc_binary(
    name = "ov-Is-sign_ldirect_bngfonly",
    srcs = ["ov-Is-skc-sign_test.s"],
    deps = [":ov-Is-skc-sign_bngfonly"] + IS_SIGN_BNGFONLY_DEPS,
)

acc_library(
    name = "ov-Is-skc-sign_sw",
    srcs = ["ov-Is-skc-sign.s"],
    copts = [],
)

IS_SIGN_SWONLY_DEPS = [
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:hash_salted_msg", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:expandv", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:expandsk_ret_O_pkseed", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:gf16_transpose_64_64",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:gaussian_elimination_64x64_sw",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:gf16mat_prod_48_64_sw",
    ":gf16_ldirect_96_64_sw",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:back_substitution_64x64_sw",
    "//sw/acc/crypto/handwritten/gf16:gf16_sw_helpers",
] + _AES_TTABLE

IS_SIGN_AESONLY_DEPS = [
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:hash_salted_msg", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:expandv", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:expandsk_ret_O_pkseed", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:gf16_transpose_64_64",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:gaussian_elimination_64x64_sw",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:gf16mat_prod_48_64_sw",
    ":gf16_ldirect_96_64_sw",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc:back_substitution_64x64_sw",
    "//sw/acc/crypto/handwritten/gf16:gf16_sw_helpers",
    "//sw/acc/crypto/handwritten/uov/shared/aes_hw:aes128hw_bank_sign",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc/AES_ttable:aes128_col_is",
]

acc_binary(
    name = "ov-Is-sign_ldirect_bnaesonly",
    srcs = ["ov-Is-skc-sign_test.s"],
    deps = [":ov-Is-skc-sign_sw"] + IS_SIGN_AESONLY_DEPS,
)

acc_binary(
    name = "ov-Is-sign_ldirect_testvec_bnaesonly",
    srcs = ["ov-Is-skc-sign_test.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
    deps = [":ov-Is-skc-sign_sw_testvec"] + IS_SIGN_AESONLY_DEPS,
)

acc_binary(
    name = "ov-Is-sign_ldirect_sw",
    srcs = ["ov-Is-skc-sign_test.s"],
    deps = [":ov-Is-skc-sign_sw"] + IS_SIGN_SWONLY_DEPS,
)

acc_library(
    name = "ov-Is-skc-sign_bngfaes_testvec",
    srcs = ["ov-Is-skc-sign.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS", "-DUSE_TESTVEC_SALT"],
)
acc_library(
    name = "ov-Is-skc-sign_bngfonly_testvec",
    srcs = ["ov-Is-skc-sign.s"],
    copts = ["-DGF_INSTRUCTIONS", "-DUSE_TESTVEC_SALT"],
)
acc_library(
    name = "ov-Is-skc-sign_sw_testvec",
    srcs = ["ov-Is-skc-sign.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
)

# Python KAT testvec_test binaries for bngfonly + sw tiers (bngfaes target above is :ov-Is-sign_ldirect_testvec_bngfaes)
acc_binary(
    name = "ov-Is-sign_ldirect_testvec_bngfonly",
    srcs = ["ov-Is-skc-sign_test.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
    deps = [":ov-Is-skc-sign_bngfonly_testvec"] + IS_SIGN_BNGFONLY_DEPS,
)

acc_binary(
    name = "ov-Is-sign_ldirect_testvec_sw",
    srcs = ["ov-Is-skc-sign_test.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
    deps = [":ov-Is-skc-sign_sw_testvec"] + IS_SIGN_SWONLY_DEPS,
)


# --- L-direct, bngfonly tier (SW AES via aes128_sign; no bn.aes128.*). Distinct
#     low-stack target: same ~196 KB S elimination, ~4.1M fewer AES cycles than the
#     bngfonly trimat in the common case; retry tail (>=2 attempts) is worse. ---
acc_library(
    name = "gf16_ldirect_96_64_bngfonly",
    srcs = ["gf16_ldirect_96_64.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)
# --- L-direct swonly tier: pure SW GF16 (gf16_macc_sw) + T-table AES, no bn.gfmul/bn.aes128. ---
acc_library(
    name = "gf16_ldirect_96_64_sw",
    srcs = ["gf16_ldirect_96_64.s"],
)
