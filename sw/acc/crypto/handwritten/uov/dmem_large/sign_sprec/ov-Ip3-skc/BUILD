load("//rules:acc.bzl", "acc_binary", "acc_library")

package(default_visibility = ["//visibility:public"])

# S-precompute (_sprec) sign of Ip3, bngfaes only. S plus the raw-P1 cache needs about
# 400 KB of DMEM, so it runs only on the 512 KiB profile (ISS). The orchestrator, the S
# builder, the L matvec and the cached quadratic live here; the rest links from the
# Ip3 L-direct sign package.

_IP3 = "//sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip3-skc"

acc_library(
    name = "sprec_build_S_74_45",
    srcs = ["sprec_build_S_74_45.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "gf256_matvec_2880_74",
    srcs = ["gf256_matvec_2880_74.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "batch_quad_cached_74",
    srcs = ["batch_quad_cached_74.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "ov-Ip3-skc-sign_sprec",
    srcs = ["ov-Ip3-skc-sign_sprec.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "ov-Ip3-skc-sign_sprec_testvec",
    srcs = ["ov-Ip3-skc-sign_sprec.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS", "-DUSE_TESTVEC_SALT"],
)

IP3_SIGN_BNGFAES_SPREC_DEPS = [
    ":sprec_build_S_74_45",
    ":gf256_matvec_2880_74",
    ":batch_quad_cached_74",
    _IP3 + ":hash_salted_msg",
    _IP3 + ":expandv",
    _IP3 + ":gf256_transpose_45_45",
    _IP3 + ":back_substitution_45x45",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip3-skc:expand_360",
    _IP3 + ":gaussian_elimination_45x45",
    _IP3 + ":gf256mat_prod_74_45",
    _IP3 + ":row_mul_O",
    "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip3-pkc+skc:expandsk_ret_O_pkseed",
]

acc_binary(
    name = "ov-Ip3-sign_sprec_bngfaes",
    srcs = ["ov-Ip3-skc-sign_sprec_test.s"],
    deps = [":ov-Ip3-skc-sign_sprec"] + IP3_SIGN_BNGFAES_SPREC_DEPS,
)

acc_binary(
    name = "ov-Ip3-sign_sprec_testvec_bngfaes",
    srcs = ["ov-Ip3-skc-sign_sprec_test.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
    deps = [":ov-Ip3-skc-sign_sprec_testvec"] + IP3_SIGN_BNGFAES_SPREC_DEPS,
)
