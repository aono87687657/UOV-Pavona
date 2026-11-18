load("//rules:acc.bzl", "acc_library", "acc_binary")
package(default_visibility = ["//visibility:public"])

acc_library(
    name = "P1O_P2",
    srcs = ["P1O_P2.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "P1O_P2_bngfonly",
    srcs = ["P1O_P2.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "P1O_P2_sw",
    srcs = ["P1O_P2.s"],
    copts = [],
)

# P3_cal: one cpp-guarded source. -DGF_INSTRUCTIONS -> HW bn.gfmul.8.acc/.acch (bngfaes/bngfonly);
# no flag -> SW gf256_macc_dualvec_sw path.
acc_library(
    name = "P3_cal",
    srcs = ["P3_cal.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "P3_cal_sw",
    srcs = ["P3_cal.s"],
)

_AES_BNGF = [
    "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_bngf:KeySchedule_keygen",
    "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_bngf:aes128_keygen",
    "//sw/acc/crypto/handwritten/uov/dmem_large/keygen_full/ov-Ip-pkc+skc/AES_bngf:aes_constants_keygen",
]

_AES_TTABLE = [
    "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes128_table",
    "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:key_schedule",
    "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes_encrypt",
    "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes128table_352",
]

# cpk_pack: pack padded P3 -> standard UNPADDED cpk (pk_seed || compact P3).
# Pure GPR word-copy, tier-independent (no GF/AES/WDR) -> no tier variants.
acc_library(
    name = "cpk_pack",
    srcs = ["cpk_pack.s"],
)

# ov_keygen orchestrator: single-binary on-ACC keygen (expandsk->P1O_P2->P3_cal->cpk_pack)
acc_library(
    name = "ov-Ip-keygen",
    srcs = ["ov-Ip-keygen.s"],
)

# bngfaes tier: HW bn.aes128 (P1O_P2 default) + HW P3_cal + cpk_pack
acc_binary(
    name = "ov-Ip-keygen_full_bngfaes",
    srcs = ["ov-Ip-keygen_test.s"],
    deps = [
        ":ov-Ip-keygen",
        ":P1O_P2",
        ":P3_cal",
        ":cpk_pack",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
    ],
)

# bngfonly tier: SW AES (AES_bngf) + HW bn.gfmul P1O_P2/P3_cal + cpk_pack
acc_binary(
    name = "ov-Ip-keygen_full_bngfonly",
    srcs = ["ov-Ip-keygen_test.s"],
    deps = [
        ":ov-Ip-keygen",
        ":P1O_P2_bngfonly",
        ":P3_cal",
        ":cpk_pack",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
    ] + _AES_BNGF,
)

# sw tier: pure SW - T-table AES + SW-GF P1O_P2_sw/P3_cal_sw + cpk_pack
acc_binary(
    name = "ov-Ip-keygen_full_sw",
    srcs = ["ov-Ip-keygen_test.s"],
    deps = [
        ":ov-Ip-keygen",
        ":P1O_P2_sw",
        ":P3_cal_sw",
        ":cpk_pack",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
        "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",  # gf256_sw_helpers' gf256_scalar_inv_sw refs it
    ] + _AES_TTABLE,
)

# RTL self-test harnesses: sk_seed baked, .text.start entry (one keypair/tier)
acc_binary(
    name = "ov-Ip-keygen_full_test_bngfaes",
    srcs = ["ov-Ip-keygen_rtl_test.s"],
    deps = [
        ":ov-Ip-keygen",
        ":P1O_P2",
        ":P3_cal",
        ":cpk_pack",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
    ],
)

acc_binary(
    name = "ov-Ip-keygen_full_test_bngfonly",
    srcs = ["ov-Ip-keygen_rtl_test.s"],
    deps = [
        ":ov-Ip-keygen",
        ":P1O_P2_bngfonly",
        ":P3_cal",
        ":cpk_pack",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
    ] + _AES_BNGF,
)

acc_binary(
    name = "ov-Ip-keygen_full_test_sw",
    srcs = ["ov-Ip-keygen_rtl_test.s"],
    deps = [
        ":ov-Ip-keygen",
        ":P1O_P2_sw",
        ":P3_cal_sw",
        ":cpk_pack",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
        "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",  # gf256_sw_helpers' gf256_scalar_inv_sw refs it
    ] + _AES_TTABLE,
)
