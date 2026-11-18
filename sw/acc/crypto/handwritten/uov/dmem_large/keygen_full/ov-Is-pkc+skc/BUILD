load("//rules:acc.bzl", "acc_library", "acc_binary")
package(default_visibility = ["//visibility:public"])

# P3_cal: one cpp-guarded source. -DGF_INSTRUCTIONS -> HW bn.gfmul.4.acc (bngfaes/bngfonly);
# no flag -> SW gf16_macc_sw path.
acc_library(
    name = "P3_cal",
    srcs = ["P3_cal.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "P3_cal_sw",
    srcs = ["P3_cal.s"],
)

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

_AES_BNGF = [
    "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc/AES_bngf:KeySchedule_keygen",
    "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc/AES_bngf:aes128_keygen",
    "//sw/acc/crypto/handwritten/uov/dmem_large/keygen_full/ov-Is-pkc+skc/AES_bngf:aes_constants_keygen",
]

_AES_TTABLE = [
    "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc/AES_ttable:aes128_table",
    "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc/AES_ttable:key_schedule",
    "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc/AES_ttable:aes_encrypt",
    "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc/AES_ttable:aes128_dual_table",
]

# cpk_pack: pack padded P3 -> standard UNPADDED cpk (pk_seed || compact P3).
# Pure GPR word-copy, tier-independent (no GF/AES/WDR) -> no tier variants.
acc_library(
    name = "cpk_pack",
    srcs = ["cpk_pack.s"],
)

# ov_keygen orchestrator: single-binary on-ACC keygen
acc_library(
    name = "ov-Is-keygen",
    srcs = ["ov-Is-keygen.s"],
)

acc_binary(
    name = "ov-Is-keygen_full_bngfaes",
    srcs = ["ov-Is-keygen_test.s"],
    deps = [
        ":ov-Is-keygen",
        ":P1O_P2",
        ":P3_cal",
        ":cpk_pack",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc:expandsk_ret_O_pkseed",
    ],
)

acc_binary(
    name = "ov-Is-keygen_full_bngfonly",
    srcs = ["ov-Is-keygen_test.s"],
    deps = [
        ":ov-Is-keygen",
        ":P1O_P2_bngfonly",
        ":P3_cal",
        ":cpk_pack",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc:expandsk_ret_O_pkseed",
    ] + _AES_BNGF,
)

acc_binary(
    name = "ov-Is-keygen_full_sw",
    srcs = ["ov-Is-keygen_test.s"],
    deps = [
        ":ov-Is-keygen",
        ":P1O_P2_sw",
        ":P3_cal_sw",
        ":cpk_pack",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/gf16:gf16_sw_helpers",
    ] + _AES_TTABLE,
)

# RTL self-test harnesses: sk_seed baked, .text.start entry (one keypair/tier)
acc_binary(
    name = "ov-Is-keygen_full_test_bngfaes",
    srcs = ["ov-Is-keygen_rtl_test.s"],
    deps = [
        ":ov-Is-keygen",
        ":P1O_P2",
        ":P3_cal",
        ":cpk_pack",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc:expandsk_ret_O_pkseed",
    ],
)

acc_binary(
    name = "ov-Is-keygen_full_test_bngfonly",
    srcs = ["ov-Is-keygen_rtl_test.s"],
    deps = [
        ":ov-Is-keygen",
        ":P1O_P2_bngfonly",
        ":P3_cal",
        ":cpk_pack",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc:expandsk_ret_O_pkseed",
    ] + _AES_BNGF,
)

acc_binary(
    name = "ov-Is-keygen_full_test_sw",
    srcs = ["ov-Is-keygen_rtl_test.s"],
    deps = [
        ":ov-Is-keygen",
        ":P1O_P2_sw",
        ":P3_cal_sw",
        ":cpk_pack",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/gf16:gf16_sw_helpers",
    ] + _AES_TTABLE,
)
