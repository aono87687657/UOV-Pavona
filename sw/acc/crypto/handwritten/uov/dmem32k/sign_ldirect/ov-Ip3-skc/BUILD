load("//rules:acc.bzl", "acc_binary", "acc_library", "acc_sim_test")

package(default_visibility = ["//visibility:public"])

acc_library(
    name = "gaussian_elimination_45x45",
    srcs = ["gaussian_elimination_45x45.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_binary(
    name = "gaussian_elimination_45x45_test",
    srcs = ["gaussian_elimination_45x45_test.s"],
    deps = [":gaussian_elimination_45x45"],
)

acc_library(
    name = "gf256_transpose_45_45",
    srcs = ["gf256_transpose_45_45.s"],
)

acc_binary(
    name = "gf256_transpose_45_45_test",
    srcs = ["gf256_transpose_45_45_test.s"],
    deps = [":gf256_transpose_45_45"],
)

acc_library(
    name = "back_substitution_45x45",
    srcs = ["back_substitution_45x45.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_binary(
    name = "back_substitution_45x45_test",
    srcs = ["back_substitution_45x45_test.s"],
    deps = [":back_substitution_45x45", ":gf256_transpose_45_45"],
)

acc_library(
    name = "row_mul_O",
    srcs = ["row_mul_O.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "gf256_ldirect_74_45",
    srcs = ["gf256_ldirect_74_45.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "ldirect_test_inputs",
    srcs = ["ldirect_test_inputs.s"],
)

acc_binary(
    name = "ldirect_kat_test_bngfaes",
    srcs = ["ldirect_kat_test.s"],
    deps = [
        ":gf256_ldirect_74_45",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip3-skc:expand_360",
        ":row_mul_O",
        ":ldirect_test_inputs",
    ],
)

acc_library(
    name = "row_mul_O_bngfonly",
    srcs = ["row_mul_O.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "gf256_ldirect_74_45_bngfonly",
    srcs = ["gf256_ldirect_74_45.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

acc_binary(
    name = "ldirect_kat_test_bngfonly",
    srcs = ["ldirect_kat_test.s"],
    copts = ["-DGF_INSTRUCTIONS"],
    deps = [
        ":gf256_ldirect_74_45_bngfonly",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip3-skc:expand_360_bngfonly",
        ":row_mul_O_bngfonly",
        ":ldirect_test_inputs",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:aes128_sign",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:KeySchedule_sign",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:aes_constants_sign",
    ],
)

acc_library(
    name = "row_mul_O_sw",
    srcs = ["row_mul_O.s"],
    copts = [],
)

acc_library(
    name = "gf256_ldirect_74_45_sw",
    srcs = ["gf256_ldirect_74_45.s"],
    copts = [],
)

acc_binary(
    name = "ldirect_kat_test_sw",
    srcs = ["ldirect_kat_test.s"],
    copts = [],
    deps = [
        ":gf256_ldirect_74_45_sw",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip3-skc:expand_360_table",
        ":row_mul_O_sw",
        ":ldirect_test_inputs",
        "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
        "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_ttable:key_schedule",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_ttable:aes_encrypt",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_ttable:aes128_table",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes128table_384",
    ],
)

# --- sign orchestrator + the kernels it calls ---
acc_library(
    name = "hash_salted_msg",
    srcs = ["hash_salted_msg.s"],
)

acc_library(
    name = "expandv",
    srcs = ["expandv.s"],
)

acc_library(
    name = "gf256mat_prod_74_45",
    srcs = ["gf256mat_prod_74_45.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "ov-Ip3-skc-sign",
    srcs = ["ov-Ip3-skc-sign.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

IP3_SIGN_BNGFAES_DEPS = [
    ":hash_salted_msg",
    ":expandv",
    ":gf256_transpose_45_45",
    ":back_substitution_45x45",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip3-skc:expand_360",
    ":gaussian_elimination_45x45",
    ":gf256mat_prod_74_45",
    ":gf256_ldirect_74_45",
    ":row_mul_O",
    "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip3-pkc+skc:expandsk_ret_O_pkseed",
]

acc_binary(
    name = "ov-Ip3-sign_ldirect_bngfaes",
    srcs = ["ov-Ip3-skc-sign_test.s"],
    deps = [":ov-Ip3-skc-sign"] + IP3_SIGN_BNGFAES_DEPS,
)

# --- sign bngfonly tier (SW AES via bn.gfmul, local AES_bngf/) ---
acc_library(
    name = "back_substitution_45x45_bngfonly",
    srcs = ["back_substitution_45x45.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "gaussian_elimination_45x45_bngfonly",
    srcs = ["gaussian_elimination_45x45.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "gf256mat_prod_74_45_bngfonly",
    srcs = ["gf256mat_prod_74_45.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "ov-Ip3-skc-sign_bngfonly",
    srcs = ["ov-Ip3-skc-sign.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

_AES_BNGF = [
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:KeySchedule_sign",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:aes128_sign",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:aes_constants_sign",
]

IP3_SIGN_BNGFONLY_DEPS = [
    ":hash_salted_msg",
    ":expandv",
    ":gf256_transpose_45_45",
    ":back_substitution_45x45_bngfonly",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip3-skc:expand_360_bngfonly",
    ":gaussian_elimination_45x45_bngfonly",
    ":gf256mat_prod_74_45_bngfonly",
    ":gf256_ldirect_74_45_bngfonly",
    ":row_mul_O_bngfonly",
    "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip3-pkc+skc:expandsk_ret_O_pkseed",
] + _AES_BNGF

acc_binary(
    name = "ov-Ip3-sign_ldirect_bngfonly",
    srcs = ["ov-Ip3-skc-sign_test.s"],
    copts = ["-DGF_INSTRUCTIONS"],
    deps = [":ov-Ip3-skc-sign_bngfonly"] + IP3_SIGN_BNGFONLY_DEPS,
)

# --- sign swonly tier: pure SW GF + T-table AES, no bn.gfmul/bn.aes128 ---
acc_library(
    name = "back_substitution_45x45_sw",
    srcs = ["back_substitution_45x45.s"],
    copts = [],
)

acc_library(
    name = "gaussian_elimination_45x45_sw",
    srcs = ["gaussian_elimination_45x45.s"],
    copts = [],
)

acc_library(
    name = "gf256mat_prod_74_45_sw",
    srcs = ["gf256mat_prod_74_45.s"],
    copts = [],
)

acc_library(
    name = "ov-Ip3-skc-sign_sw",
    srcs = ["ov-Ip3-skc-sign.s"],
    copts = [],
)

IP3_SIGN_SWONLY_DEPS = [
    ":hash_salted_msg",
    ":expandv",
    ":gf256_transpose_45_45",
    ":back_substitution_45x45_sw",
    ":gaussian_elimination_45x45_sw",
    ":gf256mat_prod_74_45_sw",
    ":gf256_ldirect_74_45_sw",
    ":row_mul_O_sw",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip3-skc:expand_360_table",
    "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip3-pkc+skc:expandsk_ret_O_pkseed",
    "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_ttable:key_schedule",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_ttable:aes_encrypt",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_ttable:aes128_table",
    "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes128table_384",
    "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
]

acc_library(
    name = "gf256_ldirect_74_45_bnaesonly",
    srcs = ["gf256_ldirect_74_45.s"],
    copts = ["-DAES_INSTRUCTIONS"],
)

IP3_SIGN_AESONLY_DEPS = [
    ":hash_salted_msg",
    ":expandv",
    ":gf256_transpose_45_45",
    ":back_substitution_45x45_sw",
    ":gaussian_elimination_45x45_sw",
    ":gf256mat_prod_74_45_sw",
    ":gf256_ldirect_74_45_bnaesonly",
    ":row_mul_O_sw",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip3-skc:expand_360_table_bnaesonly",
    "//sw/acc/crypto/handwritten/uov/shared/aes_hw:aes128hw_384_sign",
    "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip3-pkc+skc:expandsk_ret_O_pkseed",
    "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
    "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
]

acc_binary(
    name = "ov-Ip3-sign_ldirect_bnaesonly",
    srcs = ["ov-Ip3-skc-sign_test.s"],
    copts = [],
    deps = [":ov-Ip3-skc-sign_sw"] + IP3_SIGN_AESONLY_DEPS,
)

acc_binary(
    name = "ov-Ip3-sign_ldirect_testvec_bnaesonly",
    srcs = ["ov-Ip3-skc-sign_test.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
    deps = [":ov-Ip3-skc-sign_sw_testvec"] + IP3_SIGN_AESONLY_DEPS,
)

acc_binary(
    name = "ov-Ip3-sign_ldirect_sw",
    srcs = ["ov-Ip3-skc-sign_test.s"],
    copts = [],
    deps = [":ov-Ip3-skc-sign_sw"] + IP3_SIGN_SWONLY_DEPS,
)

# --- testvec tier: -DUSE_TESTVEC_SALT takes the 16-B salt from DMEM instead of
# the RNG, so a run is deterministic and comparable against a vector file.
# Vectors: the Round-3 reference set (test_data/testvectors-Ip3-pkc-skc,
# PROVENANCE.md beside it); asm blobs regenerated from it 2026-08-24.
acc_library(
    name = "ov-Ip3-skc-sign_testvec",
    srcs = ["ov-Ip3-skc-sign.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS", "-DUSE_TESTVEC_SALT"],
)

acc_library(
    name = "ov-Ip3-skc-sign_bngfonly_testvec",
    srcs = ["ov-Ip3-skc-sign.s"],
    copts = ["-DGF_INSTRUCTIONS", "-DUSE_TESTVEC_SALT"],
)

acc_library(
    name = "ov-Ip3-skc-sign_sw_testvec",
    srcs = ["ov-Ip3-skc-sign.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
)

acc_binary(
    name = "ov-Ip3-sign_ldirect_testvec_bngfaes",
    srcs = ["ov-Ip3-skc-sign_test.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
    deps = [":ov-Ip3-skc-sign_testvec"] + IP3_SIGN_BNGFAES_DEPS,
)

acc_binary(
    name = "ov-Ip3-sign_ldirect_testvec_bngfonly",
    srcs = ["ov-Ip3-skc-sign_test.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
    deps = [":ov-Ip3-skc-sign_bngfonly_testvec"] + IP3_SIGN_BNGFONLY_DEPS,
)

acc_binary(
    name = "ov-Ip3-sign_ldirect_testvec_sw",
    srcs = ["ov-Ip3-skc-sign_test.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
    deps = [":ov-Ip3-skc-sign_sw_testvec"] + IP3_SIGN_SWONLY_DEPS,
)

# Solver chain on matrices whose pivots need the rows at and below row 32 (bn.gfmul and sw arms).
acc_sim_test(
    name = "solve_45x45_test",
    srcs = ["solve_45x45_test.s"],
    dexp = "solve_45x45_test.dexp",
    pqc = True,
    deps = [
        ":gaussian_elimination_45x45",
        ":gf256_transpose_45_45",
        ":back_substitution_45x45",
    ],
)

acc_sim_test(
    name = "solve_45x45_sw_test",
    srcs = ["solve_45x45_test.s"],
    dexp = "solve_45x45_test.dexp",
    pqc = True,
    deps = [
        ":gaussian_elimination_45x45_sw",
        ":gf256_transpose_45_45",
        ":back_substitution_45x45_sw",
        "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
        "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
    ],
)
