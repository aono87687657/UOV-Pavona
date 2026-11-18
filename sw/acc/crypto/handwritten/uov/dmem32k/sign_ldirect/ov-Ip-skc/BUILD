load("//rules:acc.bzl", "acc_library", "acc_binary")
package(default_visibility = ["//visibility:public"])

acc_binary(
    name = "ov-Ip-sign_ldirect_bngfaes",
    srcs = ["ov-Ip-skc-sign_test.s"],
    deps = [":ov-Ip-skc-sign",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:hash_salted_msg", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:expandv", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:expandsk_ret_O_pkseed", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:gf256_transpose_44_44",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:batch_quad_trimat_eval_gf256",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:back_substitution_44x44",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:expand352",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:gaussian_elimination_44x44",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:gf256mat_prod_68_44",
            ":gf256_ldirect_68_44",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:row_mul_O",
            ]
)

acc_library(
    name = "ov-Ip-skc-sign",
    srcs = ["ov-Ip-skc-sign.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "ov-Ip-skc-sign_testvec",
    srcs = ["ov-Ip-skc-sign.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS", "-DUSE_TESTVEC_SALT"],
)

acc_binary(
    name = "ov-Ip-sign_ldirect_testvec_bngfaes",
    srcs = ["ov-Ip-skc-sign_test.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
    deps = [":ov-Ip-skc-sign_testvec",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:hash_salted_msg", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:expandv", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:expandsk_ret_O_pkseed", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:gf256_transpose_44_44",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:batch_quad_trimat_eval_gf256",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:back_substitution_44x44",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:expand352",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:gaussian_elimination_44x44",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:gf256mat_prod_68_44",
            ":gf256_ldirect_68_44",
            "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:row_mul_O",
            ]
)

# --- bngfaes tier (HW inline bn.aes128.*) ---

# Default sign path is L-direct (no S precompute): acch MAC kernels + gf256_ldirect_68_44.
IP_SIGN_BNGFAES_DEPS = [
    ":hash_salted_msg", ":expandv", ":expandsk_ret_O_pkseed", ":gf256_transpose_44_44",
    ":back_substitution_44x44",
    ":expand352",
    ":gaussian_elimination_44x44",
    ":gf256mat_prod_68_44",
    ":gf256_ldirect_68_44",
    ":row_mul_O",
]

acc_library(
    name = "ov-Ip-skc-sign_bngfonly",
    srcs = ["ov-Ip-skc-sign.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

# SW-AES-via-bn.gfmul bundle, factored out like the keygen BUILD. (The sw-tier
# T-table AES is left inline in IP_SIGN_SWONLY_DEPS below: its labels are
# interleaved with //gf256:gf256_sw_helpers, and that link order is load-bearing:
# extracting it shifts .text addresses, so it stays as-is.)
_AES_BNGF = [
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:KeySchedule_sign",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:aes128_sign",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:aes_constants_sign",
]

IP_SIGN_BNGFONLY_DEPS = [
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:hash_salted_msg", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:expandv", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:expandsk_ret_O_pkseed", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:gf256_transpose_44_44",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:back_substitution_44x44_bngfonly",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:expand352_bngfonly",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:gaussian_elimination_44x44_bngfonly",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:gf256mat_prod_68_44_bngfonly",
    ":gf256_ldirect_68_44_bngfonly",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:row_mul_O_bngfonly",
] + _AES_BNGF

acc_binary(
    name = "ov-Ip-sign_ldirect_bngfonly",
    srcs = ["ov-Ip-skc-sign_test.s"],
    deps = [":ov-Ip-skc-sign_bngfonly"] + IP_SIGN_BNGFONLY_DEPS,
)

acc_library(
    name = "ov-Ip-skc-sign_sw",
    srcs = ["ov-Ip-skc-sign.s"],
    copts = [],
)

IP_SIGN_SWONLY_DEPS = [
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:hash_salted_msg", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:expandv", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:expandsk_ret_O_pkseed", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:gf256_transpose_44_44",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:back_substitution_44x44_sw",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:gaussian_elimination_44x44_sw",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:gf256mat_prod_68_44_sw",
    ":gf256_ldirect_68_44_sw",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:row_mul_O_sw",
    # T-table AES objects (link order kept stable to match the other swonly targets).
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:expand_352_table",
    "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_ttable:key_schedule",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_ttable:aes_encrypt",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_ttable:aes128_table",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_ttable:aes128table_352",
    "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",  # gf256_scalar_inv_sw squarings
]

IP_SIGN_AESONLY_DEPS = [
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:hash_salted_msg", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:expandv", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:expandsk_ret_O_pkseed", "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:gf256_transpose_44_44",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:back_substitution_44x44_sw",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:gaussian_elimination_44x44_sw",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:gf256mat_prod_68_44_sw",
    ":gf256_ldirect_68_44_sw",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:row_mul_O_sw",
    "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:expand_352_table",
    "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
    "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
    "//sw/acc/crypto/handwritten/AES_ext:aes128_mem",
    "//sw/acc/crypto/handwritten/uov/shared/aes_hw:aes128hw_table_352",
]

acc_binary(
    name = "ov-Ip-sign_ldirect_bnaesonly",
    srcs = ["ov-Ip-skc-sign_test.s"],
    deps = [":ov-Ip-skc-sign_sw"] + IP_SIGN_AESONLY_DEPS,
)

acc_binary(
    name = "ov-Ip-sign_ldirect_testvec_bnaesonly",
    srcs = ["ov-Ip-skc-sign_test.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
    deps = [":ov-Ip-skc-sign_sw_testvec"] + IP_SIGN_AESONLY_DEPS,
)

acc_binary(
    name = "ov-Ip-sign_ldirect_sw",
    srcs = ["ov-Ip-skc-sign_test.s"],
    deps = [":ov-Ip-skc-sign_sw"] + IP_SIGN_SWONLY_DEPS,
)

acc_library(
    name = "ov-Ip-skc-sign_bngfaes_testvec",
    srcs = ["ov-Ip-skc-sign.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS", "-DUSE_TESTVEC_SALT"],
)
acc_library(
    name = "ov-Ip-skc-sign_bngfonly_testvec",
    srcs = ["ov-Ip-skc-sign.s"],
    copts = ["-DGF_INSTRUCTIONS", "-DUSE_TESTVEC_SALT"],
)
acc_library(
    name = "ov-Ip-skc-sign_sw_testvec",
    srcs = ["ov-Ip-skc-sign.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
)

# Python KAT testvec_test binaries for bngfonly + sw tiers (bngfaes target above is :ov-Ip-sign_ldirect_testvec_bngfaes)
acc_binary(
    name = "ov-Ip-sign_ldirect_testvec_bngfonly",
    srcs = ["ov-Ip-skc-sign_test.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
    deps = [":ov-Ip-skc-sign_bngfonly_testvec"] + IP_SIGN_BNGFONLY_DEPS,
)

acc_binary(
    name = "ov-Ip-sign_ldirect_testvec_sw",
    srcs = ["ov-Ip-skc-sign_test.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
    deps = [":ov-Ip-skc-sign_sw_testvec"] + IP_SIGN_SWONLY_DEPS,
)

# --- L-direct tier (per-attempt L = t^T*O + vin^T*P2; no S_i precompute) ---
# bngfaes (HW bn.aes128) below; a bngfonly (SW AES) ldirect tier follows further down.

acc_library(
    name = "gf256_ldirect_68_44",
    srcs = ["gf256_ldirect_68_44.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

# --- L-direct, bngfonly tier (SW AES via sw_key_schedule + bngfonly expand_352).
#     Distinct low-stack target: same S elimination as bngfaes ldirect; SW-AES makes
#     the retry tail expensive (L re-streamed per attempt). ---
acc_library(
    name = "gf256_ldirect_68_44_bngfonly",
    srcs = ["gf256_ldirect_68_44.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)
# --- L-direct swonly tier: pure SW GF (gf256_macc_dualvec_sw) + T-table AES, no bn.gfmul/bn.aes128. ---
acc_library(
    name = "gf256_ldirect_68_44_sw",
    srcs = ["gf256_ldirect_68_44.s"],
)
acc_binary(
    name = "ldirect_kat_test_bngfaes",
    srcs = ["ldirect_kat_test.s"],
    deps = [
        ":gf256_ldirect_68_44",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:expand352",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:row_mul_O",
        ":ldirect_test_inputs",
    ],
)

acc_library(
    name = "ldirect_test_inputs",
    srcs = ["ldirect_test_inputs.s"],
)
