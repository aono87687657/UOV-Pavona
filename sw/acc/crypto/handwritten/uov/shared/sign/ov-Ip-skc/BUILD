load("//rules:acc.bzl", "acc_library", "acc_binary", "acc_sim_test")
package(default_visibility = ["//visibility:public"])

acc_binary(
    name = "gf256mat_prod_68_44_test",
    srcs = ["gf256mat_prod_68_44_test.s"],
    deps = [":gf256mat_prod_68_44"],
)

acc_library(
    name = "gaussian_elimination_44x44",
    srcs = ["gaussian_elimination_44x44.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_binary(
    name= "gaussian_elimination_44x44_test",
    srcs=["gaussian_elimination_44x44_test.s"],
    deps=[":gaussian_elimination_44x44"]
)

acc_library(
    name = "gf256_transpose_44_44",
    srcs = ["gf256_transpose_44_44.s"]
)

acc_binary(
    name= "gf256_transpose_44_44_test",
    srcs=["gf256_transpose_44_44_test.s"],
    deps=[":gf256_transpose_44_44"]
)

acc_library(
    name = "partial_expandP1",
    srcs = ["partial_expandP1.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

# row_mul_O: dual-chain rewrite using bn.gfmul.8.acch for hi chain (w20),
# eliminating per-element bn.wsrw acc spills. HW tiers (bngfaes/bngfonly);
# sw builds the plain #else path via :row_mul_O_sw.
acc_library(
    name = "row_mul_O",
    srcs = ["row_mul_O.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "row_mul_O_sw",
    srcs = ["row_mul_O.s"],
    copts = [],
)

acc_library(
    name = "row_mul_O_bngfonly",
    srcs = ["row_mul_O.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

# gf256mat_prod_68_44: 3-chain rewrite (w28/w30 share ACC, w29->ACCH),
# eliminating per-element bn.wsrw acc spills on the w29 chain. HW tiers;
# sw via :gf256mat_prod_68_44_sw (#else path).
acc_library(
    name = "gf256mat_prod_68_44",
    srcs = ["gf256mat_prod_68_44.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "gf256mat_prod_68_44_sw",
    srcs = ["gf256mat_prod_68_44.s"],
    copts = [],
)

acc_library(
    name = "gf256mat_prod_68_44_bngfonly",
    srcs = ["gf256mat_prod_68_44.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

acc_binary(
    name = "back_substitution_44x44_test",
    srcs = ["back_substitution_44x44_test.s"],
    deps = [":back_substitution_44x44",":gf256_transpose_44_44"]
)

acc_library(
    name = "back_substitution_44x44",
    srcs = ["back_substitution_44x44.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

# expandsk_ret_O_pkseed now lives in ov-keygen (it is the key-derivation step).
# Sign calls keygen's via this alias; all in-package deps on :expandsk_ret_O_pkseed resolve here.
alias(
    name = "expandsk_ret_O_pkseed",
    actual = "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
)

acc_binary(
    name = "expandsk_ret_O_pkseed_test",
    srcs = ["expandsk_ret_O_pkseed_test.s"],
    deps = [":expandsk_ret_O_pkseed"]
)

acc_library(
    name = "hash_salted_msg",
    srcs = ["hash_salted_msg.s"]
)

acc_binary(
    name = "hash_salted_msg_test",
    srcs = ["hash_salted_msg_test.s"],
    deps = [":hash_salted_msg"]
)

acc_library(
    name = "expandv",
    srcs = ["expandv.s"]
)

acc_binary(
    name = "batch_quad_trimat_eval_gf256_test",
    srcs = ["batch_quad_trimat_eval_gf256_test.s"],
    deps = [":batch_quad_trimat_eval_gf256", ":expand352"]
)

# batch_quad_trimat_eval_gf256: dual-chain rewrite (w28->ACC, w29->ACCH)
# for the inner loop, eliminating per-element bn.wsrw acc spills on the w29 chain.
# Outer w20/w21 pair retains 4-wsrw spill pattern. sw via :batch_quad_trimat_eval_gf256_sw.
acc_library(
    name = "batch_quad_trimat_eval_gf256",
    srcs = ["batch_quad_trimat_eval_gf256.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "batch_quad_trimat_eval_gf256_bngfonly",
    srcs = ["batch_quad_trimat_eval_gf256.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "batch_quad_trimat_eval_gf256_sw",
    srcs = ["batch_quad_trimat_eval_gf256.s"],
    copts = [],
)

acc_library(
    name = "expand352",
    srcs = ["expand352.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

# --- bngfonly tier (local AES_bngf/) ---

acc_library(
    name = "back_substitution_44x44_bngfonly",
    srcs = ["back_substitution_44x44.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)
acc_library(
    name = "expand352_bngfonly",
    srcs = ["expand352.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)
acc_library(
    name = "gaussian_elimination_44x44_bngfonly",
    srcs = ["gaussian_elimination_44x44.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "partial_expandP1_bngfonly",
    srcs = ["partial_expandP1.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

# --- sw tier (local AES_ttable/ + SW GF helpers + table-AES wrappers) ---

acc_library(
    name = "back_substitution_44x44_sw",
    srcs = ["back_substitution_44x44.s"],
    copts = [],
)
acc_library(
    name = "expand_352_table",
    srcs = ["expand_352_table.s"],
)
acc_library(
    name = "gaussian_elimination_44x44_sw",
    srcs = ["gaussian_elimination_44x44.s"],
    copts = [],
)

acc_library(
    name = "partial_expandP1_table",
    srcs = ["partial_expandP1_table.s"],
    copts = [],
)

# Solver chain on matrices whose pivots need the rows at and below row 32 (bn.gfmul and sw arms).
acc_sim_test(
    name = "solve_44x44_test",
    srcs = ["solve_44x44_test.s"],
    dexp = "solve_44x44_test.dexp",
    pqc = True,
    deps = [
        ":gaussian_elimination_44x44",
        ":gf256_transpose_44_44",
        ":back_substitution_44x44",
    ],
)

acc_sim_test(
    name = "solve_44x44_sw_test",
    srcs = ["solve_44x44_test.s"],
    dexp = "solve_44x44_test.dexp",
    pqc = True,
    deps = [
        ":gaussian_elimination_44x44_sw",
        ":gf256_transpose_44_44",
        ":back_substitution_44x44_sw",
        "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
        "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
    ],
)
