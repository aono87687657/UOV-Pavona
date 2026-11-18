load("//rules:acc.bzl", "acc_library", "acc_binary", "acc_sim_test")
package(default_visibility = ["//visibility:public"])

acc_library(
    name = "gf16_matvec_2048_96",
    srcs = ["gf16_matvec_2048_96.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_binary(
    name = "gf16_matvec_2048_96_test",
    srcs = ["gf16_matvec_2048_96_test.s"],
    deps = [":gf16_matvec_2048_96"],
)

acc_library(
    name = "gf16_transpose_64_64",
    srcs = ["gf16_transpose_64_64.s"]
)

acc_binary(
    name = "gf16_transpose_64_64_test",
    srcs = ["gf16_transpose_64_64_test.s"],
    deps = [":gf16_transpose_64_64"]
)

acc_binary(
    name = "gf16mat_prod_48_64_test",
    srcs = ["gf16mat_prod_48_64_test.s"],
    deps = [":gf16mat_prod_48_64"],
)

acc_library(
    name = "gaussian_elimination_64x64",
    srcs = ["gaussian_elimination_64x64.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_binary(
    name = "gaussian_elimination_64x64_test",
    srcs = ["gaussian_elimination_64x64_test.s"],
    deps = [":gaussian_elimination_64x64"]
)

acc_library(
    name = "back_substitution_64x64",
    srcs = ["back_substitution_64x64.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_binary(
    name = "back_substitution_64x64_test",
    srcs = ["back_substitution_64x64_test.s"],
    deps = [":back_substitution_64x64",":gf16_transpose_64_64"]
)

# --- bngfonly tier (local AES_bngf/ subdir, SW AES via bn.gfmul) ---

acc_library(
    name = "gaussian_elimination_64x64_bngfonly",
    srcs = ["gaussian_elimination_64x64.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)
acc_library(
    name = "gf16mat_prod_48_64",
    srcs = ["gf16mat_prod_48_64.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "gf16mat_prod_48_64_sw",
    srcs = ["gf16mat_prod_48_64.s"],
    copts = [],
)
acc_library(
    name = "gf16mat_prod_48_64_bngfonly",
    srcs = ["gf16mat_prod_48_64.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "gf16_matvec_2048_96_bngfonly",
    srcs = ["gf16_matvec_2048_96.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

# --- sw tier (local AES_ttable/ subdir, pure SW AES + SW GF helpers) ---

acc_library(
    name = "gaussian_elimination_64x64_sw",
    srcs = ["gaussian_elimination_64x64.s"],
    copts = [],
)
acc_library(
    name = "back_substitution_64x64_sw",
    srcs = ["back_substitution_64x64.s"],
    copts = [],
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

# expandsk_ret_O_pkseed now lives in ov-keygen (it is the key-derivation step).
# Sign calls keygen's via this alias; all in-package deps on :expandsk_ret_O_pkseed resolve here.
alias(
    name = "expandsk_ret_O_pkseed",
    actual = "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc:expandsk_ret_O_pkseed",
)

acc_binary(
    name = "expandsk_ret_O_pkseed_test",
    srcs = ["expandsk_ret_O_pkseed_test.s"],
    deps = [":expandsk_ret_O_pkseed"]
)

acc_library(
    name = "gf16_matvec_2048_96_sw",
    srcs = ["gf16_matvec_2048_96.s"],
    copts = [],
)

# Solver chain on eight matrices, three with far-row pivots (bn.gfmul.4 and sw arms).
acc_sim_test(
    name = "solve_64x64_test",
    srcs = ["solve_64x64_test.s"],
    dexp = "solve_64x64_test.dexp",
    pqc = True,
    deps = [
        ":gaussian_elimination_64x64",
        ":gf16_transpose_64_64",
        ":back_substitution_64x64",
    ],
)

acc_sim_test(
    name = "solve_64x64_sw_test",
    srcs = ["solve_64x64_test.s"],
    dexp = "solve_64x64_test.dexp",
    deps = [
        ":gaussian_elimination_64x64_sw",
        ":gf16_transpose_64_64",
        ":back_substitution_64x64_sw",
        "//sw/acc/crypto/handwritten/gf16:gf16_sw_helpers",
    ],
)
