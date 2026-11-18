load("//rules:acc.bzl", "acc_binary", "acc_library")

package(default_visibility = ["//visibility:public"])

# S-precompute (_sprec) sign arms of Is. S plus the raw-P1 caches needs
# ~200-354 KB of DMEM, so these targets only run on an enlarged-DMEM config --
# carved out of ov-sign so the dmem32k sign package stays :all-buildable.
# Orchestrators live here; every support kernel links from the shared and dmem32k
# sign packages (absolute labels below; list order is load-bearing for the sw
# tiers -- keep it byte-stable).

_IS = "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc"

# --- OV-Is ---

acc_library(
    name = "ov-Is-skc-sign_sprec",
    srcs = ["ov-Is-skc-sign_sprec.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "ov-Is-skc-sign_sprec_bngfonly",
    srcs = ["ov-Is-skc-sign_sprec.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

# sw tier: pure-SW precompute-S (T-table AES + gf16_macc_sw). No cache (cache is
# GF-gated; sw lacks bn.gfmul), so this is the un-cached precompute-S baseline.
acc_library(
    name = "ov-Is-skc-sign_sprec_sw",
    srcs = ["ov-Is-skc-sign_sprec.s"],
    copts = [],
)

IS_SIGN_BNGFAES_SPREC_DEPS = [
    _IS + ":hash_salted_msg", _IS + ":expandv", _IS + ":expandsk_ret_O_pkseed", _IS + ":gf16_transpose_64_64",
    ":batch_quad_trimat_eval_gf16",
    _IS + ":gaussian_elimination_64x64",
    _IS + ":gf16mat_prod_48_64",
    _IS + ":gf16_matvec_2048_96",
    ":gf16trimat_2trimat_madd_96_48_64_32",
    _IS + ":back_substitution_64x64",
]

IS_SIGN_BNGFONLY_SPREC_DEPS = [
    _IS + ":hash_salted_msg", _IS + ":expandv", _IS + ":expandsk_ret_O_pkseed", _IS + ":gf16_transpose_64_64",
    ":batch_quad_trimat_eval_gf16_bngfonly",
    _IS + ":gaussian_elimination_64x64_bngfonly",
    _IS + ":gf16mat_prod_48_64_bngfonly",
    _IS + ":gf16_matvec_2048_96_bngfonly",
    ":gf16trimat_2trimat_madd_96_48_64_32_bngfonly",
    _IS + ":back_substitution_64x64",
    _IS + "/AES_bngf:KeySchedule_sign",
    _IS + "/AES_bngf:aes128_sign",
    _IS + "/AES_bngf:aes_constants_sign",
]

IS_SIGN_SWONLY_SPREC_DEPS = [
    _IS + ":hash_salted_msg", _IS + ":expandv", _IS + ":expandsk_ret_O_pkseed", _IS + ":gf16_transpose_64_64",
    ":batch_quad_trimat_eval_gf16_sw",
    _IS + ":gaussian_elimination_64x64_sw",
    _IS + ":gf16mat_prod_48_64_sw",
    _IS + ":gf16_matvec_2048_96_sw",
    ":gf16trimat_2trimat_madd_96_48_64_32_sw",
    _IS + ":back_substitution_64x64_sw",
    "//sw/acc/crypto/handwritten/gf16:gf16_sw_helpers",
    _IS + "/AES_ttable:aes128_dual_table",
    _IS + "/AES_ttable:aes128_col_is",
    _IS + "/AES_ttable:aes_encrypt",
    _IS + "/AES_ttable:key_schedule",
    _IS + "/AES_ttable:aes128_table",
]

acc_binary(
    name = "ov-Is-sign_sprec_bngfaes",
    srcs = ["ov-Is-skc-sign_sprec_test.s"],
    copts = ["-DP1_CACHE"],   # bngfaes reserves the 148992 B raw-P1 cache below S
    deps = [":ov-Is-skc-sign_sprec"] + IS_SIGN_BNGFAES_SPREC_DEPS,
)

acc_binary(
    name = "ov-Is-sign_sprec_bngfonly",
    srcs = ["ov-Is-skc-sign_sprec_test.s"],
    copts = ["-DP1_CACHE"],   # bngfonly now also reserves the 148992 B raw-P1 cache below S
    deps = [":ov-Is-skc-sign_sprec_bngfonly"] + IS_SIGN_BNGFONLY_SPREC_DEPS,
)

# testvec (USE_TESTVEC_SALT) orchestrators + testvec_test binaries for the sprec tiers
acc_library(
    name = "ov-Is-skc-sign_sprec_testvec",
    srcs = ["ov-Is-skc-sign_sprec.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS", "-DUSE_TESTVEC_SALT"],
)

acc_library(
    name = "ov-Is-skc-sign_sprec_bngfonly_testvec",
    srcs = ["ov-Is-skc-sign_sprec.s"],
    copts = ["-DGF_INSTRUCTIONS", "-DUSE_TESTVEC_SALT"],
)

acc_binary(
    name = "ov-Is-sign_sprec_testvec_bngfaes",
    srcs = ["ov-Is-skc-sign_sprec_test.s"],
    copts = ["-DUSE_TESTVEC_SALT", "-DP1_CACHE"],   # bngfaes reserves 148992 B raw-P1 cache below S
    deps = [":ov-Is-skc-sign_sprec_testvec"] + IS_SIGN_BNGFAES_SPREC_DEPS,
)

acc_binary(
    name = "ov-Is-sign_sprec_testvec_bngfonly",
    srcs = ["ov-Is-skc-sign_sprec_test.s"],
    copts = ["-DUSE_TESTVEC_SALT", "-DP1_CACHE"],   # bngfonly now also reserves the raw-P1 cache below S
    deps = [":ov-Is-skc-sign_sprec_bngfonly_testvec"] + IS_SIGN_BNGFONLY_SPREC_DEPS,
)

# sw precompute-S, cached (P1 cache default in the sw arm; reserves 148992 B below S)
acc_binary(
    name = "ov-Is-sign_sprec_sw",
    srcs = ["ov-Is-skc-sign_sprec_test.s"],
    copts = ["-DP1_CACHE"],
    deps = [":ov-Is-skc-sign_sprec_sw"] + IS_SIGN_SWONLY_SPREC_DEPS,
)

acc_library(
    name = "ov-Is-skc-sign_sprec_sw_testvec",
    srcs = ["ov-Is-skc-sign_sprec.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
)

acc_binary(
    name = "ov-Is-sign_sprec_testvec_sw",
    srcs = ["ov-Is-skc-sign_sprec_test.s"],
    copts = ["-DUSE_TESTVEC_SALT", "-DP1_CACHE"],
    deps = [":ov-Is-skc-sign_sprec_sw_testvec"] + IS_SIGN_SWONLY_SPREC_DEPS,
)

acc_binary(
    name = "batch_quad_trimat_eval_gf16_test",
    srcs = ["batch_quad_trimat_eval_gf16_test.s"],
    deps = [":batch_quad_trimat_eval_gf16"]
)

acc_library(
    name = "gf16trimat_2trimat_madd_96_48_64_32",
    srcs = ["gf16trimat_2trimat_madd_96_48_64_32.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_binary(
    name = "gf16trimat_2trimat_madd_96_48_64_32_test",
    srcs = ["gf16trimat_2trimat_madd_96_48_64_32_test.s"],
    deps = [":gf16trimat_2trimat_madd_96_48_64_32"],
)

acc_library(
    name = "batch_quad_trimat_eval_gf16",
    srcs = ["batch_quad_trimat_eval_gf16.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "batch_quad_trimat_eval_gf16_sw",
    srcs = ["batch_quad_trimat_eval_gf16.s"],
    copts = [],
)
acc_library(
    name = "batch_quad_trimat_eval_gf16_bngfonly",
    srcs = ["batch_quad_trimat_eval_gf16.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "gf16trimat_2trimat_madd_96_48_64_32_bngfonly",
    srcs = ["gf16trimat_2trimat_madd_96_48_64_32.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

# --- S-precompute trimat support. The _sprec orchestrators and their binaries
# live in //sw/acc/crypto/handwritten/uov/dmem_large/sign_sprec (oversized
# DMEM); these libs stay here and are linked from there.

acc_library(
    name = "gf16trimat_2trimat_madd_96_48_64_32_sw",
    srcs = ["gf16trimat_2trimat_madd_96_48_64_32.s"],
    copts = [],
)
