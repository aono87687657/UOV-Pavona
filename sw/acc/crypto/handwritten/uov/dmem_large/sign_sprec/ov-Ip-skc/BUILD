load("//rules:acc.bzl", "acc_binary", "acc_library")

package(default_visibility = ["//visibility:public"])

# S-precompute (_sprec) sign arms of Ip. S plus the raw-P1 caches needs
# ~200-354 KB of DMEM, so these targets only run on an enlarged-DMEM config --
# carved out of ov-sign so the dmem32k sign package stays :all-buildable.
# Orchestrators live here; every support kernel links from the shared and dmem32k
# sign packages (absolute labels below; list order is load-bearing for the sw
# tiers -- keep it byte-stable).

_IP = "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc"

# --- OV-Ip ---

acc_library(
    name = "ov-Ip-skc-sign_sprec",
    srcs = ["ov-Ip-skc-sign_sprec.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "ov-Ip-skc-sign_sprec_bngfonly",
    srcs = ["ov-Ip-skc-sign_sprec.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

# sw tier: pure-SW precompute-S (T-table AES + partial_expandP1_table + SW gf256).
acc_library(
    name = "ov-Ip-skc-sign_sprec_sw",
    srcs = ["ov-Ip-skc-sign_sprec.s"],
    copts = [],
)

IP_SIGN_BNGFAES_SPREC_DEPS = [
    _IP + ":hash_salted_msg", _IP + ":expandv", _IP + ":expandsk_ret_O_pkseed", _IP + ":gf256_transpose_44_44",
    _IP + ":batch_quad_trimat_eval_gf256",
    _IP + ":back_substitution_44x44",
    _IP + ":expand352",
    _IP + ":gaussian_elimination_44x44",
    _IP + ":gf256mat_prod_68_44",
    ":gf256_matvec_2816_68",
    ":gf256trimat_2trimat_madd_68_68_44_44",
    _IP + ":partial_expandP1",
    _IP + ":row_mul_O",
]

IP_SIGN_BNGFONLY_SPREC_DEPS = [
    _IP + ":hash_salted_msg", _IP + ":expandv", _IP + ":expandsk_ret_O_pkseed", _IP + ":gf256_transpose_44_44",
    _IP + ":batch_quad_trimat_eval_gf256_bngfonly",
    _IP + ":back_substitution_44x44_bngfonly",
    _IP + ":expand352_bngfonly",
    _IP + ":gaussian_elimination_44x44_bngfonly",
    _IP + ":gf256mat_prod_68_44_bngfonly",
    ":gf256_matvec_2816_68_bngfonly",
    ":gf256trimat_2trimat_madd_68_68_44_44_bngfonly",
    _IP + ":partial_expandP1_bngfonly",
    _IP + ":row_mul_O_bngfonly",
    _IP + "/AES_bngf:KeySchedule_sign",
    _IP + "/AES_bngf:aes128_sign",
    _IP + "/AES_bngf:aes_constants_sign",
]

IP_SIGN_SWONLY_SPREC_DEPS = [
    _IP + ":hash_salted_msg", _IP + ":expandv", _IP + ":expandsk_ret_O_pkseed", _IP + ":gf256_transpose_44_44",
    _IP + ":batch_quad_trimat_eval_gf256_sw",
    _IP + ":back_substitution_44x44_sw",
    _IP + ":gaussian_elimination_44x44_sw",
    _IP + ":gf256mat_prod_68_44_sw",
    ":gf256_matvec_2816_68_sw",
    ":gf256trimat_2trimat_madd_68_68_44_44_sw",
    _IP + ":partial_expandP1_table",
    _IP + ":row_mul_O_sw",
    # T-table AES objects (same bundle + link order as IP_SIGN_SWONLY_DEPS).
    _IP + ":expand_352_table",
    "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
    _IP + "/AES_ttable:key_schedule",
    _IP + "/AES_ttable:aes_encrypt",
    _IP + "/AES_ttable:aes128_table",
    _IP + "/AES_ttable:aes128table_352",
    ":aes128_dualblock",  # partial_expandP1_table
    "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",  # gf256_scalar_inv_sw squarings
]

acc_binary(
    name = "ov-Ip-sign_sprec_bngfaes",
    srcs = ["ov-Ip-skc-sign_sprec_test.s"],
    copts = ["-DP1_CACHE"],
    deps = [":ov-Ip-skc-sign_sprec"] + IP_SIGN_BNGFAES_SPREC_DEPS,
)

acc_binary(
    name = "ov-Ip-sign_sprec_bngfonly",
    srcs = ["ov-Ip-skc-sign_sprec_test.s"],
    copts = ["-DP1_CACHE"],
    deps = [":ov-Ip-skc-sign_sprec_bngfonly"] + IP_SIGN_BNGFONLY_SPREC_DEPS,
)

# testvec (USE_TESTVEC_SALT) orchestrators + testvec_test binaries for the sprec tiers
acc_library(
    name = "ov-Ip-skc-sign_sprec_testvec",
    srcs = ["ov-Ip-skc-sign_sprec.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS", "-DUSE_TESTVEC_SALT"],
)

acc_library(
    name = "ov-Ip-skc-sign_sprec_bngfonly_testvec",
    srcs = ["ov-Ip-skc-sign_sprec.s"],
    copts = ["-DGF_INSTRUCTIONS", "-DUSE_TESTVEC_SALT"],
)

acc_binary(
    name = "ov-Ip-sign_sprec_testvec_bngfaes",
    srcs = ["ov-Ip-skc-sign_sprec_test.s"],
    copts = ["-DUSE_TESTVEC_SALT", "-DP1_CACHE"],
    deps = [":ov-Ip-skc-sign_sprec_testvec"] + IP_SIGN_BNGFAES_SPREC_DEPS,
)

acc_binary(
    name = "ov-Ip-sign_sprec_testvec_bngfonly",
    srcs = ["ov-Ip-skc-sign_sprec_test.s"],
    copts = ["-DUSE_TESTVEC_SALT", "-DP1_CACHE"],
    deps = [":ov-Ip-skc-sign_sprec_bngfonly_testvec"] + IP_SIGN_BNGFONLY_SPREC_DEPS,
)

# sw CACHED precompute-S: sw orchestrator allocs the 150144 B raw-P1 cache below S
# (cached trimat fill + cached sw batch_quad), so the harness needs -DP1_CACHE.
acc_binary(
    name = "ov-Ip-sign_sprec_sw",
    srcs = ["ov-Ip-skc-sign_sprec_test.s"],
    copts = ["-DP1_CACHE"],
    deps = [":ov-Ip-skc-sign_sprec_sw"] + IP_SIGN_SWONLY_SPREC_DEPS,
)

acc_library(
    name = "ov-Ip-skc-sign_sprec_sw_testvec",
    srcs = ["ov-Ip-skc-sign_sprec.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
)

acc_binary(
    name = "ov-Ip-sign_sprec_testvec_sw",
    srcs = ["ov-Ip-skc-sign_sprec_test.s"],
    copts = ["-DUSE_TESTVEC_SALT", "-DP1_CACHE"],
    deps = [":ov-Ip-skc-sign_sprec_sw_testvec"] + IP_SIGN_SWONLY_SPREC_DEPS,
)

acc_library(
    name = "gf256_matvec_2816_68",
    srcs = ["gf256_matvec_2816_68.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_binary(
    name = "gf256_matvec_2816_68_test",
    srcs = ["gf256_matvec_2816_68_test.s"],
    deps = [":gf256_matvec_2816_68"],
)

acc_binary(
    name= "gf256trimat_2trimat_madd_68_68_44_44_test",
    srcs=["gf256trimat_2trimat_madd_68_68_44_44_test.s"],
    deps=[":gf256trimat_2trimat_madd_68_68_44_44",
          "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:row_mul_O",
          "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:partial_expandP1",
          "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc:expand352"]
)

acc_library(
    name = "gf256_matvec_2816_68_bngfonly",
    srcs = ["gf256_matvec_2816_68.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

# --- S-precompute trimat support (S = trimat(P1,P2,O)). The _sprec orchestrators
# and their binaries live in //sw/acc/crypto/handwritten/uov/dmem_large/sign_sprec
# (oversized DMEM); these libs stay here and are linked from there.
# gf256trimat_2trimat_madd: per-row S build; calls row_mul_O (acch hi chain on HW tiers).

acc_library(
    name = "gf256trimat_2trimat_madd_68_68_44_44",
    srcs = ["gf256trimat_2trimat_madd_68_68_44_44.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "gf256trimat_2trimat_madd_68_68_44_44_bngfonly",
    srcs = ["gf256trimat_2trimat_madd_68_68_44_44.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "gf256trimat_2trimat_madd_68_68_44_44_sw",
    srcs = ["gf256trimat_2trimat_madd_68_68_44_44.s"],
    copts = [],
)
acc_library(
    name = "gf256_matvec_2816_68_sw",
    srcs = ["gf256_matvec_2816_68.s"],
    copts = [],
)

# AES-128 dual-block wrapper (encrypts 2 contiguous CTR blocks via AES_128_encrypt).
acc_library(
    name = "aes128_dualblock",
    srcs = ["aes128_dualblock.s"],
)
