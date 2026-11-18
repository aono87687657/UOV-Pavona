load("//rules:acc.bzl", "acc_binary", "acc_library", "acc_sim_test")

package(default_visibility = ["//visibility:public"])

# Self-contained L-direct sign binaries for RTL: test vectors linked into .data,
# signature compared in-kernel (x5) and published into w0.. for an external
# host-side check. Sized to fit the 31,744 B bus-visible DMEM window.
#   cases: the full 12-msglen KAT set; 0 and 1024 are the dev endpoints
#   tiers: bngfaes, bngfonly, bnaesonly, sw (hardware GF/AES independently selected)

CASES = [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024]

TIERS = ["bngfaes", "bngfonly", "bnaesonly", "sw"]
SIGN_KERNEL_TIER = {"bngfaes": "bngfaes", "bngfonly": "bngfonly", "bnaesonly": "sw", "sw": "sw"}
SIGN_PASS = "//sw/acc/crypto/handwritten/uov/dmem32k/sign_rtl:tests/sign_pass.exp"

[acc_library(
    name = "testvectors-Is-sign_msglen{}".format(N),
    srcs = ["testvectors/testvectors-Is-sign_msglen{}.s".format(N)],
) for N in CASES]

IS = "//sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Is-skc"
IS_SHARED = "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc"

IS_COMMON = [
    IS_SHARED + ":hash_salted_msg",
    IS_SHARED + ":expandv",
    IS_SHARED + ":expandsk_ret_O_pkseed",
    IS_SHARED + ":gf16_transpose_64_64",
]

IS_TIER_DEPS = {
    "bnaesonly": IS_COMMON + [
        IS_SHARED + ":back_substitution_64x64_sw",
        IS_SHARED + ":gaussian_elimination_64x64_sw",
        IS_SHARED + ":gf16mat_prod_48_64_sw",
        IS + ":gf16_ldirect_96_64_sw",
        IS_SHARED + ":gf16_matvec_2048_96_sw",
        "//sw/acc/crypto/handwritten/gf16:gf16_sw_helpers",
        "//sw/acc/crypto/handwritten/uov/shared/aes_hw:aes128hw_bank_sign",
        IS_SHARED + "/AES_ttable:aes128_col_is",
    ],
    "bngfaes": IS_COMMON + [
        IS_SHARED + ":back_substitution_64x64",
        IS_SHARED + ":gaussian_elimination_64x64",
        IS_SHARED + ":gf16mat_prod_48_64",
        IS + ":gf16_ldirect_96_64",
        IS_SHARED + ":gf16_matvec_2048_96",
    ],
    "bngfonly": IS_COMMON + [
        IS_SHARED + ":back_substitution_64x64",
        IS_SHARED + ":gaussian_elimination_64x64_bngfonly",
        IS_SHARED + ":gf16mat_prod_48_64_bngfonly",
        IS + ":gf16_ldirect_96_64_bngfonly",
        IS_SHARED + ":gf16_matvec_2048_96_bngfonly",
        IS_SHARED + "/AES_bngf:KeySchedule_sign",
        IS_SHARED + "/AES_bngf:aes128_sign",
        IS_SHARED + "/AES_bngf:aes_constants_sign",
    ],
    "sw": IS_COMMON + [
        IS_SHARED + ":back_substitution_64x64_sw",
        IS_SHARED + ":gaussian_elimination_64x64_sw",
        IS_SHARED + ":gf16mat_prod_48_64_sw",
        IS + ":gf16_ldirect_96_64_sw",
        IS_SHARED + ":gf16_matvec_2048_96_sw",
        "//sw/acc/crypto/handwritten/gf16:gf16_sw_helpers",
        IS_SHARED + "/AES_ttable:aes128_dual_table",
        IS_SHARED + "/AES_ttable:aes128_col_is",
        IS_SHARED + "/AES_ttable:aes_encrypt",
        IS_SHARED + "/AES_ttable:key_schedule",
        IS_SHARED + "/AES_ttable:aes128_table",
    ],
}

[acc_binary(
    name = "ov-Is-sign_rtl_{}_{}".format(T, N),
    srcs = ["ov-Is-skc_sign_rtl.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
    deps = [IS + ":ov-Is-skc-sign_{}_testvec".format(SIGN_KERNEL_TIER[T])] + IS_TIER_DEPS[T] + [
        ":testvectors-Is-sign_msglen{}".format(N),
    ],
) for T in TIERS for N in CASES]

# Chip-level C driver twins, msglen 0 only (the chip cell exercises the host path and the tier datapath, not the
# message-feed loop). ACC_SYMBOL_PTR token-pastes the app name, so the name must be underscore-only.
[acc_binary(
    name = "ov_Is_sign_rtl_{}_0".format(T),
    srcs = ["ov-Is-skc_sign_rtl.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
    deps = [IS + ":ov-Is-skc-sign_{}_testvec".format(SIGN_KERNEL_TIER[T])] + IS_TIER_DEPS[T] + [
        ":testvectors-Is-sign_msglen0",
    ],
) for T in TIERS]

# Cryptotest binaries: empty buffers, not a KAT, since the host injects everything.
acc_library(
    name = "buffers-Is-sign",
    srcs = ["testvectors/buffers-Is-sign.s"],
)

[acc_binary(
    name = "ov_Is_sign_rtl_{}_hostfed".format(T),
    srcs = ["ov-Is-skc_sign_rtl.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
    deps = [IS + ":ov-Is-skc-sign_{}_testvec".format(SIGN_KERNEL_TIER[T])] + IS_TIER_DEPS[T] + [
        ":buffers-Is-sign",
    ],
) for T in TIERS]

# ISS tests: the msglen-0 cells of the chip twins, built without the RTL stop-PC
# label. Pass = the harness's own signature compare and stack guard (x5 = 0).
[acc_sim_test(
    name = "ov_Is_sign_test_{}".format(T),
    srcs = ["ov-Is-skc_sign_rtl.s"],
    copts = ["-DUSE_TESTVEC_SALT", "-DISS_SIM_TEST"],
    exp = SIGN_PASS,
    pqc = True,
    timeout = "eternal" if T == "sw" else "long",
    deps = [IS + ":ov-Is-skc-sign_{}_testvec".format(SIGN_KERNEL_TIER[T])] + IS_TIER_DEPS[T] + [
        ":testvectors-Is-sign_msglen0",
    ],
) for T in TIERS]
