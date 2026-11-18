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
    name = "testvectors-Ip-sign_msglen{}".format(N),
    srcs = ["testvectors/testvectors-Ip-sign_msglen{}.s".format(N)],
) for N in CASES]

IP = "//sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip-skc"
IP_SHARED = "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc"

IP_COMMON = [
    IP_SHARED + ":hash_salted_msg",
    IP_SHARED + ":expandv",
    IP_SHARED + ":expandsk_ret_O_pkseed",
    IP_SHARED + ":gf256_transpose_44_44",
]

IP_TIER_DEPS = {
    "bnaesonly": IP_COMMON + [
        IP_SHARED + ":back_substitution_44x44_sw",
        IP_SHARED + ":gaussian_elimination_44x44_sw",
        IP_SHARED + ":gf256mat_prod_68_44_sw",
        IP + ":gf256_ldirect_68_44_sw",
        IP_SHARED + ":row_mul_O_sw",
        IP_SHARED + ":expand_352_table",
        IP_SHARED + ":partial_expandP1_table",
        "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
        "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
        "//sw/acc/crypto/handwritten/AES_ext:aes128_mem",
        "//sw/acc/crypto/handwritten/uov/shared/aes_hw:aes128hw_table_352",
    ],
    "bngfaes": IP_COMMON + [
        IP_SHARED + ":back_substitution_44x44",
        IP_SHARED + ":gaussian_elimination_44x44",
        IP_SHARED + ":gf256mat_prod_68_44",
        IP + ":gf256_ldirect_68_44",
        IP_SHARED + ":expand352",
        IP_SHARED + ":partial_expandP1",
        IP_SHARED + ":row_mul_O",
    ],
    "bngfonly": IP_COMMON + [
        IP_SHARED + ":back_substitution_44x44_bngfonly",
        IP_SHARED + ":gaussian_elimination_44x44_bngfonly",
        IP_SHARED + ":gf256mat_prod_68_44_bngfonly",
        IP + ":gf256_ldirect_68_44_bngfonly",
        IP_SHARED + ":expand352_bngfonly",
        IP_SHARED + ":partial_expandP1_bngfonly",
        IP_SHARED + ":row_mul_O_bngfonly",
        IP_SHARED + "/AES_bngf:KeySchedule_sign",
        IP_SHARED + "/AES_bngf:aes128_sign",
        IP_SHARED + "/AES_bngf:aes_constants_sign",
    ],
    "sw": IP_COMMON + [
        IP_SHARED + ":back_substitution_44x44_sw",
        IP_SHARED + ":gaussian_elimination_44x44_sw",
        IP_SHARED + ":gf256mat_prod_68_44_sw",
        IP + ":gf256_ldirect_68_44_sw",
        IP_SHARED + ":row_mul_O_sw",
        IP_SHARED + ":expand_352_table",
        IP_SHARED + ":partial_expandP1_table",
        "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
        "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
        IP_SHARED + "/AES_ttable:key_schedule",
        IP_SHARED + "/AES_ttable:aes_encrypt",
        IP_SHARED + "/AES_ttable:aes128_table",
        IP_SHARED + "/AES_ttable:aes128table_352",
    ],
}

[acc_binary(
    name = "ov-Ip-sign_rtl_{}_{}".format(T, N),
    srcs = ["ov-Ip-skc_sign_rtl.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
    deps = [IP + ":ov-Ip-skc-sign_{}_testvec".format(SIGN_KERNEL_TIER[T])] + IP_TIER_DEPS[T] + [
        ":testvectors-Ip-sign_msglen{}".format(N),
    ],
) for T in TIERS for N in CASES]

# Chip-level C driver twins, msglen 0 only (the chip cell exercises the host path and the tier datapath, not the
# message-feed loop). ACC_SYMBOL_PTR token-pastes the app name, so the name must be underscore-only.
[acc_binary(
    name = "ov_Ip_sign_rtl_{}_0".format(T),
    srcs = ["ov-Ip-skc_sign_rtl.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
    deps = [IP + ":ov-Ip-skc-sign_{}_testvec".format(SIGN_KERNEL_TIER[T])] + IP_TIER_DEPS[T] + [
        ":testvectors-Ip-sign_msglen0",
    ],
) for T in TIERS]

# Cryptotest binaries: empty buffers, not a KAT, since the host injects everything.
acc_library(
    name = "buffers-Ip-sign",
    srcs = ["testvectors/buffers-Ip-sign.s"],
)

[acc_binary(
    name = "ov_Ip_sign_rtl_{}_hostfed".format(T),
    srcs = ["ov-Ip-skc_sign_rtl.s"],
    copts = ["-DUSE_TESTVEC_SALT"],
    deps = [IP + ":ov-Ip-skc-sign_{}_testvec".format(SIGN_KERNEL_TIER[T])] + IP_TIER_DEPS[T] + [
        ":buffers-Ip-sign",
    ],
) for T in TIERS]

# ISS tests: the msglen-0 cells of the chip twins, built without the RTL stop-PC
# label. Pass = the harness's own signature compare and stack guard (x5 = 0).
[acc_sim_test(
    name = "ov_Ip_sign_test_{}".format(T),
    srcs = ["ov-Ip-skc_sign_rtl.s"],
    copts = ["-DUSE_TESTVEC_SALT", "-DISS_SIM_TEST"],
    exp = SIGN_PASS,
    pqc = True,
    timeout = "eternal" if T == "sw" else "long",
    deps = [IP + ":ov-Ip-skc-sign_{}_testvec".format(SIGN_KERNEL_TIER[T])] + IP_TIER_DEPS[T] + [
        ":testvectors-Ip-sign_msglen0",
    ],
) for T in TIERS]
