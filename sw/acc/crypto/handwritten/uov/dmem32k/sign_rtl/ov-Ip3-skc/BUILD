load("//rules:acc.bzl", "acc_binary", "acc_library", "acc_sim_test")

package(default_visibility = ["//visibility:public"])

# Self-contained L-direct sign binaries for RTL (Round 3), msglen 0 only: test vectors linked into .data,
# signature compared in-kernel (x5). Chip-driver twins (underscore names: the driver token-pastes the app name)
# and their ISS tests. Dep lists mirror //sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip3-skc.
TIERS = ["bngfaes", "bngfonly", "bnaesonly", "sw"]
SIGN_PASS = "//sw/acc/crypto/handwritten/uov/dmem32k/sign_rtl:tests/sign_pass.exp"

IP3 = "//sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip3-skc"
IP3_SHARED = "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip3-skc"

acc_library(
    name = "testvectors-Ip3-sign_msglen0",
    srcs = ["testvectors/testvectors-Ip3-sign_msglen0.s"],
)

IP3_COMMON = [
    IP3 + ":hash_salted_msg",
    IP3 + ":expandv",
    IP3 + ":gf256_transpose_45_45",
    "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip3-pkc+skc:expandsk_ret_O_pkseed",
]

IP3_SW_GF = [
    IP3 + ":back_substitution_45x45_sw",
    IP3 + ":gaussian_elimination_45x45_sw",
    IP3 + ":gf256mat_prod_74_45_sw",
    IP3 + ":row_mul_O_sw",
    "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
    "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
]

IP3_TIER_DEPS = {
    "bngfaes": IP3_COMMON + [
        IP3 + ":back_substitution_45x45",
        IP3_SHARED + ":expand_360",
        IP3 + ":gaussian_elimination_45x45",
        IP3 + ":gf256mat_prod_74_45",
        IP3 + ":gf256_ldirect_74_45",
        IP3 + ":row_mul_O",
    ],
    "bngfonly": IP3_COMMON + [
        IP3 + ":back_substitution_45x45_bngfonly",
        IP3_SHARED + ":expand_360_bngfonly",
        IP3 + ":gaussian_elimination_45x45_bngfonly",
        IP3 + ":gf256mat_prod_74_45_bngfonly",
        IP3 + ":gf256_ldirect_74_45_bngfonly",
        IP3 + ":row_mul_O_bngfonly",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:KeySchedule_sign",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:aes128_sign",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:aes_constants_sign",
    ],
    "bnaesonly": IP3_COMMON + IP3_SW_GF + [
        IP3 + ":gf256_ldirect_74_45_bnaesonly",
        IP3_SHARED + ":expand_360_table_bnaesonly",
        "//sw/acc/crypto/handwritten/uov/shared/aes_hw:aes128hw_384_sign",
    ],
    "sw": IP3_COMMON + IP3_SW_GF + [
        IP3 + ":gf256_ldirect_74_45_sw",
        IP3_SHARED + ":expand_360_table",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_ttable:key_schedule",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_ttable:aes_encrypt",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_ttable:aes128_table",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes128table_384",
    ],
}

# The kernel body library per tier (-DUSE_TESTVEC_SALT reads the salt from DMEM).
IP3_KERNEL = {
    "bngfaes": ":ov-Ip3-skc-sign_testvec",
    "bngfonly": ":ov-Ip3-skc-sign_bngfonly_testvec",
    "bnaesonly": ":ov-Ip3-skc-sign_sw_testvec",
    "sw": ":ov-Ip3-skc-sign_sw_testvec",
}

[acc_binary(
    name = "ov_Ip3_sign_rtl_{}_0".format(T),
    srcs = ["ov-Ip3-skc_sign_rtl.s"],
    deps = [IP3 + IP3_KERNEL[T]] + IP3_TIER_DEPS[T] + [":testvectors-Ip3-sign_msglen0"],
) for T in TIERS]

# ISS tests: the chip twins built without the RTL stop-PC label. Pass = the harness's own signature compare and
# stack guard (x5 = 0).
[acc_sim_test(
    name = "ov_Ip3_sign_test_{}".format(T),
    srcs = ["ov-Ip3-skc_sign_rtl.s"],
    copts = ["-DISS_SIM_TEST"],
    exp = SIGN_PASS,
    pqc = True,
    timeout = "eternal" if T == "sw" else "long",
    deps = [IP3 + IP3_KERNEL[T]] + IP3_TIER_DEPS[T] + [":testvectors-Ip3-sign_msglen0"],
) for T in TIERS]

# Cryptotest binaries: empty buffers, not a KAT, since the host injects everything.
acc_library(
    name = "buffers-Ip3-sign",
    srcs = ["testvectors/buffers-Ip3-sign.s"],
)

[acc_binary(
    name = "ov_Ip3_sign_rtl_{}_hostfed".format(T),
    srcs = ["ov-Ip3-skc_sign_rtl.s"],
    deps = [IP3 + IP3_KERNEL[T]] + IP3_TIER_DEPS[T] + [":buffers-Ip3-sign"],
) for T in TIERS]
