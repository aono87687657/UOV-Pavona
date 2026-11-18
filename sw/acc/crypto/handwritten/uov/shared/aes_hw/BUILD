load("//rules:acc.bzl", "acc_library", "acc_sim_test")

package(default_visibility = ["//visibility:public"])

# Hardware AES leaves behind the T-table wrappers' contracts: the Round-2 AES-only sign and
# keygen kernels link these in place of the AES_ttable wrappers (both lanes, keys in registers).
acc_library(
    name = "aes128hw_table_352",
    srcs = ["aes128hw_table_352.s"],
)

acc_library(
    name = "aes128hw_dual_table",
    srcs = ["aes128hw_dual_table.s"],
)

# Ip3 sign and keygen: the leaf of //sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip3-pkc:aes128hw_384 with sign's
# register plan: duals in w0-w11, key w12 -- inside expand_360_table's "w16-w31 preserved" contract, which the verify
# plan (w18, w30) would break.
acc_library(
    name = "aes128hw_384_sign",
    srcs = ["aes128hw_384_sign.s"],
)

# Round keys held in WDRs for the whole EXECUTE: each object exports AES_128_keyschedule (each call expands the
# key into its bank and the packed schedule) and the leaf its kernels call. One object per bank: sign, keygen
# min/sp, the verifiers.
[acc_library(
    name = "aes128hw_bank_" + b,
    srcs = ["aes128hw_bank_" + b + ".s"],
) for b in ("sign", "kg", "verify")]

[acc_sim_test(
    name = "aes128hw_bank_" + b + "_test",
    srcs = ["tests/aes128hw_bank_" + b + "_test.s"],
    exp = "tests/aes128hw_bank_" + b + "_test.exp",
    dexp = "tests/aes128hw_bank_" + b + "_test.dexp",
    pqc = True,
    deps = [":aes128hw_bank_" + b],
) for b in ("sign", "kg", "verify")]
