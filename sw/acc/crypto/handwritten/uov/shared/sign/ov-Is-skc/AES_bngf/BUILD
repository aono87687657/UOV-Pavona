load("//rules:acc.bzl", "acc_library")
package(default_visibility = ["//visibility:public"])

# SW compute-AES routines for the bngfonly sign variant.
# Fresh implementation (not a literal fork of ov-verify_base AES); sign-native register layout.
# Algorithm reference: ov-verify_base/ov-Is-pkc_gf/AES/{aes128.s, KeySchedule.s}.
# KeySchedule_sign and aes_constants_sign are Ip's (the same source file); their tests are in
# ../../ov-Ip-skc/AES_bngf.

alias(
    name = "KeySchedule_sign",
    actual = "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:KeySchedule_sign",  # the same source file
)

acc_library(
    name = "aes128_sign",
    srcs = ["aes128_sign.s"],
)

# aes_constants_sign.s .data constants for SW AES. Loaded by caller via la+bn.lid.
alias(
    name = "aes_constants_sign",
    actual = "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:aes_constants_sign",  # the same source file
)
