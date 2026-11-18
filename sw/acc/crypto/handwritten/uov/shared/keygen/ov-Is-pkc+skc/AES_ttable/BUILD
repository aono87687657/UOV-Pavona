load("//rules:acc.bzl", "acc_library")
package(default_visibility = ["//visibility:public"])

# SW T-table AES routines for the Is sw keygen variant.
# local T-table AES helpers.

alias(
    name = "aes128_table",
    actual = "//sw/acc/crypto/handwritten/AES_table:aes128_table",  # the same source file
)

alias(
    name = "key_schedule",
    actual = "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:key_schedule",  # the same source file
)

alias(
    name = "aes_encrypt",
    actual = "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes_encrypt",  # the same source file
)

acc_library(
    name = "aes128_dual_table",
    srcs = ["aes128_dual_table.s"],
)
