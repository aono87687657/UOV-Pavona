load("//rules:acc.bzl", "acc_library")
package(default_visibility = ["//visibility:public"])

alias(
    name = "aes128_table",
    actual = "//sw/acc/crypto/handwritten/AES_table:aes128_table",  # the same source file
)

alias(
    name = "key_schedule",
    actual = "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_ttable:key_schedule",  # the same source file
)

alias(
    name = "aes_encrypt",
    actual = "//sw/acc/crypto/handwritten/AES_table:aes_encrypt",  # the same source file
)

acc_library(
    name = "aes128_col_is",
    srcs = ["aes128_col_is.s"],
)

acc_library(
    name = "aes128_dual_table",
    srcs = ["aes128_dual_table.s"],
)
