load("//rules:acc.bzl", "acc_library")
package(default_visibility = ["//visibility:public"])

# SW T-table AES sources for the Is-PKC verify sw tier.

# 4 KiB AES T-table data. Provides AES128_TABLE.
alias(
    name = "aes128_table",
    actual = "//sw/acc/crypto/handwritten/AES_table:aes128_table",  # the same source file
)

# AES-128 key schedule. Provides AES_128_keyschedule.
alias(
    name = "key_schedule",
    actual = "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_ttable:key_schedule",  # the same source file
)

# AES-128 single-block encrypt. Provides AES_128_encrypt.
alias(
    name = "aes_encrypt",
    actual = "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_ttable:aes_encrypt",  # the same source file
)

# AES-128-CTR single-col PRG for Is (32 B = 2 blocks). Provides aes128_col_is.
acc_library(
    name = "aes128_col_is",
    srcs = ["aes128_col_is.s"],
)
