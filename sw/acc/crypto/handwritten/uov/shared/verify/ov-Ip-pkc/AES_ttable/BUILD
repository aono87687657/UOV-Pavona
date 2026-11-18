load("//rules:acc.bzl", "acc_library")
package(default_visibility = ["//visibility:public"])

# SW T-table AES sources for the Ip-PKC verify sw tier.

# 4 KiB AES T-table data. Provides AES128_TABLE.
alias(
    name = "aes128_table",
    actual = "//sw/acc/crypto/handwritten/AES_table:aes128_table",  # the same source file
)

# AES-128 key schedule. Provides AES_128_keyschedule.
acc_library(
    name = "key_schedule",
    srcs = ["key_schedule.s"],
)

# AES-128 single-block encrypt. Provides AES_128_encrypt.
acc_library(
    name = "aes_encrypt",
    srcs = ["aes_encrypt.s"],
)

# AES-128-CTR fixed 352-byte (22-block) PRG. Provides aes128table_352.
acc_library(
    name = "aes128table_352",
    srcs = ["aes128table_352.s"],
)
