load("//rules:acc.bzl", "acc_library")
package(default_visibility = ["//visibility:public"])

# SW T-table AES routines for the sw keygen variant.
# local T-table AES helpers.

alias(
    name = "aes128_table",
    actual = "//sw/acc/crypto/handwritten/AES_table:aes128_table",  # the same source file
)

acc_library(
    name = "key_schedule",
    srcs = ["key_schedule.s"],
)

acc_library(
    name = "aes_encrypt",
    srcs = ["aes_encrypt.s"],
)

acc_library(
    name = "aes128table_352",
    srcs = ["aes128table_352.s"],
)

# 24-block (384 B) twin of aes128table_352, for the R3 expansion quantum.
acc_library(
    name = "aes128table_384",
    srcs = ["aes128table_384.s"],
)
