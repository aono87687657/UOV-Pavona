load("//rules:acc.bzl", "acc_library")
package(default_visibility = ["//visibility:public"])

# 4 KiB AES T-table (interleaved [Te2, Te0, Te3, Te1] per 16-byte entry).
# Local copy for sign-side aestable variant.
alias(
    name = "aes128_table",
    actual = "//sw/acc/crypto/handwritten/AES_table:aes128_table",  # the same source file
)

# AES-128 key schedule.
acc_library(
    name = "key_schedule",
    srcs = ["key_schedule.s"],
)

# AES-128 single-block encrypt.
alias(
    name = "aes_encrypt",
    actual = "//sw/acc/crypto/handwritten/AES_table:aes_encrypt",  # the same source file
)

# AES-128-CTR 352-byte (22-block) PRG expander.
alias(
    name = "aes128table_352",
    actual = "//sw/acc/crypto/handwritten/AES_table:aes128table_352",  # the same source file
)
