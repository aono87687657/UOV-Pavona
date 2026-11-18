load("//rules:acc.bzl", "acc_library", "acc_binary")
package(default_visibility = ["//visibility:public"])


# 4 KiB AES T-table (interleaved [Te2, Te0, Te3, Te1] per 16-byte entry).
# Provides global symbol AES128_TABLE.
acc_library(
    name = "aes128_table",
    srcs = ["aes128_table.s"],
)

# AES-128 key schedule (T-table flavour). Uses AES128_TABLE for SubWord.
# Provides AES_128_keyschedule.
acc_library(
    name = "key_schedule",
    srcs = ["key_schedule.s"],
)

# AES-128 single-block encrypt (T-table flavour). Uses AES128_TABLE.
# Provides AES_128_encrypt.
acc_library(
    name = "aes_encrypt",
    srcs = ["aes_encrypt.s"],
)

# AES-128-CTR fixed 352-byte (22-block) PRG expander.
# Wraps AES_128_encrypt with zero nonce + 32-bit BE counter.
# Provides aes128table_352.
acc_library(
    name = "aes128table_352",
    srcs = ["aes128table_352.s"],
)


# Test driver: key schedule + single-block encrypt.
acc_binary(
    name = "aes128_table_test",
    srcs = ["aes128_table_test.s"],
    deps = [
        ":aes128_table",
        ":key_schedule",
        ":aes_encrypt",
    ],
)

# Test driver: key schedule only.
acc_binary(
    name = "aes_keyschedule_test",
    srcs = ["aes_keyschedule_test.s"],
    deps = [
        ":aes128_table",
        ":key_schedule",
    ],
)

# Test driver: encrypt only (round_keys preloaded).
acc_binary(
    name = "aes_encrypt_only_test",
    srcs = ["aes_encrypt_only_test.s"],
    deps = [
        ":aes128_table",
        ":aes_encrypt",
    ],
)

# Setup-only baselines (isolate the op cost by subtraction).
acc_binary(name = "aes_keyschedule_setup_test", srcs = ["aes_keyschedule_setup_test.s"])
acc_binary(name = "aes_encrypt_only_setup_test", srcs = ["aes_encrypt_only_setup_test.s"])

# Test driver: key schedule + 352-byte PRG expansion.
acc_binary(
    name = "aes_ctr_test",
    srcs = ["aes_ctr_test.s"],
    deps = [
        ":aes128_table",
        ":key_schedule",
        ":aes_encrypt",
        ":aes128table_352",
    ],
)
