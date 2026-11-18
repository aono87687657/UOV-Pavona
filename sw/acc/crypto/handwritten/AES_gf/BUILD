load("//rules:acc.bzl", "acc_library", "acc_binary")
package(default_visibility = ["//visibility:public"])

# Dual-block AES-128 over GF(256) using bn.gfmul.8 for SubBytes
# (Itoh-Tsujii inversion) and MixColumns. Mirrors ov-Is-pkc_gf/AES.
# 1664 cycles per dual-block (KS + encrypt 32 bytes).

acc_library(
    name = "KeySchedule",
    srcs = ["KeySchedule.s"],
)

acc_library(
    name = "aes128",
    srcs = ["aes128.s"],
)

acc_binary(
    name = "aes128_test",
    srcs = ["aes128_test.s"],
    deps = [
        ":aes128",
        ":KeySchedule",
    ],
)

acc_binary(
    name = "aes128_encrypt_only_test",
    srcs = ["aes128_encrypt_only_test.s"],
    deps = [
        ":aes128",
    ],
)

# Full 10-round key schedule (cycle measurement).
acc_binary(
    name = "aes128_fullks_test",
    srcs = ["aes128_fullks_test.s"],
    deps = [
        ":KeySchedule",
    ],
)

# Setup-only baselines (isolate the op cost by subtraction).
acc_binary(name = "aes128_fullks_setup_test", srcs = ["aes128_fullks_setup_test.s"])
acc_binary(name = "aes128_encrypt_only_setup_test", srcs = ["aes128_encrypt_only_setup_test.s"])
