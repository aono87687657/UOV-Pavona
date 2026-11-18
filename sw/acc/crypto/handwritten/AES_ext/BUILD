load("//rules:acc.bzl", "acc_binary", "acc_library")
package(default_visibility = ["//visibility:public"])

acc_binary(
    name = "aes128_ext_test",
    srcs = ["aes128_ext_test.s"],
)

# Cycle-measurement isolation tests (key schedule vs encrypt).
acc_binary(
    name = "aes128_ext_ks_test",
    srcs = ["aes128_ext_ks_test.s"],
)

acc_binary(
    name = "aes128_ext_enc_test",
    srcs = ["aes128_ext_enc_test.s"],
)

# Setup-only baseline (isolates the op cost by subtraction; serves ks + enc).
acc_binary(
    name = "aes128_ext_setup_test",
    srcs = ["aes128_ext_setup_test.s"],
)

acc_binary(
    name = "aes128_mem_baseline_test",
    srcs = ["aes128_mem_test.s"],
    deps = [
        "//sw/acc/crypto/handwritten/AES_table:aes128_table",
        "//sw/acc/crypto/handwritten/AES_table:key_schedule",
        "//sw/acc/crypto/handwritten/AES_table:aes_encrypt",
    ],
)

acc_library(
    name = "aes128_mem",
    srcs = ["aes128_mem.s"],
)

acc_binary(
    name = "aes128_mem_test",
    srcs = ["aes128_mem_test.s"],
    deps = [":aes128_mem"],
)
