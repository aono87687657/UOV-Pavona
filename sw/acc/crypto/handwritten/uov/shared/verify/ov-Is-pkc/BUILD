load("//rules:acc.bzl", "acc_binary", "acc_library", "acc_sim_test")

package(default_visibility = ["//visibility:public"])

acc_library(
    name = "aes128hw_col_is",
    srcs = ["aes128hw_col_is.s"],
)

acc_sim_test(
    name = "aes128hw_col_is_test",
    srcs = ["tests/aes128hw_col_is_test.s"],
    exp = "tests/aes128hw_col_is_test.exp",
    dexp = "tests/aes128hw_col_is_test.dexp",
    pqc = True,
    deps = [
        ":aes128hw_col_is",
        "//sw/acc/crypto/handwritten/AES_ext:aes128_mem",
    ],
)
