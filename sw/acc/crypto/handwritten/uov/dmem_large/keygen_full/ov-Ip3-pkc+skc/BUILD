load("//rules:acc.bzl", "acc_library", "acc_binary")
package(default_visibility = ["//visibility:public"])

# Ip3 keygen full, bngfaes only: inline bn.aes128 stream + bn.gfmul.8 arithmetic.
acc_library(
    name = "P1O_P2",
    srcs = ["P1O_P2.s"],
)

acc_library(
    name = "P3_cal",
    srcs = ["P3_cal.s"],
)

acc_library(
    name = "cpk_pack",
    srcs = ["cpk_pack.s"],
)

acc_library(
    name = "ov-Ip3-keygen",
    srcs = ["ov-Ip3-keygen.s"],
)

acc_binary(
    name = "ov-Ip3-keygen_full_bngfaes",
    srcs = ["ov-Ip3-keygen_test.s"],
    deps = [
        ":ov-Ip3-keygen",
        ":P1O_P2",
        ":P3_cal",
        ":cpk_pack",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip3-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip3-skc:expand_360",
    ],
)
