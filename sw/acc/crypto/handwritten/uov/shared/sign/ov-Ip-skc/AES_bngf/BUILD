load("//rules:acc.bzl", "acc_library", "acc_binary")
package(default_visibility = ["//visibility:public"])

# SW compute-AES routines for the bngfonly sign variant.
# Fresh implementation (not a literal fork of ov-verify_base AES); sign-native register layout.
# Algorithm reference: ov-verify_base/ov-Is-pkc_gf/AES/{aes128.s, KeySchedule.s}.

acc_library(
    name = "KeySchedule_sign",
    srcs = ["KeySchedule_sign.s"],
)

acc_binary(
    name = "KeySchedule_sign_test",
    srcs = ["KeySchedule_sign_test.s"],
    deps = [
        ":KeySchedule_sign",
        ":aes_constants_sign",
    ],
)

acc_binary(
    name = "KeySchedule_sign_all10_test",
    srcs = ["KeySchedule_sign_all10_test.s"],
    deps = [
        ":KeySchedule_sign",
        ":aes_constants_sign",
    ],
)

acc_library(
    name = "aes128_sign",
    srcs = ["aes128_sign.s"],
)

acc_binary(
    name = "aes128_sign_test",
    srcs = ["aes128_sign_test.s"],
    deps = [
        ":aes128_sign",
        ":KeySchedule_sign",
        ":aes_constants_sign",
    ],
)

acc_binary(
    name = "aes128_sign_zerokey_test",
    srcs = ["aes128_sign_zerokey_test.s"],
    deps = [
        ":aes128_sign",
        ":KeySchedule_sign",
        ":aes_constants_sign",
    ],
)

acc_binary(
    name = "aes128_sign_nistkey_sign_iv_test",
    srcs = ["aes128_sign_nistkey_sign_iv.s"],
    deps = [
        ":aes128_sign",
        ":KeySchedule_sign",
        ":aes_constants_sign",
    ],
)

# aes_constants_sign.s .data constants for SW AES. Loaded by caller via la+bn.lid.
acc_library(
    name = "aes_constants_sign",
    srcs = ["aes_constants_sign.s"],
)
