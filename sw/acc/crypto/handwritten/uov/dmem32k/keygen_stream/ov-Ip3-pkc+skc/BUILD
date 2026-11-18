load("//rules:acc.bzl", "acc_binary", "acc_library")

package(default_visibility = ["//visibility:public"])

# --- Streamed keygen kernel (Ip3), bngfaes arm.
# expand_360 (P1/P2 leaf) is shared with the R3 sign package.
# Each kernel also gets an underscore-named twin: the chip driver token-pastes the app name.
[acc_binary(
    name = n,
    srcs = ["ov-Ip3-keygen_stream.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip3-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip3-skc:expand_360",
    ],
) for n in ["ov-Ip3-keygen_stream_bngfaes", "ov_Ip3_keygen_stream_bngfaes"]]

# Software-GF arms (WJ=5 fork): sw = T-table AES,
# aesonly = HW AES via expand_360_table_aesonly/aes128hw_384_sign.
[acc_binary(
    name = n,
    srcs = ["ov-Ip3-keygen_stream_gfsw.s"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip3-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip3-skc:expand_360_table",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes128_table",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:key_schedule",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes_encrypt",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes128table_384",
        "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
        "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
    ],
) for n in ["ov-Ip3-keygen_stream_sw", "ov_Ip3_keygen_stream_sw"]]

[acc_binary(
    name = n,
    srcs = ["ov-Ip3-keygen_stream_gfsw.s"],
    copts = ["-DAES_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip3-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip3-skc:expand_360_table_bnaesonly",
        "//sw/acc/crypto/handwritten/uov/shared/aes_hw:aes128hw_384_sign",
        "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
        "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
    ],
) for n in ["ov-Ip3-keygen_stream_bnaesonly", "ov_Ip3_keygen_stream_bnaesonly"]]

# bngfonly arm: SW AES via aes128_sign/KeySchedule_sign. AES constants are
# embedded in the kernel pad (do NOT add aes_constants_sign: duplicate globals).
[acc_binary(
    name = n,
    srcs = ["ov-Ip3-keygen_stream.s"],
    copts = ["-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip3-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip3-skc:expand_360_bngfonly",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:aes128_sign",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:KeySchedule_sign",
    ],
) for n in ["ov-Ip3-keygen_stream_bngfonly", "ov_Ip3_keygen_stream_bngfonly"]]
