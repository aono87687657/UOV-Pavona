load("//rules:acc.bzl", "acc_binary")
package(default_visibility = ["//visibility:public"])

# Round-3 Ip3 twins (forked from the R3 streamed kernel):
# same two arms as the R3 stream package, WJ=1.
[acc_binary(
    name = n,
    srcs = ["ov-Ip3-keygen_min.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip3-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip3-skc:expand_360",
    ],
) for n in ("ov-Ip3-keygen_min_bngfaes", "ov_Ip3_keygen_min_bngfaes")]

[acc_binary(
    name = n,
    srcs = ["ov-Ip3-keygen_min.s"],
    copts = ["-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip3-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip3-skc:expand_360_bngfonly",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:aes128_sign",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:KeySchedule_sign",
    ],
) for n in ("ov-Ip3-keygen_min_bngfonly", "ov_Ip3_keygen_min_bngfonly")]

# Ip3 software-GF twins (forked from the R3 gfsw kernel).
[acc_binary(
    name = n,
    srcs = ["ov-Ip3-keygen_min_sw.s"],
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
) for n in ("ov-Ip3-keygen_min_sw", "ov_Ip3_keygen_min_sw")]

[acc_binary(
    name = n,
    srcs = ["ov-Ip3-keygen_min_sw.s"],
    copts = ["-DAES_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip3-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip3-skc:expand_360_table_bnaesonly",
        "//sw/acc/crypto/handwritten/uov/shared/aes_hw:aes128hw_384_sign",
        "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
        "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
    ],
) for n in ("ov-Ip3-keygen_min_bnaesonly", "ov_Ip3_keygen_min_bnaesonly")]
