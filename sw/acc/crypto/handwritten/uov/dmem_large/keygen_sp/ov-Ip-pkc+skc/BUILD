load("//rules:acc.bzl", "acc_binary")
package(default_visibility = ["//visibility:public"])

# Single pass over P1 (one window with all 44 columns, triangle accumulator packed
# in place); same host contract as the _min twins. Needs the 128 KiB part.
[acc_binary(
    name = n,
    srcs = ["ov-Ip-keygen_sp.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
    ],
) for n in ("ov-Ip-keygen_sp_bngfaes", "ov_Ip_keygen_sp_bngfaes")]

[acc_binary(
    name = n,
    srcs = ["ov-Ip-keygen_sp.s"],
    copts = ["-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_bngf:KeySchedule_keygen",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_bngf:aes128_keygen",
    ],
) for n in ("ov-Ip-keygen_sp_bngfonly", "ov_Ip_keygen_sp_bngfonly")]

[acc_binary(
    name = n,
    srcs = ["ov-Ip-keygen_sp_sw.s"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes128_table",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:key_schedule",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes_encrypt",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes128table_352",
        "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
        "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
    ],
) for n in ("ov-Ip-keygen_sp_sw", "ov_Ip_keygen_sp_sw")]

[acc_binary(
    name = n,
    srcs = ["ov-Ip-keygen_sp_sw.s"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/AES_ext:aes128_mem",
        "//sw/acc/crypto/handwritten/uov/shared/aes_hw:aes128hw_table_352",
        "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
        "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
    ],
) for n in ("ov-Ip-keygen_sp_bnaesonly", "ov_Ip_keygen_sp_bnaesonly")]
