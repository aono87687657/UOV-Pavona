load("//rules:acc.bzl", "acc_binary", "acc_library")
package(default_visibility = ["//visibility:public"])

# One-shot UOV-Ip3 verify at 128 KiB: the streamed R3 phase bodies re-shelled
# with the whole cpk resident. Two arms from the
# hardware-GF source; the software-GF twins follow the same recipe. Each arm has
# an underscore twin with the same image for the chip test (C symbol names).

acc_library(
    name = "aes128_360_bngf_full",
    srcs = ["aes128_360_bngf_full.s"],
)

[acc_binary(
    name = n,
    srcs = ["ov-Ip3-pkc_verify_full.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip3-pkc:aes128_360",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip3-pkc:load_p3_45",
    ],
) for n in ("ov-Ip3-verify_full_bngfaes", "ov_Ip3_verify_full_bngfaes")]

[acc_binary(
    name = n,
    srcs = ["ov-Ip3-pkc_verify_full.s"],
    copts = ["-DGF_INSTRUCTIONS"],
    deps = [
        ":aes128_360_bngf_full",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip3-pkc:load_p3_45",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_bngf:KeySchedule",
    ],
) for n in ("ov-Ip3-verify_full_bngfonly", "ov_Ip3_verify_full_bngfonly")]

# Software-GF twins: swonly = T-table AES,
# aesonly = hardware AES leaf, same body and GF helper.
[acc_binary(
    name = n,
    srcs = ["ov-Ip3-pkc_verify_full_sw.s"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc:gf256_mul_pqc_w16safe",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes128table_384",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_ttable:aes_encrypt",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_ttable:key_schedule",
        "//sw/acc/crypto/handwritten/AES_table:aes128_table",
    ],
) for n in ("ov-Ip3-verify_full_sw", "ov_Ip3_verify_full_sw")]

[acc_binary(
    name = n,
    srcs = ["ov-Ip3-pkc_verify_full_sw.s"],
    copts = ["-DAES_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip3-pkc:aes128hw_384",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc:gf256_mul_pqc_w16safe",
    ],
) for n in ("ov-Ip3-verify_full_bnaesonly", "ov_Ip3_verify_full_bnaesonly")]
