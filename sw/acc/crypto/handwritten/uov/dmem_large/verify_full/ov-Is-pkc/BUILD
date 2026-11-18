load("//rules:acc.bzl", "acc_binary", "acc_library")
package(default_visibility = ["//visibility:public"])

[acc_binary(
    name = n,
    srcs = ["ov-Is-pkc_verify_full.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
) for n in ("ov-Is-verify_full_bngfaes", "ov_Is_verify_full_bngfaes")]

[acc_binary(
    name = n,
    srcs = ["ov-Is-pkc_verify_full.s"],
    copts = ["-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Is-pkc/AES_bngf:KeySchedule",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Is-pkc/AES_bngf:aes128",
    ],
) for n in ("ov-Is-verify_full_bngfonly", "ov_Is_verify_full_bngfonly")]

[acc_binary(
    name = n,
    srcs = ["ov-Is-pkc_verify_full_sw.s"],
    deps = [
        "//sw/acc/crypto/handwritten/gf16:gf16_mul",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Is-pkc/AES_ttable:aes128_col_is",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Is-pkc/AES_ttable:aes_encrypt",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Is-pkc/AES_ttable:key_schedule",
        "//sw/acc/crypto/handwritten/AES_table:aes128_table",
    ],
) for n in ("ov-Is-verify_full_sw", "ov_Is_verify_full_sw")]

[acc_binary(
    name = n,
    srcs = ["ov-Is-pkc_verify_full_sw.s"],
    copts = ["-DAES_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/gf16:gf16_mul",
        "//sw/acc/crypto/handwritten/uov/shared/aes_hw:aes128hw_bank_verify",
    ],
) for n in ("ov-Is-verify_full_bnaesonly", "ov_Is_verify_full_bnaesonly")]
