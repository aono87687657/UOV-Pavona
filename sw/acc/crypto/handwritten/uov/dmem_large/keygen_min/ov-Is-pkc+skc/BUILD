load("//rules:acc.bzl", "acc_binary")
package(default_visibility = ["//visibility:public"])

[acc_binary(
    name = n,
    srcs = ["ov-Is-keygen_min.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc:expandsk_ret_O_pkseed",
    ],
) for n in ("ov-Is-keygen_min_bngfaes", "ov_Is_keygen_min_bngfaes")]

[acc_binary(
    name = n,
    srcs = ["ov-Is-keygen_min.s"],
    copts = ["-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc/AES_bngf:KeySchedule_keygen",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc/AES_bngf:aes128_keygen",
    ],
) for n in ("ov-Is-keygen_min_bngfonly", "ov_Is_keygen_min_bngfonly")]

[acc_binary(
    name = n,
    srcs = ["ov-Is-keygen_min_sw.s"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc/AES_ttable:key_schedule",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc/AES_ttable:aes_encrypt",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc/AES_ttable:aes128_dual_table",
        "//sw/acc/crypto/handwritten/gf16:gf16_sw_helpers",
        "//sw/acc/crypto/handwritten/AES_table:aes128_table",
    ],
) for n in ("ov-Is-keygen_min_sw", "ov_Is_keygen_min_sw")]

[acc_binary(
    name = n,
    srcs = ["ov-Is-keygen_min_sw.s"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/aes_hw:aes128hw_bank_kg",
        "//sw/acc/crypto/handwritten/gf16:gf16_sw_helpers",
    ],
) for n in ("ov-Is-keygen_min_bnaesonly", "ov_Is_keygen_min_bnaesonly")]
