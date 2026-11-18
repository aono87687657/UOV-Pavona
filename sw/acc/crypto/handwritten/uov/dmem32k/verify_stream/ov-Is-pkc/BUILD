load("//rules:acc.bzl", "acc_binary", "acc_library", "acc_sim_test")

package(default_visibility = ["//visibility:public"])

[
    acc_binary(
        name = name,
        srcs = ["ov-Is-pkc_verify_stream_gfsw.s"],
        copts = ["-DAES_INSTRUCTIONS"],
        deps = [
            "//sw/acc/crypto/handwritten/gf16:gf16_mul",
            "//sw/acc/crypto/handwritten/uov/shared/aes_hw:aes128hw_bank_verify",
        ],
    )
    for name in ["ov-Is-verify_stream_bnaesonly", "ov_Is_verify_stream_bnaesonly"]
]

# OV-Is (GF16): self-contained (AES-CTR inlined via bn.aes128.kf).
acc_binary(
    name = "ov-Is-verify_stream_bngfaes",
    srcs = ["ov-Is-pkc_verify_stream_gfhw.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_binary(
    name = "ov-Is-verify_stream_bngfonly",
    srcs = ["ov-Is-pkc_verify_stream_gfhw.s"],
    copts = ["-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Is-pkc/AES_bngf:KeySchedule",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Is-pkc/AES_bngf:aes128",
    ],
)

# sw tier: T-table AES + gf16 dots, own source (window capped at 22,496 B).
# The shared AES table links after the kernel's bus-side data.
acc_binary(
    name = "ov-Is-verify_stream_sw",
    srcs = ["ov-Is-pkc_verify_stream_gfsw.s"],
    deps = [
        "//sw/acc/crypto/handwritten/gf16:gf16_mul",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Is-pkc/AES_ttable:aes128_col_is",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Is-pkc/AES_ttable:aes_encrypt",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Is-pkc/AES_ttable:key_schedule",
        "//sw/acc/crypto/handwritten/AES_table:aes128_table",
    ],
)

# Chip-level C driver twin. ACC_SYMBOL_PTR token-pastes the app name, so the
# name must be underscore-only; same sources/deps as the hyphenated targets.
acc_binary(
    name = "ov_Is_verify_stream_bngfaes",
    srcs = ["ov-Is-pkc_verify_stream_gfhw.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_binary(
    name = "ov_Is_verify_stream_bngfonly",
    srcs = ["ov-Is-pkc_verify_stream_gfhw.s"],
    copts = ["-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Is-pkc/AES_bngf:KeySchedule",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Is-pkc/AES_bngf:aes128",
    ],
)

acc_binary(
    name = "ov_Is_verify_stream_sw",
    srcs = ["ov-Is-pkc_verify_stream_gfsw.s"],
    deps = [
        "//sw/acc/crypto/handwritten/gf16:gf16_mul",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Is-pkc/AES_ttable:aes128_col_is",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Is-pkc/AES_ttable:aes_encrypt",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Is-pkc/AES_ttable:key_schedule",
        "//sw/acc/crypto/handwritten/AES_table:aes128_table",
    ],
)
