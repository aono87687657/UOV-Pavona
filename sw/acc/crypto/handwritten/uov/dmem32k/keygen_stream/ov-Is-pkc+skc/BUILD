load("//rules:acc.bzl", "acc_binary", "acc_library")
package(default_visibility = ["//visibility:public"])

[
    acc_binary(
        name = name,
        srcs = ["ov-Is-keygen_stream_sw.s"],
        copts = ["-DAES_INSTRUCTIONS"],
        deps = [
            "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc:expandsk_ret_O_pkseed",
            "//sw/acc/crypto/handwritten/AES_ext:aes128_mem",
            "//sw/acc/crypto/handwritten/uov/shared/aes_hw:aes128hw_dual_table",
            "//sw/acc/crypto/handwritten/gf16:gf16_sw_helpers",
        ],
    )
    for name in ["ov-Is-keygen_stream_bnaesonly", "ov_Is_keygen_stream_bnaesonly"]
]

# Streamed keygen (Is, bngfaes).
acc_binary(
    name = "ov-Is-keygen_stream_bngfaes",
    srcs = ["ov-Is-keygen_stream.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc:expandsk_ret_O_pkseed",
    ],
)

# Chip-level C driver twin. ACC_SYMBOL_PTR token-pastes the app name, so the
# name must be underscore-only; same sources/copts/deps as ov-Is-keygen_stream.
acc_binary(
    name = "ov_Is_keygen_stream_bngfaes",
    srcs = ["ov-Is-keygen_stream.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc:expandsk_ret_O_pkseed",
    ],
)

acc_binary(
    name = "ov-Is-keygen_stream_bngfonly",
    srcs = ["ov-Is-keygen_stream.s"],
    copts = ["-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc/AES_bngf:KeySchedule_keygen",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc/AES_bngf:aes128_keygen",
    ],
)

# sw tier: T-table AES + gf16 sw dots, WJ=10. The shared table links after
# the kernel's bus-side data, ending at the 31,744-byte boundary.
acc_binary(
    name = "ov-Is-keygen_stream_sw",
    srcs = ["ov-Is-keygen_stream_sw.s"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc/AES_ttable:key_schedule",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc/AES_ttable:aes_encrypt",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc/AES_ttable:aes128_dual_table",
        "//sw/acc/crypto/handwritten/gf16:gf16_sw_helpers",
        "//sw/acc/crypto/handwritten/AES_table:aes128_table",
    ],
)

acc_binary(
    name = "ov_Is_keygen_stream_bngfonly",
    srcs = ["ov-Is-keygen_stream.s"],
    copts = ["-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc/AES_bngf:KeySchedule_keygen",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc/AES_bngf:aes128_keygen",
    ],
)

acc_binary(
    name = "ov_Is_keygen_stream_sw",
    srcs = ["ov-Is-keygen_stream_sw.s"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc/AES_ttable:key_schedule",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc/AES_ttable:aes_encrypt",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Is-pkc+skc/AES_ttable:aes128_dual_table",
        "//sw/acc/crypto/handwritten/gf16:gf16_sw_helpers",
        "//sw/acc/crypto/handwritten/AES_table:aes128_table",
    ],
)
