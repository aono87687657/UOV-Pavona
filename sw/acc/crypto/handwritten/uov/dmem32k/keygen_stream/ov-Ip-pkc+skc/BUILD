load("//rules:acc.bzl", "acc_binary", "acc_library")
package(default_visibility = ["//visibility:public"])

# Hardware AES with the software-GF stream geometry and calling convention.
[
    acc_binary(
        name = name,
        srcs = ["ov-Ip-keygen_stream_sw.s"],
        copts = ["-DAES_INSTRUCTIONS"],
        deps = [
            "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
            "//sw/acc/crypto/handwritten/AES_ext:aes128_mem",
            "//sw/acc/crypto/handwritten/uov/shared/aes_hw:aes128hw_table_352",
            "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
            "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
        ],
    )
    for name in ["ov-Ip-keygen_stream_bnaesonly", "ov_Ip_keygen_stream_bnaesonly"]
]

# Streamed-keygen scaffolding (32 KiB DMEM target).

# Streamed keygen (Ip, bngfaes): phase-dispatch app.
acc_binary(
    name = "ov-Ip-keygen_stream_bngfaes",
    srcs = ["ov-Ip-keygen_stream.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
    ],
)

# Chip-level C driver twin. ACC_SYMBOL_PTR token-pastes the app name, so the
# name must be underscore-only; same sources/copts/deps as ov-Ip-keygen_stream.
acc_binary(
    name = "ov_Ip_keygen_stream_bngfaes",
    srcs = ["ov-Ip-keygen_stream.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
    ],
)

# bngfonly tier: SW AES via bn.gfmul helpers. AES constants are defined
# inside the stream .s (controlled placement inside the 32 KiB map); do NOT
# add aes_constants_keygen here - its .data would land past p2buf.
acc_binary(
    name = "ov-Ip-keygen_stream_bngfonly",
    srcs = ["ov-Ip-keygen_stream.s"],
    copts = ["-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_bngf:KeySchedule_keygen",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_bngf:aes128_keygen",
    ],
)

# sw tier: T-table AES + gf256 sw dots, WJ=5 geometry. The 4 KiB
# AES128_TABLE links after the in-file .data; total ~30.6 KiB, all bus-side.
acc_binary(
    name = "ov-Ip-keygen_stream_sw",
    srcs = ["ov-Ip-keygen_stream_sw.s"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes128_table",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:key_schedule",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes_encrypt",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes128table_352",
        "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
        "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
    ],
)

# Chip-level C driver twins for the slow tiers. ACC_SYMBOL_PTR token-pastes the
# app name, so these must be underscore-only; sources/copts/deps match their
# hyphenated originals exactly.
acc_binary(
    name = "ov_Ip_keygen_stream_bngfonly",
    srcs = ["ov-Ip-keygen_stream.s"],
    copts = ["-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_bngf:KeySchedule_keygen",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_bngf:aes128_keygen",
    ],
)

acc_binary(
    name = "ov_Ip_keygen_stream_sw",
    srcs = ["ov-Ip-keygen_stream_sw.s"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes128_table",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:key_schedule",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes_encrypt",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes128table_352",
        "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
        "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
    ],
)
