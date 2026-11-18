load("//rules:acc.bzl", "acc_binary", "acc_library", "acc_sim_test")

package(default_visibility = ["//visibility:public"])

# Streamed UOV-PKC verify: one phase-dispatch binary per param
# set, loaded once then EXECUTEd per phase (INIT / UPDATE x K / FINAL) with the
# {acc, oil, target} context persisting in DMEM across runs. Consumes the cpk in
# row-aligned P3 windows so it fits a 32 KiB DMEM (no enlarged-DMEM hack).
# Validated in the ISS against the Python public map for all 12 KAT cases (tests/test_i{p,s}_stream.py).

# OV-Ip (GF256): HW bn.aes128.* + bn.gfmul.8; links the bngfaes AES helpers.
acc_binary(
    name = "ov-Ip-verify_stream_bngfaes",
    srcs = ["ov-Ip-pkc_verify_stream_gfhw.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_bngfaes:aes128_352",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_bngfaes:load_p3",
    ],
)

# bngfonly arms: same sources, -DGF_INSTRUCTIONS selects the compute-AES INIT.
# Ip keeps the bngfaes load_p3: it is bn.ld/bn.rshi only and feeds UPDATE's
# unchanged w8-w23 layout; the AES_bngf flavour's w9-w24 map is another
# caller's convention, not a tier requirement.
acc_binary(
    name = "ov-Ip-verify_stream_bngfonly",
    srcs = ["ov-Ip-pkc_verify_stream_gfhw.s"],
    copts = ["-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_bngf:KeySchedule",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_bngf:aes128_352",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_bngfaes:load_p3",
    ],
)

# sw tier: T-table AES + gf256_mul (bn.mulv) dual folds. Shares the gfsw source
# with the bnaesonly arm below; the file is named for its GF engine because that
# is what picks the file. Window unchanged at 22,368. The SW target links
# the shared AES table after its bus-side data.
acc_binary(
    name = "ov-Ip-verify_stream_sw",
    srcs = ["ov-Ip-pkc_verify_stream_gfsw.s"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc:gf256_mul_pqc_w16safe",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_ttable:aes128table_352",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_ttable:aes_encrypt",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_ttable:key_schedule",
        "//sw/acc/crypto/handwritten/AES_table:aes128_table",
    ],
)


# bnaesonly tier: the SAME source as the Ip sw tier, -DAES_INSTRUCTIONS selecting
# the hardware AES leaf. Only the leaf, its prologue and the T-table are behind
# the arm, so the pair prices the AES instructions with an otherwise identical
# outer. Both arms link the same gf256_mul_pqc_w16safe, so GF is held FIXED --
# pricing GF would mean comparing against ov-Ip-pkc_verify_streamed_gfhw.s, a
# different file. No T-table, no key schedule: 4 KiB of .data and 192 B of frame
# go away.
[
    acc_binary(
        name = name,
        srcs = ["ov-Ip-pkc_verify_stream_gfsw.s"],
        copts = ["-DAES_INSTRUCTIONS"],
        deps = [
            "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc:aes128hw_352reg",
            "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc:gf256_mul_pqc_w16safe",
        ],
    )
    for name in ["ov-Ip-verify_stream_bnaesonly", "ov_Ip_verify_stream_bnaesonly"]
]

acc_binary(
    name = "ov_Ip_verify_stream_bngfaes",
    srcs = ["ov-Ip-pkc_verify_stream_gfhw.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_bngfaes:aes128_352",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_bngfaes:load_p3",
    ],
)

acc_binary(
    name = "ov_Ip_verify_stream_bngfonly",
    srcs = ["ov-Ip-pkc_verify_stream_gfhw.s"],
    copts = ["-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_bngf:KeySchedule",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_bngf:aes128_352",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_bngfaes:load_p3",
    ],
)

acc_binary(
    name = "ov_Ip_verify_stream_sw",
    srcs = ["ov-Ip-pkc_verify_stream_gfsw.s"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc:gf256_mul_pqc_w16safe",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_ttable:aes128table_352",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_ttable:aes_encrypt",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_ttable:key_schedule",
        "//sw/acc/crypto/handwritten/AES_table:aes128_table",
    ],
)
