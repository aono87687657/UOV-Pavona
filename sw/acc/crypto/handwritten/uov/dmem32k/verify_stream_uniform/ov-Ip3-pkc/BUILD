load("//rules:acc.bzl", "acc_binary", "acc_library")

package(default_visibility = ["//visibility:public"])

# Uniform (backend-ablation) verify rig at Ip3, forked from verify_stream_uniform.
# The outer compiles with NO copts and must stay byte-identical across arms.
# Host contract = verify_stream/ov-Ip3-pkc streamed verify + init_done guard.
# Four arms; sw/bnaesonly share the backend sw body (the AES leaf is an inner
# ifdef, so that pair prices AES with the GF path held fixed).
acc_library(
    name = "ov-Ip3-verify_stream_uniform_outer",
    srcs = ["ov-Ip3-verify_stream_uniform.s"],
)

_R3 = "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip3-pkc"

acc_library(
    name = "ov-Ip3-verify_backend_bngfaes",
    srcs = ["ov-Ip3-verify_backend.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

acc_library(
    name = "ov-Ip3-verify_backend_bngfonly",
    srcs = ["ov-Ip3-verify_backend.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

# Each kernel also gets an underscore-named twin: the chip driver token-pastes the app name.
[acc_binary(
    name = n,
    srcs = ["ov-Ip3-verify_stream_uniform.s"],
    deps = [
        ":ov-Ip3-verify_backend_bngfaes",
        _R3 + ":aes128_360",
        _R3 + ":load_p3_45",
    ],
) for n in ["ov-Ip3-verify_stream_uniform_bngfaes", "ov_Ip3_verify_stream_uniform_bngfaes"]]

[acc_binary(
    name = n,
    srcs = ["ov-Ip3-verify_stream_uniform.s"],
    deps = [
        ":ov-Ip3-verify_backend_bngfonly",
        "//sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/ov-Ip3-pkc:aes128_360_bngf",
        _R3 + ":load_p3_45",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_bngf:KeySchedule",
    ],
) for n in ["ov-Ip3-verify_stream_uniform_bngfonly", "ov_Ip3_verify_stream_uniform_bngfonly"]]

acc_library(
    name = "ov-Ip3-verify_backend_sw",
    srcs = ["ov-Ip3-verify_backend.s"],
)

acc_library(
    name = "ov-Ip3-verify_backend_bnaesonly",
    srcs = ["ov-Ip3-verify_backend.s"],
    copts = ["-DAES_INSTRUCTIONS"],
)

[acc_binary(
    name = n,
    srcs = ["ov-Ip3-verify_stream_uniform.s"],
    deps = [
        ":ov-Ip3-verify_backend_sw",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc:gf256_mul_pqc_w16safe",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes128table_384",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_ttable:aes_encrypt",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_ttable:key_schedule",
        "//sw/acc/crypto/handwritten/AES_table:aes128_table",
    ],
) for n in ["ov-Ip3-verify_stream_uniform_sw", "ov_Ip3_verify_stream_uniform_sw"]]

[acc_binary(
    name = n,
    srcs = ["ov-Ip3-verify_stream_uniform.s"],
    deps = [
        ":ov-Ip3-verify_backend_bnaesonly",
        _R3 + ":aes128hw_384",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc:gf256_mul_pqc_w16safe",
    ],
) for n in ["ov-Ip3-verify_stream_uniform_bnaesonly", "ov_Ip3_verify_stream_uniform_bnaesonly"]]
