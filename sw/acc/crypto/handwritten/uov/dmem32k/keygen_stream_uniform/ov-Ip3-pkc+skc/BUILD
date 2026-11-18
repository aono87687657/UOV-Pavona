load("//rules:acc.bzl", "acc_binary", "acc_library")

package(default_visibility = ["//visibility:public"])

# Backend-ablation keygen family (Ip3): ONE outer object for every arm, all
# AES/GF work behind the backend_* ABI, backend swapped by dep. WJ=5 (sw
# worst-case geometry) so tier deltas price the backend, not per-tier tuning.
# Backend lib stays FIRST in deps: single provider for the backend_* seams.

_ARMS = {
    "bngfaes": ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
    "bngfonly": ["-DGF_INSTRUCTIONS"],
    "bnaesonly": ["-DAES_INSTRUCTIONS"],
    "sw": [],
}

_ARM_DEPS = {
    "bngfaes": [
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip3-skc:expand_360",
    ],
    "bngfonly": [
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip3-skc:expand_360_bngfonly",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:aes128_sign",
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/AES_bngf:KeySchedule_sign",
    ],
    "bnaesonly": [
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip3-skc:expand_360_table_bnaesonly",
        "//sw/acc/crypto/handwritten/uov/shared/aes_hw:aes128hw_384_sign",
        "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
        "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
    ],
    "sw": [
        "//sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip3-skc:expand_360_table",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes128_table",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:key_schedule",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes_encrypt",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes128table_384",
        "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
        "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
    ],
}

[
    acc_library(
        name = "ov-Ip3-keygen_backend_" + arm,
        srcs = ["ov-Ip3-keygen_backend.s"],
        copts = _ARMS[arm],
    )
    for arm in _ARMS
]

[
    acc_binary(
        name = stem + arm,
        srcs = ["ov-Ip3-keygen_stream_uniform.s"],
        deps = [":ov-Ip3-keygen_backend_" + arm] + _ARM_DEPS[arm] + [
            "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip3-pkc+skc:expandsk_ret_O_pkseed",
        ],
    )
    for arm in _ARMS
    # underscore twin per arm: the chip driver token-pastes the app name
    for stem in ("ov-Ip3-keygen_stream_uniform_", "ov_Ip3_keygen_stream_uniform_")
]
