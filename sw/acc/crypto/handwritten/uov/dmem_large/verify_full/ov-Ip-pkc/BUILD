load("//rules:acc.bzl", "acc_binary", "acc_library")
package(default_visibility = ["//visibility:public"])

# One-shot UOV-Ip and UOV-Is verify: the 32 KiB streamed bodies of
# ../../../dmem32k/verify_stream re-shelled the same way, with the streamed
# kernels' deps.
[acc_binary(
    name = n,
    srcs = ["ov-Ip-pkc_verify_full.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_bngfaes:aes128_352",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_bngfaes:load_p3",
    ],
) for n in ("ov-Ip-verify_full_bngfaes", "ov_Ip_verify_full_bngfaes")]

[acc_binary(
    name = n,
    srcs = ["ov-Ip-pkc_verify_full.s"],
    copts = ["-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_bngf:KeySchedule",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_bngf:aes128_352",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_bngfaes:load_p3",
    ],
) for n in ("ov-Ip-verify_full_bngfonly", "ov_Ip_verify_full_bngfonly")]

[acc_binary(
    name = n,
    srcs = ["ov-Ip-pkc_verify_full_sw.s"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc:gf256_mul_pqc_w16safe",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_ttable:aes128table_352",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_ttable:aes_encrypt",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_ttable:key_schedule",
        "//sw/acc/crypto/handwritten/AES_table:aes128_table",
    ],
) for n in ("ov-Ip-verify_full_sw", "ov_Ip_verify_full_sw")]

[acc_binary(
    name = n,
    srcs = ["ov-Ip-pkc_verify_full_sw.s"],
    copts = ["-DAES_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc:aes128hw_352reg",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc:gf256_mul_pqc_w16safe",
    ],
) for n in ("ov-Ip-verify_full_bnaesonly", "ov_Ip_verify_full_bnaesonly")]
