load("//rules:acc.bzl", "acc_binary")
package(default_visibility = ["//visibility:public"])

# One-shot keygen at minimum DMEM: host writes sk_seed, one EXECUTE, reads
# cpk + csk. WJ=2 windows (Ip3: WJ=1; the narrowest that keep each kernel's pair/group
# structure) trade P1 re-expansion cycles for the smallest measured
# footprint in this family; every arm's KAT runs on the tree DMEM profile (no cap) and the
# linked end is recorded per arm.
# Ip: compact 44B GPR-written accumulator (no cpk_pack, no padding).

[acc_binary(
    name = n,
    srcs = ["ov-Ip-keygen_min.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
    ],
) for n in ("ov-Ip-keygen_min_bngfaes", "ov_Ip_keygen_min_bngfaes")]

[acc_binary(
    name = n,
    srcs = ["ov-Ip-keygen_min.s"],
    copts = ["-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_bngf:KeySchedule_keygen",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_bngf:aes128_keygen",
    ],
) for n in ("ov-Ip-keygen_min_bngfonly", "ov_Ip_keygen_min_bngfonly")]

[acc_binary(
    name = n,
    srcs = ["ov-Ip-keygen_min_sw.s"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes128_table",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:key_schedule",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes_encrypt",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes128table_352",
        "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
        "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
    ],
) for n in ("ov-Ip-keygen_min_sw", "ov_Ip_keygen_min_sw")]

# bnaesonly arms: hardware AES behind the software-GF sw sources (leaf swap,
# same entry points as the T-table library; the table is not linked).
[acc_binary(
    name = n,
    srcs = ["ov-Ip-keygen_min_sw.s"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc:expandsk_ret_O_pkseed",
        "//sw/acc/crypto/handwritten/AES_ext:aes128_mem",
        "//sw/acc/crypto/handwritten/uov/shared/aes_hw:aes128hw_table_352",
        "//sw/acc/crypto/handwritten/gf256:gf256_sw_helpers",
        "//sw/acc/crypto/handwritten/gf256:gf256mul_vxv_square",
    ],
) for n in ("ov-Ip-keygen_min_bnaesonly", "ov_Ip_keygen_min_bnaesonly")]
