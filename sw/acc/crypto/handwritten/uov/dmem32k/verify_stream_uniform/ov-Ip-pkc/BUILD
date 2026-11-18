load("//rules:acc.bzl", "acc_binary", "acc_library")

package(default_visibility = ["//visibility:public"])

# Stream-uniform verify (Ip + Is): ONE backend-neutral outer per param (streamed
# host contract + init_done guard), one cpp-guarded backend source per param.
# Same VARIANTS convention as ov-verify/ov-{Ip,Is}-pkc. The OUTER compiles
# with NO copts (its object must be byte-identical across arms - that is what
# makes the comparison fair); only the backend library gets the tier flags. Backend
# lib is FIRST in deps (shared-address rule: outer .data links first, adapter
# private .data appends after the window reservation).

# Both parameters provide all four AES/GF combinations.
VARIANTS = [
    ("sw", []),
    ("bngfonly", ["-DGF_INSTRUCTIONS"]),
    ("bngfaes", ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"]),
    ("bnaesonly", ["-DAES_INSTRUCTIONS"]),
]

_VF_IP = "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc"

IP_DEPS_PER_VARIANT = {
    # sw tier: SW T-table AES + gf256_mul (PQC-vector reduce, repo sw baseline).
    "sw": [
        _VF_IP + "/AES_ttable:aes128_table",
        _VF_IP + "/AES_ttable:key_schedule",
        _VF_IP + "/AES_ttable:aes_encrypt",
        _VF_IP + "/AES_ttable:aes128table_352",
        _VF_IP + ":gf256_mul_pqc_w16safe",
    ],
    # bngfonly tier: compute-AES (AES_bngf) + HW bn.gfmul.8.
    "bngfonly": [
        _VF_IP + "/AES_bngf:aes128_352",
        _VF_IP + "/AES_bngf:KeySchedule",
        _VF_IP + "/AES_bngf:load_p3",
    ],
    # bngfaes tier: HW bn.aes128 + HW bn.gfmul.8.
    "bngfaes": [
        _VF_IP + "/AES_bngfaes:aes128_352",
        _VF_IP + "/AES_bngfaes:load_p3",
    ],
    # bnaesonly tier: HW bn.aes128 via the memory-ABI leaf + gf256_mul. Same
    # sw arm body, same GF helper as "sw" -- only the AES leaf and its key
    # setup differ, so the pair prices the AES instructions. Not
    # AES_bngfaes:aes128_352: that leaf returns keystream in WDRs, this one
    # writes the 352-B buffer.
    "bnaesonly": [
        "//sw/acc/crypto/handwritten/uov/dmem32k/verify_stream_uniform/ov-Ip-pkc:aes128hw_352",
        _VF_IP + ":gf256_mul_pqc_w16safe",
    ],
}

# ── backend libraries (one per param x variant; same source, diff copts) ──
[
    acc_library(
        name = "ov-Ip-verify_backend_" + suffix,
        srcs = ["ov-Ip-verify_backend.s"],
        copts = copts,
    )
    for suffix, copts in VARIANTS
]

# ── stream_uniform binaries (shared outer + backend swap; outer copts-free) ──
[
    acc_binary(
        name = "ov-Ip-verify_stream_uniform_" + suffix,
        srcs = ["ov-Ip-verify_stream_uniform.s"],
        deps = [":ov-Ip-verify_backend_" + suffix] + IP_DEPS_PER_VARIANT[suffix],
    )
    for suffix, copts in VARIANTS
]

# Chip-level C driver twin. ACC_SYMBOL_PTR token-pastes the app name, so it must
# be underscore-only; same sources and deps as ov-Ip-verify_stream_uniform_bngfaes.
acc_binary(
    name = "ov_Ip_verify_stream_uniform_bngfaes",
    srcs = ["ov-Ip-verify_stream_uniform.s"],
    deps = [":ov-Ip-verify_backend_bngfaes"] + IP_DEPS_PER_VARIANT["bngfaes"],
)

# The remaining five twins, generated the same way the hyphenated binaries are so
# the two lists cannot drift. Underscore-only for ACC_SYMBOL_PTR.
[
    acc_binary(
        name = "ov_Ip_verify_stream_uniform_" + suffix,
        srcs = ["ov-Ip-verify_stream_uniform.s"],
        deps = [":ov-Ip-verify_backend_" + suffix] + IP_DEPS_PER_VARIANT[suffix],
    )
    for suffix, copts in VARIANTS
    if suffix != "bngfaes"
]

# HW-AES leaf carrying the aes128table_352 ABI: 11 duals into the same 352-B
# buffer, same counter chaining. The key is reloaded per call -- the caller owns
# every WDR that survives one.
acc_library(
    name = "aes128hw_352",
    srcs = ["aes128hw_352.s"],
)
