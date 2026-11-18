load("//rules:acc.bzl", "acc_binary", "acc_library")

package(default_visibility = ["//visibility:public"])

# Four verify tiers, two sources. Each source fixes the GF engine; the cpp flag
# picks the AES engine inside it.
#
# NOTE: GF_INSTRUCTIONS is NOT tested in either source -- the GF engine is chosen
# by which file you build, so that flag is inert here and carrying it is only a
# statement of intent. Only AES_INSTRUCTIONS actually selects anything:
#
#   source        no flags    -DAES_INSTRUCTIONS   (-DGF_INSTR is inert)
#   -----------   ---------   ------------------
#   ..._gfhw.s    bngfonly    bngfaes
#   ..._gfsw.s    swonly      bnaesonly
#
# So the hazard is NOT "falls through to the sw arm". _gfhw.s has no sw arm. The
# real hazard is the opposite: a target named _aesonly pointed at _gfhw.s builds
# a full bngfaes kernel and reports ~155k cycles as the software-GF arm -- an ~8x
# overstatement of what bn.gfmul buys. Each source #errors on the flag
# combination that is not its own, so that mistake fails at assembly time.
#
#   tier        GF          AES                   target suffix
#   ---------   ---------   -------------------   -------------
#   bngfaes     bn.gfmul    bn.aes128             (none)
#   bngfonly    bn.gfmul    built from bn.gfmul   _bngfonly
#   bnaesonly   gf256_mul   bn.aes128             _aesonly
#   swonly      gf256_mul   T-table               _sw
#
# Check a tier is what it claims: acc_objdump.py -d <elf> | grep -c bn.gfmul

# Streamed UOV-Ip3 verify, Round-3 parameters (v=74, o=m=45,
# n=119, signature 135 B). Forked from //sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/ov-Ip-pkc.
#
# The 135-B signature occupies a 160-B slot, so seed and the P3 window sit 32 B
# above their R2 addresses -- a host ABI change. The host must also zero
# sig[135..159]: INIT's salt read spans the whole slot.
#
# Each kernel also gets an underscore-named twin: the chip driver token-pastes the app name.
[acc_binary(
    name = n,
    srcs = ["ov-Ip3-pkc_verify_stream_gfhw.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip3-pkc:aes128_360",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip3-pkc:load_p3_45",
    ],
) for n in ["ov-Ip3-verify_stream_bngfaes", "ov_Ip3_verify_stream_bngfaes"]]

# Compute-AES twin of aes128_360: round function in bn.gfmul, keys from rkbuf,
# each finished dual spilled to blkbuf so 12 blocks need no WDR housing. Same
# w8..w23 outputs as the bngfaes flavour, so the kernel body is shared.
acc_library(
    name = "aes128_360_bngf",
    srcs = ["aes128_360_bngf.s"],
)

# bngfonly tier: -DGF_INSTRUCTIONS selects the compute-AES INIT prologue.
[acc_binary(
    name = n,
    srcs = ["ov-Ip3-pkc_verify_stream_gfhw.s"],
    copts = ["-DGF_INSTRUCTIONS"],
    deps = [
        ":aes128_360_bngf",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip3-pkc:load_p3_45",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_bngf:KeySchedule",
    ],
) for n in ["ov-Ip3-verify_stream_bngfonly", "ov_Ip3_verify_stream_bngfonly"]]

# _swgf.s = the software-GF fold, two tiers from one body: no flags gives swonly
# (T-table AES), -DAES_INSTRUCTIONS gives bnaesonly (HW AES). The file is named
# for the axis it fixes -- the GF fold -- not for either tier.
#
# swonly tier: T-table AES (aes128table_384) + gf256_mul dual folds.
# 8 x 45 B = 360 B is not a whole number of loads, so each consumption loop is a
# phase ladder: INIT 2 phases (16-B AES blocks absorb the half-block), UPDATE 4
# (bn.lid is 32-B). The SW target links the shared AES table after its
# bus-side data.
[acc_binary(
    name = n,
    srcs = ["ov-Ip3-pkc_verify_stream_gfsw.s"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc:gf256_mul_pqc_w16safe",
        "//sw/acc/crypto/handwritten/uov/shared/keygen/ov-Ip-pkc+skc/AES_ttable:aes128table_384",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_ttable:aes_encrypt",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc/AES_ttable:key_schedule",
        "//sw/acc/crypto/handwritten/AES_table:aes128_table",
    ],
) for n in ["ov-Ip3-verify_stream_sw", "ov_Ip3_verify_stream_sw"]]

# bnaesonly tier: the SAME source as swonly, -DAES_INSTRUCTIONS selecting the
# hardware AES leaf. Only the leaf, its prologue and the T-table are behind the
# arm, so the pair prices the AES instructions with a compiler-identical outer.
# Both arms link the same gf256_mul_pqc_w16safe, so GF is held FIXED here --
# pricing GF would mean comparing against _gfhw.s, which is a different file.
# No T-table, no key schedule: 4 KiB of .data and 192 B of frame go away.
[acc_binary(
    name = n,
    srcs = ["ov-Ip3-pkc_verify_stream_gfsw.s"],
    copts = ["-DAES_INSTRUCTIONS"],
    deps = [
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip3-pkc:aes128hw_384",
        "//sw/acc/crypto/handwritten/uov/shared/verify/ov-Ip-pkc:gf256_mul_pqc_w16safe",
    ],
) for n in ["ov-Ip3-verify_stream_bnaesonly", "ov_Ip3_verify_stream_bnaesonly"]]
