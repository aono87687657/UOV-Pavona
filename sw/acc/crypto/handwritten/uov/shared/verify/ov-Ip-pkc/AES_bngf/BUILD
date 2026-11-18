load("//rules:acc.bzl", "acc_library")
package(default_visibility = ["//visibility:public"])

# Compute-AES (SubBytes via bn.gfmul.8.vv Itoh-Tsujii) sources for the
# Ip-PKC verify bngfonly tier.

# AES-128 key schedule (compute flavour). Provides KeySchedule.
acc_library(
    name = "KeySchedule",
    srcs = ["KeySchedule.s"],
)

# AES-128-CTR 352-byte (22-block) compute-AES PRG. Provides aes128_352.
acc_library(
    name = "aes128_352",
    srcs = ["aes128_352.s"],
)

# P3 oil-oil matrix DMEM loader (bngfonly flavour uses w15..w19 with
# different bn.rshi pattern from the bngfaes load_p3 in ../AES_bngfaes/).
# Both files are named load_p3.s and export the same symbol load_p3,
# but they are NOT byte-identical; do not collapse to a shared lib.
# Provides load_p3.
acc_library(
    name = "load_p3",
    srcs = ["load_p3.s"],
)
