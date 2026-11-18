load("//rules:acc.bzl", "acc_library")
package(default_visibility = ["//visibility:public"])

# Full-HW AES helpers for the Ip-PKC verify bngfaes tier.

# AES-128-CTR 352-byte PRG using bn.aes128.kf + encm + encf.
# Provides aes128_352.
acc_library(
    name = "aes128_352",
    srcs = ["aes128_352.s"],
)

# P3 oil-oil matrix DMEM loader for the OxO phase. Provides load_p3.
acc_library(
    name = "load_p3",
    srcs = ["load_p3.s"],
)
