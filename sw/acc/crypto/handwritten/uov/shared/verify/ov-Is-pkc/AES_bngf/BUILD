load("//rules:acc.bzl", "acc_library")
package(default_visibility = ["//visibility:public"])

# Compute-AES (SubBytes via bn.gfmul.8.vv Itoh-Tsujii) sources for the
# Is-PKC verify bngfonly tier.

# AES-128 key schedule (compute flavour). Provides KeySchedule.
acc_library(
    name = "KeySchedule",
    srcs = ["KeySchedule.s"],
)

# AES-128 single dual-block encrypt (compute flavour). Provides aes128.
acc_library(
    name = "aes128",
    srcs = ["aes128.s"],
)
