load("//rules:acc.bzl", "acc_library", "acc_binary")
package(default_visibility = ["//visibility:public"])

# SW compute-AES routines for the bngfonly keygen variant.
# local AES_bngf helpers (SW AES via bn.gfmul).

acc_library(
    name = "KeySchedule_keygen",
    srcs = ["KeySchedule_keygen.s"],
)

acc_library(
    name = "aes128_keygen",
    srcs = ["aes128_keygen.s"],
)
