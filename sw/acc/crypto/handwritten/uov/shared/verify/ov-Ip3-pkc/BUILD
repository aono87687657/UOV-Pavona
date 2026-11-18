load("//rules:acc.bzl", "acc_binary", "acc_library")

package(default_visibility = ["//visibility:public"])

# AES-128-CTR 360-byte PRG: 45-B entries, so the batch is not a whole number of
# AES blocks and the expansion runs a 4-phase window over 12 duals.
acc_library(
    name = "aes128_360",
    srcs = ["aes128_360.s"],
)

# P3 loader for 45-B columns. 360 B/batch walks the 32-B alignment 4/12/20/28,
# and bn.ld traps unaligned, so each phase carries its own realign schedule.
acc_library(
    name = "load_p3_45",
    srcs = ["load_p3_45.s"],
)

# HW-AES leaf carrying the aes128table_384 ABI: 12 duals into the same 384-B
# buffer, same counter chaining. The key is reloaded per call -- the caller owns
# every WDR that survives one.
acc_library(
    name = "aes128hw_384",
    srcs = ["aes128hw_384.s"],
)
