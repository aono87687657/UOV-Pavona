load("//rules:acc.bzl", "acc_binary", "acc_library")

package(default_visibility = ["//visibility:public"])

# Keygen and sign share the padded-96 O layout with zero-filled slack.
acc_library(
    name = "expandsk_ret_O_pkseed",
    srcs = ["expandsk_ret_O_pkseed.s"],
)
