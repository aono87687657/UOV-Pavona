load("//rules:acc.bzl", "acc_binary", "acc_library")

package(default_visibility = ["//visibility:public"])

# --- L-direct (per-attempt L = t^T*O + vin^T*P2; no S_i precompute) ---
acc_library(
    name = "expand_360",
    srcs = ["expand_360.s"],
    copts = ["-DAES_INSTRUCTIONS", "-DGF_INSTRUCTIONS"],
)

# --- L-direct, bngfonly tier (SW AES via sw_key_schedule + bngfonly expand_360) ---
acc_library(
    name = "expand_360_bngfonly",
    srcs = ["expand_360.s"],
    copts = ["-DGF_INSTRUCTIONS"],
)

# --- L-direct swonly tier: pure SW GF + T-table AES, no bn.gfmul/bn.aes128 ---
acc_library(
    name = "expand_360_table",
    srcs = ["expand_360_table.s"],
)

# --- bnaesonly tier: HW bn.aes128 + software GF. Same kernel source as swonly
# (it has no cpp arms at all -- the tier is entirely which libraries it links);
# -DAES_INSTRUCTIONS swaps the AES leaf inside expand_360_table and drops the
# round-key schedule in ldirect, so x18 carries the key instead of an RK base.
acc_library(
    name = "expand_360_table_bnaesonly",
    srcs = ["expand_360_table.s"],
    copts = ["-DAES_INSTRUCTIONS"],
)
