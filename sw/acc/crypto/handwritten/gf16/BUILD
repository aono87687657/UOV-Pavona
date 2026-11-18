load("//rules:acc.bzl", "acc_library", "acc_binary","acc_sim_test")
package(default_visibility = ["//visibility:public"])

acc_library(
    name = "gf16_mul",
    srcs = ["gf16_mul.s"],
)

# SW GF(16) multiply-accumulate helpers (gf16_macc_sw, gf16_scalar_inv_sw).
# Cross-cutting: linked by the sw/bngfonly keygen + sign kernels.
acc_library(
    name = "gf16_sw_helpers",
    srcs = ["gf16_sw_helpers.s"],
)




# gf16_macc_sw on every scalar 0..15 against a reference GF(2^4) multiply.
acc_sim_test(
    name = "gf16_macc_sw_test",
    srcs = ["gf16_macc_sw_test.s"],
    dexp = "gf16_macc_sw_test.dexp",
    deps = [":gf16_sw_helpers"],
)


acc_sim_test(
    name = "gf16_mul_test",    
    srcs = ["gf16_mul_test.s"],
    exp = "gf16_mul_test.exp",
    deps = [":gf16_mul"],      
)


acc_sim_test(
    name = "gf16_extmul_test",
    srcs = ["gf16_extmul_test.s"],
    exp = "gf16_extmul_test.exp",
    pqc = True,
)

acc_binary(
    name = "gf16_mul_rand_test",
    srcs = ["gf16_mul_rand_test.s"],
    deps = [":gf16_mul"],
)
# Cycle-measurement isolation driver (one SW GF16 vector*scalar op).
acc_binary(
    name = "gf16_mul_op_test",
    srcs = ["gf16_mul_op_test.s"],
    deps = [":gf16_mul"],
)

# Cycle-measurement isolation driver (one HW GF16 bn.gfmul.4).
acc_binary(
    name = "gf16_gfmul_op_test",
    srcs = ["gf16_gfmul_op_test.s"],
)

# Setup-only baselines (isolate the op cost by subtraction).
acc_binary(name = "gf16_setup_hw_test", srcs = ["gf16_setup_hw_test.s"])
acc_binary(name = "gf16_setup_sw_test", srcs = ["gf16_setup_sw_test.s"])
