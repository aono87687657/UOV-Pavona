load("//rules:acc.bzl", "acc_library", "acc_binary")
package(default_visibility = ["//visibility:public"])

# sw-tier GF256 scalar multiply: PQC-vector (bn.mulv.l) variant of //gf256:gf256_mul,
# w16-safe (saves/restores w16 around the reduction). Same symbol, drop-in for the
# sw dep below. Requires EN_PQC.
acc_library(
    name = "gf256_mul_pqc_w16safe",
    srcs = ["gf256_mul_pqc_w16safe.s"],
)

# Register-returning twin: same keystream, no stores. The gfsw fold reads its
# columns straight out of the 11 lanes, so the bnaesonly arm pays no DMEM round
# trip for keystream it just generated.
acc_library(
    name = "aes128hw_352reg",
    srcs = ["aes128hw_352reg.s"],
)
