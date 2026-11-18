/* gf256_ldirect_74_45 kernel KAT test: inputs from ldirect_test_inputs.s
 * (generated), result L dumped at ld_L_out for python comparison. 2026-08-18. */
.section .text.start
.balign 4
.global ldirect_kat_test
ldirect_kat_test:
    la x2, ld_stack_end
    la x10, ld_pk_seed
    la x11, ld_vinegar
    la x12, ld_L_out
    la x13, ld_O
    la x14, ld_y_out               /* fused ldirect y-out slot (64B) */
    jal x1, gf256_ldirect_74_45
    ecall
