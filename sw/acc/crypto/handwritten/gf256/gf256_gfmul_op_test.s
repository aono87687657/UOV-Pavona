/* gf256_gfmul_op_test.s - one HW GF(256) vector*scalar multiply (bn.gfmul.8,
 * 32 bytes). Op cost = this run - gf256_setup_hw_test. --dump-stats.
 */
.section .data
.balign 32
val_a:
    .word 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0
    .word 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0
.balign 32
val_b:
    .word 0xb5, 0, 0, 0, 0, 0, 0, 0

.section .text.start
.balign 4
.global main
main:
    la x5, val_a
    la x6, val_b
    li x2, 1
    li x3, 2
    bn.lid x2, 0(x5)
    bn.lid x3, 0(x6)
    li x23, 0x11b
    csrrw x0, mod0, x23         /* GF(256) AES poly */
    csrrw x0, mod1, x0          /* byte-0 scalar mode */
    bn.gfmul.8 w0, w1, w2
    ecall
