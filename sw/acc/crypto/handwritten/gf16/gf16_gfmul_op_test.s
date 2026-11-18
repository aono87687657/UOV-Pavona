/* gf16_gfmul_op_test.s - one HW GF(16) vector*scalar multiply (bn.gfmul.4,
 * 64 nibbles). Op cost = this run - gf16_setup_hw_test (the same setup with
 * no op). --dump-stats.
 */
.section .data
.balign 32
val_a:
    .word 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0
    .word 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0
.balign 32
val_b:
    .word 0xb, 0, 0, 0, 0, 0, 0, 0

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
    li x23, 0x13
    csrrw x0, mod0, x23         /* GF(16) poly */
    csrrw x0, mod1, x0          /* nibble-0 scalar mode */
    bn.gfmul.4 w0, w1, w2
    ecall
