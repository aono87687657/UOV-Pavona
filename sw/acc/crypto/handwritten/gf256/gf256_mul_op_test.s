/* gf256_mul_op_test.s - one SW GF(256) vector*scalar multiply (gf256_mul,
 * 32 bytes). Op cost = this run - gf256_setup_sw_test. --dump-stats.
 */
.section .data
.balign 32
val_a:
    .word 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0
    .word 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0
.balign 32
val_b:
    .word 0xb5, 0, 0, 0, 0, 0, 0, 0
.balign 32
msb_mask:
    .word 0x80808080, 0x80808080, 0x80808080, 0x80808080
    .word 0x80808080, 0x80808080, 0x80808080, 0x80808080

.section .text.start
.balign 4
.global main
main:
    la x5, val_a
    la x6, val_b
    la x7, msb_mask
    li x2, 1
    li x3, 2
    li x4, 17
    bn.lid x2, 0(x5)         /* w1 = 32 GF(256) elements */
    bn.lid x3, 0(x6)         /* w2 = scalar */
    bn.lid x4, 0(x7)         /* w17 = msb_mask */
    jal x1, gf256_mul        /* w0 = w1 * w2 */
    ecall
