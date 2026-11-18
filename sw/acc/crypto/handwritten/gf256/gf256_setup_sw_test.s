/* Baseline for the GF256 SW op drivers (gf256_mul + gf256_mul_pqc share this
 * setup): identical operand+mask load, no call.
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
    li x4, 3
    bn.lid x2, 0(x5)
    bn.lid x3, 0(x6)
    bn.lid x4, 0(x7)
    ecall
