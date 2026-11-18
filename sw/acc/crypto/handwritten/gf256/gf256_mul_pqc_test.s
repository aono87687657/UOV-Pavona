/*gf256_mul_pqc_test.s — same inputs as gf256_mul_test.s */

.section .data
.balign 32
/* 256-bit operand*/
val_a:
    .word 0x12345678, 0x9ABCDEF0, 0x12345678, 0x9ABCDEF0,0x12345678, 0x9ABCDEF0,0x12345678, 0x9ABCDEF0
.balign 32
val_b:
/* 256-bit operand: "0" in the lowest word, zeros above. */
    .word 0x000000FF, 0, 0, 0, 0, 0, 0, 0
.balign 32
msb_mask:
    .word 0x80808080, 0x80808080, 0x80808080, 0x80808080
    .word 0x80808080, 0x80808080, 0x80808080, 0x80808080

.section .text.start
.balign 4
.global main
main:
    /* load msb_mask into w3 */
    la x5, msb_mask
    li x6, 3
    bn.lid x6, 0(x5)

    /*load val_a in to w01*/
    la x5, val_a
    li x6, 1
    bn.lid x6,0(x5)

    /*load val_b in to w02*/
    la x5, val_b
    li x6, 2
    bn.lid x6,0(x5)

    jal x1, gf256_mul_pqc

    ecall
