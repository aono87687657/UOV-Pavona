/*gf16_mul_test.s*/

.section .data
.balign 32
/* 256-bit operand */
.balign 32
val_a:
    .word 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0
	.word 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0
.balign 32
val_b:
    .word 0x9,0x0,0x0,0x0
    .word 0x0,0x0,0x0,0x0
.balign 32
msb_mask:
    .word 0x88888888,0x88888888,0x88888888, 0x88888888
    .word 0x88888888,0x88888888,0x88888888, 0x88888888
.section .text.start
.balign 4
.global main
main:

    /* load msb_mask into w3 */
    la x5, msb_mask
    li x6, 3
    bn.lid x6, 0(x5)

    /* load val_a into w01 */
    la x5, val_a
    li x6, 1
    bn.lid x6, 0(x5)

    /* load val_b into w02 */
    la x5, val_b
    li x6, 2
    bn.lid x6, 0(x5)

    jal x1, gf16_mul

    ecall
