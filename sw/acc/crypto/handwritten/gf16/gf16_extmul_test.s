/*gf16_extmul_test.s*/
/*
Use own gf16 extension multiplication
*/
.section .data
.balign 32
val_a:
    .word 0x12345678, 0x9abcdef0
	.word 0x12345678, 0x9abcdef0
	.word 0x12345678, 0x9abcdef0
	.word 0x12345678, 0x9abcdef0

.balign 32
val_b:
    .word 0xb,0,0,0,0,0,0,0

.balign 32
result:
    .zero 32

.section .text.start
.balign 4
.global gf16_extmul
gf16_extmul:

    la x5, val_a
    la x6, val_b
    addi x2, x0, 1
    addi x3, x0, 2
    bn.lid x2, 0(x5)
    bn.lid x3, 0(x6)

    # Set GF(16) polynomial in mod0 CSR: x^4 + x + 1 = 0x13
    li x23, 0x00000013
    csrrw x0, mod0, x23

    bn.gfmul.4 w0, w1, w2

    ecall
