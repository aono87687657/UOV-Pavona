/*gf256_extmul_test.s*/
/*
Use own gf256 extension multiplication
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
    .word 0x0055,0,0,0,0,0,0,0


.section .text.start
.balign 4
.global gf256_extmul
gf256_extmul:

    la x5, val_a
    la x6, val_b
    addi x2, x0, 1
    addi x3, x0, 2
    bn.lid x2, 0(x5)
    bn.lid x3, 0(x6)

    # Set GF(256) polynomial in mod0 CSR: x^8 + x^4 + x^3 + x + 1 = 0x11B
    li x23, 0x0000011b
    csrrw x0, mod0, x23

    bn.gfmul.8 w0, w1, w2



    ecall
