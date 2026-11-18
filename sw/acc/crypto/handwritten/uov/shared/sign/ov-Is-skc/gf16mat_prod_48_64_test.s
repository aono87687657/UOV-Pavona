.section .data 
.balign 32
O:
    .zero 3072
.balign 32
vec:
    .zero 32

.section .text.start
.global gf16_matvec_48_64_test
gf16_matvec_48_64_test:
   
    la x10, O
    la x11, vec
    bn.lid x0, 0(x11)
    jal x1, gf16_matvec_48_64

ecall