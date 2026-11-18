.section .data
.balign 32
matrixA:
    .zero 2992
    .zero 16 #padded 16 byte
.balign 32
vectorB:
    .zero 64
.balign 32
accumulator:
    .zero 96


.section .text.start
.global main
.balign 4
main:

    /*x10:accumulator*/
    la x10, accumulator

    /*x11:matrixA*/
    la x11, matrixA

    /*x12:vectorB*/
    la x12, vectorB

    jal x1, gf256mat_prod_68_44

    ecall