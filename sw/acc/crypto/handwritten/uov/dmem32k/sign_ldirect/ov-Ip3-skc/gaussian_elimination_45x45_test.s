.section .data
.balign 32
mat:
    .zero 4096
.balign 32
solution:
    .zero 64
.balign 32
stack:
    .zero 128

stack_end:
.section .text.start
.global main
.balign 4
main:

    la x2, stack_end
    la x10, mat
    la x11, solution
    jal x1, gaussian_elimination_45x45

ecall