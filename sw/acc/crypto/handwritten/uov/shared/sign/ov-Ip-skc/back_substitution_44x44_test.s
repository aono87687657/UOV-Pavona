.section .data
.balign 32
mat:
    .zero 4096
.balign 32
vec:
    .zero 64
.balign 32
.global mask
mask:
    .word 0x00ff00ff, 0x00ff00ff, 0x00ff00ff, 0x00ff00ff, 0x00ff00ff, 0x00ff00ff, 0x00ff00ff, 0x00ff00ff
    .word 0x0000ffff, 0x0000ffff, 0x0000ffff, 0x0000ffff, 0x0000ffff, 0x0000ffff, 0x0000ffff, 0x0000ffff
    .word 0xffffffff, 0x00000000, 0xffffffff, 0x00000000, 0xffffffff, 0x00000000, 0xffffffff, 0x00000000
    .word 0xffffffff, 0xffffffff, 0x00000000, 0x00000000, 0xffffffff, 0xffffffff, 0x00000000, 0x00000000
    .word 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 0x00000000, 0x00000000, 0x00000000
.balign 32
stack:
    .zero 4096
    .zero 32
stack_end:
.section .text.start
.balign 4
.global main
main:
    la x2, stack_end
    la x10, mat
    jal x1, gf256_transpose_44_44
    la x10, mat
    la x11, vec
    jal x1, back_substitution

ecall

