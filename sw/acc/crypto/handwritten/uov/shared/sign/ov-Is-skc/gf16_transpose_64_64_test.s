.section .data
.balign 32
mat:
    .zero 2048
.balign 32
.global mask
mask:
    .word 0x0f0f0f0f, 0x0f0f0f0f, 0x0f0f0f0f, 0x0f0f0f0f
    .word 0x0f0f0f0f, 0x0f0f0f0f, 0x0f0f0f0f, 0x0f0f0f0f
.balign 32
.global mask_2
mask_2:
    .word 0x00ff00ff, 0x00ff00ff, 0x00ff00ff, 0x00ff00ff
    .word 0x00ff00ff, 0x00ff00ff, 0x00ff00ff, 0x00ff00ff
.balign 32
.global mask_3
mask_3:
    .word 0x0000ffff, 0x0000ffff, 0x0000ffff, 0x0000ffff
    .word 0x0000ffff, 0x0000ffff, 0x0000ffff, 0x0000ffff
.balign 32
.global mask_4
mask_4:
    .word 0xffffffff, 0x00000000, 0xffffffff, 0x00000000
    .word 0xffffffff, 0x00000000, 0xffffffff, 0x00000000
.balign 32
.global mask_5
mask_5:
    .word 0xffffffff, 0xffffffff, 0x00000000,  0x00000000
    .word 0xffffffff, 0xffffffff, 0x00000000,  0x00000000
.balign 32
.global mask_6
mask_6:
    .word 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff
    .word 0x00000000, 0x00000000, 0x00000000, 0x00000000
.balign 32
stack:
    .zero 2048
stack_end:
.section .text.start
.global main
.balign 4
main:
    la x2, stack_end
    la x10, mat
    jal x1, gf16_transpose_64_64
    ecall
