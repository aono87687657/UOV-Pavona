/*
 * Test harness for in-place GF(2^4) 64x64 Gaussian elimination.
 *
 * Memory layout:
 *   mat      – 2048 bytes (64 rows × 32 bytes), modified in-place
 *   solution – 32 bytes   (64 nibbles packed), modified in-place
 *   stack    – 32 bytes   of stack space
 */
.section .data
.balign 32
mat:
    .zero 2048
.balign 32
solution:
    .zero 32
.balign 32
stack:
    .zero 32
stack_end:

.section .text.start
.global main
.balign 4
main:
    /* Assume matrix is already in row-major layout */
    la x2, stack_end
    la x10, mat
    la x11, solution
    jal x1, gaussian_elemination_64x64

ecall
