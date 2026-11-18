/* Baseline for the GF256 HW op driver: identical setup (load + mod0/mod1), no op.
 */
.section .data
.balign 32
val_a:
    .word 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0
    .word 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0
.balign 32
val_b:
    .word 0xb5, 0, 0, 0, 0, 0, 0, 0
.section .text.start
.balign 4
.global main
main:
    la x5, val_a
    la x6, val_b
    li x2, 1
    li x3, 2
    bn.lid x2, 0(x5)
    bn.lid x3, 0(x6)
    li x23, 0x11b
    csrrw x0, mod0, x23
    csrrw x0, mod1, x0
    ecall
