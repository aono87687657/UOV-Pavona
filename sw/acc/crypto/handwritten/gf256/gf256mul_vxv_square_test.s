/* gf256mul_vxv_square_test.s
*/
.section .data
.balign 32
val:
    .zero 32 
output:
    .zero 32
lsb_mask:
    .word 0x01010101, 0x01010101, 0x01010101, 0x01010101
    .word 0x01010101, 0x01010101, 0x01010101, 0x01010101

.section .text.start
.balign 4
.global main
main:
    li      x5, 0

    /* w1 = input from DMEM[0x000] */
    li      x6, 1
    bn.lid  x6, 0(x5)

    /* w17 = lsb_mask from .data (use `la` so linker keeps the symbol) */
    la      x30, lsb_mask
    li      x29, 17
    bn.lid  x29, 0(x30)

    /* w31 = 0 */
    bn.xor  w31, w31, w31

    jal     x1, gf256mul_vxv_square

    /* Store w0 → DMEM[0x020] */
    li      x6, 0
    bn.sid  x6, 32(x5)

    ecall
