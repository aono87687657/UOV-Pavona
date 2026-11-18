/* gf256mul_vxv_test.s
 *
 * Harness for gf256mul_vxv. Python injects:
 *   DMEM[0x000] — val_a (32 bytes)
 *   DMEM[0x020] — val_b (32 bytes)
 * Harness stores the 32-byte per-byte product to DMEM[0x040].
 */

.section .data
.balign 32
val_a_mem:
    .zero 32
val_b_mem:
    .zero 32
out_mem:
    .zero 32
lsb_mask:
    .word 0x01010101, 0x01010101, 0x01010101, 0x01010101
    .word 0x01010101, 0x01010101, 0x01010101, 0x01010101

.section .text.start
.balign 4
.global main
main:
    li      x5, 0

    /* w1 = val_a from DMEM[0x000] */
    li      x6, 1
    bn.lid  x6, 0(x5)

    /* w2 = val_b from DMEM[0x020] */
    li      x6, 2
    bn.lid  x6, 32(x5)

    /* w17 = lsb_mask (from .data; force symbol via `la`) */
    la      x30, lsb_mask
    li      x29, 17
    bn.lid  x29, 0(x30)

    /* w31 = 0 */
    bn.xor  w31, w31, w31

    jal     x1, gf256mul_vxv

    /* Store w0 → DMEM[0x040] */
    li      x6, 0
    bn.sid  x6, 64(x5)

    ecall
