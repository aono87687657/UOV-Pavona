/* gf16_mul_rand_test.s
 *
 * Test harness for gf16_mul with DMEM-injected inputs.
 * Python test script injects val_a, val_b, msb_mask at known addresses.
 *
 * DMEM layout:
 *   0x000: val_a    (32 bytes — 64 GF(16) elements, nibble-packed)
 *   0x020: val_b    (32 bytes — scalar in low nibble of byte 0)
 *   0x040: msb_mask (32 bytes — 0x88888888...88)
 */

.section .text.start
.balign 4
.global main
main:
    li x5, 0

    /* w1 = val_a from DMEM[0x000] */
    li x6, 1
    bn.lid x6, 0(x5)

    /* w2 = val_b from DMEM[0x020] */
    li x6, 2
    bn.lid x6, 32(x5)

    /* w3 = msb_mask from DMEM[0x040] */
    li x6, 3
    bn.lid x6, 64(x5)

    jal x1, gf16_mul

    ecall
