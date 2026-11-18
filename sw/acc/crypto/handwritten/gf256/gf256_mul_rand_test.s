/* gf256_mul_rand_test.s
 *
 * Test harness for gf256_mul with DMEM-injected inputs.
 * Python test script injects val_a, val_b, msb_mask at known addresses.
 *
 * DMEM layout:
 *   0x000: val_a    (32 bytes — 32 GF(256) elements)
 *   0x020: val_b    (32 bytes — scalar in byte 0)
 *   0x040: msb_mask (32 bytes — 0x80808080...80)
 *   0x060: result   (32 bytes — written after multiply)
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

    /* w17 = msb_mask from DMEM[0x040] */
    li x6, 17
    bn.lid x6, 64(x5)

    jal x1, gf256_mul

    /* Store result w0 to DMEM[0x060] */
    li x6, 0
    bn.sid x6, 96(x5)

    ecall
