/*
 * gf16_mul — Multiply 64 GF(2^4) elements by a single GF(2^4) scalar
 *
 * Computes w0 = w1 * w2 in GF(2^4) with reduction polynomial x^4 + x + 1.
 * w1 holds 64 elements packed as 4-bit nibbles in a 256-bit WDR.
 * w2 holds the scalar in bits [3:0] (upper bits ignored).
 *
 * Algorithm: Russian-peasant (bit-serial) multiplication.
 *   For each bit i of scalar b (from bit 0 to bit 3):
 *     1. If bit i is set, XOR current a into the accumulator (w0)
 *     2. Multiply a by x in GF(2^4): shift left 1, reduce with poly 0x3
 *        - Extract MSBs of all 64 nibbles (bit 3 of each)
 *        - Clear MSBs, shift whole register left by 1
 *        - Distribute reduction poly 0x3 = 0b11 via two shifts:
 *            MSB >> 2 → bit 1 (the 'x' term)
 *            MSB >> 3 → bit 0 (the '1' term)
 *
 * The whole-register shift (bn.rshi) works because MSBs are cleared first,
 * so no carry leaks across nibble boundaries.
 *
 * The reduction polynomial 0x3 has only 2 set bits, so it can be applied
 * with simple shift+XOR — no multiplication instruction needed.
 *
 * @param[out]  w0   result (64 GF(16) products)
 * @param[in]   w1   input a — 64 GF(16) elements, 4-bit packed
 * @param[in]   w2   input b — 1 GF(16) scalar (bits [3:0])
 * @param[in]   w3   msb_mask = 0x88888888...88 (bit 3 set in each nibble)
 *
 * Clobbered registers:
 *   WDR: w0 (output), w1 (destroyed), w4, w28, w29, w30, w31
 *   GPR: none
 *   Flags: FG0
 */

.section .text
.balign 4
.global gf16_mul
gf16_mul:

    /* -- Initialization -- */
    bn.xor w31, w31, w31              /* w31 = 0 (zero constant)              */
    bn.xor w0, w0, w0                 /* w0  = 0 (accumulator for result)     */
    bn.addi w28, w31, 1               /* w28 = 1 (mask for single-bit test)   */

    /* -- Bit 0 of b: conditional accumulate -- */
    bn.and w30, w2, w28, FG0          /* test bit 0 of b, set FG0.L flag      */
    bn.sel w0, w1, w31, FG0.l         /* w0 = (bit0 ? a : 0)                  */

    /* -- Multiply a by x in GF(16), then test bit 1 -- */
    bn.and w4, w3, w1                 /* w4 = MSBs of each nibble (0x8 or 0x0)*/
    bn.xor w1, w1, w4                 /* clear MSBs in a (safe to shift now)  */
    bn.rshi w1, w1, w31 >> 255        /* a <<= 1 (whole-register left shift)  */
    bn.rshi w4, w31, w4 >> 2          /* 0x8 >> 2 = 0x2 (bit 1 of poly 0x3)  */
    bn.xor w1, w1, w4                 /* XOR 'x' term of reduction into a     */
    bn.rshi w4, w31, w4 >> 1          /* 0x2 >> 1 = 0x1 (bit 0 of poly 0x3)  */
    bn.xor w1, w1, w4                 /* XOR '1' term of reduction into a     */

    bn.rshi w30, w31, w2 >> 1         /* shift bit 1 of b to position 0       */
    bn.and w30, w28, w30, FG0         /* test bit 1, set FG0.L flag           */
    bn.sel w29, w1, w31, FG0.l        /* w29 = (bit1 ? a : 0)                 */
    bn.xor w0, w0, w29                /* accumulate into result                */

    /* -- Multiply a by x, then test bit 2 -- */
    bn.and w4, w3, w1
    bn.xor w1, w1, w4
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w4, w31, w4 >> 2          /* distribute 'x' term                  */
    bn.xor w1, w1, w4
    bn.rshi w4, w31, w4 >> 1          /* distribute '1' term                  */
    bn.xor w1, w1, w4

    bn.rshi w30, w31, w2 >> 2
    bn.and w30, w28, w30, FG0
    bn.sel w29, w1, w31, FG0.l
    bn.xor w0, w0, w29

    /* -- Multiply a by x, then test bit 3 -- */
    bn.and w4, w3, w1
    bn.xor w1, w1, w4
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w4, w31, w4 >> 2
    bn.xor w1, w1, w4
    bn.rshi w4, w31, w4 >> 1
    bn.xor w1, w1, w4

    bn.rshi w30, w31, w2 >> 3
    bn.and w30, w28, w30, FG0
    bn.sel w29, w1, w31, FG0.l
    bn.xor w0, w0, w29

    ret
