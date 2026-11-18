/*
 * gf256_mul_pqc — Multiply 32 GF(2^8) elements by a single GF(2^8) scalar
 *                 PQC-optimized version (requires EN_PQC / --pqc true)
 *
 * Functionally identical to gf256_mul. Same inputs, same output.
 *
 * Optimization: replaces 4x bn.mulqacc per iteration with 1x bn.mulv.l.16H.lo.
 * The bn.mulv.l instruction broadcasts scalar 0x1b from w16 lane 0 and multiplies
 * all 16 half-word (16-bit) lanes simultaneously. This works because each lane
 * holds two bytes that are each 0x00 or 0x01, and 0x0101 * 0x001b = 0x1b1b
 * still fits in 16 bits — no cross-byte carry.
 *
 * Instruction count: 76 vs 97 original (22% reduction, saves 21 instructions).
 *
 * @param[out]  w0   result (32 GF(256) products)
 * @param[in]   w1   input a — 32 GF(256) elements, 8-bit packed
 * @param[in]   w2   input b — 1 GF(256) scalar (bits [7:0])
 * @param[in]   w3   msb_mask = 0x80808080...80 (pre-loaded by caller)
 *
 * Clobbered registers:
 *   WDR: w0 (output), w1 (destroyed), w4, w16, w27, w29, w30, w31
 *   GPR: none
 *   Flags: FG0
 *
 * NOTE: Clobbers w16 (used as bn.mulv.l scalar register sw0).
 *       Original gf256_mul uses w28 instead. Callers that use w16
 *       must save/restore it.
 */

.section .text
.balign 4
.global gf256_mul_pqc
gf256_mul_pqc:
    /* -- Initialization -- */
    bn.xor w31, w31, w31              /* w31 = 0 (zero constant)              */
    bn.addi w16, w31, 0x1b            /* w16 = 0x1b (sw0 lane 0 for bn.mulv.l)*/
    bn.addi w27, w31, 1               /* w27 = 1 (mask for single-bit test)   */

    /* -- Bit 0 of b: conditional accumulate -- */
    bn.and w30, w2, w27, FG0          /* test bit 0 of b, set FG0.L flag      */
    bn.sel w0, w1, w31, FG0.l         /* w0 = (bit0 ? a : 0)                  */

    /* -- Multiply a by x in GF(256), then test bit 1 --
     *    1. Extract MSBs:        w4 = a & 0x80..80
     *    2. Clear MSBs in a:     a  = a ^ w4
     *    3. Shift a left by 1:   a  = a << 1  (safe, MSBs cleared)
     *    4. Normalize MSBs:      w4 = w4 >> 7  (0x80 → 0x01, 0x00 → 0x00)
     *    5. Multiply by 0x1b:    w30 = w4 * 0x1b  (1x bn.mulv.l, all 16 lanes)
     *    6. Apply reduction:     a  = a ^ w30
     */
    bn.and w4, w1, w3                 /* w4 = MSBs of each byte (0x80 or 0x00)*/
    bn.xor w1, w1, w4                 /* clear MSBs in a (safe to shift now)  */
    bn.rshi w1, w1, w31 >> 255        /* a <<= 1 (whole-register left shift)  */
    bn.rshi w4, w31, w4 >> 7          /* normalize: 0x80 → 0x01              */
    bn.mulv.l.16H.lo w30, w4, sw0.0   /* all 32 bytes * 0x1b in one instr    */
    bn.xor w1, w1, w30               /* a ^= reduction (0x1b where MSB was set)*/

    bn.rshi w30, w31, w2 >> 1        /* shift bit 1 of b to position 0       */
    bn.and w30, w27, w30, FG0        /* test bit 1, set FG0.L flag           */
    bn.sel w29, w1, w31, FG0.l       /* w29 = (bit1 ? a : 0)                 */
    bn.xor w0, w0, w29               /* accumulate into result                */

    /* -- Multiply a by x, then test bit 2 -- */
    bn.and w4, w1, w3
    bn.xor w1, w1, w4
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w4, w31, w4 >> 7
    bn.mulv.l.16H.lo w30, w4, sw0.0
    bn.xor w1, w1, w30

    bn.rshi w30, w31, w2 >> 2
    bn.and w30, w27, w30, FG0
    bn.sel w29, w1, w31, FG0.l
    bn.xor w0, w0, w29

    /* -- Multiply a by x, then test bit 3 -- */
    bn.and w4, w1, w3
    bn.xor w1, w1, w4
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w4, w31, w4 >> 7
    bn.mulv.l.16H.lo w30, w4, sw0.0
    bn.xor w1, w1, w30

    bn.rshi w30, w31, w2 >> 3
    bn.and w30, w27, w30, FG0
    bn.sel w29, w1, w31, FG0.l
    bn.xor w0, w0, w29

    /* -- Multiply a by x, then test bit 4 -- */
    bn.and w4, w1, w3
    bn.xor w1, w1, w4
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w4, w31, w4 >> 7
    bn.mulv.l.16H.lo w30, w4, sw0.0
    bn.xor w1, w1, w30

    bn.rshi w30, w31, w2 >> 4
    bn.and w30, w27, w30, FG0
    bn.sel w29, w1, w31, FG0.l
    bn.xor w0, w0, w29

    /* -- Multiply a by x, then test bit 5 -- */
    bn.and w4, w1, w3
    bn.xor w1, w1, w4
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w4, w31, w4 >> 7
    bn.mulv.l.16H.lo w30, w4, sw0.0
    bn.xor w1, w1, w30

    bn.rshi w30, w31, w2 >> 5
    bn.and w30, w27, w30, FG0
    bn.sel w29, w1, w31, FG0.l
    bn.xor w0, w0, w29

    /* -- Multiply a by x, then test bit 6 -- */
    bn.and w4, w1, w3
    bn.xor w1, w1, w4
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w4, w31, w4 >> 7
    bn.mulv.l.16H.lo w30, w4, sw0.0
    bn.xor w1, w1, w30

    bn.rshi w30, w31, w2 >> 6
    bn.and w30, w27, w30, FG0
    bn.sel w29, w1, w31, FG0.l
    bn.xor w0, w0, w29

    /* -- Multiply a by x, then test bit 7 -- */
    bn.and w4, w1, w3
    bn.xor w1, w1, w4
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w4, w31, w4 >> 7
    bn.mulv.l.16H.lo w30, w4, sw0.0
    bn.xor w1, w1, w30

    bn.rshi w30, w31, w2 >> 7
    bn.and w30, w27, w30, FG0
    bn.sel w29, w1, w31, FG0.l
    bn.xor w0, w0, w29

    ret
