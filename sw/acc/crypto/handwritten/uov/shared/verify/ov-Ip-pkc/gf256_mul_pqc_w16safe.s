/*
 * gf256_mul (PQC-vector, w16-safe) — 32-byte vector × 1 scalar, GF(2^8), AES poly 0x11B.
 *
 * Drop-in for gf256/gf256_mul.s in the verify-Ip sw tier: identical interface and
 * result, but the per-byte ×0x1b reduction uses one bn.mulv.l (PQC vector) instead
 * of 4x bn.mulqacc. Requires EN_PQC.
 *
 * bn.mulv.l reads its scalar only from w16 (sw0) or w17 (sw1). w17 is the caller's
 * msb_mask, so the 0x1b scalar must live in w16. The publicmap caller keeps cpk data
 * in w16 across the P3-phase calls, so w16 is saved on entry (into the now-free w4)
 * and restored before ret — the routine is w16-preserving, exactly like gf256_mul.
 *
 * @param[out]  w0    result (32 GF(256) products)
 * @param[in]   w1    input a — 32 GF(256) elements, 8-bit packed (destroyed)
 * @param[in]   w2    input b — 1 GF(256) scalar (bits [7:0])
 * @param[in]   w17   msb_mask = 0x80808080...80
 * @param[in]   w31   0
 *
 * Clobbered registers:
 *   WDR: w0 (output), w1 (destroyed), w3, w4, w5, w6 (w16 saved+restored, preserved)
 *   GPR: none
 *   Flags: FG0
 */

.section .text
.balign 4
.global gf256_mul
gf256_mul:
    /* -- Initialization -- */
    bn.xor  w31, w31, w31             /* w31 = 0 (zero constant)              */
    bn.mov  w4,  w16                  /* save caller's live w16 (cpk slot)    */
    bn.addi w16, w31, 0x1b            /* w16 low byte = 0x1b scalar (sw0)     */
    bn.addi w5,  w31, 1               /* w5  = 1 (mask for single-bit test)   */

    /* -- Bit 0 of b: conditional accumulate -- */
    bn.and w6, w2, w5, FG0            /* test bit 0 of b, set FG0.L flag      */
    bn.sel w0, w1, w31, FG0.l         /* w0 = (bit0 ? a : 0)                  */

    /* -- Multiply a by x in GF(256), then test bit 1 --
     *    1. Extract MSBs:        w3 = a & 0x80..80
     *    2. Clear MSBs in a:     a  = a ^ w3
     *    3. Shift a left by 1:   a  = a << 1  (safe, MSBs cleared)
     *    4. Normalize MSBs:      w3 = w3 >> 7  (0x80 → 0x01, 0x00 → 0x00)
     *    5. Multiply by 0x1b:    w6 = w3 * 0x1b  (1x bn.mulv.l, all 16 lanes)
     *    6. Apply reduction:     a  = a ^ w6
     */
    bn.and w3, w1, w17                 /* w3 = MSBs of each byte (0x80 or 0x00)*/
    bn.xor w1, w1, w3                 /* clear MSBs in a (safe to shift now)  */
    bn.rshi w1, w1, w31 >> 255        /* a <<= 1 (whole-register left shift)  */
    bn.rshi w3, w31, w3 >> 7          /* normalize: 0x80 → 0x01              */
    bn.mulv.l.16H.lo w6, w3, sw0.0    /* w6 = w3 * 0x1b per byte (vector)     */
    bn.xor w1, w1, w6                /* a ^= reduction (0x1b where MSB was set)*/

    bn.rshi w6, w31, w2 >> 1         /* shift bit 1 of b to position 0       */
    bn.and w6, w5, w6, FG0           /* test bit 1, set FG0.L flag           */
    bn.sel w3, w1, w31, FG0.l        /* w3 = (bit1 ? a : 0)                  */
    bn.xor w0, w0, w3                /* accumulate into result                */

    /* -- Multiply a by x, then test bit 2 -- */
    bn.and w3, w1, w17
    bn.xor w1, w1, w3
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w3, w31, w3 >> 7
    bn.mulv.l.16H.lo w6, w3, sw0.0
    bn.xor w1, w1, w6

    bn.rshi w6, w31, w2 >> 2
    bn.and w6, w5, w6, FG0
    bn.sel w3, w1, w31, FG0.l
    bn.xor w0, w0, w3

    /* -- Multiply a by x, then test bit 3 -- */
    bn.and w3, w1, w17
    bn.xor w1, w1, w3
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w3, w31, w3 >> 7
    bn.mulv.l.16H.lo w6, w3, sw0.0
    bn.xor w1, w1, w6

    bn.rshi w6, w31, w2 >> 3
    bn.and w6, w5, w6, FG0
    bn.sel w3, w1, w31, FG0.l
    bn.xor w0, w0, w3

    /* -- Multiply a by x, then test bit 4 -- */
    bn.and w3, w1, w17
    bn.xor w1, w1, w3
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w3, w31, w3 >> 7
    bn.mulv.l.16H.lo w6, w3, sw0.0
    bn.xor w1, w1, w6

    bn.rshi w6, w31, w2 >> 4
    bn.and w6, w5, w6, FG0
    bn.sel w3, w1, w31, FG0.l
    bn.xor w0, w0, w3

    /* -- Multiply a by x, then test bit 5 -- */
    bn.and w3, w1, w17
    bn.xor w1, w1, w3
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w3, w31, w3 >> 7
    bn.mulv.l.16H.lo w6, w3, sw0.0
    bn.xor w1, w1, w6

    bn.rshi w6, w31, w2 >> 5
    bn.and w6, w5, w6, FG0
    bn.sel w3, w1, w31, FG0.l
    bn.xor w0, w0, w3

    /* -- Multiply a by x, then test bit 6 -- */
    bn.and w3, w1, w17
    bn.xor w1, w1, w3
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w3, w31, w3 >> 7
    bn.mulv.l.16H.lo w6, w3, sw0.0
    bn.xor w1, w1, w6

    bn.rshi w6, w31, w2 >> 6
    bn.and w6, w5, w6, FG0
    bn.sel w3, w1, w31, FG0.l
    bn.xor w0, w0, w3

    /* -- Multiply a by x, then test bit 7 -- */
    bn.and w3, w1, w17
    bn.xor w1, w1, w3
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w3, w31, w3 >> 7
    bn.mulv.l.16H.lo w6, w3, sw0.0
    bn.xor w1, w1, w6

    bn.rshi w6, w31, w2 >> 7
    bn.and w6, w5, w6, FG0
    bn.sel w3, w1, w31, FG0.l
    bn.xor w0, w0, w3

    bn.mov w16, w4                    /* restore caller's w16 */
    ret
