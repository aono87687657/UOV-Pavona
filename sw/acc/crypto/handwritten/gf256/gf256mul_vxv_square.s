/*
 * gf256mul_vxv_square — Parallel per-byte GF(2^8) squaring of a 32-byte vector.
 *
 * For each byte k: w0[k] = w1[k]^2 in GF(256) with AES poly x^8+x^4+x^3+x+1.
 *
 * Algorithm: per output bit y_i, compute XOR of specific input bits
 * (the linearized squaring matrix over GF(2)):
 *   y0 = p0 ⊕ p4 ⊕ p6
 *   y1 = p4 ⊕ p6 ⊕ p7
 *   y2 = p1 ⊕ p5
 *   y3 = p4 ⊕ p5 ⊕ p6 ⊕ p7
 *   y4 = p2 ⊕ p4 ⊕ p7
 *   y5 = p5 ⊕ p6
 *   y6 = p3 ⊕ p5
 *   y7 = p6 ⊕ p7
 * where p_i = bit_i of each input byte, broadcast at byte position.
 *
 * @param[out]  w0    32 output bytes, each = square of input byte in GF(256)
 * @param[in]   w1    32 input bytes (preserved)
 * @param[in]   w17   lsb_mask = 0x0101...01 per byte
 * @param[in]   w31   0
 *
 * Clobbered registers:
 *   WDR: w0 (output),
 *        w2 = rolling scratch for p0/p1/p2/p3 (each used once → one slot)
 *        w3 = p4 stored (used 4×: y0, y1, y3, y4)
 *        w4 = p5 stored (used 4×: y2, y3, y5, y6)
 *        w5 = p6 stored (used 5×: y0, y1, y3, y5, y7)
 *        w6 = p7 stored (used 4×: y1, y3, y4, y7)
 *        w7 = shift temp (combines XOR terms, then rshi to target bit position)
 *   WSR: none
 *   GPR: none
 *   Flags: none
 */

.section .text
.balign 4
.global gf256mul_vxv_square
gf256mul_vxv_square:
    /* -- Extract p4..p7 (multi-use; stored in w3..w6) -- */
    bn.rshi w3, w31, w1 >> 4
    bn.and  w3, w3, w17                   /* w3 = p4 */
    bn.rshi w4, w31, w1 >> 5
    bn.and  w4, w4, w17                   /* w4 = p5 */
    bn.rshi w5, w31, w1 >> 6
    bn.and  w5, w5, w17                   /* w5 = p6 */
    bn.rshi w6, w31, w1 >> 7
    bn.and  w6, w6, w17                   /* w6 = p7 */

    /* -- y0 = p0 ⊕ p4 ⊕ p6  (no shift; seeds w0) -- */
    bn.and  w2, w1, w17                   /* w2 = p0 (single-use) */
    bn.xor  w0, w2, w3                    /* w0 = p0 ⊕ p4 */
    bn.xor  w0, w0, w5                    /* w0 = y0 */

    /* -- y1 = (p4 ⊕ p6 ⊕ p7) << 1 -- */
    bn.xor  w7, w3, w5
    bn.xor  w7, w7, w6
    bn.rshi w7, w7, w31 >> 255
    bn.xor  w0, w0, w7

    /* -- y2 = (p1 ⊕ p5) << 2 -- */
    bn.rshi w2, w31, w1 >> 1
    bn.and  w2, w2, w17                   /* w2 = p1 (single-use) */
    bn.xor  w7, w2, w4
    bn.rshi w7, w7, w31 >> 254
    bn.xor  w0, w0, w7

    /* -- y3 = (p4 ⊕ p5 ⊕ p6 ⊕ p7) << 3 -- */
    bn.xor  w7, w3, w4
    bn.xor  w7, w7, w5
    bn.xor  w7, w7, w6
    bn.rshi w7, w7, w31 >> 253
    bn.xor  w0, w0, w7

    /* -- y4 = (p2 ⊕ p4 ⊕ p7) << 4 -- */
    bn.rshi w2, w31, w1 >> 2
    bn.and  w2, w2, w17                   /* w2 = p2 (single-use) */
    bn.xor  w7, w2, w3
    bn.xor  w7, w7, w6
    bn.rshi w7, w7, w31 >> 252
    bn.xor  w0, w0, w7

    /* -- y5 = (p5 ⊕ p6) << 5 -- */
    bn.xor  w7, w4, w5
    bn.rshi w7, w7, w31 >> 251
    bn.xor  w0, w0, w7

    /* -- y6 = (p3 ⊕ p5) << 6 -- */
    bn.rshi w2, w31, w1 >> 3
    bn.and  w2, w2, w17                   /* w2 = p3 (single-use) */
    bn.xor  w7, w2, w4
    bn.rshi w7, w7, w31 >> 250
    bn.xor  w0, w0, w7

    /* -- y7 = (p6 ⊕ p7) << 7 -- */
    bn.xor  w7, w5, w6
    bn.rshi w7, w7, w31 >> 249
    bn.xor  w0, w0, w7

    ret
