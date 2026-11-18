/*
 * gf256mul_vxv — Parallel per-byte GF(2^8) multiply of two 32-byte vectors.
 *
 * @param[out]  w0    32 output bytes, each = a[k] * b[k] in GF(256)
 * @param[in]   w1    operand a — 32 GF(256) bytes (destroyed)
 * @param[in]   w2    operand b — 32 GF(256) bytes (preserved; read via rshi)
 * @param[in]   w17   lsb_mask = 0x0101...01 per byte
 * @param[in]   w31   0
 *
 * Clobbered registers:
 *   WDR: w0 (output), w1 (destroyed), w3, w4, w5, w6, w7
 *   WSR: ACC (used by bn.mulqacc)
 *   GPR: none
 *   Flags: FG0
 */

.section .text
.balign 4
.global gf256mul_vxv
gf256mul_vxv:
    /* Init constants */
    bn.xor  w0, w0, w0                    /* result = 0                       */
    bn.addi w5, w31, 0x1b                 /* w5[7:0] = 0x1B (reduction poly)  */
    bn.addi w7, w31, 0xff                 /* w7[7:0] = 0xFF (spread scalar)   */
    bn.rshi w6, w17, w31 >> 249           /* w6  = 0x80 per byte (msb_mask)   */

    /* --- Round 0 (bit 0 of b) --- */
    bn.and  w3, w2, w17                   /* bit0 of each byte of b at pos 0  */
    /* spread 0x01 → 0xFF per byte via mulqacc-by-0xFF; self-write w3 */
    bn.mulqacc.z    w3.0, w7.0, 0
    bn.mulqacc      w3.1, w7.0, 64
    bn.mulqacc      w3.2, w7.0, 128
    bn.mulqacc.wo   w3, w3.3, w7.0, 192
    /* select + accumulate */
    bn.and  w3, w1, w3
    bn.xor  w0, w0, w3
    /* mul a by x */
    bn.and  w4, w1, w6
    bn.xor  w1, w1, w4
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w4, w31, w4 >> 7
    bn.mulqacc.z    w4.0, w5.0, 0
    bn.mulqacc      w4.1, w5.0, 64
    bn.mulqacc      w4.2, w5.0, 128
    bn.mulqacc.wo   w4, w4.3, w5.0, 192
    bn.xor  w1, w1, w4

    /* --- Round 1 (bit 1 of b) --- */
    bn.rshi w3, w31, w2 >> 1
    bn.and  w3, w3, w17
    bn.mulqacc.z    w3.0, w7.0, 0
    bn.mulqacc      w3.1, w7.0, 64
    bn.mulqacc      w3.2, w7.0, 128
    bn.mulqacc.wo   w3, w3.3, w7.0, 192
    bn.and  w3, w1, w3
    bn.xor  w0, w0, w3
    bn.and  w4, w1, w6
    bn.xor  w1, w1, w4
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w4, w31, w4 >> 7
    bn.mulqacc.z    w4.0, w5.0, 0
    bn.mulqacc      w4.1, w5.0, 64
    bn.mulqacc      w4.2, w5.0, 128
    bn.mulqacc.wo   w4, w4.3, w5.0, 192
    bn.xor  w1, w1, w4

    /* --- Round 2 (bit 2 of b) --- */
    bn.rshi w3, w31, w2 >> 2
    bn.and  w3, w3, w17
    bn.mulqacc.z    w3.0, w7.0, 0
    bn.mulqacc      w3.1, w7.0, 64
    bn.mulqacc      w3.2, w7.0, 128
    bn.mulqacc.wo   w3, w3.3, w7.0, 192
    bn.and  w3, w1, w3
    bn.xor  w0, w0, w3
    bn.and  w4, w1, w6
    bn.xor  w1, w1, w4
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w4, w31, w4 >> 7
    bn.mulqacc.z    w4.0, w5.0, 0
    bn.mulqacc      w4.1, w5.0, 64
    bn.mulqacc      w4.2, w5.0, 128
    bn.mulqacc.wo   w4, w4.3, w5.0, 192
    bn.xor  w1, w1, w4

    /* --- Round 3 (bit 3 of b) --- */
    bn.rshi w3, w31, w2 >> 3
    bn.and  w3, w3, w17
    bn.mulqacc.z    w3.0, w7.0, 0
    bn.mulqacc      w3.1, w7.0, 64
    bn.mulqacc      w3.2, w7.0, 128
    bn.mulqacc.wo   w3, w3.3, w7.0, 192
    bn.and  w3, w1, w3
    bn.xor  w0, w0, w3
    bn.and  w4, w1, w6
    bn.xor  w1, w1, w4
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w4, w31, w4 >> 7
    bn.mulqacc.z    w4.0, w5.0, 0
    bn.mulqacc      w4.1, w5.0, 64
    bn.mulqacc      w4.2, w5.0, 128
    bn.mulqacc.wo   w4, w4.3, w5.0, 192
    bn.xor  w1, w1, w4

    /* --- Round 4 (bit 4 of b) --- */
    bn.rshi w3, w31, w2 >> 4
    bn.and  w3, w3, w17
    bn.mulqacc.z    w3.0, w7.0, 0
    bn.mulqacc      w3.1, w7.0, 64
    bn.mulqacc      w3.2, w7.0, 128
    bn.mulqacc.wo   w3, w3.3, w7.0, 192
    bn.and  w3, w1, w3
    bn.xor  w0, w0, w3
    bn.and  w4, w1, w6
    bn.xor  w1, w1, w4
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w4, w31, w4 >> 7
    bn.mulqacc.z    w4.0, w5.0, 0
    bn.mulqacc      w4.1, w5.0, 64
    bn.mulqacc      w4.2, w5.0, 128
    bn.mulqacc.wo   w4, w4.3, w5.0, 192
    bn.xor  w1, w1, w4

    /* --- Round 5 (bit 5 of b) --- */
    bn.rshi w3, w31, w2 >> 5
    bn.and  w3, w3, w17
    bn.mulqacc.z    w3.0, w7.0, 0
    bn.mulqacc      w3.1, w7.0, 64
    bn.mulqacc      w3.2, w7.0, 128
    bn.mulqacc.wo   w3, w3.3, w7.0, 192
    bn.and  w3, w1, w3
    bn.xor  w0, w0, w3
    bn.and  w4, w1, w6
    bn.xor  w1, w1, w4
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w4, w31, w4 >> 7
    bn.mulqacc.z    w4.0, w5.0, 0
    bn.mulqacc      w4.1, w5.0, 64
    bn.mulqacc      w4.2, w5.0, 128
    bn.mulqacc.wo   w4, w4.3, w5.0, 192
    bn.xor  w1, w1, w4

    /* --- Round 6 (bit 6 of b) --- */
    bn.rshi w3, w31, w2 >> 6
    bn.and  w3, w3, w17
    bn.mulqacc.z    w3.0, w7.0, 0
    bn.mulqacc      w3.1, w7.0, 64
    bn.mulqacc      w3.2, w7.0, 128
    bn.mulqacc.wo   w3, w3.3, w7.0, 192
    bn.and  w3, w1, w3
    bn.xor  w0, w0, w3
    bn.and  w4, w1, w6
    bn.xor  w1, w1, w4
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w4, w31, w4 >> 7
    bn.mulqacc.z    w4.0, w5.0, 0
    bn.mulqacc      w4.1, w5.0, 64
    bn.mulqacc      w4.2, w5.0, 128
    bn.mulqacc.wo   w4, w4.3, w5.0, 192
    bn.xor  w1, w1, w4

    /* --- Round 7 (bit 7 of b) — last, skip mul-by-x --- */
    bn.rshi w3, w31, w2 >> 7
    bn.and  w3, w3, w17
    bn.mulqacc.z    w3.0, w7.0, 0
    bn.mulqacc      w3.1, w7.0, 64
    bn.mulqacc      w3.2, w7.0, 128
    bn.mulqacc.wo   w3, w3.3, w7.0, 192
    bn.and  w3, w1, w3
    bn.xor  w0, w0, w3

    ret
