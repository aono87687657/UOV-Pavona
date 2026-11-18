/* SW GF(256) helpers. mod 0x11b.
 * helpers: gf256_macc_sw, gf256_macc_sw_batched, gf256_scalar_inv_sw, gf256_macc_dualvec_sw.
 * data   : msb_mask (per-byte 0x80; used by all sw GF arithmetic kernels).
 */

.section .data
.balign 32
.global msb_mask
msb_mask:
    .word 0x80808080, 0x80808080, 0x80808080, 0x80808080
    .word 0x80808080, 0x80808080, 0x80808080, 0x80808080

/* gf256_macc_sw : w20 ^= w0 * scalar
 * setup: w0=vec, w19=scalar@byte 0, w20=acc, w16=0x80/byte, w17=0x1b bcast, w31=0
 * clob : w0, w18, w19, w20, FG0
 */
.section .text
.balign 4
.global gf256_macc_sw
gf256_macc_sw:
    /* === BIT 0 === */
    bn.addi w18, w31, 1
    bn.and  w18, w19, w18, FG0
    bn.sel  w18, w0, w31, FG0.l
    bn.xor  w20, w20, w18

    /* === BIT 1 === */
    bn.and  w18, w0, w16
    bn.xor  w0, w0, w18
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w18, w31, w18 >> 7
    bn.mulv.l.16H.lo w18, w18, sw1.0   /* w18 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w0, w0, w18
    bn.rshi w19, w31, w19 >> 1
    bn.addi w18, w31, 1
    bn.and  w18, w19, w18, FG0
    bn.sel  w18, w0, w31, FG0.l
    bn.xor  w20, w20, w18

    /* === BIT 2 === */
    bn.and  w18, w0, w16
    bn.xor  w0, w0, w18
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w18, w31, w18 >> 7
    bn.mulv.l.16H.lo w18, w18, sw1.0   /* w18 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w0, w0, w18
    bn.rshi w19, w31, w19 >> 1
    bn.addi w18, w31, 1
    bn.and  w18, w19, w18, FG0
    bn.sel  w18, w0, w31, FG0.l
    bn.xor  w20, w20, w18

    /* === BIT 3 === */
    bn.and  w18, w0, w16
    bn.xor  w0, w0, w18
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w18, w31, w18 >> 7
    bn.mulv.l.16H.lo w18, w18, sw1.0   /* w18 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w0, w0, w18
    bn.rshi w19, w31, w19 >> 1
    bn.addi w18, w31, 1
    bn.and  w18, w19, w18, FG0
    bn.sel  w18, w0, w31, FG0.l
    bn.xor  w20, w20, w18

    /* === BIT 4 === */
    bn.and  w18, w0, w16
    bn.xor  w0, w0, w18
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w18, w31, w18 >> 7
    bn.mulv.l.16H.lo w18, w18, sw1.0   /* w18 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w0, w0, w18
    bn.rshi w19, w31, w19 >> 1
    bn.addi w18, w31, 1
    bn.and  w18, w19, w18, FG0
    bn.sel  w18, w0, w31, FG0.l
    bn.xor  w20, w20, w18

    /* === BIT 5 === */
    bn.and  w18, w0, w16
    bn.xor  w0, w0, w18
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w18, w31, w18 >> 7
    bn.mulv.l.16H.lo w18, w18, sw1.0   /* w18 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w0, w0, w18
    bn.rshi w19, w31, w19 >> 1
    bn.addi w18, w31, 1
    bn.and  w18, w19, w18, FG0
    bn.sel  w18, w0, w31, FG0.l
    bn.xor  w20, w20, w18

    /* === BIT 6 === */
    bn.and  w18, w0, w16
    bn.xor  w0, w0, w18
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w18, w31, w18 >> 7
    bn.mulv.l.16H.lo w18, w18, sw1.0   /* w18 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w0, w0, w18
    bn.rshi w19, w31, w19 >> 1
    bn.addi w18, w31, 1
    bn.and  w18, w19, w18, FG0
    bn.sel  w18, w0, w31, FG0.l
    bn.xor  w20, w20, w18

    /* === BIT 7 === */
    bn.and  w18, w0, w16
    bn.xor  w0, w0, w18
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w18, w31, w18 >> 7
    bn.mulv.l.16H.lo w18, w18, sw1.0   /* w18 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w0, w0, w18
    bn.rshi w19, w31, w19 >> 1
    bn.addi w18, w31, 1
    bn.and  w18, w19, w18, FG0
    bn.sel  w18, w0, w31, FG0.l
    bn.xor  w20, w20, w18

    ret


/* gf256_macc_sw_batched : w20 ^= w0 * scalar (high-reg variant)
 * setup: w0=vec, w19=scalar@byte 0, w20=acc, w22=0x80/byte, w23=0x1b bcast, w31=0
 * clob : w0, w19, w20, w21, FG0
 */
.balign 4
.global gf256_macc_sw_batched
gf256_macc_sw_batched:
    /* === BIT 0 === */
    bn.addi w21, w31, 1
    bn.and  w21, w19, w21, FG0
    bn.sel  w21, w0, w31, FG0.l
    bn.xor  w20, w20, w21

    /* === BIT 1 === */
    bn.and  w21, w0, w22
    bn.xor  w0, w0, w21
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w21, w31, w21 >> 7
    bn.mulqacc.z   w21.0, w23.0, 0
    bn.mulqacc     w21.1, w23.0, 64
    bn.mulqacc     w21.2, w23.0, 128
    bn.mulqacc.wo  w21, w21.3, w23.0, 192
    bn.xor  w0, w0, w21
    bn.rshi w19, w31, w19 >> 1
    bn.addi w21, w31, 1
    bn.and  w21, w19, w21, FG0
    bn.sel  w21, w0, w31, FG0.l
    bn.xor  w20, w20, w21

    /* === BIT 2 === */
    bn.and  w21, w0, w22
    bn.xor  w0, w0, w21
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w21, w31, w21 >> 7
    bn.mulqacc.z   w21.0, w23.0, 0
    bn.mulqacc     w21.1, w23.0, 64
    bn.mulqacc     w21.2, w23.0, 128
    bn.mulqacc.wo  w21, w21.3, w23.0, 192
    bn.xor  w0, w0, w21
    bn.rshi w19, w31, w19 >> 1
    bn.addi w21, w31, 1
    bn.and  w21, w19, w21, FG0
    bn.sel  w21, w0, w31, FG0.l
    bn.xor  w20, w20, w21

    /* === BIT 3 === */
    bn.and  w21, w0, w22
    bn.xor  w0, w0, w21
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w21, w31, w21 >> 7
    bn.mulqacc.z   w21.0, w23.0, 0
    bn.mulqacc     w21.1, w23.0, 64
    bn.mulqacc     w21.2, w23.0, 128
    bn.mulqacc.wo  w21, w21.3, w23.0, 192
    bn.xor  w0, w0, w21
    bn.rshi w19, w31, w19 >> 1
    bn.addi w21, w31, 1
    bn.and  w21, w19, w21, FG0
    bn.sel  w21, w0, w31, FG0.l
    bn.xor  w20, w20, w21

    /* === BIT 4 === */
    bn.and  w21, w0, w22
    bn.xor  w0, w0, w21
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w21, w31, w21 >> 7
    bn.mulqacc.z   w21.0, w23.0, 0
    bn.mulqacc     w21.1, w23.0, 64
    bn.mulqacc     w21.2, w23.0, 128
    bn.mulqacc.wo  w21, w21.3, w23.0, 192
    bn.xor  w0, w0, w21
    bn.rshi w19, w31, w19 >> 1
    bn.addi w21, w31, 1
    bn.and  w21, w19, w21, FG0
    bn.sel  w21, w0, w31, FG0.l
    bn.xor  w20, w20, w21

    /* === BIT 5 === */
    bn.and  w21, w0, w22
    bn.xor  w0, w0, w21
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w21, w31, w21 >> 7
    bn.mulqacc.z   w21.0, w23.0, 0
    bn.mulqacc     w21.1, w23.0, 64
    bn.mulqacc     w21.2, w23.0, 128
    bn.mulqacc.wo  w21, w21.3, w23.0, 192
    bn.xor  w0, w0, w21
    bn.rshi w19, w31, w19 >> 1
    bn.addi w21, w31, 1
    bn.and  w21, w19, w21, FG0
    bn.sel  w21, w0, w31, FG0.l
    bn.xor  w20, w20, w21

    /* === BIT 6 === */
    bn.and  w21, w0, w22
    bn.xor  w0, w0, w21
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w21, w31, w21 >> 7
    bn.mulqacc.z   w21.0, w23.0, 0
    bn.mulqacc     w21.1, w23.0, 64
    bn.mulqacc     w21.2, w23.0, 128
    bn.mulqacc.wo  w21, w21.3, w23.0, 192
    bn.xor  w0, w0, w21
    bn.rshi w19, w31, w19 >> 1
    bn.addi w21, w31, 1
    bn.and  w21, w19, w21, FG0
    bn.sel  w21, w0, w31, FG0.l
    bn.xor  w20, w20, w21

    /* === BIT 7 === */
    bn.and  w21, w0, w22
    bn.xor  w0, w0, w21
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w21, w31, w21 >> 7
    bn.mulqacc.z   w21.0, w23.0, 0
    bn.mulqacc     w21.1, w23.0, 64
    bn.mulqacc     w21.2, w23.0, 128
    bn.mulqacc.wo  w21, w21.3, w23.0, 192
    bn.xor  w0, w0, w21
    bn.rshi w19, w31, w19 >> 1
    bn.addi w21, w31, 1
    bn.and  w21, w19, w21, FG0
    bn.sel  w21, w0, w31, FG0.l
    bn.xor  w20, w20, w21

    ret


/* gf256_scalar_inv_sw : w29[byte 0] = inv(w29[byte 0]) = a^254 (Itoh-Tsujii)
 *   chain a->a^3->a^15->a^63->a^127->a^254 : 4 GF-mults + 7 squarings.
 *   mults via gf256_macc_sw; squarings via gf256mul_vxv_square (linear, ~2x cheaper).
 * setup: w29[byte 0]=a, rest=0; w16=0x80/byte, w31=0 (w17 built per phase, left=0x1b)
 * stack: 160 B (w0@0, x1@32, w1@64, w2@96, w3@128)
 * clob : w4..w7, w18..w20, w23..w25; x4; FG0   (w0..w3 saved/restored; w17 left=0x1b)
 */
.balign 4
.global gf256_scalar_inv_sw
gf256_scalar_inv_sw:
    /* 160 B frame: save w0 and w1..w3 (caller-live in GE) + x1. */
    addi x2, x2, -160
    sw x1, 32(x2)
    li x4, 0
    bn.sid x4, 0(x2)
    li x4, 1
    bn.sid x4, 64(x2)
    li x4, 2
    bn.sid x4, 96(x2)
    li x4, 3
    bn.sid x4, 128(x2)

    /* w17 = 0x01 (square lsb_mask) / 0x1b (macc reduce) built inline per phase.
     * vxv_square: in w1, out w0, clob w0,w2..w7. macc: w20 ^= w0*w19[0], clob w0,w18..w20.
     * b1 = a stays in w29 (neither helper clobbers it) until the final result store. */

    /* b2 = a^2 * a = a^3 -> w23 */
    bn.addi w17, w31, 1
    bn.mov w1, w29
    jal x1, gf256mul_vxv_square     /* w0 = a^2 */
    bn.addi w17, w31, 27
    bn.mov w19, w29
    bn.mov w20, w31
    jal x1, gf256_macc_sw           /* w20 = a^2 * a */
    bn.mov w23, w20

    /* b4 = (a^3)^4 * a^3 = a^15 -> w24 */
    bn.addi w17, w31, 1
    bn.mov w1, w23
    jal x1, gf256mul_vxv_square     /* w0 = a^6 */
    bn.mov w1, w0
    jal x1, gf256mul_vxv_square     /* w0 = a^12 */
    bn.addi w17, w31, 27
    bn.mov w19, w23
    bn.mov w20, w31
    jal x1, gf256_macc_sw           /* w20 = a^12 * a^3 */
    bn.mov w24, w20

    /* b6 = (a^15)^4 * a^3 = a^63 -> w25 */
    bn.addi w17, w31, 1
    bn.mov w1, w24
    jal x1, gf256mul_vxv_square     /* w0 = a^30 */
    bn.mov w1, w0
    jal x1, gf256mul_vxv_square     /* w0 = a^60 */
    bn.addi w17, w31, 27
    bn.mov w19, w23
    bn.mov w20, w31
    jal x1, gf256_macc_sw           /* w20 = a^60 * a^3 */
    bn.mov w25, w20

    /* b7 = (a^63)^2 * a = a^127, then square -> a^254 = a^{-1} -> w29 */
    bn.addi w17, w31, 1
    bn.mov w1, w25
    jal x1, gf256mul_vxv_square     /* w0 = a^126 */
    bn.addi w17, w31, 27
    bn.mov w19, w29
    bn.mov w20, w31
    jal x1, gf256_macc_sw           /* w20 = a^126 * a = a^127 */
    bn.addi w17, w31, 1
    bn.mov w1, w20
    jal x1, gf256mul_vxv_square     /* w0 = a^254 */
    bn.mov w29, w0

    /* leave w17 = 0x1b for the caller's immediate gf256_macc_sw/_dualvec_sw, restore w0..w3 + x1 */
    bn.addi w17, w31, 27
    li x4, 0
    bn.lid x4, 0(x2)
    li x4, 1
    bn.lid x4, 64(x2)
    li x4, 2
    bn.lid x4, 96(x2)
    li x4, 3
    bn.lid x4, 128(x2)
    lw x1, 32(x2)
    addi x2, x2, 160
    ret


/* gf256_macc_dualvec_sw : w20 ^= w0*s ; w30 ^= w1*s
 * setup: w0+w1=vecs, w19=scalar@byte 0, w20+w30=accs, w16=0x80/byte, w17=0x1b bcast, w31=0
 * clob : w0, w1, w18, w19, w20, w30, FG0 M/L/Z, FG1
 * Each scalar bit is tested once into FG1; the bn.xor between the two selects writes FG0 only.
 */
.balign 4
.global gf256_macc_dualvec_sw
gf256_macc_dualvec_sw:
    /* === BIT 0 === */
    bn.add  w18, w19, w31, FG1
    bn.sel  w18, w0, w31, FG1.l
    bn.xor  w20, w20, w18
    bn.sel  w18, w1, w31, FG1.l
    bn.xor  w30, w30, w18

    /* === BIT 1 === */
    bn.and  w18, w0, w16
    bn.xor  w0, w0, w18
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w18, w31, w18 >> 7
    bn.mulv.l.16H.lo w18, w18, sw1.0   /* w18 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w0, w0, w18
    bn.and  w18, w1, w16
    bn.xor  w1, w1, w18
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w18, w31, w18 >> 7
    bn.mulv.l.16H.lo w18, w18, sw1.0   /* w18 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w1, w1, w18
    bn.rshi w19, w31, w19 >> 1
    bn.add  w18, w19, w31, FG1
    bn.sel  w18, w0, w31, FG1.l
    bn.xor  w20, w20, w18
    bn.sel  w18, w1, w31, FG1.l
    bn.xor  w30, w30, w18

    /* === BIT 2 === */
    bn.and  w18, w0, w16
    bn.xor  w0, w0, w18
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w18, w31, w18 >> 7
    bn.mulv.l.16H.lo w18, w18, sw1.0   /* w18 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w0, w0, w18
    bn.and  w18, w1, w16
    bn.xor  w1, w1, w18
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w18, w31, w18 >> 7
    bn.mulv.l.16H.lo w18, w18, sw1.0   /* w18 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w1, w1, w18
    bn.rshi w19, w31, w19 >> 1
    bn.add  w18, w19, w31, FG1
    bn.sel  w18, w0, w31, FG1.l
    bn.xor  w20, w20, w18
    bn.sel  w18, w1, w31, FG1.l
    bn.xor  w30, w30, w18

    /* === BIT 3 === */
    bn.and  w18, w0, w16
    bn.xor  w0, w0, w18
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w18, w31, w18 >> 7
    bn.mulv.l.16H.lo w18, w18, sw1.0   /* w18 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w0, w0, w18
    bn.and  w18, w1, w16
    bn.xor  w1, w1, w18
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w18, w31, w18 >> 7
    bn.mulv.l.16H.lo w18, w18, sw1.0   /* w18 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w1, w1, w18
    bn.rshi w19, w31, w19 >> 1
    bn.add  w18, w19, w31, FG1
    bn.sel  w18, w0, w31, FG1.l
    bn.xor  w20, w20, w18
    bn.sel  w18, w1, w31, FG1.l
    bn.xor  w30, w30, w18

    /* === BIT 4 === */
    bn.and  w18, w0, w16
    bn.xor  w0, w0, w18
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w18, w31, w18 >> 7
    bn.mulv.l.16H.lo w18, w18, sw1.0   /* w18 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w0, w0, w18
    bn.and  w18, w1, w16
    bn.xor  w1, w1, w18
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w18, w31, w18 >> 7
    bn.mulv.l.16H.lo w18, w18, sw1.0   /* w18 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w1, w1, w18
    bn.rshi w19, w31, w19 >> 1
    bn.add  w18, w19, w31, FG1
    bn.sel  w18, w0, w31, FG1.l
    bn.xor  w20, w20, w18
    bn.sel  w18, w1, w31, FG1.l
    bn.xor  w30, w30, w18

    /* === BIT 5 === */
    bn.and  w18, w0, w16
    bn.xor  w0, w0, w18
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w18, w31, w18 >> 7
    bn.mulv.l.16H.lo w18, w18, sw1.0   /* w18 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w0, w0, w18
    bn.and  w18, w1, w16
    bn.xor  w1, w1, w18
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w18, w31, w18 >> 7
    bn.mulv.l.16H.lo w18, w18, sw1.0   /* w18 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w1, w1, w18
    bn.rshi w19, w31, w19 >> 1
    bn.add  w18, w19, w31, FG1
    bn.sel  w18, w0, w31, FG1.l
    bn.xor  w20, w20, w18
    bn.sel  w18, w1, w31, FG1.l
    bn.xor  w30, w30, w18

    /* === BIT 6 === */
    bn.and  w18, w0, w16
    bn.xor  w0, w0, w18
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w18, w31, w18 >> 7
    bn.mulv.l.16H.lo w18, w18, sw1.0   /* w18 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w0, w0, w18
    bn.and  w18, w1, w16
    bn.xor  w1, w1, w18
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w18, w31, w18 >> 7
    bn.mulv.l.16H.lo w18, w18, sw1.0   /* w18 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w1, w1, w18
    bn.rshi w19, w31, w19 >> 1
    bn.add  w18, w19, w31, FG1
    bn.sel  w18, w0, w31, FG1.l
    bn.xor  w20, w20, w18
    bn.sel  w18, w1, w31, FG1.l
    bn.xor  w30, w30, w18

    /* === BIT 7 === */
    bn.and  w18, w0, w16
    bn.xor  w0, w0, w18
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w18, w31, w18 >> 7
    bn.mulv.l.16H.lo w18, w18, sw1.0   /* w18 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w0, w0, w18
    bn.and  w18, w1, w16
    bn.xor  w1, w1, w18
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w18, w31, w18 >> 7
    bn.mulv.l.16H.lo w18, w18, sw1.0   /* w18 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w1, w1, w18
    bn.rshi w19, w31, w19 >> 1
    bn.add  w18, w19, w31, FG1
    bn.sel  w18, w0, w31, FG1.l
    bn.xor  w20, w20, w18
    bn.sel  w18, w1, w31, FG1.l
    bn.xor  w30, w30, w18

    ret
