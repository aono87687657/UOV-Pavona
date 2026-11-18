/* row_mul_O (Ip3, v=74 o=45, padded O). L = t^T * O over GF(256),
 * 45 cols x 64 B. Low chain (w19) in ACC, high chain (w20) in ACCH[.inc],
 * dropping the two per-element acc spills.
 * Order is load-bearing: low .acc must read the mod1 cursor before high
 * .acch[.inc] advances it.
 *
 * O is column-major with a 96-B (3-WDR) slot per column: low 74 B are the
 * column, 22 slack bytes are loaded but never used (the segment walk stops
 * at 74). Slack must be initialized memory. Every column is the same
 * 32/32/10 segment walk with mod1 reset per
 * column - no windows, no schedule.
 *
 *   variant     cpp flag             body
 *   sw          (none)               SW row_mul_O_macc_sw helper-based
 *   bngfonly    -DGF_INSTRUCTIONS    HW bn.gfmul.8 .acc.z/.acch.z.inc peel
 *   bngfaes     -DAES_|GF_           HW bn.gfmul.8 .acc + .acch.inc
 *
 * in:    x6 t base (32-B aligned), x11 O padded (col-major, 96 B/slot,
 *        32-B aligned - all arms load it with bn.lid), x12 L out, x19=1,
 *        x28=19, x29=20, mod0=0x11b, w31=0. mod1 in: don't-care (reset per
 *        column on the HW arms; the sw arm never reads it).
 * clob:  x5, x8, x11 (+4320, all arms), x12 (+2880)
 * wdr:   w0, w1, w19, w20 + w2..w4 (HW) / w2..w4,
 *        w21..w27 (sw; the helper stashes caller w16 in w24 and
 *        restores it - w16 is NOT net-clobbered)
 * stack: none (no frame). HW arms are leaf; the sw arm is NOT - it jal's the
 *        macc helper, so it costs one HW call-stack slot
 * HW arms also clobber ACC/ACCH and mod1 (mod1 back to 0 before ret);
 * the sw arm leaves mod1 alone and dirties FG0.
 * Reads O[0..4319] exactly - the slot structure already covers the
 * aligned loads, so O's reservation is 4320 B with no extra pad.
 */

.section .text
.balign 4
.global row_mul_O

#if defined(AES_INSTRUCTIONS) && defined(GF_INSTRUCTIONS)

/* =============== bngfaes (HW bn.gfmul.8) =============== */
row_mul_O:

    /* 45 identical columns: w2..w4 = the 96-B slot, segments 32/32/10.
     * mod1 must be reset per column (74 .inc steps leave 10, not 0). */
    loopi 45, 26                   /* 45 columns of O */
        li x8, 2
        bn.lid x8++, 0(x11)
        bn.lid x8++, 32(x11)
        bn.lid x8++, 64(x11)
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x5, x0, x6                 /* reset the t cursor */
        csrrw x0, mod1, x0             /* mod1 = 0 */
        loopi 32, 4                    /* seg 1: w2[0..31] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w2
            bn.gfmul.8.acch.inc w20, w1, w2
        loopi 32, 4                    /* seg 2: w3[0..31] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w3
            bn.gfmul.8.acch.inc w20, w1, w3
        loopi 10, 4                    /* seg 3: w4[0..9] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w4
            bn.gfmul.8.acch.inc w20, w1, w4
        bn.sid x28, 0(x12++)
        bn.sid x29, 0(x12++)
        addi x11, x11, 96              /* next 96-B slot */

    csrrw x0, mod1, x0             /* mod1 reset before ret (mod1 leak convention) */
    ret

#elif defined(GF_INSTRUCTIONS)

/* =============== bngfonly (HW bn.gfmul.8 with .acc.z/.acch.z variants) =============== */
row_mul_O:

    /* 45 identical columns: w2..w4 = the 96-B slot, segments 32/32/10.
     * mod1 must be reset per column (74 .inc steps leave 10, not 0). */
    loopi 45, 28                   /* 45 columns of O */
        li x8, 2
        bn.lid x8++, 0(x11)
        bn.lid x8++, 32(x11)
        bn.lid x8++, 64(x11)
        add x5, x0, x6                 /* reset the t cursor */
        csrrw x0, mod1, x0             /* mod1 = 0 */
        /* peel seg1 first iter: .acc.z zeros ACC (w19 chain), .acch.z.inc zeros ACCH (w20) */
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc.z w19, w0, w2
        bn.gfmul.8.acch.z.inc w20, w1, w2
        loopi 31, 4                    /* seg 1 rest: w2[1..31] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w2
            bn.gfmul.8.acch.inc w20, w1, w2
        loopi 32, 4                    /* seg 2: w3[0..31] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w3
            bn.gfmul.8.acch.inc w20, w1, w3
        loopi 10, 4                    /* seg 3: w4[0..9] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w4
            bn.gfmul.8.acch.inc w20, w1, w4
        bn.sid x28, 0(x12++)
        bn.sid x29, 0(x12++)
        addi x11, x11, 96              /* next 96-B slot */

    csrrw x0, mod1, x0             /* mod1 reset before ret (mod1 leak convention) */
    ret

#else

/* =============== sw (SW row_mul_O_macc_sw helper-based) =============== */
.global row_mul_O_macc_sw
row_mul_O_macc_sw:
    /* w19 ^= w0 * s, w20 ^= w1 * s over GF(256), bit-serial and branch-free.
     * in:   w0/w1 t element (DESTROYED, left as orig * x^7), w22 scalar in
     *       byte 0 (DESTROYED, left as s>>7), w21 msb_mask, w31 = 0
     * in/out: w19/w20 accumulator chain
     * clob: w23 mask, w24 stashed caller w16, w25/w26 partials, w27 scratch,
     *       FG0; w16 = 0x1b for bn.mulv.l (sw0) and restored on exit
     * clob: x1.  No loops, so callable from a depth-2 nest. */
    bn.addi w23, w31, 1               /* w23 = 0x01 (mask for bit-0 test) */
    bn.mov  w24, w16                  /* stash caller's live w16 (streaming slot) */
    bn.addi w16, w31, 0x1b            /* w16 low byte = 0x1b reduction scalar (sw0) */

    /* === BIT 0 of scalar ===
     * Initialize local accumulators based on bit 0 of scalar. */
    bn.and w27, w22, w23, FG0         /* FG0.l = bit 0 of scalar */
    bn.sel w25, w0, w31, FG0.l        /* w25 = (bit0) ? w0 : 0 */
    bn.sel w26, w1, w31, FG0.l        /* w26 = (bit0) ? w1 : 0 */

    /* === BIT 1 ===
     * Multiply w0 ×= x (GF), multiply w1 ×= x, shift scalar, accumulate. */
    /* mul w0 by x: */
    bn.and  w27, w0, w21                          /* MSBs of each byte */
    bn.xor  w0, w0, w27                           /* clear MSBs */
    bn.rshi w0, w0, w31 >> 255                    /* w0 <<= 1 */
    bn.rshi w27, w31, w27 >> 7                    /* normalize 0x80→0x01 */
    bn.mulv.l.16H.lo w27, w27, sw0.0   /* w27 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w0, w0, w27                           /* apply 0x1b reduction */
    /* mul w1 by x: */
    bn.and  w27, w1, w21
    bn.xor  w1, w1, w27
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w27, w31, w27 >> 7
    bn.mulv.l.16H.lo w27, w27, sw0.0   /* w27 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w1, w1, w27
    /* shift scalar right by 1, test new bit 0, conditional accumulate: */
    bn.rshi w22, w31, w22 >> 1
    bn.and  w27, w22, w23, FG0
    bn.sel  w27, w0, w31, FG0.l
    bn.xor  w25, w25, w27
    bn.addi w23, w31, 1
    bn.and  w27, w22, w23, FG0
    bn.sel  w27, w1, w31, FG0.l
    bn.xor  w26, w26, w27

    /* === BIT 2 === */
    bn.and  w27, w0, w21
    bn.xor  w0, w0, w27
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w27, w31, w27 >> 7
    bn.mulv.l.16H.lo w27, w27, sw0.0   /* w27 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w0, w0, w27
    bn.and  w27, w1, w21
    bn.xor  w1, w1, w27
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w27, w31, w27 >> 7
    bn.mulv.l.16H.lo w27, w27, sw0.0   /* w27 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w1, w1, w27
    bn.rshi w22, w31, w22 >> 1
    bn.and  w27, w22, w23, FG0
    bn.sel  w27, w0, w31, FG0.l
    bn.xor  w25, w25, w27
    bn.addi w23, w31, 1
    bn.and  w27, w22, w23, FG0
    bn.sel  w27, w1, w31, FG0.l
    bn.xor  w26, w26, w27

    /* === BIT 3 === */
    bn.and  w27, w0, w21
    bn.xor  w0, w0, w27
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w27, w31, w27 >> 7
    bn.mulv.l.16H.lo w27, w27, sw0.0   /* w27 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w0, w0, w27
    bn.and  w27, w1, w21
    bn.xor  w1, w1, w27
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w27, w31, w27 >> 7
    bn.mulv.l.16H.lo w27, w27, sw0.0   /* w27 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w1, w1, w27
    bn.rshi w22, w31, w22 >> 1
    bn.and  w27, w22, w23, FG0
    bn.sel  w27, w0, w31, FG0.l
    bn.xor  w25, w25, w27
    bn.addi w23, w31, 1
    bn.and  w27, w22, w23, FG0
    bn.sel  w27, w1, w31, FG0.l
    bn.xor  w26, w26, w27

    /* === BIT 4 === */
    bn.and  w27, w0, w21
    bn.xor  w0, w0, w27
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w27, w31, w27 >> 7
    bn.mulv.l.16H.lo w27, w27, sw0.0   /* w27 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w0, w0, w27
    bn.and  w27, w1, w21
    bn.xor  w1, w1, w27
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w27, w31, w27 >> 7
    bn.mulv.l.16H.lo w27, w27, sw0.0   /* w27 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w1, w1, w27
    bn.rshi w22, w31, w22 >> 1
    bn.and  w27, w22, w23, FG0
    bn.sel  w27, w0, w31, FG0.l
    bn.xor  w25, w25, w27
    bn.addi w23, w31, 1
    bn.and  w27, w22, w23, FG0
    bn.sel  w27, w1, w31, FG0.l
    bn.xor  w26, w26, w27

    /* === BIT 5 === */
    bn.and  w27, w0, w21
    bn.xor  w0, w0, w27
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w27, w31, w27 >> 7
    bn.mulv.l.16H.lo w27, w27, sw0.0   /* w27 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w0, w0, w27
    bn.and  w27, w1, w21
    bn.xor  w1, w1, w27
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w27, w31, w27 >> 7
    bn.mulv.l.16H.lo w27, w27, sw0.0   /* w27 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w1, w1, w27
    bn.rshi w22, w31, w22 >> 1
    bn.and  w27, w22, w23, FG0
    bn.sel  w27, w0, w31, FG0.l
    bn.xor  w25, w25, w27
    bn.addi w23, w31, 1
    bn.and  w27, w22, w23, FG0
    bn.sel  w27, w1, w31, FG0.l
    bn.xor  w26, w26, w27

    /* === BIT 6 === */
    bn.and  w27, w0, w21
    bn.xor  w0, w0, w27
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w27, w31, w27 >> 7
    bn.mulv.l.16H.lo w27, w27, sw0.0   /* w27 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w0, w0, w27
    bn.and  w27, w1, w21
    bn.xor  w1, w1, w27
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w27, w31, w27 >> 7
    bn.mulv.l.16H.lo w27, w27, sw0.0   /* w27 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w1, w1, w27
    bn.rshi w22, w31, w22 >> 1
    bn.and  w27, w22, w23, FG0
    bn.sel  w27, w0, w31, FG0.l
    bn.xor  w25, w25, w27
    bn.addi w23, w31, 1
    bn.and  w27, w22, w23, FG0
    bn.sel  w27, w1, w31, FG0.l
    bn.xor  w26, w26, w27

    /* === BIT 7 === */
    bn.and  w27, w0, w21
    bn.xor  w0, w0, w27
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w27, w31, w27 >> 7
    bn.mulv.l.16H.lo w27, w27, sw0.0   /* w27 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w0, w0, w27
    bn.and  w27, w1, w21
    bn.xor  w1, w1, w27
    bn.rshi w1, w1, w31 >> 255
    bn.rshi w27, w31, w27 >> 7
    bn.mulv.l.16H.lo w27, w27, sw0.0   /* w27 *= 0x1b per byte (GF reduce, vector) */
    bn.xor  w1, w1, w27
    bn.rshi w22, w31, w22 >> 1
    bn.and  w27, w22, w23, FG0
    bn.sel  w27, w0, w31, FG0.l
    bn.xor  w25, w25, w27
    bn.addi w23, w31, 1
    bn.and  w27, w22, w23, FG0
    bn.sel  w27, w1, w31, FG0.l
    bn.xor  w26, w26, w27

    /* Final: w19 ^= w0_orig × scalar; w20 ^= w1_orig × scalar */
    bn.xor w19, w19, w25
    bn.xor w20, w20, w26

    bn.mov w16, w24                   /* restore caller's w16 */
    ret

/* row_mul_O - entry point, exported as `row_mul_O` (drop-in replacement
 * for the HW-gfmul version when linked via the sw BUILD target). */
.global row_mul_O
row_mul_O:

    /* Load msb_mask into w21 (caller may not have it). */
    la x5, msb_mask
    li x8, 21
    bn.lid x8, 0(x5)

    /* 45 identical columns: the 96-B slot is 32-B aligned, so
     * w2..w4 load directly and one 8-bit slide per element
     * feeds the helper from w2 byte 0. */
    loopi 45, 18                   /* 45 columns of O */
        li x8, 2
        bn.lid x8++, 0(x11)
        bn.lid x8++, 32(x11)
        bn.lid x8++, 64(x11)
        bn.xor w19, w19, w19           /* acc_lo = 0 */
        bn.xor w20, w20, w20           /* acc_hi = 0 */
        add x5, x0, x6                 /* reset the t cursor */
        loopi 74, 7                    /* 74 t rows */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)            /* x19 = 1 -> loads w1 */
            bn.mov w22, w2                 /* scalar copy for the helper */
            jal x1, row_mul_O_macc_sw
            bn.rshi w2, w3, w2 >> 8
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w31, w4 >> 8
        bn.sid x28, 0(x12++)
        bn.sid x29, 0(x12++)
        addi x11, x11, 96              /* next 96-B slot */

    /* No mod1 reset needed - we don't touch mod1.  (Caller's mod1 invariant
     * preserved: mod1 stays at whatever value caller had on entry.) */
    ret

#endif
