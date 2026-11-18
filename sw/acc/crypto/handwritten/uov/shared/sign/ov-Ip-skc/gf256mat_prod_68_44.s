/* gf256mat_prod_68_44 (Ip). Holds the mid row chain (w29, rows 32..63) in
 * ACCH; w28 (rows 0..31) and w30 (rows 64..67)
 * share ACC. Drops the per-column acc spill on the w29 chain.
 *
 *   variant     cpp flag             body
 *   sw          (none)               SW gf256 multiply
 *   bngfonly    -DGF_INSTRUCTIONS    HW bn.gfmul.8/.acch (mod1=0 entry asm)
 *   bngfaes     -DAES_|GF_           HW bn.gfmul.8/.acch (explicit mod1=0 reset)
 *
 * in : x10 = y out (96B, stored via w28/w29/w30), x11 = matrix (col-major,
 *      walked/advanced), x12 = b vector ptr (read-only)
 * clob (bngfaes) : x11, x17, x31; w0-w19 (w2-w18 batch lids), w28-w31; ACC, ACCH;
 *                  FG0 M/L/Z; sets mod0=0x11b; mod1 reset entry+exit
 * clob (bngfonly): same, but mod1=0 ASSUMED on entry (exit reset only)
 * clob (sw)      : x4, x5, x11, x17, x31; w0, w2-w18 (batch lids), w19-w23,
 *                  w26-w31 (w21 via gf256_macc_sw_batched); FG0 incl C (bn.addi)
 * stack: none (all arms leaf-frame; sw's jals nest via the x1 call stack)
 */

.section .text
.balign 4
.global gf256mat_prod_68_44


#if defined(AES_INSTRUCTIONS) && defined(GF_INSTRUCTIONS)

/* =============== bngfaes (HW bn.gfmul.8, explicit mod1=0 reset) =============== */
gf256mat_prod_68_44:

    bn.xor w31, w31, w31
    li x31, 0x11b
    csrrw x0, mod0, x31
    csrrw x0, mod1, x0                  /* start mod1=0 (byte 0 of w0) */

    li x31, 0
    bn.lid x31, 0(x12)                  /* w0 = b[0..31]  */
    li x31, 1
    bn.lid x31, 32(x12)                 /* w1 = b[32..43] + pad */

    bn.mov w28, w31
    bn.mov w29, w31
    bn.mov w30, w31
    bn.wsrw acc, w31                    /* ACC = 0 (w28/w30 share ACC) */
    bn.wsrw acch, w31                   /* ACCH = 0 (w29 chain) */

    /* ============================================================
     * Phase 1: 4 batches × 8 cols = cols 0..31. Scalar source = w0.
     * mod1 increments 0 → 32 (wraps to 0 naturally at boundary).
     * Body size 80.
     * ============================================================ */
    loopi 4, 80
        /* Batch-load 17 WDRs */
        li x17, 2
        bn.lid x17++, 0(x11)
        bn.lid x17++, 32(x11)
        bn.lid x17++, 64(x11)
        bn.lid x17++, 96(x11)
        bn.lid x17++, 128(x11)
        bn.lid x17++, 160(x11)
        bn.lid x17++, 192(x11)
        bn.lid x17++, 224(x11)
        bn.lid x17++, 256(x11)
        bn.lid x17++, 288(x11)
        bn.lid x17++, 320(x11)
        bn.lid x17++, 352(x11)
        bn.lid x17++, 384(x11)
        bn.lid x17++, 416(x11)
        bn.lid x17++, 448(x11)
        bn.lid x17++, 480(x11)
        bn.lid x17++, 512(x11)
        /* 18 instr */

        /* Col 0: shift=0, w2/w3/w4 */
        bn.wsrw acc, w28
        bn.gfmul.8.acc w28, w2, w0
        bn.gfmul.8.acch w29, w3, w0
        bn.wsrw acc, w30
        bn.gfmul.8.acc.inc w30, w4, w0  /* INC: mod1+=1 */
        /* 5 instr */

        /* Col 1: shift=32, (w4,w5)(w5,w6)(w6,w7) */
        bn.rshi w19, w5, w4 >> 32
        bn.wsrw acc, w28
        bn.gfmul.8.acc w28, w19, w0
        bn.rshi w19, w6, w5 >> 32
        bn.gfmul.8.acch w29, w19, w0
        bn.rshi w19, w7, w6 >> 32
        bn.wsrw acc, w30
        bn.gfmul.8.acc.inc w30, w19, w0
        /* 8 instr */

        /* Col 2: shift=64 */
        bn.rshi w19, w7, w6 >> 64
        bn.wsrw acc, w28
        bn.gfmul.8.acc w28, w19, w0
        bn.rshi w19, w8, w7 >> 64
        bn.gfmul.8.acch w29, w19, w0
        bn.rshi w19, w9, w8 >> 64
        bn.wsrw acc, w30
        bn.gfmul.8.acc.inc w30, w19, w0
        /* 8 instr */

        /* Col 3: shift=96 */
        bn.rshi w19, w9, w8 >> 96
        bn.wsrw acc, w28
        bn.gfmul.8.acc w28, w19, w0
        bn.rshi w19, w10, w9 >> 96
        bn.gfmul.8.acch w29, w19, w0
        bn.rshi w19, w11, w10 >> 96
        bn.wsrw acc, w30
        bn.gfmul.8.acc.inc w30, w19, w0
        /* 8 instr */

        /* Col 4: shift=128 */
        bn.rshi w19, w11, w10 >> 128
        bn.wsrw acc, w28
        bn.gfmul.8.acc w28, w19, w0
        bn.rshi w19, w12, w11 >> 128
        bn.gfmul.8.acch w29, w19, w0
        bn.rshi w19, w13, w12 >> 128
        bn.wsrw acc, w30
        bn.gfmul.8.acc.inc w30, w19, w0
        /* 8 instr */

        /* Col 5: shift=160 */
        bn.rshi w19, w13, w12 >> 160
        bn.wsrw acc, w28
        bn.gfmul.8.acc w28, w19, w0
        bn.rshi w19, w14, w13 >> 160
        bn.gfmul.8.acch w29, w19, w0
        bn.rshi w19, w15, w14 >> 160
        bn.wsrw acc, w30
        bn.gfmul.8.acc.inc w30, w19, w0
        /* 8 instr */

        /* Col 6: shift=192 */
        bn.rshi w19, w15, w14 >> 192
        bn.wsrw acc, w28
        bn.gfmul.8.acc w28, w19, w0
        bn.rshi w19, w16, w15 >> 192
        bn.gfmul.8.acch w29, w19, w0
        bn.rshi w19, w17, w16 >> 192
        bn.wsrw acc, w30
        bn.gfmul.8.acc.inc w30, w19, w0
        /* 8 instr */

        /* Col 7: shift=224, (w18,w31) terminates */
        bn.rshi w19, w17, w16 >> 224
        bn.wsrw acc, w28
        bn.gfmul.8.acc w28, w19, w0
        bn.rshi w19, w18, w17 >> 224
        bn.gfmul.8.acch w29, w19, w0
        bn.rshi w19, w31, w18 >> 224
        bn.wsrw acc, w30
        bn.gfmul.8.acc.inc w30, w19, w0
        /* 8 instr */

        addi x11, x11, 544
        /* 1 instr */
    /* loopi body = 18 + 5 + 6×8 + 8 + 1 = 80 */

    /* ============================================================
     * Phase 2: 5th batch (cols 32..39). Scalar source = w1.
     * mod1 wrapped from 32 to 0 naturally — already at 0 for w1[0].
     * ============================================================ */

    /* Batch-load 17 WDRs */
    li x17, 2
    bn.lid x17++, 0(x11)
    bn.lid x17++, 32(x11)
    bn.lid x17++, 64(x11)
    bn.lid x17++, 96(x11)
    bn.lid x17++, 128(x11)
    bn.lid x17++, 160(x11)
    bn.lid x17++, 192(x11)
    bn.lid x17++, 224(x11)
    bn.lid x17++, 256(x11)
    bn.lid x17++, 288(x11)
    bn.lid x17++, 320(x11)
    bn.lid x17++, 352(x11)
    bn.lid x17++, 384(x11)
    bn.lid x17++, 416(x11)
    bn.lid x17++, 448(x11)
    bn.lid x17++, 480(x11)
    bn.lid x17++, 512(x11)

    /* Col 32: shift=0, scalar = w1 */
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w2, w1
    bn.gfmul.8.acch w29, w3, w1
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w4, w1

    /* Col 33 */
    bn.rshi w19, w5, w4 >> 32
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w19, w1
    bn.rshi w19, w6, w5 >> 32
    bn.gfmul.8.acch w29, w19, w1
    bn.rshi w19, w7, w6 >> 32
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w19, w1

    /* Col 34 */
    bn.rshi w19, w7, w6 >> 64
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w19, w1
    bn.rshi w19, w8, w7 >> 64
    bn.gfmul.8.acch w29, w19, w1
    bn.rshi w19, w9, w8 >> 64
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w19, w1

    /* Col 35 */
    bn.rshi w19, w9, w8 >> 96
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w19, w1
    bn.rshi w19, w10, w9 >> 96
    bn.gfmul.8.acch w29, w19, w1
    bn.rshi w19, w11, w10 >> 96
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w19, w1

    /* Col 36 */
    bn.rshi w19, w11, w10 >> 128
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w19, w1
    bn.rshi w19, w12, w11 >> 128
    bn.gfmul.8.acch w29, w19, w1
    bn.rshi w19, w13, w12 >> 128
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w19, w1

    /* Col 37 */
    bn.rshi w19, w13, w12 >> 160
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w19, w1
    bn.rshi w19, w14, w13 >> 160
    bn.gfmul.8.acch w29, w19, w1
    bn.rshi w19, w15, w14 >> 160
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w19, w1

    /* Col 38 */
    bn.rshi w19, w15, w14 >> 192
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w19, w1
    bn.rshi w19, w16, w15 >> 192
    bn.gfmul.8.acch w29, w19, w1
    bn.rshi w19, w17, w16 >> 192
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w19, w1

    /* Col 39 */
    bn.rshi w19, w17, w16 >> 224
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w19, w1
    bn.rshi w19, w18, w17 >> 224
    bn.gfmul.8.acch w29, w19, w1
    bn.rshi w19, w31, w18 >> 224
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w19, w1

    addi x11, x11, 544

    /* ============================================================
     * Phase 3: trailing 4 cols (40..43). Scalar source = w1.
     * mod1 = 8 at entry (continued from Phase 2).
     * Load 9 WDRs (288 B = 4 misaligned cols).
     * ============================================================ */

    li x17, 2
    bn.lid x17++, 0(x11)
    bn.lid x17++, 32(x11)
    bn.lid x17++, 64(x11)
    bn.lid x17++, 96(x11)
    bn.lid x17++, 128(x11)
    bn.lid x17++, 160(x11)
    bn.lid x17++, 192(x11)
    bn.lid x17++, 224(x11)
    bn.lid x17++, 256(x11)

    /* Col 40: shift=0 */
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w2, w1
    bn.gfmul.8.acch w29, w3, w1
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w4, w1

    /* Col 41 */
    bn.rshi w19, w5, w4 >> 32
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w19, w1
    bn.rshi w19, w6, w5 >> 32
    bn.gfmul.8.acch w29, w19, w1
    bn.rshi w19, w7, w6 >> 32
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w19, w1

    /* Col 42 */
    bn.rshi w19, w7, w6 >> 64
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w19, w1
    bn.rshi w19, w8, w7 >> 64
    bn.gfmul.8.acch w29, w19, w1
    bn.rshi w19, w9, w8 >> 64
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w19, w1

    /* Col 43: last — no inc needed (terminating column) */
    bn.rshi w19, w9, w8 >> 96
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w19, w1
    bn.rshi w19, w10, w9 >> 96
    bn.gfmul.8.acch w29, w19, w1
    bn.rshi w19, w31, w10 >> 96
    bn.wsrw acc, w30
    bn.gfmul.8.acc w30, w19, w1
    /* no .inc on last column */

    /* Reset mod1 before ret (per index-kernel convention) */
    csrrw x0, mod1, x0

    /* Mask w30: keep only bytes 0-3 */
    bn.not w0, w31
    bn.rshi w0, w31, w0 >> 224
    bn.and w30, w30, w0

    li x17, 28
    bn.sid x17++, 0(x10)
    bn.sid x17++, 32(x10)
    bn.sid x17++, 64(x10)

    ret

#elif defined(GF_INSTRUCTIONS)

/* =============== bngfonly (HW bn.gfmul.8, mod1=0 entry assumed) =============== */
gf256mat_prod_68_44:

    bn.xor w31, w31, w31
    li x31, 0x11b
    csrrw x0, mod0, x31
    /* mod1=0 assumed on entry per kernel exit convention */

    li x31, 0
    bn.lid x31, 0(x12)                  /* w0 = b[0..31]  */
    li x31, 1
    bn.lid x31, 32(x12)                 /* w1 = b[32..43] + pad */

    bn.mov w28, w31
    bn.mov w29, w31
    bn.mov w30, w31
    bn.wsrw acc, w31                    /* ACC = 0 (w28/w30 share ACC) */
    bn.wsrw acch, w31                   /* ACCH = 0 (w29 chain) */

    /* ============================================================
     * Phase 1: 4 batches x 8 cols = cols 0..31. Scalar source = w0.
     * mod1 increments 0 to 32 (wraps to 0 naturally at boundary).
     * Body size 80.
     * ============================================================ */
    loopi 4, 80
        /* Batch-load 17 WDRs */
        li x17, 2
        bn.lid x17++, 0(x11)
        bn.lid x17++, 32(x11)
        bn.lid x17++, 64(x11)
        bn.lid x17++, 96(x11)
        bn.lid x17++, 128(x11)
        bn.lid x17++, 160(x11)
        bn.lid x17++, 192(x11)
        bn.lid x17++, 224(x11)
        bn.lid x17++, 256(x11)
        bn.lid x17++, 288(x11)
        bn.lid x17++, 320(x11)
        bn.lid x17++, 352(x11)
        bn.lid x17++, 384(x11)
        bn.lid x17++, 416(x11)
        bn.lid x17++, 448(x11)
        bn.lid x17++, 480(x11)
        bn.lid x17++, 512(x11)
        /* 18 instr */

        /* Col 0: shift=0, w2/w3/w4 */
        bn.wsrw acc, w28
        bn.gfmul.8.acc w28, w2, w0
        bn.gfmul.8.acch w29, w3, w0
        bn.wsrw acc, w30
        bn.gfmul.8.acc.inc w30, w4, w0  /* INC: mod1+=1 */
        /* 5 instr */

        /* Col 1: shift=32, (w4,w5)(w5,w6)(w6,w7) */
        bn.rshi w19, w5, w4 >> 32
        bn.wsrw acc, w28
        bn.gfmul.8.acc w28, w19, w0
        bn.rshi w19, w6, w5 >> 32
        bn.gfmul.8.acch w29, w19, w0
        bn.rshi w19, w7, w6 >> 32
        bn.wsrw acc, w30
        bn.gfmul.8.acc.inc w30, w19, w0
        /* 8 instr */

        /* Col 2: shift=64 */
        bn.rshi w19, w7, w6 >> 64
        bn.wsrw acc, w28
        bn.gfmul.8.acc w28, w19, w0
        bn.rshi w19, w8, w7 >> 64
        bn.gfmul.8.acch w29, w19, w0
        bn.rshi w19, w9, w8 >> 64
        bn.wsrw acc, w30
        bn.gfmul.8.acc.inc w30, w19, w0
        /* 8 instr */

        /* Col 3: shift=96 */
        bn.rshi w19, w9, w8 >> 96
        bn.wsrw acc, w28
        bn.gfmul.8.acc w28, w19, w0
        bn.rshi w19, w10, w9 >> 96
        bn.gfmul.8.acch w29, w19, w0
        bn.rshi w19, w11, w10 >> 96
        bn.wsrw acc, w30
        bn.gfmul.8.acc.inc w30, w19, w0
        /* 8 instr */

        /* Col 4: shift=128 */
        bn.rshi w19, w11, w10 >> 128
        bn.wsrw acc, w28
        bn.gfmul.8.acc w28, w19, w0
        bn.rshi w19, w12, w11 >> 128
        bn.gfmul.8.acch w29, w19, w0
        bn.rshi w19, w13, w12 >> 128
        bn.wsrw acc, w30
        bn.gfmul.8.acc.inc w30, w19, w0
        /* 8 instr */

        /* Col 5: shift=160 */
        bn.rshi w19, w13, w12 >> 160
        bn.wsrw acc, w28
        bn.gfmul.8.acc w28, w19, w0
        bn.rshi w19, w14, w13 >> 160
        bn.gfmul.8.acch w29, w19, w0
        bn.rshi w19, w15, w14 >> 160
        bn.wsrw acc, w30
        bn.gfmul.8.acc.inc w30, w19, w0
        /* 8 instr */

        /* Col 6: shift=192 */
        bn.rshi w19, w15, w14 >> 192
        bn.wsrw acc, w28
        bn.gfmul.8.acc w28, w19, w0
        bn.rshi w19, w16, w15 >> 192
        bn.gfmul.8.acch w29, w19, w0
        bn.rshi w19, w17, w16 >> 192
        bn.wsrw acc, w30
        bn.gfmul.8.acc.inc w30, w19, w0
        /* 8 instr */

        /* Col 7: shift=224, (w18,w31) terminates */
        bn.rshi w19, w17, w16 >> 224
        bn.wsrw acc, w28
        bn.gfmul.8.acc w28, w19, w0
        bn.rshi w19, w18, w17 >> 224
        bn.gfmul.8.acch w29, w19, w0
        bn.rshi w19, w31, w18 >> 224
        bn.wsrw acc, w30
        bn.gfmul.8.acc.inc w30, w19, w0
        /* 8 instr */

        addi x11, x11, 544
        /* 1 instr */
    /* loopi body = 18 + 5 + 6x8 + 8 + 1 = 80 */

    /* ============================================================
     * Phase 2: 5th batch (cols 32..39). Scalar source = w1.
     * mod1 wrapped from 32 to 0 naturally already at 0 for w1[0].
     * ============================================================ */

    /* Batch-load 17 WDRs */
    li x17, 2
    bn.lid x17++, 0(x11)
    bn.lid x17++, 32(x11)
    bn.lid x17++, 64(x11)
    bn.lid x17++, 96(x11)
    bn.lid x17++, 128(x11)
    bn.lid x17++, 160(x11)
    bn.lid x17++, 192(x11)
    bn.lid x17++, 224(x11)
    bn.lid x17++, 256(x11)
    bn.lid x17++, 288(x11)
    bn.lid x17++, 320(x11)
    bn.lid x17++, 352(x11)
    bn.lid x17++, 384(x11)
    bn.lid x17++, 416(x11)
    bn.lid x17++, 448(x11)
    bn.lid x17++, 480(x11)
    bn.lid x17++, 512(x11)

    /* Col 32: shift=0, scalar = w1 */
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w2, w1
    bn.gfmul.8.acch w29, w3, w1
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w4, w1

    /* Col 33 */
    bn.rshi w19, w5, w4 >> 32
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w19, w1
    bn.rshi w19, w6, w5 >> 32
    bn.gfmul.8.acch w29, w19, w1
    bn.rshi w19, w7, w6 >> 32
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w19, w1

    /* Col 34 */
    bn.rshi w19, w7, w6 >> 64
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w19, w1
    bn.rshi w19, w8, w7 >> 64
    bn.gfmul.8.acch w29, w19, w1
    bn.rshi w19, w9, w8 >> 64
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w19, w1

    /* Col 35 */
    bn.rshi w19, w9, w8 >> 96
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w19, w1
    bn.rshi w19, w10, w9 >> 96
    bn.gfmul.8.acch w29, w19, w1
    bn.rshi w19, w11, w10 >> 96
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w19, w1

    /* Col 36 */
    bn.rshi w19, w11, w10 >> 128
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w19, w1
    bn.rshi w19, w12, w11 >> 128
    bn.gfmul.8.acch w29, w19, w1
    bn.rshi w19, w13, w12 >> 128
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w19, w1

    /* Col 37 */
    bn.rshi w19, w13, w12 >> 160
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w19, w1
    bn.rshi w19, w14, w13 >> 160
    bn.gfmul.8.acch w29, w19, w1
    bn.rshi w19, w15, w14 >> 160
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w19, w1

    /* Col 38 */
    bn.rshi w19, w15, w14 >> 192
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w19, w1
    bn.rshi w19, w16, w15 >> 192
    bn.gfmul.8.acch w29, w19, w1
    bn.rshi w19, w17, w16 >> 192
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w19, w1

    /* Col 39 */
    bn.rshi w19, w17, w16 >> 224
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w19, w1
    bn.rshi w19, w18, w17 >> 224
    bn.gfmul.8.acch w29, w19, w1
    bn.rshi w19, w31, w18 >> 224
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w19, w1

    addi x11, x11, 544

    /* ============================================================
     * Phase 3: trailing 4 cols (40..43). Scalar source = w1.
     * mod1 = 8 at entry (continued from Phase 2).
     * Load 9 WDRs (288 B = 4 misaligned cols).
     * ============================================================ */

    li x17, 2
    bn.lid x17++, 0(x11)
    bn.lid x17++, 32(x11)
    bn.lid x17++, 64(x11)
    bn.lid x17++, 96(x11)
    bn.lid x17++, 128(x11)
    bn.lid x17++, 160(x11)
    bn.lid x17++, 192(x11)
    bn.lid x17++, 224(x11)
    bn.lid x17++, 256(x11)

    /* Col 40: shift=0 */
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w2, w1
    bn.gfmul.8.acch w29, w3, w1
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w4, w1

    /* Col 41 */
    bn.rshi w19, w5, w4 >> 32
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w19, w1
    bn.rshi w19, w6, w5 >> 32
    bn.gfmul.8.acch w29, w19, w1
    bn.rshi w19, w7, w6 >> 32
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w19, w1

    /* Col 42 */
    bn.rshi w19, w7, w6 >> 64
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w19, w1
    bn.rshi w19, w8, w7 >> 64
    bn.gfmul.8.acch w29, w19, w1
    bn.rshi w19, w9, w8 >> 64
    bn.wsrw acc, w30
    bn.gfmul.8.acc.inc w30, w19, w1

    /* Col 43: last no inc needed (terminating column) */
    bn.rshi w19, w9, w8 >> 96
    bn.wsrw acc, w28
    bn.gfmul.8.acc w28, w19, w1
    bn.rshi w19, w10, w9 >> 96
    bn.gfmul.8.acch w29, w19, w1
    bn.rshi w19, w31, w10 >> 96
    bn.wsrw acc, w30
    bn.gfmul.8.acc w30, w19, w1
    /* no .inc on last column */

    /* Reset mod1 before ret (per index-kernel convention) */
    csrrw x0, mod1, x0

    /* Mask w30: keep only bytes 0-3 */
    bn.not w0, w31
    bn.rshi w0, w31, w0 >> 224
    bn.and w30, w30, w0

    li x17, 28
    bn.sid x17++, 0(x10)
    bn.sid x17++, 32(x10)
    bn.sid x17++, 64(x10)

    ret

#else

/* sw tier: pure SW GF256 multiply; copied from gf256mat_prod_68_44.s sw arm, ACCH-independent. */

/* =============== sw (SW gf256 multiply) =============== */
gf256mat_prod_68_44:

    bn.xor w31, w31, w31

    /* Load helper constants. */
    la x4, msb_mask
    li x5, 22
    bn.lid x5, 0(x4)              /* w22 = msb_mask */
    bn.addi w23, w31, 0x1b        /* w23 = 0x1b broadcast */

    /* Load b vector into sliding window. */
    li x31, 26
    bn.lid x31, 0(x12)            /* w26 = b[0..31] */
    li x31, 27
    bn.lid x31, 32(x12)           /* w27 = b[32..43] || pad */

    bn.mov w28, w31
    bn.mov w29, w31
    bn.mov w30, w31

    /* ============================================================
     * Phase 1: 4 batches × 8 cols = cols 0..31.
     * Each col-group: 3 helper calls (chunks for w28/w29/w30) + 1 slide.
     * Body size 144.
     * ============================================================ */
    loopi 4, 155
        /* Batch-load 17 WDRs (w2..w18) */
        li x17, 2
        bn.lid x17++, 0(x11)
        bn.lid x17++, 32(x11)
        bn.lid x17++, 64(x11)
        bn.lid x17++, 96(x11)
        bn.lid x17++, 128(x11)
        bn.lid x17++, 160(x11)
        bn.lid x17++, 192(x11)
        bn.lid x17++, 224(x11)
        bn.lid x17++, 256(x11)
        bn.lid x17++, 288(x11)
        bn.lid x17++, 320(x11)
        bn.lid x17++, 352(x11)
        bn.lid x17++, 384(x11)
        bn.lid x17++, 416(x11)
        bn.lid x17++, 448(x11)
        bn.lid x17++, 480(x11)
        bn.lid x17++, 512(x11)
        /* 18 instr */

        /* === Col 0: shift=0, chunks w2/w3/w4. === */
        bn.mov w0, w2
        bn.mov w19, w26
        bn.mov w20, w28
        jal x1, gf256_macc_sw_batched
        bn.mov w28, w20
        bn.mov w0, w3
        bn.mov w19, w26
        bn.mov w20, w29
        jal x1, gf256_macc_sw_batched
        bn.mov w29, w20
        bn.mov w0, w4
        bn.mov w19, w26
        bn.mov w20, w30
        jal x1, gf256_macc_sw_batched
        bn.mov w30, w20
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w31, w27 >> 8
        /* 17 instr */

        /* === Col 1: shift=32, (w4,w5)/(w5,w6)/(w6,w7) === */
        bn.rshi w0, w5, w4 >> 32
        bn.mov w19, w26
        bn.mov w20, w28
        jal x1, gf256_macc_sw_batched
        bn.mov w28, w20
        bn.rshi w0, w6, w5 >> 32
        bn.mov w19, w26
        bn.mov w20, w29
        jal x1, gf256_macc_sw_batched
        bn.mov w29, w20
        bn.rshi w0, w7, w6 >> 32
        bn.mov w19, w26
        bn.mov w20, w30
        jal x1, gf256_macc_sw_batched
        bn.mov w30, w20
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w31, w27 >> 8
        /* 17 instr */

        /* === Col 2: shift=64 === */
        bn.rshi w0, w7, w6 >> 64
        bn.mov w19, w26
        bn.mov w20, w28
        jal x1, gf256_macc_sw_batched
        bn.mov w28, w20
        bn.rshi w0, w8, w7 >> 64
        bn.mov w19, w26
        bn.mov w20, w29
        jal x1, gf256_macc_sw_batched
        bn.mov w29, w20
        bn.rshi w0, w9, w8 >> 64
        bn.mov w19, w26
        bn.mov w20, w30
        jal x1, gf256_macc_sw_batched
        bn.mov w30, w20
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w31, w27 >> 8

        /* === Col 3: shift=96 === */
        bn.rshi w0, w9, w8 >> 96
        bn.mov w19, w26
        bn.mov w20, w28
        jal x1, gf256_macc_sw_batched
        bn.mov w28, w20
        bn.rshi w0, w10, w9 >> 96
        bn.mov w19, w26
        bn.mov w20, w29
        jal x1, gf256_macc_sw_batched
        bn.mov w29, w20
        bn.rshi w0, w11, w10 >> 96
        bn.mov w19, w26
        bn.mov w20, w30
        jal x1, gf256_macc_sw_batched
        bn.mov w30, w20
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w31, w27 >> 8

        /* === Col 4: shift=128 === */
        bn.rshi w0, w11, w10 >> 128
        bn.mov w19, w26
        bn.mov w20, w28
        jal x1, gf256_macc_sw_batched
        bn.mov w28, w20
        bn.rshi w0, w12, w11 >> 128
        bn.mov w19, w26
        bn.mov w20, w29
        jal x1, gf256_macc_sw_batched
        bn.mov w29, w20
        bn.rshi w0, w13, w12 >> 128
        bn.mov w19, w26
        bn.mov w20, w30
        jal x1, gf256_macc_sw_batched
        bn.mov w30, w20
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w31, w27 >> 8

        /* === Col 5: shift=160 === */
        bn.rshi w0, w13, w12 >> 160
        bn.mov w19, w26
        bn.mov w20, w28
        jal x1, gf256_macc_sw_batched
        bn.mov w28, w20
        bn.rshi w0, w14, w13 >> 160
        bn.mov w19, w26
        bn.mov w20, w29
        jal x1, gf256_macc_sw_batched
        bn.mov w29, w20
        bn.rshi w0, w15, w14 >> 160
        bn.mov w19, w26
        bn.mov w20, w30
        jal x1, gf256_macc_sw_batched
        bn.mov w30, w20
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w31, w27 >> 8

        /* === Col 6: shift=192 === */
        bn.rshi w0, w15, w14 >> 192
        bn.mov w19, w26
        bn.mov w20, w28
        jal x1, gf256_macc_sw_batched
        bn.mov w28, w20
        bn.rshi w0, w16, w15 >> 192
        bn.mov w19, w26
        bn.mov w20, w29
        jal x1, gf256_macc_sw_batched
        bn.mov w29, w20
        bn.rshi w0, w17, w16 >> 192
        bn.mov w19, w26
        bn.mov w20, w30
        jal x1, gf256_macc_sw_batched
        bn.mov w30, w20
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w31, w27 >> 8

        /* === Col 7: shift=224, terminates with w18 === */
        bn.rshi w0, w17, w16 >> 224
        bn.mov w19, w26
        bn.mov w20, w28
        jal x1, gf256_macc_sw_batched
        bn.mov w28, w20
        bn.rshi w0, w18, w17 >> 224
        bn.mov w19, w26
        bn.mov w20, w29
        jal x1, gf256_macc_sw_batched
        bn.mov w29, w20
        bn.rshi w0, w31, w18 >> 224
        bn.mov w19, w26
        bn.mov w20, w30
        jal x1, gf256_macc_sw_batched
        bn.mov w30, w20
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w31, w27 >> 8

        addi x11, x11, 544
        /* 1 instr */
    /* loopi body = 155 (18 batch-load + 8x17 col-group + 1 addi) */

    /* ============================================================
     * Phase 2: 5th batch (cols 32..39).
     * ============================================================ */

    li x17, 2
    bn.lid x17++, 0(x11)
    bn.lid x17++, 32(x11)
    bn.lid x17++, 64(x11)
    bn.lid x17++, 96(x11)
    bn.lid x17++, 128(x11)
    bn.lid x17++, 160(x11)
    bn.lid x17++, 192(x11)
    bn.lid x17++, 224(x11)
    bn.lid x17++, 256(x11)
    bn.lid x17++, 288(x11)
    bn.lid x17++, 320(x11)
    bn.lid x17++, 352(x11)
    bn.lid x17++, 384(x11)
    bn.lid x17++, 416(x11)
    bn.lid x17++, 448(x11)
    bn.lid x17++, 480(x11)
    bn.lid x17++, 512(x11)

    /* Col 32: shift=0 */
    bn.mov w0, w2
    bn.mov w19, w26
    bn.mov w20, w28
    jal x1, gf256_macc_sw_batched
    bn.mov w28, w20
    bn.mov w0, w3
    bn.mov w19, w26
    bn.mov w20, w29
    jal x1, gf256_macc_sw_batched
    bn.mov w29, w20
    bn.mov w0, w4
    bn.mov w19, w26
    bn.mov w20, w30
    jal x1, gf256_macc_sw_batched
    bn.mov w30, w20
    bn.rshi w26, w27, w26 >> 8
    bn.rshi w27, w31, w27 >> 8

    /* Col 33: shift=32 */
    bn.rshi w0, w5, w4 >> 32
    bn.mov w19, w26
    bn.mov w20, w28
    jal x1, gf256_macc_sw_batched
    bn.mov w28, w20
    bn.rshi w0, w6, w5 >> 32
    bn.mov w19, w26
    bn.mov w20, w29
    jal x1, gf256_macc_sw_batched
    bn.mov w29, w20
    bn.rshi w0, w7, w6 >> 32
    bn.mov w19, w26
    bn.mov w20, w30
    jal x1, gf256_macc_sw_batched
    bn.mov w30, w20
    bn.rshi w26, w27, w26 >> 8
    bn.rshi w27, w31, w27 >> 8

    /* Col 34: shift=64 */
    bn.rshi w0, w7, w6 >> 64
    bn.mov w19, w26
    bn.mov w20, w28
    jal x1, gf256_macc_sw_batched
    bn.mov w28, w20
    bn.rshi w0, w8, w7 >> 64
    bn.mov w19, w26
    bn.mov w20, w29
    jal x1, gf256_macc_sw_batched
    bn.mov w29, w20
    bn.rshi w0, w9, w8 >> 64
    bn.mov w19, w26
    bn.mov w20, w30
    jal x1, gf256_macc_sw_batched
    bn.mov w30, w20
    bn.rshi w26, w27, w26 >> 8
    bn.rshi w27, w31, w27 >> 8

    /* Col 35: shift=96 */
    bn.rshi w0, w9, w8 >> 96
    bn.mov w19, w26
    bn.mov w20, w28
    jal x1, gf256_macc_sw_batched
    bn.mov w28, w20
    bn.rshi w0, w10, w9 >> 96
    bn.mov w19, w26
    bn.mov w20, w29
    jal x1, gf256_macc_sw_batched
    bn.mov w29, w20
    bn.rshi w0, w11, w10 >> 96
    bn.mov w19, w26
    bn.mov w20, w30
    jal x1, gf256_macc_sw_batched
    bn.mov w30, w20
    bn.rshi w26, w27, w26 >> 8
    bn.rshi w27, w31, w27 >> 8

    /* Col 36: shift=128 */
    bn.rshi w0, w11, w10 >> 128
    bn.mov w19, w26
    bn.mov w20, w28
    jal x1, gf256_macc_sw_batched
    bn.mov w28, w20
    bn.rshi w0, w12, w11 >> 128
    bn.mov w19, w26
    bn.mov w20, w29
    jal x1, gf256_macc_sw_batched
    bn.mov w29, w20
    bn.rshi w0, w13, w12 >> 128
    bn.mov w19, w26
    bn.mov w20, w30
    jal x1, gf256_macc_sw_batched
    bn.mov w30, w20
    bn.rshi w26, w27, w26 >> 8
    bn.rshi w27, w31, w27 >> 8

    /* Col 37: shift=160 */
    bn.rshi w0, w13, w12 >> 160
    bn.mov w19, w26
    bn.mov w20, w28
    jal x1, gf256_macc_sw_batched
    bn.mov w28, w20
    bn.rshi w0, w14, w13 >> 160
    bn.mov w19, w26
    bn.mov w20, w29
    jal x1, gf256_macc_sw_batched
    bn.mov w29, w20
    bn.rshi w0, w15, w14 >> 160
    bn.mov w19, w26
    bn.mov w20, w30
    jal x1, gf256_macc_sw_batched
    bn.mov w30, w20
    bn.rshi w26, w27, w26 >> 8
    bn.rshi w27, w31, w27 >> 8

    /* Col 38: shift=192 */
    bn.rshi w0, w15, w14 >> 192
    bn.mov w19, w26
    bn.mov w20, w28
    jal x1, gf256_macc_sw_batched
    bn.mov w28, w20
    bn.rshi w0, w16, w15 >> 192
    bn.mov w19, w26
    bn.mov w20, w29
    jal x1, gf256_macc_sw_batched
    bn.mov w29, w20
    bn.rshi w0, w17, w16 >> 192
    bn.mov w19, w26
    bn.mov w20, w30
    jal x1, gf256_macc_sw_batched
    bn.mov w30, w20
    bn.rshi w26, w27, w26 >> 8
    bn.rshi w27, w31, w27 >> 8

    /* Col 39: shift=224 */
    bn.rshi w0, w17, w16 >> 224
    bn.mov w19, w26
    bn.mov w20, w28
    jal x1, gf256_macc_sw_batched
    bn.mov w28, w20
    bn.rshi w0, w18, w17 >> 224
    bn.mov w19, w26
    bn.mov w20, w29
    jal x1, gf256_macc_sw_batched
    bn.mov w29, w20
    bn.rshi w0, w31, w18 >> 224
    bn.mov w19, w26
    bn.mov w20, w30
    jal x1, gf256_macc_sw_batched
    bn.mov w30, w20
    bn.rshi w26, w27, w26 >> 8
    bn.rshi w27, w31, w27 >> 8

    addi x11, x11, 544

    /* ============================================================
     * Phase 3: trailing 4 cols (40..43). Load 9 WDRs (288 B = 4 misaligned cols).
     * ============================================================ */

    li x17, 2
    bn.lid x17++, 0(x11)
    bn.lid x17++, 32(x11)
    bn.lid x17++, 64(x11)
    bn.lid x17++, 96(x11)
    bn.lid x17++, 128(x11)
    bn.lid x17++, 160(x11)
    bn.lid x17++, 192(x11)
    bn.lid x17++, 224(x11)
    bn.lid x17++, 256(x11)

    /* Col 40: shift=0 */
    bn.mov w0, w2
    bn.mov w19, w26
    bn.mov w20, w28
    jal x1, gf256_macc_sw_batched
    bn.mov w28, w20
    bn.mov w0, w3
    bn.mov w19, w26
    bn.mov w20, w29
    jal x1, gf256_macc_sw_batched
    bn.mov w29, w20
    bn.mov w0, w4
    bn.mov w19, w26
    bn.mov w20, w30
    jal x1, gf256_macc_sw_batched
    bn.mov w30, w20
    bn.rshi w26, w27, w26 >> 8
    bn.rshi w27, w31, w27 >> 8

    /* Col 41: shift=32 */
    bn.rshi w0, w5, w4 >> 32
    bn.mov w19, w26
    bn.mov w20, w28
    jal x1, gf256_macc_sw_batched
    bn.mov w28, w20
    bn.rshi w0, w6, w5 >> 32
    bn.mov w19, w26
    bn.mov w20, w29
    jal x1, gf256_macc_sw_batched
    bn.mov w29, w20
    bn.rshi w0, w7, w6 >> 32
    bn.mov w19, w26
    bn.mov w20, w30
    jal x1, gf256_macc_sw_batched
    bn.mov w30, w20
    bn.rshi w26, w27, w26 >> 8
    bn.rshi w27, w31, w27 >> 8

    /* Col 42: shift=64 */
    bn.rshi w0, w7, w6 >> 64
    bn.mov w19, w26
    bn.mov w20, w28
    jal x1, gf256_macc_sw_batched
    bn.mov w28, w20
    bn.rshi w0, w8, w7 >> 64
    bn.mov w19, w26
    bn.mov w20, w29
    jal x1, gf256_macc_sw_batched
    bn.mov w29, w20
    bn.rshi w0, w9, w8 >> 64
    bn.mov w19, w26
    bn.mov w20, w30
    jal x1, gf256_macc_sw_batched
    bn.mov w30, w20
    bn.rshi w26, w27, w26 >> 8
    bn.rshi w27, w31, w27 >> 8

    /* Col 43: shift=96. Last col — no further slide needed. */
    bn.rshi w0, w9, w8 >> 96
    bn.mov w19, w26
    bn.mov w20, w28
    jal x1, gf256_macc_sw_batched
    bn.mov w28, w20
    bn.rshi w0, w10, w9 >> 96
    bn.mov w19, w26
    bn.mov w20, w29
    jal x1, gf256_macc_sw_batched
    bn.mov w29, w20
    bn.rshi w0, w31, w10 >> 96
    bn.mov w19, w26
    bn.mov w20, w30
    jal x1, gf256_macc_sw_batched
    bn.mov w30, w20

    /* Mask w30: keep only bytes 0-3 (y[64..67]). */
    bn.not w0, w31
    bn.rshi w0, w31, w0 >> 224
    bn.and w30, w30, w0

    li x17, 28
    bn.sid x17++, 0(x10)
    bn.sid x17++, 32(x10)
    bn.sid x17++, 64(x10)

    ret

#endif
