/* gf16_matvec_2048_96 — Is GF16 matrix-vector accumulator.
 *
 *   variant     cpp flag                                  body
 *   sw      (none)                                    SW gf16_macc_sw per iter
 *   bngfonly    -DGF_INSTRUCTIONS                         HW bn.gfmul.4 with peeled .acc.z.inc
 *   bngfaes     -DAES_INSTRUCTIONS|GF_INSTRUCTIONS        HW bn.gfmul.4 with wsrw-acc clear per col
 *
 * I/O:
 *   x10 = accumulator output (2048 B, post-inc inside)
 *   x11 = matrixA base
 *   x12 = n_A_byte (unused here, callers preserve)
 *   x13 = n_A_width (unused here)
 *   x14 = vectorB (unused; halves preloaded in w28/w29 by caller)
 *   w28 = vec_B low 64 nibbles
 *   w29 = vec_B high 32 nibbles
 */

.section .text
.balign 4
.global gf16_matvec_2048_96

#if defined(AES_INSTRUCTIONS) && defined(GF_INSTRUCTIONS)

/* --------------------------- bngfaes (HW bn.gfmul.4) --------------------------- */
gf16_matvec_2048_96:

    bn.xor w31, w31, w31
    /*Setup Reduction Poly*/
    li x31, 0x13
    csrrw x0, mod0, x31
    /*Make Sure Accumulator address is all zero*/
    li x31, 31
    loopi 32, 2
        bn.sid x31, 0(x10++)
        bn.sid x31, 0(x10++)
    addi x10, x10, -2048
    /*VecB Already in w28, w29 */
    /*x30:for accessing w4*/
    li x30, 4
    li x29, 2048
    li x31, 27

    loopi 64, 16
        add x5, x0, x11 /*x5:temp MatrixA address*/
        bn.wsrw acc, w31    /*Clear Accumulator first*/
        bn.mov w2, w28  #w3(higher part),w2(lower part)temporary vectorB
        bn.mov w3, w29
        csrrw x0, mod1, x0
        loopi 64, 3
            bn.lid x30, 0(x5)
            add x5, x5, x29
            bn.gfmul.4.acc.inc w27, w4, w2
        csrrw x0, mod1, x0
        loopi 32, 3
            bn.lid x30, 0(x5)
            add x5, x5, x29
            bn.gfmul.4.acc.inc w27, w4, w3
        bn.sid x31, 0(x10++)
        addi x11, x11, 32
    addi x10, x10, -2048

    csrrw x0, mod1, x0   # reset mod1 = 0 so downstream bn.gfmul.4 callers see clean state
    ret

#elif defined(GF_INSTRUCTIONS)

/* --------------------- bngfonly (HW bn.gfmul.4, peeled acc.z) --------------------- */
gf16_matvec_2048_96:

    bn.xor w31, w31, w31
    /*Setup Reduction Poly*/
    li x31, 0x13
    csrrw x0, mod0, x31
    /*Make Sure Accumulator address is all zero*/
    li x31, 31
    loopi 32, 2
        bn.sid x31, 0(x10++)
        bn.sid x31, 0(x10++)
    addi x10, x10, -2048
    /*VecB Already in w28, w29 */
    /*x30:for accessing w4*/
    li x30, 4
    li x29, 2048
    li x31, 27

    loopi 64, 17
        add x5, x0, x11 /*x5:temp MatrixA address*/
        bn.mov w2, w28  #w3(higher part),w2(lower part)temporary vectorB
        bn.mov w3, w29
        csrrw x0, mod1, x0
        # Peel seg1 first iter fold bn.wsrw acc, w31 into .acc.z.inc
        bn.lid x30, 0(x5)
        add x5, x5, x29
        bn.gfmul.4.acc.z.inc w27, w4, w2
        loopi 63, 3
            bn.lid x30, 0(x5)
            add x5, x5, x29
            bn.gfmul.4.acc.inc w27, w4, w2
        # mod1 wrapped to 0 after seg1's 64 .inc (.4 wraps at 64)
        loopi 32, 3
            bn.lid x30, 0(x5)
            add x5, x5, x29
            bn.gfmul.4.acc.inc w27, w4, w3
        bn.sid x31, 0(x10++)
        addi x11, x11, 32
    addi x10, x10, -2048

    csrrw x0, mod1, x0   # reset mod1 = 0 so downstream bn.gfmul.4 callers see clean state
    ret

#else

/* ----------------------- sw (SW gf16_macc_sw) ----------------------- */
/* SW helper consumes 1 nib of w19/call. Loop body cannot end on jal (HW constraint).
 * Clobbers: w0, w16..w20, w27..w29, w31; helper preserves w15.
 */
gf16_matvec_2048_96:
    bn.xor w31, w31, w31

    /* Build msb_mask in w16. */
    bn.addi w16, w31, 0x88
    bn.rshi w17, w16, w31 >> 248
    bn.or   w16, w16, w17
    bn.rshi w17, w16, w31 >> 240
    bn.or   w16, w16, w17
    bn.rshi w17, w16, w31 >> 224
    bn.or   w16, w16, w17
    bn.rshi w17, w16, w31 >> 192
    bn.or   w16, w16, w17
    bn.rshi w17, w16, w31 >> 128
    bn.or   w16, w16, w17

    /* Zero output buffer (2048 bytes = 32 × 32B). */
    li x31, 31
    loopi 32, 2
        bn.sid x31, 0(x10++)
        bn.sid x31, 0(x10++)
    addi x10, x10, -2048

    li x29, 2048
    li x6, 0                            /* WDR idx 0 for bn.lid (load row -> w0) */
    li x7, 20                           /* WDR idx 20 (bn.sid w20 out) */

    loopi 64, 16
        add x5, x0, x11                 /* x5 = matrix col cursor */
        bn.mov w20, w31                 /* acc = 0 */
        bn.mov w19, w28                 /* scalar source = vec_B low 64 nibbles */
        loopi 64, 4
            bn.lid x6, 0(x5)            /* w0 = matrix[col][k] (row k of col) */
            add x5, x5, x29
            jal x1, gf16_macc_sw  /* w20 ^= w0 * w19[nib0]; w19 shifts */
            nop                          /* loop-body end-PC: must not be jal */
        bn.mov w19, w29                 /* scalar source = vec_B high 32 nibbles */
        loopi 32, 4
            bn.lid x6, 0(x5)
            add x5, x5, x29
            jal x1, gf16_macc_sw
            nop
        bn.sid x7, 0(x10++)             /* store w20 to acc[col] */
        addi x11, x11, 32               /* next column base */
    addi x10, x10, -2048

    ret

#endif
