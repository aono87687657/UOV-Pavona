/* gf256_matvec_2816_68 (Ip) - L = S^T . v; 2816x68 matrix.
 *
 *   variant     cpp flag             body
 *   sw      (none)               SW gf256_macc_sw_batched + sliding scalar window
 *   bngfonly    -DGF_INSTRUCTIONS    HW bn.gfmul.8 with peeled .acc.z.inc (seg1)
 *   bngfaes     -DAES_|GF_           HW bn.gfmul.8 with explicit bn.wsrw acc + csrrw mod1 between segs
 *
 * I/O: x10=accumulator (4096 B, 2816 valid), x11=matrix S (col-major), w28/w29/w30=vinegar.
 *
 * clob (bngfaes) : x5, x6, x30, x31; w3-w6, w27, w31; ACC; FG0; sets mod0=0x11b,
 *                  mod1=0 on exit. x10 net-preserved (advance+rewind); x11 +2,816.
 * clob (bngfonly): same, but NO mod1 entry reset (mod1=0 assumed on entry; exit reset only).
 * clob (sw)      : x4-x7, x11(+2,816); w0, w3-w6, w19-w23, w31; FG0; no CSR/WSR.
 *                  w21 clobbered via gf256_macc_sw_batched. x10 net-preserved.
 * stack: none (all arms leaf-frame; sw's jal nests via the x1 call stack).
 */

.section .text
.balign 4
.global gf256_matvec_2816_68

#if defined(AES_INSTRUCTIONS) && defined(GF_INSTRUCTIONS)

/* =============== bngfaes (HW bn.gfmul.8 explicit wsrw + csrrw mod1) =============== */
gf256_matvec_2816_68:

    bn.xor w31, w31, w31

    /* Set GF(256) reduction polynomial: x^8 + x^4 + x^3 + x + 1 */
    li x31, 0x11b
    csrrw x0, mod0, x31

    /* Zero the accumulator: 128 × 32 = 4096 bytes */
    li x31, 31
    loopi 128, 1
        bn.sid x31, 0(x10++)
    li x31, 4096
    sub x10, x10, x31

    /* VecB already in w28, w29, w30 from expandv */

    /* Setup constants */
    li x6, 2816               /* column stride (n_A_byte) */
    li x30, 6                 /* WDR index for loads → w6 */
    li x31, 27                /* WDR index for stores → w27 */

    /* Main loop: 88 output rows × 32 bytes = 2816 bytes */
    loopi 88, 22
        /* x5 = base address for current row across all columns */
        add x5, x0, x11
        /* Clear ACC register */
        bn.wsrw acc, w31
        /* Copy vinegar vector into scratch WDRs for mod1-indexed reads */
        bn.mov w3, w28
        bn.mov w4, w29
        bn.mov w5, w30

        /* Segment 1: vinegar bytes 0..31 from w3 (mod1 = 0..31) */
        csrrw x0, mod1, x0
        loopi 32, 3
            bn.lid x30, 0(x5)             /* w6 = 32 bytes of current column at current row */
            add x5, x5, x6                /* advance to same row in next column (+2816) */
            bn.gfmul.8.acc.inc w27, w6, w3 /* ACC += w6 × w3[mod1++] */

        /* Segment 2: vinegar bytes 32..63 from w4 (mod1 wrapped to 0, restart 0..31) */
        csrrw x0, mod1, x0
        loopi 32, 3
            bn.lid x30, 0(x5)
            add x5, x5, x6
            bn.gfmul.8.acc.inc w27, w6, w4

        /* Segment 3: vinegar bytes 64..67 from w5 (only 4 bytes used) */
        csrrw x0, mod1, x0
        loopi 4, 3
            bn.lid x30, 0(x5)
            add x5, x5, x6
            bn.gfmul.8.acc.inc w27, w6, w5

        bn.sid x31, 0(x10++)              /* store 32 bytes of accumulated result */
        addi x11, x11, 32                 /* advance to next 32-byte row */

    sub x10, x10, x6                      /* reset x10 to start of accumulator */

    csrrw x0, mod1, x0                    /* reset mod1 = 0 so downstream callers see clean state */
    ret

#elif defined(GF_INSTRUCTIONS)

/* =============== bngfonly (HW bn.gfmul.8 peeled acc.z.inc) =============== */
gf256_matvec_2816_68:

    bn.xor w31, w31, w31

    /* Set GF(256) reduction polynomial: x^8 + x^4 + x^3 + x + 1 */
    li x31, 0x11b
    csrrw x0, mod0, x31

    /* Zero the accumulator: 128 x 32 = 4096 bytes */
    li x31, 31
    loopi 128, 1
        bn.sid x31, 0(x10++)
    li x31, 4096
    sub x10, x10, x31

    /* VecB already in w28, w29, w30 from expandv */

    /* Setup constants */
    li x6, 2816               /* column stride (n_A_byte) */
    li x30, 6                 /* WDR index for loads to w6 */
    li x31, 27                /* WDR index for stores to w27 */

    /* Main loop: 88 output rows x 32 bytes = 2816 bytes */
    loopi 88, 22
        /* x5 = base address for current row across all columns */
        add x5, x0, x11
        /* Copy vinegar vector into scratch WDRs for mod1-indexed reads */
        bn.mov w3, w28
        bn.mov w4, w29
        bn.mov w5, w30

        /* Segment 1: vinegar bytes 0..31 from w3 (mod1 = 0..31) */
        csrrw x0, mod1, x0
        /* Peel seg1 first iter fold bn.wsrw acc, w31 into .acc.z.inc */
        bn.lid x30, 0(x5)
        add x5, x5, x6
        bn.gfmul.8.acc.z.inc w27, w6, w3
        loopi 31, 3
            bn.lid x30, 0(x5)             /* w6 = 32 bytes of current column at current row */
            add x5, x5, x6                /* advance to same row in next column (+2816) */
            bn.gfmul.8.acc.inc w27, w6, w3 /* ACC += w6 x w3[mod1++] */

        /* Segment 2: vinegar bytes 32..63 from w4 (mod1 wrapped to 0 from seg1) */
        loopi 32, 3
            bn.lid x30, 0(x5)
            add x5, x5, x6
            bn.gfmul.8.acc.inc w27, w6, w4

        /* Segment 3: vinegar bytes 64..67 from w5 (only 4 bytes used; mod1 wrapped to 0 from seg2) */
        loopi 4, 3
            bn.lid x30, 0(x5)
            add x5, x5, x6
            bn.gfmul.8.acc.inc w27, w6, w5

        bn.sid x31, 0(x10++)              /* store 32 bytes of accumulated result */
        addi x11, x11, 32                 /* advance to next 32-byte row */

    sub x10, x10, x6                      /* reset x10 to start of accumulator */

    csrrw x0, mod1, x0                    /* reset mod1 = 0 so downstream callers see clean state */
    ret

#else

/* =============== sw (SW gf256_macc_sw_batched) =============== */
gf256_matvec_2816_68:

    bn.xor w31, w31, w31

    /* Helper constants. */
    la x4, msb_mask
    li x5, 22
    bn.lid x5, 0(x4)              /* w22 = msb_mask */
    bn.addi w23, w31, 0x1b        /* w23 = 0x1b */

    /* Zero the accumulator: 128 × 32 = 4096 bytes */
    li x4, 31
    loopi 128, 1
        bn.sid x4, 0(x10++)
    li x4, 4096
    sub x10, x10, x4

    /* Setup constants. */
    li x6, 2816                   /* column stride */
    li x4, 6                      /* WDR idx for matrix-col bn.lid → w6 */
    li x5, 20                     /* WDR idx for output bn.sid ← w20 */

    /* Outer loop: 88 output rows */
    loopi 88, 16
        add x7, x0, x11           /* x7 = base addr for current row across cols */

        bn.mov w3, w28            /* sliding scalar window */
        bn.mov w4, w29
        bn.mov w5, w30
        bn.mov w20, w31           /* acc = 0 */

        /* 68 inner iters: load col, helper(vec=w6, scalar=byte0(w3), acc=w20), slide */
        loopi 68, 8
            bn.lid x4, 0(x7)           /* w6 = matrix col data */
            add x7, x7, x6             /* advance to next col same row */
            bn.mov w0, w6              /* helper vec input */
            bn.mov w19, w3             /* helper scalar input */
            jal x1, gf256_macc_sw_batched
            bn.rshi w3, w4, w3 >> 8    /* slide scalar window */
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8

        bn.sid x5, 0(x10++)            /* store w20 → output */
        addi x11, x11, 32              /* next row */

    li x4, 2816
    sub x10, x10, x4                   /* reset x10 to start of accumulator */

    ret

#endif
