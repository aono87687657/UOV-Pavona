/* row_mul_O (Ip). Low chain (w19) in ACC, high chain (w20) in ACCH[.inc],
 * dropping the two per-element acc spills.
 * Order is load-bearing: low .acc must read the mod1 cursor before high
 * .acch[.inc] advances it.
 *
 *   variant     cpp flag             body
 *   sw          (none)               SW row_mul_O_macc_sw helper-based
 *   bngfonly    -DGF_INSTRUCTIONS    HW bn.gfmul.8.acc + .acch.z.inc
 *   bngfaes     -DAES_|GF_           HW bn.gfmul.8.acc + .acch.inc
 */

.section .text
.balign 4
.global row_mul_O


#if defined(AES_INSTRUCTIONS) && defined(GF_INSTRUCTIONS)

/* =============== bngfaes (HW bn.gfmul.8) =============== */
row_mul_O:

    /* --------------------------------------------------------------
     *  OUTER LOOP: 5 iters, each processes 8 columns of O (8 × 68 = 544 B)
     *  K=180: preamble(18) + col1(21) + col2-7(20×6=120) + col8(20) + addi(1)
     * -------------------------------------------------------------- */
    loopi 5, 180
        /* Load 17 WDRs (544 B = 8 columns of O at 68 B each) into w2..w18 */
        li x8, 2
        bn.lid x8++,0(x11)
        bn.lid x8++,32(x11)
        bn.lid x8++,64(x11)
        bn.lid x8++,96(x11)
        bn.lid x8++,128(x11)
        bn.lid x8++,160(x11)
        bn.lid x8++,192(x11)
        bn.lid x8++,224(x11)
        bn.lid x8++,256(x11)
        bn.lid x8++,288(x11)
        bn.lid x8++,320(x11)
        bn.lid x8++,352(x11)
        bn.lid x8++,384(x11)
        bn.lid x8++,416(x11)
        bn.lid x8++,448(x11)
        bn.lid x8++,480(x11)
        bn.lid x8++,512(x11)
        /* ------ COL 1: bytes 0..67 → w2[0..31] + w3[0..31] + w4[0..3] ------ */
        /* K=21: wsrw acc(1)+wsrw acch(1)+add(1)+csrrw(1) + 3×(loopi+4body)=15 + 2 sid */
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x5, x0, x6
        csrrw x0, mod1, x0          /* mod1 = 0 */
        loopi 32, 4                  /* seg 1: 32 iters reading w2[0..31] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w2
            bn.gfmul.8.acch.inc w20, w1, w2
        /* mod1 wrapped to 0 after 32nd .inc */
        loopi 32, 4                  /* seg 2: 32 iters reading w3[0..31] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w3
            bn.gfmul.8.acch.inc w20, w1, w3
        loopi 4, 4                   /* seg 3: 4 iters reading w4[0..3] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w4
            bn.gfmul.8.acch.inc w20, w1, w4
        bn.sid x28, 0(x12++)
        bn.sid x29, 0(x12++)
        /* ------ COL 2: bytes 68..135 → w4[4..31] + w5[0..31] + w6[0..7] ------ */
        /* K=20: wsrw acc(1)+wsrw acch(1)+add(1) + 3×(loopi+4body)=15 + 2 sid */
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x5, x0, x6
        /* mod1 already = 4 from COL 1 seg 3 (auto-inc'd 0..3, mod1=4) */
        loopi 28, 4                  /* seg 1: 28 iters reading w4[4..31] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w4
            bn.gfmul.8.acch.inc w20, w1, w4
        /* mod1 wrapped to 0 after .inc through 31 */
        loopi 32, 4                  /* seg 2: 32 iters reading w5 */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w5
            bn.gfmul.8.acch.inc w20, w1, w5
        loopi 8, 4                   /* seg 3: 8 iters reading w6[0..7] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w6
            bn.gfmul.8.acch.inc w20, w1, w6
        bn.sid x28, 0(x12++)
        bn.sid x29, 0(x12++)
        /* ------ COL 3: bytes 136..203 → w6[8..31] + w7[0..31] + w8[0..11] ------ */
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x5, x0, x6
        /* mod1 = 8 from COL 2 seg 3 */
        loopi 24, 4                  /* seg 1: w6[8..31] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w6
            bn.gfmul.8.acch.inc w20, w1, w6
        loopi 32, 4                  /* seg 2: w7 */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w7
            bn.gfmul.8.acch.inc w20, w1, w7
        loopi 12, 4                  /* seg 3: w8[0..11] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w8
            bn.gfmul.8.acch.inc w20, w1, w8
        bn.sid x28, 0(x12++)
        bn.sid x29, 0(x12++)
        /* ------ COL 4: bytes 204..271 → w8[12..31] + w9[0..31] + w10[0..15] ------ */
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x5, x0, x6
        /* mod1 = 12 */
        loopi 20, 4                  /* seg 1: w8[12..31] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w8
            bn.gfmul.8.acch.inc w20, w1, w8
        loopi 32, 4                  /* seg 2: w9 */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w9
            bn.gfmul.8.acch.inc w20, w1, w9
        loopi 16, 4                  /* seg 3: w10[0..15] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w10
            bn.gfmul.8.acch.inc w20, w1, w10
        bn.sid x28, 0(x12++)
        bn.sid x29, 0(x12++)
        /* ------ COL 5: bytes 272..339 → w10[16..31] + w11[0..31] + w12[0..19] ------ */
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x5, x0, x6
        /* mod1 = 16 */
        loopi 16, 4                  /* seg 1: w10[16..31] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w10
            bn.gfmul.8.acch.inc w20, w1, w10
        loopi 32, 4                  /* seg 2: w11 */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w11
            bn.gfmul.8.acch.inc w20, w1, w11
        loopi 20, 4                  /* seg 3: w12[0..19] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w12
            bn.gfmul.8.acch.inc w20, w1, w12
        bn.sid x28, 0(x12++)
        bn.sid x29, 0(x12++)
        /* ------ COL 6: bytes 340..407 → w12[20..31] + w13[0..31] + w14[0..23] ------ */
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x5, x0, x6
        /* mod1 = 20 */
        loopi 12, 4                  /* seg 1: w12[20..31] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w12
            bn.gfmul.8.acch.inc w20, w1, w12
        loopi 32, 4                  /* seg 2: w13 */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w13
            bn.gfmul.8.acch.inc w20, w1, w13
        loopi 24, 4                  /* seg 3: w14[0..23] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w14
            bn.gfmul.8.acch.inc w20, w1, w14
        bn.sid x28, 0(x12++)
        bn.sid x29, 0(x12++)
        /* ------ COL 7: bytes 408..475 → w14[24..31] + w15[0..31] + w16[0..27] ------ */
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x5, x0, x6
        /* mod1 = 24 */
        loopi 8, 4                   /* seg 1: w14[24..31] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w14
            bn.gfmul.8.acch.inc w20, w1, w14
        loopi 32, 4                  /* seg 2: w15 */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w15
            bn.gfmul.8.acch.inc w20, w1, w15
        loopi 28, 4                  /* seg 3: w16[0..27] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w16
            bn.gfmul.8.acch.inc w20, w1, w16
        bn.sid x28, 0(x12++)
        bn.sid x29, 0(x12++)
        /* ------ COL 8: bytes 476..543 → w16[28..31] + w17[0..31] + w18[0..31] ------ */
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x5, x0, x6
        /* mod1 = 28 */
        loopi 4, 4                   /* seg 1: w16[28..31] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w16
            bn.gfmul.8.acch.inc w20, w1, w16
        loopi 32, 4                  /* seg 2: w17 */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w17
            bn.gfmul.8.acch.inc w20, w1, w17
        loopi 32, 4                  /* seg 3: w18 (full) */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w18
            bn.gfmul.8.acch.inc w20, w1, w18
        bn.sid x28, 0(x12++)
        bn.sid x29, 0(x12++)
        addi x11, x11, 544           /* advance to next 8-col batch */

    /* --------------------------------------------------------------
     *  TRAILING 4 COLS: bytes 0..271 → w2..w10 (9 WDRs covers 272 valid bytes)
     * -------------------------------------------------------------- */
    li x8, 2
    bn.lid x8++,0(x11)
    bn.lid x8++,32(x11)
    bn.lid x8++,64(x11)
    bn.lid x8++,96(x11)
    bn.lid x8++,128(x11)
    bn.lid x8++,160(x11)
    bn.lid x8++,192(x11)
    bn.lid x8++,224(x11)
    bn.lid x8++,256(x11)

    /* ------ TRAIL COL 1: bytes 0..67 → w2 + w3 + w4[0..3] ------ */
    bn.wsrw acc, w31
    bn.wsrw acch, w31
    add x5, x0, x6
    csrrw x0, mod1, x0
    loopi 32, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w2
        bn.gfmul.8.acch.inc w20, w1, w2
    loopi 32, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w3
        bn.gfmul.8.acch.inc w20, w1, w3
    loopi 4, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w4
        bn.gfmul.8.acch.inc w20, w1, w4
    bn.sid x28, 0(x12++)
    bn.sid x29, 0(x12++)

    /* ------ TRAIL COL 2: bytes 68..135 → w4[4..31] + w5 + w6[0..7] ------ */
    bn.wsrw acc, w31
    bn.wsrw acch, w31
    add x5, x0, x6
    /* mod1 = 4 */
    loopi 28, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w4
        bn.gfmul.8.acch.inc w20, w1, w4
    loopi 32, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w5
        bn.gfmul.8.acch.inc w20, w1, w5
    loopi 8, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w6
        bn.gfmul.8.acch.inc w20, w1, w6
    bn.sid x28, 0(x12++)
    bn.sid x29, 0(x12++)

    /* ------ TRAIL COL 3: bytes 136..203 → w6[8..31] + w7 + w8[0..11] ------ */
    bn.wsrw acc, w31
    bn.wsrw acch, w31
    add x5, x0, x6
    /* mod1 = 8 */
    loopi 24, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w6
        bn.gfmul.8.acch.inc w20, w1, w6
    loopi 32, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w7
        bn.gfmul.8.acch.inc w20, w1, w7
    loopi 12, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w8
        bn.gfmul.8.acch.inc w20, w1, w8
    bn.sid x28, 0(x12++)
    bn.sid x29, 0(x12++)

    /* ------ TRAIL COL 4: bytes 204..271 → w8[12..31] + w9 + w10[0..15] ------ */
    bn.wsrw acc, w31
    bn.wsrw acch, w31
    add x5, x0, x6
    /* mod1 = 12 */
    loopi 20, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w8
        bn.gfmul.8.acch.inc w20, w1, w8
    loopi 32, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w9
        bn.gfmul.8.acch.inc w20, w1, w9
    loopi 16, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w10
        bn.gfmul.8.acch.inc w20, w1, w10
    bn.sid x28, 0(x12++)
    bn.sid x29, 0(x12++)

    csrrw x0, mod1, x0          /* mod1 reset before ret (mod1 leak convention) */
    ret

#elif defined(GF_INSTRUCTIONS)

/* =============== bngfonly (HW bn.gfmul.8 with .acc.z/.acch.z variants) =============== */
row_mul_O:

    /* --------------------------------------------------------------
     *  OUTER LOOP: 5 iters, each processes 8 columns of O (8 x 68 = 544 B)
     *  K=195: preamble(18) + col1-7(22×7=154) + col8(22) + addi(1)
     *  mod1=0 on entry per kernel exit convention
     * -------------------------------------------------------------- */
    loopi 5, 195
        /* Load 17 WDRs (544 B = 8 columns of O at 68 B each) into w2..w18 */
        li x8, 2
        bn.lid x8++,0(x11)
        bn.lid x8++,32(x11)
        bn.lid x8++,64(x11)
        bn.lid x8++,96(x11)
        bn.lid x8++,128(x11)
        bn.lid x8++,160(x11)
        bn.lid x8++,192(x11)
        bn.lid x8++,224(x11)
        bn.lid x8++,256(x11)
        bn.lid x8++,288(x11)
        bn.lid x8++,320(x11)
        bn.lid x8++,352(x11)
        bn.lid x8++,384(x11)
        bn.lid x8++,416(x11)
        bn.lid x8++,448(x11)
        bn.lid x8++,480(x11)
        bn.lid x8++,512(x11)
        /* ------ COL 1: bytes 0..67 to w2[0..31] + w3[0..31] + w4[0..3] ------ */
        /* K=22: add(1)+peel(4)+loopi31,4(1+4)+loopi32,4(1+4)+loopi4,4(1+4)+2sid */
        add x5, x0, x6
        /* Peel seg1 first iter: .acc.z zeros ACC (w19 chain), .acch.z.inc zeros ACCH (w20) */
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc.z w19, w0, w2
        bn.gfmul.8.acch.z.inc w20, w1, w2
        loopi 31, 4                  /* remaining 31 iters of seg 1 */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w2
            bn.gfmul.8.acch.inc w20, w1, w2
        /* mod1 wrapped to 0 after 32nd .inc */
        loopi 32, 4                  /* seg 2: 32 iters reading w3[0..31] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w3
            bn.gfmul.8.acch.inc w20, w1, w3
        loopi 4, 4                   /* seg 3: 4 iters reading w4[0..3] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w4
            bn.gfmul.8.acch.inc w20, w1, w4
        bn.sid x28, 0(x12++)
        bn.sid x29, 0(x12++)
        /* ------ COL 2: bytes 68..135 to w4[4..31] + w5[0..31] + w6[0..7] ------ */
        add x5, x0, x6
        /* mod1 already = 4 from COL 1 seg 3 (auto-inc'd 0..3, mod1=4) */
        /* Peel seg1 first iter */
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc.z w19, w0, w4
        bn.gfmul.8.acch.z.inc w20, w1, w4
        loopi 27, 4
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w4
            bn.gfmul.8.acch.inc w20, w1, w4
        /* mod1 wrapped to 0 after .inc through 31 */
        loopi 32, 4                  /* seg 2: 32 iters reading w5 */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w5
            bn.gfmul.8.acch.inc w20, w1, w5
        loopi 8, 4                   /* seg 3: 8 iters reading w6[0..7] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w6
            bn.gfmul.8.acch.inc w20, w1, w6
        bn.sid x28, 0(x12++)
        bn.sid x29, 0(x12++)
        /* ------ COL 3: bytes 136..203 to w6[8..31] + w7[0..31] + w8[0..11] ------ */
        add x5, x0, x6
        /* mod1 = 8 from COL 2 seg 3 */
        /* Peel seg1 first iter */
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc.z w19, w0, w6
        bn.gfmul.8.acch.z.inc w20, w1, w6
        loopi 23, 4
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w6
            bn.gfmul.8.acch.inc w20, w1, w6
        loopi 32, 4                  /* seg 2: w7 */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w7
            bn.gfmul.8.acch.inc w20, w1, w7
        loopi 12, 4                  /* seg 3: w8[0..11] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w8
            bn.gfmul.8.acch.inc w20, w1, w8
        bn.sid x28, 0(x12++)
        bn.sid x29, 0(x12++)
        /* ------ COL 4: bytes 204..271 to w8[12..31] + w9[0..31] + w10[0..15] ------ */
        add x5, x0, x6
        /* mod1 = 12 */
        /* Peel seg1 first iter */
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc.z w19, w0, w8
        bn.gfmul.8.acch.z.inc w20, w1, w8
        loopi 19, 4
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w8
            bn.gfmul.8.acch.inc w20, w1, w8
        loopi 32, 4                  /* seg 2: w9 */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w9
            bn.gfmul.8.acch.inc w20, w1, w9
        loopi 16, 4                  /* seg 3: w10[0..15] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w10
            bn.gfmul.8.acch.inc w20, w1, w10
        bn.sid x28, 0(x12++)
        bn.sid x29, 0(x12++)
        /* ------ COL 5: bytes 272..339 to w10[16..31] + w11[0..31] + w12[0..19] ------ */
        add x5, x0, x6
        /* mod1 = 16 */
        /* Peel seg1 first iter */
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc.z w19, w0, w10
        bn.gfmul.8.acch.z.inc w20, w1, w10
        loopi 15, 4
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w10
            bn.gfmul.8.acch.inc w20, w1, w10
        loopi 32, 4                  /* seg 2: w11 */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w11
            bn.gfmul.8.acch.inc w20, w1, w11
        loopi 20, 4                  /* seg 3: w12[0..19] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w12
            bn.gfmul.8.acch.inc w20, w1, w12
        bn.sid x28, 0(x12++)
        bn.sid x29, 0(x12++)
        /* ------ COL 6: bytes 340..407 to w12[20..31] + w13[0..31] + w14[0..23] ------ */
        add x5, x0, x6
        /* mod1 = 20 */
        /* Peel seg1 first iter */
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc.z w19, w0, w12
        bn.gfmul.8.acch.z.inc w20, w1, w12
        loopi 11, 4
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w12
            bn.gfmul.8.acch.inc w20, w1, w12
        loopi 32, 4                  /* seg 2: w13 */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w13
            bn.gfmul.8.acch.inc w20, w1, w13
        loopi 24, 4                  /* seg 3: w14[0..23] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w14
            bn.gfmul.8.acch.inc w20, w1, w14
        bn.sid x28, 0(x12++)
        bn.sid x29, 0(x12++)
        /* ------ COL 7: bytes 408..475 to w14[24..31] + w15[0..31] + w16[0..27] ------ */
        add x5, x0, x6
        /* mod1 = 24 */
        /* Peel seg1 first iter */
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc.z w19, w0, w14
        bn.gfmul.8.acch.z.inc w20, w1, w14
        loopi 7, 4
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w14
            bn.gfmul.8.acch.inc w20, w1, w14
        loopi 32, 4                  /* seg 2: w15 */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w15
            bn.gfmul.8.acch.inc w20, w1, w15
        loopi 28, 4                  /* seg 3: w16[0..27] */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w16
            bn.gfmul.8.acch.inc w20, w1, w16
        bn.sid x28, 0(x12++)
        bn.sid x29, 0(x12++)
        /* ------ COL 8: bytes 476..543 to w16[28..31] + w17[0..31] + w18[0..31] ------ */
        add x5, x0, x6
        /* mod1 = 28 */
        /* Peel seg1 first iter */
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc.z w19, w0, w16
        bn.gfmul.8.acch.z.inc w20, w1, w16
        loopi 3, 4
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w16
            bn.gfmul.8.acch.inc w20, w1, w16
        loopi 32, 4                  /* seg 2: w17 */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w17
            bn.gfmul.8.acch.inc w20, w1, w17
        loopi 32, 4                  /* seg 3: w18 (full) */
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.gfmul.8.acc w19, w0, w18
            bn.gfmul.8.acch.inc w20, w1, w18
        bn.sid x28, 0(x12++)
        bn.sid x29, 0(x12++)
        addi x11, x11, 544           /* advance to next 8-col batch */

    /* --------------------------------------------------------------
     *  TRAILING 4 COLS: bytes 0..271 to w2..w10 (9 WDRs covers 272 valid bytes)
     * -------------------------------------------------------------- */
    li x8, 2
    bn.lid x8++,0(x11)
    bn.lid x8++,32(x11)
    bn.lid x8++,64(x11)
    bn.lid x8++,96(x11)
    bn.lid x8++,128(x11)
    bn.lid x8++,160(x11)
    bn.lid x8++,192(x11)
    bn.lid x8++,224(x11)
    bn.lid x8++,256(x11)

    /* ------ TRAIL COL 1: bytes 0..67 to w2 + w3 + w4[0..3] ------ */
    add x5, x0, x6
    /* mod1 = 0 from end of outer loopi 5 (8 cols x 68 .inc = 544; 544 mod 32 = 0) */
    /* Peel seg1 first iter */
    bn.lid x0, 0(x5++)
    bn.lid x19, 0(x5++)
    bn.gfmul.8.acc.z w19, w0, w2
    bn.gfmul.8.acch.z.inc w20, w1, w2
    loopi 31, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w2
        bn.gfmul.8.acch.inc w20, w1, w2
    loopi 32, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w3
        bn.gfmul.8.acch.inc w20, w1, w3
    loopi 4, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w4
        bn.gfmul.8.acch.inc w20, w1, w4
    bn.sid x28, 0(x12++)
    bn.sid x29, 0(x12++)

    /* ------ TRAIL COL 2: bytes 68..135 to w4[4..31] + w5 + w6[0..7] ------ */
    add x5, x0, x6
    /* mod1 = 4 */
    /* Peel seg1 first iter */
    bn.lid x0, 0(x5++)
    bn.lid x19, 0(x5++)
    bn.gfmul.8.acc.z w19, w0, w4
    bn.gfmul.8.acch.z.inc w20, w1, w4
    loopi 27, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w4
        bn.gfmul.8.acch.inc w20, w1, w4
    loopi 32, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w5
        bn.gfmul.8.acch.inc w20, w1, w5
    loopi 8, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w6
        bn.gfmul.8.acch.inc w20, w1, w6
    bn.sid x28, 0(x12++)
    bn.sid x29, 0(x12++)

    /* ------ TRAIL COL 3: bytes 136..203 to w6[8..31] + w7 + w8[0..11] ------ */
    add x5, x0, x6
    /* mod1 = 8 */
    /* Peel seg1 first iter */
    bn.lid x0, 0(x5++)
    bn.lid x19, 0(x5++)
    bn.gfmul.8.acc.z w19, w0, w6
    bn.gfmul.8.acch.z.inc w20, w1, w6
    loopi 23, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w6
        bn.gfmul.8.acch.inc w20, w1, w6
    loopi 32, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w7
        bn.gfmul.8.acch.inc w20, w1, w7
    loopi 12, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w8
        bn.gfmul.8.acch.inc w20, w1, w8
    bn.sid x28, 0(x12++)
    bn.sid x29, 0(x12++)

    /* ------ TRAIL COL 4: bytes 204..271 to w8[12..31] + w9 + w10[0..15] ------ */
    add x5, x0, x6
    /* mod1 = 12 */
    /* Peel seg1 first iter */
    bn.lid x0, 0(x5++)
    bn.lid x19, 0(x5++)
    bn.gfmul.8.acc.z w19, w0, w8
    bn.gfmul.8.acch.z.inc w20, w1, w8
    loopi 19, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w8
        bn.gfmul.8.acch.inc w20, w1, w8
    loopi 32, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w9
        bn.gfmul.8.acch.inc w20, w1, w9
    loopi 16, 4
        bn.lid x0, 0(x5++)
        bn.lid x19, 0(x5++)
        bn.gfmul.8.acc w19, w0, w10
        bn.gfmul.8.acch.inc w20, w1, w10
    bn.sid x28, 0(x12++)
    bn.sid x29, 0(x12++)

    csrrw x0, mod1, x0          /* mod1 reset before ret (mod1 leak convention) */
    ret

#else

/* =============== sw (SW row_mul_O_macc_sw helper-based) =============== */
.global row_mul_O_macc_sw
row_mul_O_macc_sw:
    /* w23 = mask 0x01 (for bit-extract); w24 = scratch holding saved caller w16
     * until restore (caller-visible w24 stays clobbered); w25/w26 = local product
     * accumulators for w0×s / w1×s; w27 = reduction-poly product scratch.
     * w16 = 0x1b reduction scalar for bn.mulv.l (sw0). */
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

/* -------------------------------------------------------------------------
 * row_mul_O — entry point, exported as `row_mul_O` (drop-in replacement
 * for the HW-gfmul version when linked via the sw BUILD target).
 *
 * Algorithm: 5 outer batches × 8 cols (40 cols total) + 4 trailing cols.
 * Per col: init accumulators to 0, loop 68 inner iters (each: load 64 B of
 * P1+P1^T, SW-gfmul-accumulate, slide w2..w18 by 1 byte), store accumulators
 * to result.
 *
 * NOTE on slide chain length: This implementation uses a UNIFORM 17-WDR
 * slide chain per inner iter regardless of col. The HW pre-index variant
 * optimized this (col K used 17-2*(K-1) slides). Skipped here for clarity;
 * uniform slide is correctness-preserving and adds ~1.3M wasted slide ops
 * per gf256trimat call — drowned by the dominant SW gfmul cost.
 */
.global row_mul_O
row_mul_O:

    /* Load msb_mask into w21 (caller may not have it). */
    la x5, msb_mask
    li x8, 21
    bn.lid x8, 0(x5)

    /* --- 5 batches × 8 cols of O --- */
    loopi 5, 47
        /* Load 17 WDRs (= 544 B = 8 cols of O at 68 B each) into w2..w18 */
        li x8, 2
        bn.lid x8++, 0(x11)
        bn.lid x8++, 32(x11)
        bn.lid x8++, 64(x11)
        bn.lid x8++, 96(x11)
        bn.lid x8++, 128(x11)
        bn.lid x8++, 160(x11)
        bn.lid x8++, 192(x11)
        bn.lid x8++, 224(x11)
        bn.lid x8++, 256(x11)
        bn.lid x8++, 288(x11)
        bn.lid x8++, 320(x11)
        bn.lid x8++, 352(x11)
        bn.lid x8++, 384(x11)
        bn.lid x8++, 416(x11)
        bn.lid x8++, 448(x11)
        bn.lid x8++, 480(x11)
        bn.lid x8++, 512(x11)

        /* 8 cols per batch */
        loopi 8, 27
            bn.xor w19, w19, w19                 /* acc_lo = 0 */
            bn.xor w20, w20, w20                 /* acc_hi = 0 */
            add x5, x0, x6                        /* reset P1+P1^T cursor */
            loopi 68, 21
                bn.lid x0, 0(x5++)
                bn.lid x19, 0(x5++)               /* x19 = 1 → loads w1 */
                bn.mov w22, w2                    /* scalar copy for helper */
                jal x1, row_mul_O_macc_sw
                /* slide w2..w18 by 1 byte (17 bn.rshi) */
                bn.rshi w2,  w3,  w2  >> 8
                bn.rshi w3,  w4,  w3  >> 8
                bn.rshi w4,  w5,  w4  >> 8
                bn.rshi w5,  w6,  w5  >> 8
                bn.rshi w6,  w7,  w6  >> 8
                bn.rshi w7,  w8,  w7  >> 8
                bn.rshi w8,  w9,  w8  >> 8
                bn.rshi w9,  w10, w9  >> 8
                bn.rshi w10, w11, w10 >> 8
                bn.rshi w11, w12, w11 >> 8
                bn.rshi w12, w13, w12 >> 8
                bn.rshi w13, w14, w13 >> 8
                bn.rshi w14, w15, w14 >> 8
                bn.rshi w15, w16, w15 >> 8
                bn.rshi w16, w17, w16 >> 8
                bn.rshi w17, w18, w17 >> 8
                bn.rshi w18, w31, w18 >> 8
            bn.sid x28, 0(x12++)                  /* store w19 */
            bn.sid x29, 0(x12++)                  /* store w20 */
        addi x11, x11, 544                        /* next 8-col batch */

    /* --- Trailing 4 cols (272 B) --- */
    li x8, 2
    bn.lid x8++, 0(x11)
    bn.lid x8++, 32(x11)
    bn.lid x8++, 64(x11)
    bn.lid x8++, 96(x11)
    bn.lid x8++, 128(x11)
    bn.lid x8++, 160(x11)
    bn.lid x8++, 192(x11)
    bn.lid x8++, 224(x11)
    bn.lid x8++, 256(x11)

    loopi 4, 27
        bn.xor w19, w19, w19
        bn.xor w20, w20, w20
        add x5, x0, x6
        loopi 68, 21
            bn.lid x0, 0(x5++)
            bn.lid x19, 0(x5++)
            bn.mov w22, w2
            jal x1, row_mul_O_macc_sw
            bn.rshi w2,  w3,  w2  >> 8
            bn.rshi w3,  w4,  w3  >> 8
            bn.rshi w4,  w5,  w4  >> 8
            bn.rshi w5,  w6,  w5  >> 8
            bn.rshi w6,  w7,  w6  >> 8
            bn.rshi w7,  w8,  w7  >> 8
            bn.rshi w8,  w9,  w8  >> 8
            bn.rshi w9,  w10, w9  >> 8
            bn.rshi w10, w11, w10 >> 8
            bn.rshi w11, w12, w11 >> 8
            bn.rshi w12, w13, w12 >> 8
            bn.rshi w13, w14, w13 >> 8
            bn.rshi w14, w15, w14 >> 8
            bn.rshi w15, w16, w15 >> 8
            bn.rshi w16, w17, w16 >> 8
            bn.rshi w17, w18, w17 >> 8
            bn.rshi w18, w31, w18 >> 8
        bn.sid x28, 0(x12++)
        bn.sid x29, 0(x12++)

    /* No mod1 reset needed — we don't touch mod1. (Caller's mod1 invariant
     * preserved: mod1 stays at whatever value caller had on entry.) */
    ret

#endif
