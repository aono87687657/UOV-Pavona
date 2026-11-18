/* gf16_ldirect_96_64: build the UOV-Is GE matrix L + quadratic y per attempt, no S buffer.
 *   L = t^T*O + vin^T*P2,  t = (P1+P1^T)*vin    GF16 (poly 0x13), v=96, o=64.
 *   y = vin^T*P1*vin (32B), fused into the single P1 stream (HW arms): y ^= vin[row]*chain
 *   + P1[row][row]*vin[row]^2 (diag AES-generated since Is skips it), RMW'd into y slot (x14).
 * P1 is streamed once from AES-CTR (1 entry = 64 nibbles = 1 WDR). Diagonals are
 * skipped (P1+P1^T diagonal = 0) but still advance the counter.
 *   build-t : per off-diag e@(row,col)  t[row] ^= vin[col]*e (ACC chain),  t[col] ^= vin[row]*e (mem RMW)
 *   t^T*O   : L = t^T*O            (O dual-col packed = scalar source, t = the vectors)
 *   v^T*P2  : keep streaming       L[c] ^= vin[r]*P2[r][c]
 *
 * in    : x10 pk_seed, x11 vinegar(48B), x12 L out(2048B), x13 O, x14 y out(32B)
 * clob  : w0-w9, w20-w30, ACC, x5-x9, x14-x17, x26-x31   (x1-x3, x10-x13 preserved; x14 consumed)
 * wdr   : w0 ctr  w1 +2inc  w2 entry  w3/w4 vin[col] win  w5/w6 vin[row] win
 *         w7 chain  w8 rmw  w9 prod  w20-w30 round keys  w31 0
 * stack : 3104B frame (32 args + 3072 t), freed on ret.  mod0=0x13, mod1=0.
 */

.section .text
.balign 4
.global gf16_ldirect_96_64

#if defined(AES_INSTRUCTIONS) && defined(GF_INSTRUCTIONS)

gf16_ldirect_96_64:
    bn.xor w31, w31, w31
    li x5, 3104                    /* frame: [0..31] args, [32..3103] t */
    sub x2, x2, x5
    add x8, x0, x2
    sw x10, 0(x8)
    sw x11, 4(x8)
    sw x12, 8(x8)
    sw x13, 12(x8)
    addi x9, x8, 32
    sw x9, 16(x8)                  /* t base (reloaded in phase t^T*O) */
    sw x14, 20(x8)                 /* y-out ptr (caller-owned 32B slot) */
    lw x26, 20(x8)                 /* y ptr: zeroed here, then loop-invariant (aes128_sign keeps x26) */
    bn.sd w31, 0(x26)

    li x31, 0x13
    csrrw x0, mod0, x31
    csrrw x0, mod1, x0             /* mod1 = 0: scalar = wrs2 nibble 0 */

    /* zero L (64x32B) and t (96x32B) */
    add x14, x0, x12
    loopi 64, 1
        bn.sd w31, 0(x14++)
    add x14, x0, x9
    loopi 96, 1
        bn.sd w31, 0(x14++)

    /* AES key schedule: RK0=key in w30, RK1..RK10 in w29..w20 (kept resident) */
    li x31, 30
    bn.lid x31, 0(x10)
    bn.or w30, w30, w30 << 128
    bn.aes128.kf w29, w30,  1
    bn.aes128.kf w28, w29,  2
    bn.aes128.kf w27, w28,  3
    bn.aes128.kf w26, w27,  4
    bn.aes128.kf w25, w26,  5
    bn.aes128.kf w24, w25,  6
    bn.aes128.kf w23, w24,  7
    bn.aes128.kf w22, w23,  8
    bn.aes128.kf w21, w22,  9
    bn.aes128.kf w20, w21, 10

    /* AES-CTR counter: w0 = slot (0,0), w1 = +2 per entry (dual block) */
    bn.addi w0, w31, 1
    bn.rshi w0, w0, w31 >> 32
    bn.or  w1, w0, w0 >> 128
    bn.add w1, w1, w1

    /* vinegar windows: working w3/w4 (vin[col]), backup w5/w6 (vin[row]), nibble0 = vin[0] */
    li x31, 3
    bn.lid x31++, 0(x11)
    bn.lid x31, 32(x11)
    bn.mov w5, w3
    bn.mov w6, w4

    /* ---- phase build-t: t = (P1+P1^T)*vin ---- */
    add x14, x0, x9                /* x14 = t[row] ptr */
    li x7, 95                      /* row 0 has 95 off-diag entries */

    loopi 95, 55
        /* fused y: diagonal P1[row][row]=AES(w0) (Is skips the diag entry, so generate
         *    it); y ^= P1[row][row]*vin[row]^2 (vin[row]=w5 nib0). Before the counter bump. */
        bn.aes128.encz.swap w2, w0, w30
        bn.aes128.encm w2, w2, w29
        bn.aes128.encm w2, w2, w28
        bn.aes128.encm w2, w2, w27
        bn.aes128.encm w2, w2, w26
        bn.aes128.encm w2, w2, w25
        bn.aes128.encm w2, w2, w24
        bn.aes128.encm w2, w2, w23
        bn.aes128.encm w2, w2, w22
        bn.aes128.encm w2, w2, w21
        bn.aes128.encf w2, w2, w20
        bn.gfmul.4 w9, w2, w5
        bn.gfmul.4 w9, w9, w5
        bn.ld w8, 0(x26)
        bn.xor w8, w8, w9
        bn.sd w8, 0(x26)
        /* diagonal (row==col): bump counter, slide working window */
        bn.add w0, w0, w1
        bn.rshi w3, w4, w3 >> 4
        bn.rshi w4, w31, w4 >> 4
        bn.wsrw acc, w31           /* clear chain */
        addi x15, x14, 32          /* t[col] ptr = t[row+1] */
        loop x7, 20
            bn.aes128.encz.swap w2, w0, w30      /* e = AES(counter) */
            bn.aes128.encm w2, w2, w29
            bn.aes128.encm w2, w2, w28
            bn.aes128.encm w2, w2, w27
            bn.aes128.encm w2, w2, w26
            bn.aes128.encm w2, w2, w25
            bn.aes128.encm w2, w2, w24
            bn.aes128.encm w2, w2, w23
            bn.aes128.encm w2, w2, w22
            bn.aes128.encm w2, w2, w21
            bn.aes128.encf w2, w2, w20
            bn.add w0, w0, w1
            bn.gfmul.4.acc w7, w2, w3            /* chain  t[row] ^= vin[col]*e */
            bn.ld w8, 0(x15)                     /* scatter t[col] ^= vin[row]*e */
            bn.gfmul.4 w9, w2, w5
            bn.xor w8, w8, w9
            bn.sd w8, 0(x15)
            addi x15, x15, 32
            bn.rshi w3, w4, w3 >> 4              /* vin[col] -> vin[col+1] */
            bn.rshi w4, w31, w4 >> 4
        /* fused y: off-diag part  y ^= vin[row]*chain (w7 = ACC chain, pre-RMW). Must
         *    precede the t-RMW (it reuses w8; w7 read by both, not clobbered here). */
        bn.gfmul.4 w9, w7, w5
        bn.ld w8, 0(x26)
        bn.xor w8, w8, w9
        bn.sd w8, 0(x26)
        /* write t[row] (RMW: earlier rows scattered into it) */
        bn.ld w8, 0(x14)
        bn.xor w8, w8, w7
        bn.sd w8, 0(x14)
        addi x14, x14, 32
        bn.rshi w5, w6, w5 >> 4                  /* vin[row] -> vin[row+1] */
        bn.rshi w6, w31, w6 >> 4
        bn.mov w3, w5                            /* working = backup */
        bn.mov w4, w6
        addi x7, x7, -1

    /* fused y: row-95 diagonal P1[95][95]=AES(w0); y ^= P1[95][95]*vin[95]^2 (vin[95]=w5 nib0) */
    bn.aes128.encz.swap w2, w0, w30
    bn.aes128.encm w2, w2, w29
    bn.aes128.encm w2, w2, w28
    bn.aes128.encm w2, w2, w27
    bn.aes128.encm w2, w2, w26
    bn.aes128.encm w2, w2, w25
    bn.aes128.encm w2, w2, w24
    bn.aes128.encm w2, w2, w23
    bn.aes128.encm w2, w2, w22
    bn.aes128.encm w2, w2, w21
    bn.aes128.encf w2, w2, w20
    bn.gfmul.4 w9, w2, w5
    bn.gfmul.4 w9, w9, w5
    bn.ld w8, 0(x26)
    bn.xor w8, w8, w9
    bn.sd w8, 0(x26)
    bn.add w0, w0, w1              /* eat row-95 diagonal so P2 starts at slot 4656 */

    /* ---- phase t^T*O: L = t^T*O (O = scalar source, 2 cols / 96B per outer iter) ---- */
    lw x11, 12(x8)                 /* O */
    lw x12, 8(x8)                  /* L */
    li x29, 3
    li x28, 4
    li x27, 5
    li x26, 6
    li x25, 7
    csrrw x0, mod1, x0
    loopi 32, 34
        lw x9, 16(x8)             /* t base */
        bn.lid x29, 0(x11++)      /* w3 = O col_i, w4 = col_i+1|col_i, w5 = col_i+1 */
        bn.lid x28, 0(x11++)
        bn.lid x27, 0(x11++)
        bn.wsrw acc, w31
        csrrw x0, mod1, x0
        loopi 32, 4
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.gfmul.4.acc.inc w8, w6, w3
            bn.gfmul.4.acc.inc w8, w7, w3
        csrrw x0, mod1, x0
        loopi 16, 4
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.gfmul.4.acc.inc w8, w6, w4
            bn.gfmul.4.acc.inc w8, w7, w4
        bn.sd w8, 0(x12++)      /* L[col_i] */
        bn.wsrw acc, w31
        li x9, 32
        csrrw x0, mod1, x9        /* mod1 = 32 for col_i+1's low half */
        lw x9, 16(x8)
        loopi 16, 4
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.gfmul.4.acc.inc w8, w6, w4
            bn.gfmul.4.acc.inc w8, w7, w4
        csrrw x0, mod1, x0
        loopi 32, 4
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.gfmul.4.acc.inc w8, w6, w5
            bn.gfmul.4.acc.inc w8, w7, w5
        bn.sd w8, 0(x12++)      /* L[col_i+1] */

    csrrw x0, mod1, x0            /* mod1 = 0 */

    /* ---- phase v^T*P2: L ^= vin^T*P2 (stream continues at slot 4656) ---- */
    lw x12, 8(x8)
    lw x11, 4(x8)                 /* vinegar */
    li x31, 3
    bn.lid x31++, 0(x11)
    bn.lid x31, 32(x11)

    loopi 96, 21
        add x15, x0, x12          /* L ptr = base */
        loopi 64, 17
            bn.aes128.encz.swap w2, w0, w30
            bn.aes128.encm w2, w2, w29
            bn.aes128.encm w2, w2, w28
            bn.aes128.encm w2, w2, w27
            bn.aes128.encm w2, w2, w26
            bn.aes128.encm w2, w2, w25
            bn.aes128.encm w2, w2, w24
            bn.aes128.encm w2, w2, w23
            bn.aes128.encm w2, w2, w22
            bn.aes128.encm w2, w2, w21
            bn.aes128.encf w2, w2, w20
            bn.add w0, w0, w1
            bn.ld w8, 0(x15)
            bn.gfmul.4 w9, w2, w3                /* vin[r]*P2[r][c] */
            bn.xor w8, w8, w9
            bn.sd w8, 0(x15)
            addi x15, x15, 32
        bn.rshi w3, w4, w3 >> 4                  /* vin[r] -> vin[r+1] */
        bn.rshi w4, w31, w4 >> 4

    li x5, 3104
    add x2, x2, x5
    ret

#elif defined(GF_INSTRUCTIONS)

/* bngfonly: same kernel, P stream via SW AES (jal aes128_sign / KeySchedule_sign)
 * instead of inline bn.aes128.*. aes128_sign needs masks resident (w7 byte_swap,
 * w8 affine, w9 msb) and clobbers w1,w10-w17, so the +2 CTR increment moves to w19
 * and IV is passed in w18. aes128_sign preserves w0, w3-w6 and ACC but leaves
 * mod0=0x11B -> we re-set 0x13 (resident x17) right after every call; the phase
 * build-t ACC chain and the vinegar windows survive each call.
 *   wdr : w0 ctr  w18 IV  w19 +2inc  w2 entry  w3/w4 vin[col]  w5/w6 vin[row]
 *         w7/w8/w9 AES masks  w11 rcon(KS only)  w20-w30 round keys  w31 0
 *         w1 chain/acc dst  w10 rmw  w12 prod  w6/w17 phase t^T*O t pair
 */
gf16_ldirect_96_64:
    bn.xor w31, w31, w31
    li x5, 3104
    sub x2, x2, x5
    add x8, x0, x2
    sw x10, 0(x8)
    sw x11, 4(x8)
    sw x12, 8(x8)
    sw x13, 12(x8)
    addi x9, x8, 32
    sw x9, 16(x8)                  /* t base (reloaded in phase t^T*O) */
    sw x14, 20(x8)                 /* y-out ptr (caller-owned 32B slot) */
    lw x26, 20(x8)                 /* y ptr: zeroed here, then loop-invariant (aes128_sign keeps x26) */
    bn.sd w31, 0(x26)

    /* zero L (64x32B) and t (96x32B) */
    add x14, x0, x12
    loopi 64, 1
        bn.sd w31, 0(x14++)
    add x14, x0, x9
    loopi 96, 1
        bn.sd w31, 0(x14++)

    /* SW-AES constants: affine->w8, msb->w9, rcon->w11 (need x5/x6 scratch) */
    la x5, affine_value
    li x6, 8
    bn.lid x6, 0(x5)
    la x5, msb_mask
    li x6, 9
    bn.lid x6, 0(x5)
    la x5, rcon
    li x6, 11
    bn.lid x6, 0(x5)

    /* load key -> w30, prime w17 for KS (reads w17[255:96]=0), dual-store RK0 */
    li x31, 30
    bn.lid x31, 0(x10)
    bn.mov w17, w30
    bn.or w30, w30, w30 << 128

    /* 10 SW key-schedule rounds: RK1..RK10 -> w20..w29 (forward), each dual-stored */
    jal x1, KeySchedule_sign
    bn.mov w20, w17
    bn.or  w20, w20, w20 << 128
    jal x1, KeySchedule_sign
    bn.mov w21, w17
    bn.or  w21, w21, w21 << 128
    jal x1, KeySchedule_sign
    bn.mov w22, w17
    bn.or  w22, w22, w22 << 128
    jal x1, KeySchedule_sign
    bn.mov w23, w17
    bn.or  w23, w23, w23 << 128
    jal x1, KeySchedule_sign
    bn.mov w24, w17
    bn.or  w24, w24, w24 << 128
    jal x1, KeySchedule_sign
    bn.mov w25, w17
    bn.or  w25, w25, w25 << 128
    jal x1, KeySchedule_sign
    bn.mov w26, w17
    bn.or  w26, w26, w26 << 128
    jal x1, KeySchedule_sign
    bn.mov w27, w17
    bn.or  w27, w27, w27 << 128
    jal x1, KeySchedule_sign
    bn.mov w28, w17
    bn.or  w28, w28, w28 << 128
    jal x1, KeySchedule_sign
    bn.mov w29, w17
    bn.or  w29, w29, w29 << 128

    /* reload byte_swap_mask -> w7 (KS clobbered it as scratch) */
    la x5, byte_swap_mask
    li x6, 7
    bn.lid x6, 0(x5)

    /* GF16 poly + scalar cursor 0 (KS left mod0 = 0x11B). x17 stays resident:
       aes128_sign leaves mod0 = 0x11B, we restore 0x13 after every call */
    li x17, 0x13
    csrrw x0, mod0, x17
    csrrw x0, mod1, x0

    /* AES-CTR: w0 = entry-0 dual counter (blocks 0,1), w19 = +2 per entry */
    bn.addi w0, w31, 1
    bn.rshi w0, w0, w31 >> 32
    bn.or  w19, w0, w0 >> 128
    bn.add w19, w19, w19

    /* vinegar windows: working w3/w4 (vin[col]), backup w5/w6 (vin[row]) */
    li x31, 3
    bn.lid x31++, 0(x11)
    bn.lid x31, 32(x11)
    bn.mov w5, w3
    bn.mov w6, w4

    /* ---- phase build-t: t = (P1+P1^T)*vin ---- */
    add x14, x0, x9                /* x14 = t[row] ptr */
    li x7, 95                      /* row 0 has 95 off-diag entries */

    loopi 95, 39
        /* fused y: diagonal P1[row][row]=AES(w0) (Is skips the diag entry, so generate
         *    it via SW-AES); y ^= P1[row][row]*vin[row]^2 (vin[row]=w5 nib0). aes128_sign
         *    preserves w0/w3-w6/ACC, leaves mod0=0x11B. Before the counter bump. */
        bn.mov w18, w0
        jal x1, aes128_sign
        csrrw x0, mod0, x17
        bn.gfmul.4 w12, w2, w5
        bn.gfmul.4 w12, w12, w5
        bn.ld w10, 0(x26)
        bn.xor w10, w10, w12
        bn.sd w10, 0(x26)
        /* diagonal (row==col): bump counter, slide working window */
        bn.add w0, w0, w19
        bn.rshi w3, w4, w3 >> 4
        bn.rshi w4, w31, w4 >> 4
        bn.wsrw acc, w31           /* clear chain */
        addi x15, x14, 32          /* t[col] ptr = t[row+1] */
        loop x7, 12
            bn.mov w18, w0
            jal x1, aes128_sign                  /* e = AES(counter) -> w2 */
            csrrw x0, mod0, x17
            bn.add w0, w0, w19
            bn.gfmul.4.acc w1, w2, w3            /* chain  t[row] ^= vin[col]*e */
            bn.ld w10, 0(x15)                    /* scatter t[col] ^= vin[row]*e */
            bn.gfmul.4 w12, w2, w5
            bn.xor w10, w10, w12
            bn.sd w10, 0(x15)
            addi x15, x15, 32
            bn.rshi w3, w4, w3 >> 4              /* vin[col] -> vin[col+1] */
            bn.rshi w4, w31, w4 >> 4
        /* fused y: off-diag part  y ^= vin[row]*chain (w1 = ACC chain, pre-RMW). Precedes
         *    the t-RMW (reuses w10; w1 read by both, not clobbered here). */
        bn.gfmul.4 w12, w1, w5
        bn.ld w10, 0(x26)
        bn.xor w10, w10, w12
        bn.sd w10, 0(x26)
        /* write t[row] (RMW: earlier rows scattered into it) */
        bn.ld w10, 0(x14)
        bn.xor w10, w10, w1
        bn.sd w10, 0(x14)
        addi x14, x14, 32
        bn.rshi w5, w6, w5 >> 4                  /* vin[row] -> vin[row+1] */
        bn.rshi w6, w31, w6 >> 4
        bn.mov w3, w5                            /* working = backup */
        bn.mov w4, w6
        addi x7, x7, -1

    /* fused y: row-95 diagonal P1[95][95]=AES(w0); y ^= P1[95][95]*vin[95]^2 (vin[95]=w5 nib0) */
    bn.mov w18, w0
    jal x1, aes128_sign
    csrrw x0, mod0, x17
    bn.gfmul.4 w12, w2, w5
    bn.gfmul.4 w12, w12, w5
    bn.ld w10, 0(x26)
    bn.xor w10, w10, w12
    bn.sd w10, 0(x26)
    bn.add w0, w0, w19              /* eat row-95 diagonal so P2 starts at slot 4656 */

    /* ---- phase t^T*O: L = t^T*O (O = scalar source, 2 cols / 96B per outer iter) ---- */
    lw x11, 12(x8)                 /* O */
    lw x12, 8(x8)                  /* L */
    li x29, 3
    li x28, 4
    li x27, 5
    li x26, 6
    li x25, 17
    csrrw x0, mod1, x0
    loopi 32, 34
        lw x9, 16(x8)             /* t base */
        bn.lid x29, 0(x11++)      /* w3 = O col_i, w4 = col_i+1|col_i, w5 = col_i+1 */
        bn.lid x28, 0(x11++)
        bn.lid x27, 0(x11++)
        bn.wsrw acc, w31
        csrrw x0, mod1, x0
        loopi 32, 4
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.gfmul.4.acc.inc w1, w6, w3
            bn.gfmul.4.acc.inc w1, w17, w3
        csrrw x0, mod1, x0
        loopi 16, 4
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.gfmul.4.acc.inc w1, w6, w4
            bn.gfmul.4.acc.inc w1, w17, w4
        bn.sd w1, 0(x12++)      /* L[col_i] */
        bn.wsrw acc, w31
        li x9, 32
        csrrw x0, mod1, x9        /* mod1 = 32 for col_i+1's low half */
        lw x9, 16(x8)
        loopi 16, 4
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.gfmul.4.acc.inc w1, w6, w4
            bn.gfmul.4.acc.inc w1, w17, w4
        csrrw x0, mod1, x0
        loopi 32, 4
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.gfmul.4.acc.inc w1, w6, w5
            bn.gfmul.4.acc.inc w1, w17, w5
        bn.sd w1, 0(x12++)      /* L[col_i+1] */

    csrrw x0, mod1, x0            /* mod1 = 0 */

    /* ---- phase v^T*P2: L ^= vin^T*P2 (stream continues at slot 4656) ---- */
    lw x12, 8(x8)
    lw x11, 4(x8)                 /* vinegar */
    li x31, 3
    bn.lid x31++, 0(x11)
    bn.lid x31, 32(x11)

    loopi 96, 13
        add x15, x0, x12          /* L ptr = base */
        loopi 64, 9
            bn.mov w18, w0
            jal x1, aes128_sign
            csrrw x0, mod0, x17
            bn.add w0, w0, w19
            bn.ld w10, 0(x15)
            bn.gfmul.4 w12, w2, w3                /* vin[r]*P2[r][c] */
            bn.xor w10, w10, w12
            bn.sd w10, 0(x15)
            addi x15, x15, 32
        bn.rshi w3, w4, w3 >> 4                  /* vin[r] -> vin[r+1] */
        bn.rshi w4, w31, w4 >> 4

    li x5, 3104
    add x2, x2, x5
    ret

#else
/* ===================== swonly (pure SW: no bn.gfmul, no bn.aes128) =====================
 * GF16 L-direct in software: GF MAC via gf16_macc_sw (w16=0x88../nibble msb, w19=scalar),
 * AES-CTR via AES_128_keyschedule (round keys -> DMEM) + aes128_dual_table (w18=IV, w2=ct).
 * chain t[row]^=vin[col]*e and scatter t[col]^=vin[row]*e are per-entry memory RMW (no ACC).
 * Fused y like the HW arms (one P1 pass): diag slots generated (not skipped), y ^= e*vin[r]^2
 * via two chained MACs; off-diag rows recovered by XOR-differencing t[row] (stash w8), then
 * y ^= vin[row]*chain. y lives in w7, stored once after build-t. w19 reloaded before every
 * macc call (helper shifts it).
 * Counter w21, +2inc w22 (macc-safe; aes128_dual_table is WDR-GPR-only, touches only w2/w18).
 * t/L pointers in AES-preserved GPRs (x9,x23,x24); x4 mirrors frame base x8 (x3 is caller-owned).
 * in  : x10 pk_seed, x11 vinegar(96 nib), x12 L out(64x32B), x13 O, x14 y out(32B)
 *       (x10-x13 preserved; x14 consumed)
 * clob: w0-w8, w15-w22, x4-x9, x14-x31   (net incl AES helper clobbers; x10-x13, w31 preserved)
 * wdr : w0/w18/w19/w20 macc scratch  w2 entry  w3/w4 vin[col]/Ocol  w5/w6 vin[row]/Ocol
 *       w7 y acc  w8 t[row] stash  w1 phase t^T*O acc  w15 rshi tmp  w16 msb  w21 ctr  w22 +2inc  w31 0
 * stack: 3296B (32 args + 192 round keys + 3072 t).  mod0 unused by SW GF.
 */
gf16_ldirect_96_64:
    bn.xor w31, w31, w31
    li x5, 3296
    sub x2, x2, x5
    add x8, x0, x2
    add x4, x0, x8                 /* x4 = frame-base mirror (AES preserves x1-x4; x3 caller-owned) */
    sw x10, 0(x8)
    sw x11, 4(x8)
    sw x12, 8(x8)
    sw x13, 12(x8)
    sw x14, 20(x8)                 /* y-out ptr (caller-owned 32B slot) */
    addi x9, x8, 224               /* t base */
    sw x9, 16(x8)

    /* zero L (64x32B) and t (96x32B) */
    add x14, x0, x12
    loopi 64, 1
        bn.sd w31, 0(x14++)
    add x14, x0, x9
    loopi 96, 1
        bn.sd w31, 0(x14++)

    /* AES round keys -> DMEM (x18 base = x8+32) */
    lw x10, 0(x8)                  /* pk_seed ptr */
    addi x11, x8, 32               /* RK dest */
    jal x1, AES_128_keyschedule
    add x8, x0, x4                 /* restore x8 (KS clobbers x5-x8) */
    addi x18, x8, 32               /* RK base */

    /* GF16 msb_mask 0x88../nibble -> w16 (built once; aes128_dual_table is WDR-safe) */
    bn.addi w16, w31, 0x88
    bn.rshi w15, w16, w31 >> 248
    bn.or   w16, w16, w15
    bn.rshi w15, w16, w31 >> 240
    bn.or   w16, w16, w15
    bn.rshi w15, w16, w31 >> 224
    bn.or   w16, w16, w15
    bn.rshi w15, w16, w31 >> 192
    bn.or   w16, w16, w15
    bn.rshi w15, w16, w31 >> 128
    bn.or   w16, w16, w15

    /* dual-block counter w21 (entry-0 = (0,0) diag), +2inc w22; loop skips the diag */
    bn.addi w21, w31, 1
    bn.rshi w21, w21, w31 >> 32
    bn.or  w22, w21, w21 >> 128
    bn.add w22, w22, w22

    /* vinegar windows: working w3/w4 (vin[col]), backup w5/w6 (vin[row]) */
    lw x11, 4(x8)
    li x31, 3
    bn.lid x31++, 0(x11)
    bn.lid x31, 32(x11)
    bn.mov w5, w3
    bn.mov w6, w4
    bn.mov w7, w31                 /* y = 0 (resident through build-t) */

    /* ---- phase build-t: t = (P1+P1^T)*vin, fused y ---- */
    add x23, x0, x9                /* x23 = t[row] ptr (AES-preserved) */
    li x25, 95                     /* row 0: 95 off-diag */

    /* outer = 16 pre + 1 loop-insn + 16 inner + 12 post = 45 */
    loopi 95, 45
        /* -- diag (r,r): generate e, y ^= e*vin[r]^2 (two MACs, w19 reloaded) -- */
        bn.mov w18, w21
        jal x1, aes128_dual_table  /* e -> w2 */
        bn.add w21, w21, w22
        bn.mov w20, w31            /* d = 0 */
        bn.mov w0, w2
        bn.mov w19, w5             /* scalar = vin[r] */
        jal x1, gf16_macc_sw       /* d = e*vin[r] */
        bn.mov w0, w20
        bn.mov w19, w5             /* reload (macc shifted w19) */
        bn.mov w20, w7
        jal x1, gf16_macc_sw       /* y ^= d*vin[r] */
        bn.mov w7, w20
        bn.ld w8, 0(x23)           /* stash t[row] pre-chain (y differencing) */
        bn.rshi w3, w4, w3 >> 4    /* vin[col] starts at col=r+1 */
        bn.rshi w4, w31, w4 >> 4
        addi x24, x23, 32          /* t[col] ptr = t[row+1] */
        loop x25, 16
            bn.mov w18, w21
            jal x1, aes128_dual_table     /* e -> w2 */
            bn.add w21, w21, w22
            bn.ld w20, 0(x23)             /* chain: t[row] ^= vin[col]*e */
            bn.mov w0, w2
            bn.mov w19, w3
            jal x1, gf16_macc_sw
            bn.sd w20, 0(x23)
            bn.ld w20, 0(x24)             /* scatter: t[col] ^= vin[row]*e */
            bn.mov w0, w2
            bn.mov w19, w5
            jal x1, gf16_macc_sw
            bn.sd w20, 0(x24)
            addi x24, x24, 32
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
        /* -- fused y: chain = t[row] after ^ stash; y ^= vin[row]*chain (before w5 slide) -- */
        bn.ld w0, 0(x23)
        bn.xor w0, w0, w8
        bn.mov w19, w5
        bn.mov w20, w7
        jal x1, gf16_macc_sw
        bn.mov w7, w20
        addi x23, x23, 32
        bn.rshi w5, w6, w5 >> 4          /* vin[row] -> vin[row+1] */
        bn.rshi w6, w31, w6 >> 4
        bn.mov w3, w5                    /* working = backup */
        bn.mov w4, w6
        addi x25, x25, -1

    /* row-95 lone diag: y ^= e*vin[95]^2 (w5 nib0 = vin[95] after the loop);
     * counter still advances -> P2 stays at slot 4656. Store y. */
    bn.mov w18, w21
    jal x1, aes128_dual_table
    bn.add w21, w21, w22
    bn.mov w20, w31
    bn.mov w0, w2
    bn.mov w19, w5
    jal x1, gf16_macc_sw
    bn.mov w0, w20
    bn.mov w19, w5
    bn.mov w20, w7
    jal x1, gf16_macc_sw
    lw x26, 20(x4)                       /* y-out ptr (x4 = frame mirror) */
    bn.sd w20, 0(x26)

    /* ---- phase t^T*O: L = t^T*O (2 cols/iter; O col = 96 nibbles = w3 lo64 + w4 hi32) ---- */
    add x8, x0, x4
    lw x11, 12(x8)                 /* O */
    lw x12, 8(x8)                  /* L out */
    li x29, 3
    li x28, 4
    li x27, 5
    li x26, 6
    li x25, 17
    /* outer = 17 singles + 4x(10-insn body) = 57 */
    loopi 32, 57
        lw x9, 16(x8)
        bn.lid x29, 0(x11++)       /* w3 = O col_i nibbles 0..63 */
        bn.lid x28, 0(x11++)       /* w4 = col_i 64..95 | col_i+1 0..31 */
        bn.lid x27, 0(x11++)       /* w5 = col_i+1 32..95 */
        bn.mov w19, w3             /* col_i scalar = w3 */
        bn.xor w1, w1, w1
        loopi 32, 10               /* col_i rows 0..63 */
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.mov w0, w6
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
            bn.mov w0, w17
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
        bn.mov w19, w4             /* col_i rows 64..95 = w4 low 32 nibbles */
        loopi 16, 10
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.mov w0, w6
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
            bn.mov w0, w17
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
        bn.sd w1, 0(x12++)       /* store L[col_i] */
        bn.xor w1, w1, w1
        bn.rshi w19, w31, w4 >> 128  /* col_i+1 rows 0..31 = w4 high 32 nibbles */
        lw x9, 16(x8)
        loopi 16, 10
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.mov w0, w6
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
            bn.mov w0, w17
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
        bn.mov w19, w5             /* col_i+1 rows 32..95 = w5 */
        loopi 32, 10
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.mov w0, w6
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
            bn.mov w0, w17
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
        bn.sd w1, 0(x12++)       /* store L[col_i+1] */

    /* ---- phase v^T*P2: L ^= vin^T*P2 (counter continues at slot 4656) ---- */
    lw x23, 8(x8)                  /* L base (AES-preserved reg) */
    lw x11, 4(x8)                  /* vinegar */
    li x31, 3
    bn.lid x31++, 0(x11)
    bn.lid x31, 32(x11)
    /* outer = 1 pre + 1 loop-insn + 9 inner + 2 post = 13 */
    loopi 96, 13
        add x24, x0, x23           /* L ptr = base */
        loopi 64, 9
            bn.mov w18, w21
            jal x1, aes128_dual_table
            bn.add w21, w21, w22
            bn.ld w20, 0(x24)
            bn.mov w0, w2
            bn.mov w19, w3         /* scalar = vin[r] */
            jal x1, gf16_macc_sw
            bn.sd w20, 0(x24)
            addi x24, x24, 32
        bn.rshi w3, w4, w3 >> 4    /* vin[r] -> vin[r+1] */
        bn.rshi w4, w31, w4 >> 4

    /* restore caller args (aes128_dual_table clobbered x10-x16) */
    lw x10, 0(x4)
    lw x11, 4(x4)
    lw x12, 8(x4)
    lw x13, 12(x4)
    li x5, 3296
    add x2, x2, x5
    ret

#endif
