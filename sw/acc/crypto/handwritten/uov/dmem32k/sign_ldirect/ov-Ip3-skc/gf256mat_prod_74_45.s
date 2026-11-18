/* gf256mat_prod_74_45 (Ip3, padded O). y = A*b over GF(256). Holds the mid
 * row chain (w29, rows 32..63) in ACCH; w28 (rows 0..31) and w30 (rows
 * 64..73) share ACC. A is col-major with a 96-B (3-WDR) slot per column:
 * every column is w2/w3/w4 loaded straight - no realign shifts, no batch
 * windows. Slack lanes (74..95) multiply into masked-off bytes, so slack
 * must be initialized memory; its value is don't-care.
 *
 *   variant     cpp flag             body
 *   sw          (none)               SW gf256 multiply
 *   bngfonly    -DGF_INSTRUCTIONS    HW bn.gfmul.8/.acch (mod1=0 entry asm)
 *   bngfaes     -DAES_|GF_           HW bn.gfmul.8/.acch (explicit mod1=0 reset)
 *
 * in : x10 = y out (96B via w28/w29/w30, bytes 74..95 stored zero), x11 =
 *      A padded (col-major, 96 B/slot, 32-B aligned), x12 = b vector ptr
 *      (45 B in a 64-B slot, read-only)
 * clob (bngfaes) : x11 (+4320), x17, x31; w0-w4, w28-w31; ACC, ACCH;
 *                  FG0 M/L/Z; sets mod0=0x11b; mod1 reset entry+exit
 * clob (bngfonly): same, but mod1=0 ASSUMED on entry (exit reset only)
 * clob (sw)      : x4, x5, x11 (+4320), x17, x31; w0, w2-w4, w19-w23,
 *                  w26-w31 (w21 via gf256_macc_sw_batched); FG0 incl C
 * stack: none (all arms leaf-frame; sw's jals nest via the x1 call stack)
 */

.section .text
.balign 4
.global gf256mat_prod_74_45


#if defined(AES_INSTRUCTIONS) && defined(GF_INSTRUCTIONS)

/* =============== bngfaes (HW bn.gfmul.8, explicit mod1=0 reset) =============== */
gf256mat_prod_74_45:

    bn.xor w31, w31, w31
    li x31, 0x11b
    csrrw x0, mod0, x31
    csrrw x0, mod1, x0                  /* start mod1=0 (byte 0 of w0) */

    li x31, 0
    bn.lid x31, 0(x12)                  /* w0 = b[0..31]  */
    li x31, 1
    bn.lid x31, 32(x12)                 /* w1 = b[32..44] + pad */

    bn.mov w28, w31
    bn.mov w29, w31
    bn.mov w30, w31
    bn.wsrw acc, w31                    /* ACC = 0 (w28/w30 share ACC) */
    bn.wsrw acch, w31                   /* ACCH = 0 (w29 chain) */

    /* Cols 0..31: scalar = w0 via mod1; .inc wraps 31 -> 0 for w1. */
    loopi 32, 10
        li x17, 2
        bn.lid x17++, 0(x11)
        bn.lid x17++, 32(x11)
        bn.lid x17++, 64(x11)
        bn.wsrw acc, w28
        bn.gfmul.8.acc w28, w2, w0
        bn.gfmul.8.acch w29, w3, w0
        bn.wsrw acc, w30
        bn.gfmul.8.acc.inc w30, w4, w0
        addi x11, x11, 96

    /* Cols 32..44: scalar = w1, mod1 walks 0..12 (the last .inc dies at
     * the exit reset). */
    loopi 13, 10
        li x17, 2
        bn.lid x17++, 0(x11)
        bn.lid x17++, 32(x11)
        bn.lid x17++, 64(x11)
        bn.wsrw acc, w28
        bn.gfmul.8.acc w28, w2, w1
        bn.gfmul.8.acch w29, w3, w1
        bn.wsrw acc, w30
        bn.gfmul.8.acc.inc w30, w4, w1
        addi x11, x11, 96

    /* Reset mod1 before ret (per index-kernel convention) */
    csrrw x0, mod1, x0

    /* Mask w30: keep only bytes 0-9 */
    bn.not w0, w31
    bn.rshi w0, w31, w0 >> 176
    bn.and w30, w30, w0

    li x17, 28
    bn.sid x17++, 0(x10)
    bn.sid x17++, 32(x10)
    bn.sid x17++, 64(x10)

    ret

#elif defined(GF_INSTRUCTIONS)

/* =============== bngfonly (HW bn.gfmul.8, mod1=0 entry assumed) =============== */
gf256mat_prod_74_45:

    bn.xor w31, w31, w31
    li x31, 0x11b
    csrrw x0, mod0, x31
    /* mod1=0 assumed on entry per kernel exit convention */

    li x31, 0
    bn.lid x31, 0(x12)                  /* w0 = b[0..31]  */
    li x31, 1
    bn.lid x31, 32(x12)                 /* w1 = b[32..44] + pad */

    bn.mov w28, w31
    bn.mov w29, w31
    bn.mov w30, w31
    bn.wsrw acc, w31                    /* ACC = 0 (w28/w30 share ACC) */
    bn.wsrw acch, w31                   /* ACCH = 0 (w29 chain) */

    /* Cols 0..31: scalar = w0 via mod1; .inc wraps 31 -> 0 for w1. */
    loopi 32, 10
        li x17, 2
        bn.lid x17++, 0(x11)
        bn.lid x17++, 32(x11)
        bn.lid x17++, 64(x11)
        bn.wsrw acc, w28
        bn.gfmul.8.acc w28, w2, w0
        bn.gfmul.8.acch w29, w3, w0
        bn.wsrw acc, w30
        bn.gfmul.8.acc.inc w30, w4, w0
        addi x11, x11, 96

    /* Cols 32..44: scalar = w1, mod1 walks 0..12 (the last .inc dies at
     * the exit reset). */
    loopi 13, 10
        li x17, 2
        bn.lid x17++, 0(x11)
        bn.lid x17++, 32(x11)
        bn.lid x17++, 64(x11)
        bn.wsrw acc, w28
        bn.gfmul.8.acc w28, w2, w1
        bn.gfmul.8.acch w29, w3, w1
        bn.wsrw acc, w30
        bn.gfmul.8.acc.inc w30, w4, w1
        addi x11, x11, 96

    /* Reset mod1 before ret (per index-kernel convention) */
    csrrw x0, mod1, x0

    /* Mask w30: keep only bytes 0-9 */
    bn.not w0, w31
    bn.rshi w0, w31, w0 >> 176
    bn.and w30, w30, w0

    li x17, 28
    bn.sid x17++, 0(x10)
    bn.sid x17++, 32(x10)
    bn.sid x17++, 64(x10)

    ret

#else

/* =============== sw (SW gf256 multiply) =============== */
gf256mat_prod_74_45:

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
    bn.lid x31, 32(x12)           /* w27 = b[32..44] || pad */

    bn.mov w28, w31
    bn.mov w29, w31
    bn.mov w30, w31

    /* 45 identical columns: slot -> w2/w3/w4, helper per chunk, slide b
     * one byte so the scalar is always w26 byte 0. */
    loopi 45, 22
        li x17, 2
        bn.lid x17++, 0(x11)
        bn.lid x17++, 32(x11)
        bn.lid x17++, 64(x11)
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
        addi x11, x11, 96

    /* Mask w30: keep only bytes 0-9 (y[64..73]). */
    bn.not w0, w31
    bn.rshi w0, w31, w0 >> 176
    bn.and w30, w30, w0

    li x17, 28
    bn.sid x17++, 0(x10)
    bn.sid x17++, 32(x10)
    bn.sid x17++, 64(x10)

    ret

#endif
