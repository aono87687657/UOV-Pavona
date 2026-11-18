/* gf256_ldirect_68_44: build the UOV-Ip GE matrix L + quadratic y per attempt, no S buffer.
 *   L = t^T*O + vin^T*P2,  t = (P1+P1^T)*vin    GF256 (poly 0x11B), v=68, o=44.
 *   y = vin^T*P1*vin (64B), fused into the single P1 stream: y ^= vin[row]*chain (off-diag
 *   ACC/ACCH chain) + P1[row][row]*vin[row]^2 (diagonal), RMW'd into the caller y slot (x14).
 * P1 is streamed once from AES-CTR (expand_352 batches). Diagonals are skipped
 * (P1+P1^T diagonal = 0) but still advance the counter. vin scalar stays at byte0
 * of its window (mod1=0); the window slides via bn.rshi (vinegar spans 3 WDRs).
 *   build-t : per off-diag e@(row,col)  t[row] ^= vin[col]*e (ACC/ACCH chains), t[col] ^= vin[row]*e (mem RMW)
 *   t^T*O   : L = t^T*O            (row_mul_O; t = 64B-padded pair layout)
 *   v^T*P2  : keep streaming       L[c] ^= vin[r]*P2[r][c]
 * in    : x10 pk_seed(16B), x11 vinegar(68B), x12 L out(4096B), x13 O, x14 y out(64B)
 * clob  : w0-w30, ACC, ACCH, x5-x9, x14-x17, x19, x26-x31  (w31, x10-x13 preserved; x14 consumed)
 * wdr   : w0-w15 expand batch  w16 prod  w18 IV  w19 +2inc  w20/w21 t[col] RMW
 *         w22-w24 vin[row] win  w25-w27 vin[col] win  w28/w29 t[row] chains  w30 RK0  w31 0
 * stack : 4640B frame (32 args + 256 regen-spill + 4352 t), freed on ret.  mod0=0x11B, mod1=0.
 * AES key schedule: bngfaes = inline bn.aes128.kf; bngfonly = jal sw_key_schedule (SW
 * KeySchedule_sign), forward layout w20..w29 = RK1..RK10. expand_352 picks its tier by build.
 */

.section .text
.balign 4
.global gf256_ldirect_68_44

#if defined(GF_INSTRUCTIONS)

gf256_ldirect_68_44:
    /* frame: [0..31] args (x10-x13), [32..287] regen-spill area (w22-w29), [288..4639] t */
    li x5, 4640
    sub x2, x2, x5
    sw x10, 0(x2)
    sw x11, 4(x2)
    sw x12, 8(x2)
    sw x13, 12(x2)
    sw x14, 16(x2)                  /* y-out ptr (caller-owned 64B slot) */

    bn.xor w31, w31, w31
    lw x26, 16(x2)                  /* y ptr: zeroed here, then loop-invariant (regen/helpers keep x26) */
    bn.sd w31, 0(x26)
    bn.sd w31, 32(x26)
    li x31, 0x11b
    csrrw x0, mod0, x31             /* GF(256) poly for gfmul */
    csrrw x0, mod1, x0              /* mod1 = 0: gfmul.8 scalar = wrs2 byte 0 */

    /* ---- zero L (4,096 B) and t (4,352 B) ---- */
    add x14, x0, x12

    loopi 128, 1
        bn.sd w31, 0(x14++)        /* L: 128 x 32 B */
    addi x14, x2, 288              /* t base (after args + regen-spill area) */
    loopi 136, 1
        bn.sd w31, 0(x14++)        /* t: 136 x 32 B */

    /* ---- AES key schedule (RK0..RK10), IV = 1, inc = +2 dual ---- */
    bn.ld w30, 0(x10)              /* w30 = pk_seed low 128 */
    bn.or w30, w30, w30 << 128
    #if defined(AES_INSTRUCTIONS)
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
    #else
        jal x1, sw_key_schedule        /* w20..w29 = RK1..RK10 (SW, forward) */
        /* cache the schedule once; the 3 re-derive sites reload (10 lid, not 10 KS) */
        la x5, rk_cache
        li x17, 20
        bn.sid x17, 0(x5)
        addi x17, x17, 1
        bn.sid x17, 32(x5)
        addi x17, x17, 1
        bn.sid x17, 64(x5)
        addi x17, x17, 1
        bn.sid x17, 96(x5)
        addi x17, x17, 1
        bn.sid x17, 128(x5)
        addi x17, x17, 1
        bn.sid x17, 160(x5)
        addi x17, x17, 1
        bn.sid x17, 192(x5)
        addi x17, x17, 1
        bn.sid x17, 224(x5)
        addi x17, x17, 1
        bn.sid x17, 256(x5)
        addi x17, x17, 1
        bn.sid x17, 288(x5)
    #endif
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160    /* w19 = +2 per 128-bit lane (dual-block inc) */
    bn.addi w18, w31, 1
    bn.rshi w18, w18, w31 >> 32     /* IV = counter 1 at bytes 12..15 per lane */

    jal x1, expand_352              /* w0..w15 = P1 entries 0..7 */

    /* ---- vinegar windows: backup w22..w24, working w25..w27 ---- */
    li x31, 22
    bn.lid x31++, 0(x11)
    bn.lid x31++, 32(x11)
    bn.lid x31++, 64(x11)
    bn.mov w25, w22
    bn.mov w26, w23
    bn.mov w27, w24

    /* ---- phase build-t loop state ----
     * x29 = batch pair index (0,2,..,14; 16 = exhausted), x28 = 16, x30 = 1,
     * x14 = t[row] write ptr, x15 = t[col] scatter ptr, x7 = off-diag count.
     * Off-diag inner is a head/mid/tail split (off=x29>>1): x5=off, x6=head,
     * x8=mid batches, x9=tail. Rows 0..66 looped (67); row 67 = a lone diagonal
     * consumed after the loop (t[67] built by earlier rows' scatter).
     */
    li x29, 0
    li x28, 16
    li x30, 1
    addi x14, x2, 288               /* t[row] ptr = t base     */
    li x7, 67                       /* row 0: 67 off-diag      */

    /* rows 0..59 hybrid (len>=8): diag + head/mid/tail off-diag + fused-y/row-end */
    loopi 60, 203
        /* diagonal slot (row==col): fused y ^= P1[r][r]*vin[r]^2 */
        bn.movr x0, x29++
        bn.movr x30, x29++
        bn.gfmul.8 w16, w22, w22
        bn.gfmul.8 w20, w1, w16
        bn.gfmul.8 w16, w0, w16
        bn.ld w21, 0(x26)
        bn.xor w21, w21, w16
        bn.sd w21, 0(x26)
        bn.ld w21, 32(x26)
        bn.xor w21, w21, w20
        bn.sd w21, 32(x26)
        bne x29, x28, bt_skip_d_h
        jal x1, regen_p1_batch
        bt_skip_d_h: bn.rshi w25, w26, w25 >> 8
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w31, w27 >> 8
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        addi x15, x14, 64
        /* off = x29>>1; h=(8-off)&7; nb=(L-h)>>3; t=(L-h)&7  (L=x7) */
        srli x5, x29, 1
        li x31, 8
        sub x6, x31, x5
        andi x6, x6, 7
        sub x31, x7, x6
        srli x8, x31, 3
        andi x9, x31, 7
        beq x6, x0, bt_skip_head
        loop x6, 18
            bn.movr x0, x29++
            bn.movr x30, x29++
            bn.gfmul.8.acc  w28, w0, w25
            bn.gfmul.8.acch w29, w1, w25
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w0, w22
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w1, w22
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            bne x29, x28, bt_h_skip
            jal x1, regen_p1_batch
            bt_h_skip: addi x15, x15, 64
            bn.rshi w25, w26, w25 >> 8
            bn.rshi w26, w27, w26 >> 8
            bn.rshi w27, w31, w27 >> 8
        bt_skip_head:
        beq x8, x0, bt_skip_mid
        loop x8, 113
            bn.gfmul.8.acc  w28, w0, w25
            bn.gfmul.8.acch w29, w1, w25
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w0, w22
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w1, w22
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.rshi w25, w26, w25 >> 8
            bn.rshi w26, w27, w26 >> 8
            bn.rshi w27, w31, w27 >> 8
            bn.gfmul.8.acc  w28, w2, w25
            bn.gfmul.8.acch w29, w3, w25
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w2, w22
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w3, w22
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.rshi w25, w26, w25 >> 8
            bn.rshi w26, w27, w26 >> 8
            bn.rshi w27, w31, w27 >> 8
            bn.gfmul.8.acc  w28, w4, w25
            bn.gfmul.8.acch w29, w5, w25
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w4, w22
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w5, w22
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.rshi w25, w26, w25 >> 8
            bn.rshi w26, w27, w26 >> 8
            bn.rshi w27, w31, w27 >> 8
            bn.gfmul.8.acc  w28, w6, w25
            bn.gfmul.8.acch w29, w7, w25
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w6, w22
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w7, w22
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.rshi w25, w26, w25 >> 8
            bn.rshi w26, w27, w26 >> 8
            bn.rshi w27, w31, w27 >> 8
            bn.gfmul.8.acc  w28, w8, w25
            bn.gfmul.8.acch w29, w9, w25
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w8, w22
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w9, w22
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.rshi w25, w26, w25 >> 8
            bn.rshi w26, w27, w26 >> 8
            bn.rshi w27, w31, w27 >> 8
            bn.gfmul.8.acc  w28, w10, w25
            bn.gfmul.8.acch w29, w11, w25
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w10, w22
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w11, w22
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.rshi w25, w26, w25 >> 8
            bn.rshi w26, w27, w26 >> 8
            bn.rshi w27, w31, w27 >> 8
            bn.gfmul.8.acc  w28, w12, w25
            bn.gfmul.8.acch w29, w13, w25
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w12, w22
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w13, w22
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.rshi w25, w26, w25 >> 8
            bn.rshi w26, w27, w26 >> 8
            bn.rshi w27, w31, w27 >> 8
            bn.gfmul.8.acc  w28, w14, w25
            bn.gfmul.8.acch w29, w15, w25
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w14, w22
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w15, w22
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            jal x1, regen_p1_batch
            addi x15, x15, 64
            bn.rshi w25, w26, w25 >> 8
            bn.rshi w26, w27, w26 >> 8
            bn.rshi w27, w31, w27 >> 8
        bt_skip_mid:
        beq x9, x0, bt_skip_tail
        loop x9, 18
            bn.movr x0, x29++
            bn.movr x30, x29++
            bn.gfmul.8.acc  w28, w0, w25
            bn.gfmul.8.acch w29, w1, w25
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w0, w22
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w1, w22
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            bne x29, x28, bt_t_skip
            jal x1, regen_p1_batch
            bt_t_skip: addi x15, x15, 64
            bn.rshi w25, w26, w25 >> 8
            bn.rshi w26, w27, w26 >> 8
            bn.rshi w27, w31, w27 >> 8
        bt_skip_tail:
        /* fused y: off-diag part y ^= vin[row]*chain */
        bn.gfmul.8 w16, w28, w22
        bn.gfmul.8 w20, w29, w22
        bn.ld w21, 0(x26)
        bn.xor w21, w21, w16
        bn.sd w21, 0(x26)
        bn.ld w21, 32(x26)
        bn.xor w21, w21, w20
        bn.sd w21, 32(x26)
        bn.ld w16, 0(x14)
        bn.ld w20, 32(x14)
        bn.xor w28, w28, w16
        bn.xor w29, w29, w20
        bn.sd w28, 0(x14)
        bn.sd w29, 32(x14)
        addi x14, x14, 64
        bn.rshi w22, w23, w22 >> 8
        bn.rshi w23, w24, w23 >> 8
        bn.rshi w24, w31, w24 >> 8
        bn.mov w25, w22
        bn.mov w26, w23
        bn.mov w27, w24
        addi x7, x7, -1
    /* rows 60..66 (off-diag len<8): pure-cursor body, identical to the original loop */
    loopi 7, 60
        /* diagonal slot (row==col): fused y ^= P1[r][r]*vin[r]^2 */
        bn.movr x0, x29++
        bn.movr x30, x29++
        bn.gfmul.8 w16, w22, w22
        bn.gfmul.8 w20, w1, w16
        bn.gfmul.8 w16, w0, w16
        bn.ld w21, 0(x26)
        bn.xor w21, w21, w16
        bn.sd w21, 0(x26)
        bn.ld w21, 32(x26)
        bn.xor w21, w21, w20
        bn.sd w21, 32(x26)
        bne x29, x28, bt_skip_d_p
        jal x1, regen_p1_batch
        bt_skip_d_p: bn.rshi w25, w26, w25 >> 8
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w31, w27 >> 8
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        addi x15, x14, 64
        loop x7, 18
            bn.movr x0, x29++
            bn.movr x30, x29++
            bn.gfmul.8.acc  w28, w0, w25
            bn.gfmul.8.acch w29, w1, w25
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w0, w22
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w1, w22
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            bne x29, x28, bt_e_skip
            jal x1, regen_p1_batch
            bt_e_skip: addi x15, x15, 64
            bn.rshi w25, w26, w25 >> 8
            bn.rshi w26, w27, w26 >> 8
            bn.rshi w27, w31, w27 >> 8
        /* fused y: off-diag part y ^= vin[row]*chain */
        bn.gfmul.8 w16, w28, w22
        bn.gfmul.8 w20, w29, w22
        bn.ld w21, 0(x26)
        bn.xor w21, w21, w16
        bn.sd w21, 0(x26)
        bn.ld w21, 32(x26)
        bn.xor w21, w21, w20
        bn.sd w21, 32(x26)
        bn.ld w16, 0(x14)
        bn.ld w20, 32(x14)
        bn.xor w28, w28, w16
        bn.xor w29, w29, w20
        bn.sd w28, 0(x14)
        bn.sd w29, 32(x14)
        addi x14, x14, 64
        bn.rshi w22, w23, w22 >> 8
        bn.rshi w23, w24, w23 >> 8
        bn.rshi w24, w31, w24 >> 8
        bn.mov w25, w22
        bn.mov w26, w23
        bn.mov w27, w24
        addi x7, x7, -1

    /* rows 0..66 consumed 67 diag + 2,278 off-diag = 2,345 slots; row 67 is a
     * single diagonal entry (slot 2,346): no t contribution, but fused y needs
     * y ^= P1[67][67]*vin[67]^2 (w22 byte0 = vin[67] after the loop). Consume it. */
    bne x29, x28, ld_skip_d67
    jal x1, regen_p1_batch
    ld_skip_d67:
    bn.movr x0, x29++
    bn.movr x30, x29++
    bn.gfmul.8 w16, w22, w22
    bn.gfmul.8 w20, w1, w16
    bn.gfmul.8 w16, w0, w16
    bn.ld w21, 0(x26)
    bn.xor w21, w21, w16
    bn.sd w21, 0(x26)
    bn.ld w21, 32(x26)
    bn.xor w21, w21, w20
    bn.sd w21, 32(x26)

    /* ================= phase t^T*O: L_base = t^T * O ================= */
    csrrw x0, mod1, x0
    addi x6, x2, 288                /* stream base = t */
    add x5, x0, x6
    lw x11, 12(x2)                  /* x11 = O */
    lw x12, 8(x2)                   /* x12 = L out */
    li x19, 1
    li x28, 19
    li x29, 20
    jal x1, row_mul_O          /* clobbers w0..w20, x5,x6,x8,x11,x12 */

    /* ================= phase v^T*P2: L ^= vin^T * P2 ================= */
    csrrw x0, mod1, x0              /* mod1 = 0 (row_mul already reset it; keep for clarity) */
    /* re-derive RKs (w20..w29 clobbered above; w30 = RK0 survived row_mul) */
    #if defined(AES_INSTRUCTIONS)
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
    #else
        la x5, rk_cache                /* reload cached RK1..RK10 (built at init) */
        li x17, 20
        bn.lid x17++, 0(x5)
        bn.lid x17++, 32(x5)
        bn.lid x17++, 64(x5)
        bn.lid x17++, 96(x5)
        bn.lid x17++, 128(x5)
        bn.lid x17++, 160(x5)
        bn.lid x17++, 192(x5)
        bn.lid x17++, 224(x5)
        bn.lid x17++, 256(x5)
        bn.lid x17++, 288(x5)
    #endif
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160
    /* IV = P1/P2 boundary batch base: [22*293+1 | 22*293] (trimat idiom) */
    bn.addi w0, w31, 22
    bn.addi w1, w31, 293
    bn.mulqacc.wo.z w0, w0.0, w1.0, 0
    bn.addi w1, w0, 1
    bn.or w18, w0, w1 << 128
    bn.rshi w18, w18, w31 >> 160

    jal x1, expand_352              /* slots 0,1 = P1 tail; P2 from slot 2 */

    /* vinegar window directly in w25..w27 (no backup needed: P2 walk is 1 byte
     * per row, never resets; regen saves/restores the current shifted state) */
    lw x11, 4(x2)
    li x31, 25
    bn.lid x31++, 0(x11)
    bn.lid x31++, 32(x11)
    bn.lid x31++, 64(x11)

    li x29, 4                       /* skip slots 0,1: pair index starts at 2*2 */
    li x28, 16
    li x30, 1
    lw x12, 8(x2)                   /* L base */

    /* outer body = 1 pre + 1 loop-insn + 13 inner + 3 post = 18 */
    loopi 34, 811
        add x15, x0, x12
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w4, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w5, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w6, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w7, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w8, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w9, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w10, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w11, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w12, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w13, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w14, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w15, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            jal x1, regen_p2_batch
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w0, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w1, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w2, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w3, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w4, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w5, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w6, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w7, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w8, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w9, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w10, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w11, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w12, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w13, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w14, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w15, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            jal x1, regen_p2_batch
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w0, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w1, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w2, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w3, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w4, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w5, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w6, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w7, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w8, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w9, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w10, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w11, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w12, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w13, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w14, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w15, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            jal x1, regen_p2_batch
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w0, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w1, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w2, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w3, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w4, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w5, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w6, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w7, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w8, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w9, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w10, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w11, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w12, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w13, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w14, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w15, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            jal x1, regen_p2_batch
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w0, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w1, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w2, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w3, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w4, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w5, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w6, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w7, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w8, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w9, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w10, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w11, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w12, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w13, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w14, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w15, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            jal x1, regen_p2_batch
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w0, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w1, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w2, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w3, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w4, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w5, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w6, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w7, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w8, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w9, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w10, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w11, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
        bn.rshi w25, w26, w25 >> 8
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w31, w27 >> 8
        add x15, x0, x12
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w12, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w13, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w14, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w15, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            jal x1, regen_p2_batch
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w0, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w1, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w2, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w3, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w4, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w5, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w6, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w7, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w8, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w9, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w10, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w11, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w12, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w13, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w14, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w15, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            jal x1, regen_p2_batch
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w0, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w1, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w2, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w3, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w4, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w5, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w6, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w7, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w8, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w9, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w10, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w11, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w12, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w13, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w14, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w15, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            jal x1, regen_p2_batch
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w0, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w1, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w2, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w3, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w4, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w5, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w6, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w7, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w8, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w9, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w10, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w11, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w12, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w13, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w14, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w15, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            jal x1, regen_p2_batch
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w0, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w1, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w2, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w3, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w4, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w5, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w6, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w7, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w8, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w9, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w10, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w11, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w12, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w13, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w14, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w15, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            jal x1, regen_p2_batch
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w0, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w1, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w2, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w3, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w4, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w5, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w6, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w7, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w8, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w9, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w10, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w11, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w12, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w13, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w14, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w15, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            jal x1, regen_p2_batch
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w0, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w1, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
            bn.ld w20, 0(x15)
            bn.ld w21, 32(x15)
            bn.gfmul.8 w16, w2, w25
            bn.xor w20, w20, w16
            bn.gfmul.8 w16, w3, w25
            bn.xor w21, w21, w16
            bn.sd w20, 0(x15)
            bn.sd w21, 32(x15)
            addi x15, x15, 64
        bn.rshi w25, w26, w25 >> 8
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w31, w27 >> 8

    /* ---- epilogue ---- */
    lw x10, 0(x2)
    lw x11, 4(x2)
    lw x12, 8(x2)
    lw x13, 12(x2)
    li x5, 4640
    add x2, x2, x5
    ret

/* regen_p1_batch (phase build-t): batch exhausted mid-stream. Save live working WDRs, restore
 * RK identity for expand_352, expand, restore, re-seat ACC/ACCH chains.
 * w28/w29 may be stale if no gfmul ran since the row's wsrw-zero (diag slot at a
 * batch boundary), so capture the true accumulators with bn.wsrr BEFORE saving. */
regen_p1_batch:
    /* w20/w21 dead at both call sites (t[col] pair already stored / not yet
     * loaded); w19 = +2-inc constant survives (KF chain stops at w20,
     * expand_352 reads it). Live: w22..w27 windows + w28/w29 chains. */
    bn.wsrr w28, acc
    bn.wsrr w29, acch
    bn.sd w22, 32(x2)
    bn.sd w23, 64(x2)
    bn.sd w24, 96(x2)
    bn.sd w25, 128(x2)
    bn.sd w26, 160(x2)
    bn.sd w27, 192(x2)
    bn.sd w28, 224(x2)
    bn.sd w29, 256(x2)
    #if defined(AES_INSTRUCTIONS)
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
    #else
        la x5, rk_cache                /* reload cached RK1..RK10 (built at init) */
        li x17, 20
        bn.lid x17++, 0(x5)
        bn.lid x17++, 32(x5)
        bn.lid x17++, 64(x5)
        bn.lid x17++, 96(x5)
        bn.lid x17++, 128(x5)
        bn.lid x17++, 160(x5)
        bn.lid x17++, 192(x5)
        bn.lid x17++, 224(x5)
        bn.lid x17++, 256(x5)
        bn.lid x17++, 288(x5)
    #endif
    jal x1, expand_352
    bn.ld w22, 32(x2)
    bn.ld w23, 64(x2)
    bn.ld w24, 96(x2)
    bn.ld w25, 128(x2)
    bn.ld w26, 160(x2)
    bn.ld w27, 192(x2)
    bn.ld w28, 224(x2)
    bn.ld w29, 256(x2)
    bn.wsrw acc,  w28
    bn.wsrw acch, w29
    li x29, 0
    ret

/* regen_p2_batch (phase v^T*P2): no ACC chains live; w20/w21 dead at the call site
 * (RMW pair already stored), w22..w24 unused in P2, w19 inc untouched by
 * KF chain/expand_352 (w17 is now free). Only vinegar window w25..w27 lives. */
regen_p2_batch:
    bn.sd w25, 128(x2)
    bn.sd w26, 160(x2)
    bn.sd w27, 192(x2)
    #if defined(AES_INSTRUCTIONS)
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
    #else
        la x5, rk_cache                /* reload cached RK1..RK10 (built at init) */
        li x17, 20
        bn.lid x17++, 0(x5)
        bn.lid x17++, 32(x5)
        bn.lid x17++, 64(x5)
        bn.lid x17++, 96(x5)
        bn.lid x17++, 128(x5)
        bn.lid x17++, 160(x5)
        bn.lid x17++, 192(x5)
        bn.lid x17++, 224(x5)
        bn.lid x17++, 256(x5)
        bn.lid x17++, 288(x5)
    #endif
    jal x1, expand_352
    bn.ld w25, 128(x2)
    bn.ld w26, 160(x2)
    bn.ld w27, 192(x2)
    li x29, 0
    ret

#if !defined(AES_INSTRUCTIONS)
/* RK cache (bngfonly): schedule built ONCE at kernel init by sw_key_schedule,
 * dual-stored RK1..RK10 parked here; the 3 re-derive sites reload via 10 bn.lid
 * (20 cyc) instead of 10 KeySchedule_sign calls (~700 cyc). 320 B = exact. */
.section .data
.balign 32
rk_cache:  .zero 320
.section .text

/* sw_key_schedule (bngfonly): RK0 -> RK1..RK10 via SW KeySchedule_sign.
* in : w30 = RK0|RK0 (dual-stored).  out: w20..w29 = RK1..RK10 (each dual-stored).
* clob: w7-w9, w11-w17, x5,x6.  needs aes_constants_sign (affine/msb/rcon).  mod0 left 0x11B. */
sw_key_schedule:
    la x5, affine_value
    li x6, 8
    bn.lid x6, 0(x5)               /* w8 = affine_value */
    la x5, msb_mask
    li x6, 9
    bn.lid x6, 0(x5)               /* w9 = msb_mask */
    la x5, rcon
    li x6, 11
    bn.lid x6, 0(x5)               /* w11 = rcon carrier */
    bn.rshi w17, w31, w30 >> 128   /* w17 = RK0 (low 128, high 0) */
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
    ret
#endif

#else
/* ===================== swonly (pure SW: no bn.gfmul, no bn.aes128) =====================
 * Same L = t^T*O + vin^T*P2 algorithm, fused y like the HW arm (one P1 pass).
 * GF MAC via gf256_macc_dualvec_sw (bit-serial, w16=msb 0x80/byte, w17=0x1b bcast).
 * AES-CTR P1/P2 stream via AES_128_keyschedule (round keys -> DMEM) +
 * expand_352_table (x10 = RK base, x13 = LE block counter).
 * No ACC/ACCH: the chain t[row]^=vin[col]*e is a per-entry memory RMW; the row
 * chain for y is recovered by XOR-differencing (t[row] after ^ before the row),
 * so the inner entry loop is untouched. Diag y = two chained scalar MACs.
 * in  : x10 pk_seed(16B), x11 vinegar(68B), x12 L out(4096B), x13 O, x14 y out(64B)
 *       (x10-x13 preserved; x14 consumed)
 * clob: w0-w30, x4-x9, x14-x22, x26, x28-x31   (net incl AES helper clobbers)
 * wdr : w0-w15 expand batch  w16 msb  w17 0x1b  w18/w19 helper scratch  w20/w30 helper acc
 *       w22-w24 vin[row] win  w25-w27 vin[col] win  w28/w29 entry save + row-end
 *       w0/w1 save  w31 0
 * stack: 4640B frame (32 args + 192 round keys + 64 chain stash + 4352 t).  mod0=0x11B.
 */
gf256_ldirect_68_44:
    li x5, 4640
    sub x2, x2, x5
    sw x10, 0(x2)
    sw x11, 4(x2)
    sw x12, 8(x2)
    sw x13, 12(x2)
    sw x14, 16(x2)

    bn.xor w31, w31, w31
    add x26, x0, x14               /* y ptr, loop-invariant (all callees keep x26) */
    bn.sd w31, 0(x26)
    bn.sd w31, 32(x26)
    li x31, 0x11b
    csrrw x0, mod0, x31             /* GF(256) poly (AES + SW GF share 0x11B) */

    /* ---- zero L (4,096 B) and t (4,352 B) ---- */
    add x14, x0, x12
    loopi 128, 1
        bn.sd w31, 0(x14++)        /* L: 128 x 32 B */
    addi x14, x2, 288              /* t base (after args + round keys + chain stash) */
    loopi 136, 1
        bn.sd w31, 0(x14++)        /* t: 136 x 32 B */

    /* ---- AES round keys -> DMEM [32..207]; x18 = RK base survivor ---- */
    lw x10, 0(x2)                  /* pk_seed ptr (key input) */
    addi x11, x2, 32               /* RK output base */
    jal x1, AES_128_keyschedule
    addi x18, x2, 32

    /* ---- SW GF helper constants ---- */
    la x4, msb_mask
    li x5, 16
    bn.lid x5, 0(x4)               /* w16 = 0x80/byte */
    bn.addi w17, w31, 0x1b         /* w17 = 0x1b broadcast (low byte) */

    /* ---- first P1 batch (counter 0) ---- */
    li x13, 0
    addi x10, x18, 0
    jal x1, expand_352_table       /* w0..w15 = entries 0..7; x13 -> 22 */

    /* ---- vinegar windows: backup w22..w24 (vin[row]), working w25..w27 (vin[col]) ---- */
    lw x11, 4(x2)
    li x31, 22
    bn.lid x31++, 0(x11)
    bn.lid x31++, 32(x11)
    bn.lid x31, 64(x11)
    bn.mov w25, w22
    bn.mov w26, w23
    bn.mov w27, w24

    /* ---- phase build-t loop state ---- */
    li x29, 0                       /* batch pair index */
    li x28, 16                      /* exhausted sentinel */
    li x30, 1                       /* hi-dest WDR index for bn.movr */
    addi x8, x2, 288                /* t[row] ptr (x8/x9: expand_352_table saves/restores them) */
    li x7, 67                       /* row 0: 67 off-diag */

    /* outer body = 24 pre + 1 loop-insn + 24 inner + 24 post = 73 */
    loopi 67, 73
        /* -- diagonal slot (row==col): fused y ^= e*vin[r]^2 (two chained MACs) -- */
        bn.movr x0, x29++
        bn.movr x30, x29++
        bn.mov w20, w31             /* d = 0 */
        bn.mov w30, w31
        bn.mov w19, w22             /* scalar = vin[r] @ byte0 */
        jal x1, gf256_macc_dualvec_sw   /* d = e_diag*vin[r]; consumes w0/w1 */
        bn.mov w0, w20              /* vectors = d */
        bn.mov w1, w30
        bn.mov w19, w22             /* scalar again (helper shifted w19 out) */
        bn.ld w20, 0(x26)
        bn.ld w30, 32(x26)
        jal x1, gf256_macc_dualvec_sw   /* y ^= d*vin[r] */
        bn.sd w20, 0(x26)
        bn.sd w30, 32(x26)
        bne x29, x28, ld_skip_d
        jal x1, regen_batch_sw
        ld_skip_d: bn.rshi w25, w26, w25 >> 8
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w31, w27 >> 8
        addi x9, x8, 64             /* t[col] ptr = t[row+1] */
        /* -- stash t[row] before this row's chain lands (y differencing) -- */
        bn.ld w20, 0(x8)
        bn.ld w30, 32(x8)
        bn.sd w20, 224(x2)
        bn.sd w30, 256(x2)
        /* -- off-diagonal entries of this row -- */
        loop x7, 24
            bn.movr x0, x29++       /* w0 = entry lo */
            bn.movr x30, x29++      /* w1 = entry hi */
            bn.mov w28, w0          /* save entry (dualvec destroys w0/w1) */
            bn.mov w29, w1
            /* chain: t[row] ^= vin[col]*e  (mem RMW) */
            bn.ld w20, 0(x8)
            bn.ld w30, 32(x8)
            bn.mov w19, w25         /* scalar = vin[col] @ byte0 */
            jal x1, gf256_macc_dualvec_sw
            bn.sd w20, 0(x8)
            bn.sd w30, 32(x8)
            /* scatter: t[col] ^= vin[row]*e  (mem RMW) */
            bn.mov w0, w28          /* restore entry */
            bn.mov w1, w29
            bn.ld w20, 0(x9)
            bn.ld w30, 32(x9)
            bn.mov w19, w22         /* scalar = vin[row] @ byte0 */
            jal x1, gf256_macc_dualvec_sw
            bn.sd w20, 0(x9)
            bn.sd w30, 32(x9)
            bne x29, x28, ld_skip_e
            jal x1, regen_batch_sw
            ld_skip_e: addi x9, x9, 64
            bn.rshi w25, w26, w25 >> 8   /* next vin[col] */
            bn.rshi w26, w27, w26 >> 8
            bn.rshi w27, w31, w27 >> 8
        /* -- fused y: chain = t[row] after ^ before; y ^= vin[row]*chain.
         * w28/w29 guard batch entry 0 (fresh if the tail regen just fired). -- */
        bn.mov w28, w0
        bn.mov w29, w1
        bn.ld w0, 0(x8)
        bn.ld w1, 32(x8)
        bn.ld w20, 224(x2)
        bn.ld w30, 256(x2)
        bn.xor w0, w0, w20
        bn.xor w1, w1, w30
        bn.mov w19, w22             /* scalar = vin[row] (window slides below) */
        bn.ld w20, 0(x26)
        bn.ld w30, 32(x26)
        jal x1, gf256_macc_dualvec_sw
        bn.sd w20, 0(x26)
        bn.sd w30, 32(x26)
        bn.mov w0, w28
        bn.mov w1, w29
        /* -- row end: advance t[row]; backup window -> vin[row+1]; reset working -- */
        addi x8, x8, 64
        bn.rshi w22, w23, w22 >> 8
        bn.rshi w23, w24, w23 >> 8
        bn.rshi w24, w31, w24 >> 8
        bn.mov w25, w22
        bn.mov w26, w23
        bn.mov w27, w24
        addi x7, x7, -1

    /* rows 0..66 consumed 2,345 slots; row 67 is a lone diagonal (slot 2,346):
     * no t contribution, but fused y needs y ^= P1[67][67]*vin[67]^2
     * (w22 byte0 = vin[67] after the loop). Consume it. */
    bne x29, x28, ld_skip_d67
    jal x1, regen_batch_sw
    ld_skip_d67:
    bn.movr x0, x29++
    bn.movr x30, x29++
    bn.mov w20, w31
    bn.mov w30, w31
    bn.mov w19, w22
    jal x1, gf256_macc_dualvec_sw
    bn.mov w0, w20
    bn.mov w1, w30
    bn.mov w19, w22
    bn.ld w20, 0(x26)
    bn.ld w30, 32(x26)
    jal x1, gf256_macc_dualvec_sw
    bn.sd w20, 0(x26)
    bn.sd w30, 32(x26)

    /* ================= phase t^T*O: L = t^T * O ================= */
    addi x6, x2, 288                /* stream base = t */
    add x5, x0, x6
    lw x11, 12(x2)                  /* O */
    lw x12, 8(x2)                   /* L out */
    li x19, 1
    li x28, 19
    li x29, 20
    jal x1, row_mul_O          /* SW row_mul_O (64B-padded t-pair layout) */

    /* row_mul_O loads O columns into w2..w18, clobbering the SW GF consts — reload */
    la x4, msb_mask
    li x5, 16
    bn.lid x5, 0(x4)                /* w16 = 0x80/byte */
    bn.addi w17, w31, 0x1b          /* w17 = 0x1b broadcast */

    /* ================= phase v^T*P2: L ^= vin^T * P2 ================= */
    li x13, 6446                    /* P2 start block = 22*293 */
    addi x10, x18, 0
    jal x1, expand_352_table        /* slots 0,1 = P1 tail; P2 from slot 2 */
    li x29, 4                       /* skip slots 0,1 (pair index 2*2) */
    li x28, 16
    li x30, 1
    lw x11, 4(x2)
    li x31, 25
    bn.lid x31++, 0(x11)            /* vinegar window directly in w25..w27 */
    bn.lid x31++, 32(x11)
    bn.lid x31, 64(x11)
    lw x12, 8(x2)                   /* L base */

    /* outer body = 1 pre + 1 loop-insn + 11 inner + 3 post = 16 */
    loopi 68, 16
        add x9, x0, x12             /* L ptr resets to base each row (x9 survives expand) */
        loopi 44, 11
            bn.movr x0, x29++
            bn.movr x30, x29++
            bn.ld w20, 0(x9)
            bn.ld w30, 32(x9)
            bn.mov w19, w25         /* scalar = vin[r] @ byte0 */
            jal x1, gf256_macc_dualvec_sw
            bn.sd w20, 0(x9)
            bn.sd w30, 32(x9)
            bne x29, x28, ld_skip_p2
            jal x1, regen_batch_sw
            ld_skip_p2: addi x9, x9, 64
        bn.rshi w25, w26, w25 >> 8  /* next row: vin[r+1] */
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w31, w27 >> 8

    /* ---- epilogue ---- */
    lw x10, 0(x2)
    lw x11, 4(x2)
    lw x12, 8(x2)
    lw x13, 12(x2)
    li x5, 4640
    add x2, x2, x5
    ret

/* regen_batch_sw: batch exhausted -> refill w0..w15 from the CTR stream. expand_352_table
 * net-clobbers only x10/x13 and preserves w16-w31, so no window/const spill is needed. */
regen_batch_sw:
    addi x10, x18, 0
    jal x1, expand_352_table
    li x29, 0
    ret

#endif
