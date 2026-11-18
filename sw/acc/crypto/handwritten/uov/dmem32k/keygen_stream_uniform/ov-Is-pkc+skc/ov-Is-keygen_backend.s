/* ov-Is-keygen_backend.s - backend arms for the keygen-Is stream_uniform outer.
 * bngfaes = inline bn.aes128 + bn.gfmul.4; bngfonly = AES_bngf compute-AES
 * helpers + bn.gfmul.4; sw = T-table AES + gf16_macc_sw. cpp picks the
 * arm. The R=4 fold is pure GF -> the same fold body is emitted in both
 * hw arms; the sw fold is its own column-major splice. */
/* ---- bngfaes arm (-DAES_INSTRUCTIONS -DGF_INSTRUCTIONS) ----
 * Inline bn.aes128 CTR (RKs w20..w30, P1 IV w1 rides across rows, P2 IV w2
 * per row). Runtime nibble-banding unifies the oracle band A/B (row<64: segA
 * 64-r on w3/w9 + segB 32 on w4/w10, cursor row; row>=64: segB 96-r on
 * w4/w10, cursor row-64). No jal -> x1 untouched. mod0=0x13 set by
 * window_init, inline AES leaves it (only compute-AES clobbers mod0). */
#if defined(AES_INSTRUCTIONS) && defined(GF_INSTRUCTIONS)
.section .bss
.balign 32
bk_ivb: .zero 32

.section .text
.balign 4
.global backend_init_once
backend_init_once:
    ret

/* per WINDOW: RK derive (kf chain) + inc + P1 IV + idx GPRs + mod0=0x13. */
.global backend_window_init
backend_window_init:
    li x31, 30
    bn.lid x31, 0(x10)        /* w30 = pk_seed (AES key) */
    bn.aes128.kf w29, w30, 1
    bn.aes128.kf w28, w29, 2
    bn.aes128.kf w27, w28, 3
    bn.aes128.kf w26, w27, 4
    bn.aes128.kf w25, w26, 5
    bn.aes128.kf w24, w25, 6
    bn.aes128.kf w23, w24, 7
    bn.aes128.kf w22, w23, 8
    bn.aes128.kf w21, w22, 9
    bn.aes128.kf w20, w21, 10
    bn.addi w19, w31, 2       /* CTR +2 (dual-block), positioned */
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160
    bn.addi w1, w31, 1        /* P1 IV [ctr1@224|ctr0@96], rides rows */
    bn.rshi w1, w1, w31 >> 32
    li x31, 31
    li x23, 6
    li x25, 8
    li x8,  12
    li x26, 3
    li x27, 4
    li x28, 5
    la x22, p1buf
    li x4, 0x13
    csrrw x0, mod0, x4
    csrrw x0, mod1, x0
    ret

/* one row: P1 fill (96-r entries) + pair loop (banded GF dot + inline P2
 * AES + store). in x7=row, x30=96-r, x13=P2 ctr, x10=gbuf dst, x18=wc. */
.global backend_row
backend_row:
    /* -- P1 fill: (96-r) dual-block entries -> p1buf, w1 running IV -- */
    add x9, x0, x22
    loop x30, 13
        bn.aes128.encz.swap w0, w1, w30
        bn.aes128.encm w0, w0, w29
        bn.aes128.encm w0, w0, w28
        bn.aes128.encm w0, w0, w27
        bn.aes128.encm w0, w0, w26
        bn.aes128.encm w0, w0, w25
        bn.aes128.encm w0, w0, w24
        bn.aes128.encm w0, w0, w23
        bn.aes128.encm w0, w0, w22
        bn.aes128.encm w0, w0, w21
        bn.aes128.encf w0, w0, w20
        bn.sid x0, 0(x9++)
        bn.add w1, w1, w19
    lw x12, 8(x3)             /* window O base */
    /* -- P2 IV in w2 from the integer counter x13 -- */
    la x5, bk_ivb
    bn.sid x31, 0(x5)
    sw x13, 0(x5)
    li x6, 14
    bn.lid x6, 0(x5)
    bn.addi w15, w14, 1
    bn.rshi w2, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w2, w2, w15
    /* -- runtime band: segA(w3/w9) len x20, segB(w4/w10) len x11, cursor x17 -- */
    addi x5, x7, -64
    srli x5, x5, 31           /* 1 if row < 64 */
    beq x5, x0, _bkr_hi
    li x20, 64
    sub x20, x20, x7          /* segA = 64 - row */
    li x11, 32                /* segB = 32 */
    add x17, x0, x7           /* cursor = row */
    beq x0, x0, _bkr_go
_bkr_hi:
    li x20, 0                 /* segA skipped */
    li x11, 96
    sub x11, x11, x7          /* segB = 96 - row */
    addi x17, x7, -64         /* cursor = row - 64 */
_bkr_go:
    srli x19, x18, 1          /* pair count = col_count / 2 */
    loop x19, 46
        add x9, x0, x22
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        bn.rshi w9, w5, w4 >> 128
        bn.rshi w10, w31, w5 >> 128
        csrrw x0, mod1, x17
        beq x20, x0, _bkr_segb
        loop x20, 3
            bn.lid x23, 0(x9++)
            bn.gfmul.4.acc      w8,  w6, w3
            bn.gfmul.4.acch.inc w12, w6, w9
        _bkr_segb:
        loop x11, 3
            bn.lid x23, 0(x9++)
            bn.gfmul.4.acc      w8,  w6, w4
            bn.gfmul.4.acch.inc w12, w6, w10
        bn.aes128.encz.swap w0, w2, w30
        bn.aes128.encm w0, w0, w29
        bn.aes128.encm w0, w0, w28
        bn.aes128.encm w0, w0, w27
        bn.aes128.encm w0, w0, w26
        bn.aes128.encm w0, w0, w25
        bn.aes128.encm w0, w0, w24
        bn.aes128.encm w0, w0, w23
        bn.aes128.encm w0, w0, w22
        bn.aes128.encm w0, w0, w21
        bn.aes128.encf w0, w0, w20
        bn.add w2, w2, w19
        bn.xor w8, w8, w0
        bn.sid x25, 0(x10++)
        bn.aes128.encz.swap w0, w2, w30
        bn.aes128.encm w0, w0, w29
        bn.aes128.encm w0, w0, w28
        bn.aes128.encm w0, w0, w27
        bn.aes128.encm w0, w0, w26
        bn.aes128.encm w0, w0, w25
        bn.aes128.encm w0, w0, w24
        bn.aes128.encm w0, w0, w23
        bn.aes128.encm w0, w0, w22
        bn.aes128.encm w0, w0, w21
        bn.aes128.encf w0, w0, w20
        bn.add w2, w2, w19
        bn.xor w12, w12, w0
        bn.sid x8, 0(x10++)
    ret

/* R=4 fold (shared hw arms, pure bn.gfmul.4): slice[k,pair] ^=
 * sum_{r<4} group[r,pair]*O[i0+r,k]. in x21=i0, x13/x14 gbuf, x11 slice,
 * x18=col_count. Runtime band on i0 (mod1 64-nibble wrap). No jal. */
.global backend_fold_group
backend_fold_group:
    li x5, 13
    li x6, 16
    li x25, 8
    li x8, 12
    li x26, 3
    li x27, 4
    li x28, 5
    addi x9, x21, -64
    srli x9, x9, 31           /* 1 if i0 < 64 (band A) */
    beq x9, x0, _fold_hi
    loop x18, 35
      li x17, 0
      bn.lid x17, 0(x13)
      li x17, 2
      bn.lid x17, 320(x13)
      li x17, 6
      bn.lid x17, 0(x14)
      li x17, 7
      bn.lid x17, 320(x14)
      lw x4, 0(x3)
      add x10, x0, x11
      loopi 32, 21
        bn.lid x26, 0(x4++)
        bn.lid x27, 0(x4++)
        bn.lid x28, 0(x4++)
        bn.rshi w9, w5, w4 >> 128
        bn.rshi w10, w31, w5 >> 128
        csrrw x0, mod1, x21
        bn.lid x5, 0(x10)
        bn.lid x6, 320(x10)
        bn.wsrw acc, w13
        bn.wsrw acch, w16
        bn.gfmul.4.acc      w8,  w0, w3
        bn.gfmul.4.acch.inc w12, w0, w9
        bn.gfmul.4.acc      w8,  w2, w3
        bn.gfmul.4.acch.inc w12, w2, w9
        bn.gfmul.4.acc      w8,  w6, w3
        bn.gfmul.4.acch.inc w12, w6, w9
        bn.gfmul.4.acc      w8,  w7, w3
        bn.gfmul.4.acch.inc w12, w7, w9
        bn.sid x25, 0(x10)
        bn.sid x8, 320(x10)
        addi x10, x10, 640
      addi x11, x11, 32
      addi x13, x13, 32
      addi x14, x14, 32
    ret
_fold_hi:
    addi x21, x21, -64       /* cursor = i0 - 64 (band B) */
    loop x18, 35
      li x17, 0
      bn.lid x17, 0(x13)
      li x17, 2
      bn.lid x17, 320(x13)
      li x17, 6
      bn.lid x17, 0(x14)
      li x17, 7
      bn.lid x17, 320(x14)
      lw x4, 0(x3)
      add x10, x0, x11
      loopi 32, 21
        bn.lid x26, 0(x4++)
        bn.lid x27, 0(x4++)
        bn.lid x28, 0(x4++)
        bn.rshi w9, w5, w4 >> 128
        bn.rshi w10, w31, w5 >> 128
        csrrw x0, mod1, x21
        bn.lid x5, 0(x10)
        bn.lid x6, 320(x10)
        bn.wsrw acc, w13
        bn.wsrw acch, w16
        bn.gfmul.4.acc      w8,  w0, w4
        bn.gfmul.4.acch.inc w12, w0, w10
        bn.gfmul.4.acc      w8,  w2, w4
        bn.gfmul.4.acch.inc w12, w2, w10
        bn.gfmul.4.acc      w8,  w6, w4
        bn.gfmul.4.acch.inc w12, w6, w10
        bn.gfmul.4.acc      w8,  w7, w4
        bn.gfmul.4.acch.inc w12, w7, w10
        bn.sid x25, 0(x10)
        bn.sid x8, 320(x10)
        addi x10, x10, 640
      addi x11, x11, 32
      addi x13, x13, 32
      addi x14, x14, 32
    ret

/* ---- bngfonly arm (-DGF_INSTRUCTIONS) ----
 * Compute-AES via AES_bngf leaf helpers; P1 ctr = persistent GPR x24 (no
 * riding WDR IV), both IVs built via the bk_ivb bounce. Helpers leave
 * mod0=0x11B -> restore 0x13 after every call cluster; they clobber
 * x18/x19 -> col_count reloaded from 8(x0) after the P1 fill. Persistent:
 * x15/x16 const bases, x29=9, x24 ctr, idx x22/x23/x25..x28/x31. */
#elif defined(GF_INSTRUCTIONS)
.section .data
/* helpers la these by name (constants lib not linked) */
.balign 32
.global byte_swap_mask
byte_swap_mask:
    .word 0, 0, 0, 0x000000ff
    .word 0, 0, 0, 0x000000ff
.global affine_value
affine_value:
    .word 0x63636363, 0x63636363, 0x63636363, 0x63636363
    .word 0x63636363, 0x63636363, 0x63636363, 0x63636363
.global msb_mask
msb_mask:
    .word 0x80808080, 0x80808080, 0x80808080, 0x80808080
    .word 0x80808080, 0x80808080, 0x80808080, 0x80808080
.global shiftrow_mask
shiftrow_mask:
    .word 0x0000ff00, 0x0000ff00, 0x0000ff00, 0x0000ff00
    .word 0x0000ff00, 0x0000ff00, 0x0000ff00, 0x0000ff00
.global rcon
rcon:
    .word 0x08040201, 0x80402010, 0x361b, 0
    .zero 16
.section .bss
.balign 32
bk_ivb: .zero 32

.section .text
.balign 4
.global backend_init_once
backend_init_once:
    ret

/* per WINDOW: SW key schedule (RK1..RK10 dual FWD in w20..w29, w30=RK0
 * dual) + GF consts/idx GPRs + P1 ctr reset. mod0=0x13 at exit. */
.global backend_window_init
backend_window_init:
    li x31, 30
    bn.lid x31, 0(x10)        /* w30 = pk_seed (AES key) */
    /* SW KS via KeySchedule_keygen: RK1..RK10 dual-stored FORWARD in
     * w20..w29 (aes128_keygen layout), w30 = RK0 dual. Clobbers w7,
     * w11..w16, x5, x13..x15 (all dead here). */
    la x13, affine_value
    li x6, 8
    bn.lid x6, 0(x13)
    la x14, msb_mask
    li x6, 9
    bn.lid x6, 0(x14)
    la x15, rcon
    li x6, 11
    bn.lid x6, 0(x15)
    bn.mov w17, w30
    bn.or w30, w30, w30 << 128
    jal x1, KeySchedule_keygen
    bn.mov w20, w17
    bn.or  w20, w20, w20 << 128
    jal x1, KeySchedule_keygen
    bn.mov w21, w17
    bn.or  w21, w21, w21 << 128
    jal x1, KeySchedule_keygen
    bn.mov w22, w17
    bn.or  w22, w22, w22 << 128
    jal x1, KeySchedule_keygen
    bn.mov w23, w17
    bn.or  w23, w23, w23 << 128
    jal x1, KeySchedule_keygen
    bn.mov w24, w17
    bn.or  w24, w24, w24 << 128
    jal x1, KeySchedule_keygen
    bn.mov w25, w17
    bn.or  w25, w25, w25 << 128
    jal x1, KeySchedule_keygen
    bn.mov w26, w17
    bn.or  w26, w26, w26 << 128
    jal x1, KeySchedule_keygen
    bn.mov w27, w17
    bn.or  w27, w27, w27 << 128
    jal x1, KeySchedule_keygen
    bn.mov w28, w17
    bn.or  w28, w28, w28 << 128
    jal x1, KeySchedule_keygen
    bn.mov w29, w17
    bn.or  w29, w29, w29 << 128
    li x4, 0x13
    csrrw x0, mod0, x4        /* KS left mod0=0x11B; Is walks are GF(16) */
    la x15, affine_value      /* stable const bases for in-loop reloads */
    la x16, msb_mask
    li x29, 9                 /* w9 idx (w9 reload sites) */
    li x24, 0                 /* P1 CTR (counter units), advances per row */
    bn.addi w19, w31, 2       /* CTR +2 (dual-block), positioned */
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160
    li x31, 31
    li x23, 6
    li x25, 8
    li x26, 3
    li x27, 4
    li x28, 5
    la x22, p1buf
    csrrw x0, mod1, x0
    ret

/* one row: P1 fill (96-r entries via helper, ctr x24) + pair loop (banded
 * GF dot + helper P2 AES + store). in x7=row, x30=96-r, x13=P2 ctr,
 * x10=gbuf dst, x18=wc. x13 survives the P1 fill (helpers clob x18/x19). */
.global backend_row
backend_row:
    la x12, byte_swap_mask
    li x5, 7
    bn.lid x5, 0(x12)         /* w7 (walks never touch it) */
    bn.lid x25, 0(x15)        /* w8 = affine_value */
    bn.lid x29, 0(x16)        /* w9 = msb_mask */
    la x5, bk_ivb
    bn.sid x31, 0(x5)
    sw x24, 0(x5)
    li x12, 14
    bn.lid x12, 0(x5)         /* w14 = P1 ctr */
    bn.addi w15, w14, 1
    bn.rshi w18, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w18, w18, w15      /* [ctr+1@224 | ctr@96] */
    add x9, x0, x22
    li x12, 2                 /* w2 store idx */
    loop x30, 3
        jal x1, aes128_keygen
        bn.sid x12, 0(x9++)
        bn.add w18, w18, w19
    slli x5, x30, 1
    add x24, x24, x5          /* P1 ctr += 2*(96-r) */
    /* -- P2 IV from the integer counter x13, helper IV lives in w18 -- */
    la x5, bk_ivb
    bn.sid x31, 0(x5)
    sw x13, 0(x5)
    li x12, 14
    bn.lid x12, 0(x5)
    bn.addi w15, w14, 1
    bn.rshi w18, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w18, w18, w15
    li x5, 0x13
    csrrw x0, mod0, x5        /* helper left 0x11B; walks need GF(16) */
    lw x18, 8(x0)             /* helper clobbered x18/x19 */
    lw x12, 8(x3)             /* window O base */
    /* -- runtime band: segA(w3/w9) len x20, segB(w4/w10) len x11, cursor x17 -- */
    addi x5, x7, -64
    srli x5, x5, 31           /* 1 if row < 64 */
    beq x5, x0, _bkr_hi
    li x20, 64
    sub x20, x20, x7          /* segA = 64 - row */
    li x11, 32                /* segB = 32 */
    add x17, x0, x7           /* cursor = row */
    beq x0, x0, _bkr_go
_bkr_hi:
    li x20, 0                 /* segA skipped */
    li x11, 96
    sub x11, x11, x7          /* segB = 96 - row */
    addi x17, x7, -64         /* cursor = row - 64 */
_bkr_go:
    srli x19, x18, 1          /* pair count = col_count / 2 */
    loop x19, 32
        add x9, x0, x22
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        bn.rshi w9, w5, w4 >> 128
        bn.rshi w10, w31, w5 >> 128
        csrrw x0, mod1, x17
        beq x20, x0, _bkr_segb
        loop x20, 3
            bn.lid x23, 0(x9++)
            bn.gfmul.4.acc      w8,  w6, w3
            bn.gfmul.4.acch.inc w12, w6, w9
        _bkr_segb:
        loop x11, 3
            bn.lid x23, 0(x9++)
            bn.gfmul.4.acc      w8,  w6, w4
            bn.gfmul.4.acch.inc w12, w6, w10
        bn.mov w6, w8             /* park ACC dot (helper wants w8=affine) */
        bn.mov w3, w12            /* park ACCH dot (helper clobbers w10-w17) */
        bn.lid x25, 0(x15)        /* w8 = affine_value (walk overwrote it) */
        bn.lid x29, 0(x16)        /* w9 = msb_mask (view build overwrote) */
        jal x1, aes128_keygen     /* w2 = keystream pair (IV in w18) */
        bn.add w18, w18, w19
        bn.xor w6, w6, w2
        bn.sid x23, 0(x10++)
        jal x1, aes128_keygen
        bn.add w18, w18, w19
        bn.xor w3, w3, w2
        bn.sid x26, 0(x10++)
        li x5, 0x13
        csrrw x0, mod0, x5        /* helper left 0x11B */
    ret

/* R=4 fold (shared hw arms, pure bn.gfmul.4): slice[k,pair] ^=
 * sum_{r<4} group[r,pair]*O[i0+r,k]. in x21=i0, x13/x14 gbuf, x11 slice,
 * x18=col_count. Runtime band on i0 (mod1 64-nibble wrap). No jal. */
.global backend_fold_group
backend_fold_group:
    li x5, 13
    li x6, 16
    li x25, 8
    li x8, 12
    li x26, 3
    li x27, 4
    li x28, 5
    addi x9, x21, -64
    srli x9, x9, 31           /* 1 if i0 < 64 (band A) */
    beq x9, x0, _fold_hi
    loop x18, 35
      li x17, 0
      bn.lid x17, 0(x13)
      li x17, 2
      bn.lid x17, 320(x13)
      li x17, 6
      bn.lid x17, 0(x14)
      li x17, 7
      bn.lid x17, 320(x14)
      lw x4, 0(x3)
      add x10, x0, x11
      loopi 32, 21
        bn.lid x26, 0(x4++)
        bn.lid x27, 0(x4++)
        bn.lid x28, 0(x4++)
        bn.rshi w9, w5, w4 >> 128
        bn.rshi w10, w31, w5 >> 128
        csrrw x0, mod1, x21
        bn.lid x5, 0(x10)
        bn.lid x6, 320(x10)
        bn.wsrw acc, w13
        bn.wsrw acch, w16
        bn.gfmul.4.acc      w8,  w0, w3
        bn.gfmul.4.acch.inc w12, w0, w9
        bn.gfmul.4.acc      w8,  w2, w3
        bn.gfmul.4.acch.inc w12, w2, w9
        bn.gfmul.4.acc      w8,  w6, w3
        bn.gfmul.4.acch.inc w12, w6, w9
        bn.gfmul.4.acc      w8,  w7, w3
        bn.gfmul.4.acch.inc w12, w7, w9
        bn.sid x25, 0(x10)
        bn.sid x8, 320(x10)
        addi x10, x10, 640
      addi x11, x11, 32
      addi x13, x13, 32
      addi x14, x14, 32
    ret
_fold_hi:
    addi x21, x21, -64       /* cursor = i0 - 64 (band B) */
    loop x18, 35
      li x17, 0
      bn.lid x17, 0(x13)
      li x17, 2
      bn.lid x17, 320(x13)
      li x17, 6
      bn.lid x17, 0(x14)
      li x17, 7
      bn.lid x17, 320(x14)
      lw x4, 0(x3)
      add x10, x0, x11
      loopi 32, 21
        bn.lid x26, 0(x4++)
        bn.lid x27, 0(x4++)
        bn.lid x28, 0(x4++)
        bn.rshi w9, w5, w4 >> 128
        bn.rshi w10, w31, w5 >> 128
        csrrw x0, mod1, x21
        bn.lid x5, 0(x10)
        bn.lid x6, 320(x10)
        bn.wsrw acc, w13
        bn.wsrw acch, w16
        bn.gfmul.4.acc      w8,  w0, w4
        bn.gfmul.4.acch.inc w12, w0, w10
        bn.gfmul.4.acc      w8,  w2, w4
        bn.gfmul.4.acch.inc w12, w2, w10
        bn.gfmul.4.acc      w8,  w6, w4
        bn.gfmul.4.acch.inc w12, w6, w10
        bn.gfmul.4.acc      w8,  w7, w4
        bn.gfmul.4.acch.inc w12, w7, w10
        bn.sid x25, 0(x10)
        bn.sid x8, 320(x10)
        addi x10, x10, 640
      addi x11, x11, 32
      addi x13, x13, 32
      addi x14, x14, 32
    ret

/* ---- sw arm (no ISE): T-table AES + gf16_macc_sw dots ---- */
#else
/* ACC-private scratch above the bus window, continuing the outer kernel's region
 * (gbuf23 31,744 / frame 32,384). Addresses only: no load image, no host access,
 * each written before it is read. In .bss these 256 B pushed the sw arm 640 B past
 * the 31,744 B window, since only this arm also links the 4 KiB AES T-tables. */
.set rkbuf,       32416      /* 192 B, AES_128_keyschedule out, INIT-persistent */
.set ivb,         32608      /* 32 B */
.set swframe,     32640      /* 32 B, aes128_dual_table frame */
.set swframe_end, 32672      /* 96 B of the 1 KiB scratch still free */

.section .text
.balign 4
/* INIT: SW AES key schedule once, pk_seed (x10) -> rkbuf. */
.global backend_init_once
backend_init_once:
    la x11, rkbuf
    jal x1, AES_128_keyschedule
    ret

/* per WINDOW: sw stack + macc mask + IV state + idx GPRs. No mod0 (no GF
 * insns in this arm). p1buf published at 12(x3) (dual_table rows drop x22). */
.global backend_window_init
backend_window_init:
    la x6, p1buf
    sw x6, 12(x3)
    la x2, swframe_end        /* dual_table pushes its 32B frame here */
    /* gf16_macc_sw mask: w16 = 0x88.. per nibble (monolith recipe) */
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
    /* IV increment (+2 per dual-block) + P1 IV [1|0] parked in w0 */
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160
    bn.addi w0, w31, 1
    bn.rshi w0, w0, w31 >> 32
    /* WDR-index GPR constants (all in dual_table preserve set) */
    li x31, 31
    li x17, 2                 /* w2 = dual_table output */
    li x23, 6
    li x25, 8
    li x26, 3
    li x27, 4
    li x28, 5
    ret

/* one row: P1 fill (96-r entries via dual_table) + pair loop (nibble-slide
 * O views + gf16_macc_sw dots + dual_table P2 + store). in x7=row,
 * x30=96-r, x13=P2 ctr, x10=gbuf dst; pairs re-read from 8(x0) (x18 is the
 * RK base here). */
.global backend_row
backend_row:
    la x18, rkbuf
    sw x13, 16(x3)            /* P2 ctr; dual_table clobbers x10-x16, so */
    sw x10, 20(x3)            /* park BOTH ABI ins across the P1 fill */
    bn.mov w10, w18
    bn.mov w18, w0
    bn.mov w0,  w10
    lw x9, 12(x3)
    sw x7, 28(x3)
    loop x30, 3
        jal x1, aes128_dual_table
        bn.sid x17, 0(x9++)
        bn.add w18, w18, w19
    lw x7, 28(x3)
    bn.mov w10, w18
    bn.mov w18, w0
    bn.mov w0,  w10
    lw   x4, 16(x3)           /* P2 IV from the parked integer ctr */
    la   x5, ivb
    li   x31, 31
    bn.sid x31, 0(x5)
    sw   x4, 0(x5)
    li   x6, 14
    bn.lid x6, 0(x5)
    bn.addi w15, w14, 1
    bn.rshi w18, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w18, w18, w15
    lw x12, 8(x3)             /* window O base */
    lw x10, 20(x3)            /* gbuf dst back (P1 fill clobbered it) */
    lw x19, 8(x0)
    srli x19, x19, 1          /* pair count */
    loop x19, 69
        lw x9, 12(x3)
        bn.mov w21, w0
        bn.mov w22, w18
        bn.mov w23, w19
        bn.xor w20, w20, w20
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        beq x7, x0, _nsa_0
        loop x7, 3
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w5, w4 >> 4
            bn.rshi w5, w31, w5 >> 4
_nsa_0:
        li x8, 96
        sub x8, x8, x7
        loop x8, 7
            bn.lid x23, 0(x9++)
            bn.mov w0, w6
            bn.mov w19, w3
            jal x1, gf16_macc_sw
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w5, w4 >> 4
            bn.rshi w5, w31, w5 >> 4
        bn.mov w8, w20
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        sw x10, 20(x3)
        sw x12, 24(x3)
        sw x7,  28(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        lw x7,  28(x3)
        bn.add w18, w18, w19
        bn.xor w8, w8, w2
        bn.sid x25, 0(x10++)
        bn.mov w21, w0
        bn.mov w22, w18
        bn.mov w23, w19
        bn.xor w20, w20, w20
        lw x9, 12(x3)
        beq x7, x0, _nsb_0
        loop x7, 2
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
_nsb_0:
        li x8, 96
        sub x8, x8, x7
        loop x8, 6
            bn.lid x23, 0(x9++)
            bn.mov w0, w6
            bn.mov w19, w3
            jal x1, gf16_macc_sw
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
        bn.mov w8, w20
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        sw x10, 20(x3)
        sw x12, 24(x3)
        sw x7,  28(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        lw x7,  28(x3)
        bn.add w18, w18, w19
        bn.xor w8, w8, w2
        bn.sid x25, 0(x10++)
    ret

/* R=4 fold, column-major: per window col j, per O-col pair k, 4 macc rows.
 * in x21=i0, x13/x14 gbuf, x11 slice; wc re-read from 8(x0). Restores the
 * w0 P1 IV and the w19 increment it clobbers. */
.global backend_fold_group
backend_fold_group:
    bn.mov w21, w0            /* park P1 IV (macc clobbers w0) */
    srli x20, x21, 1
    andi x20, x20, 2
    slli x20, x20, 3
    la x24, ivb
    lw x5, 8(x0)
    loop x5, 67
      li x8, 2
      bn.lid x8, 0(x13)
      li x8, 6
      bn.lid x8, 320(x13)
      li x8, 7
      bn.lid x8, 0(x14)
      li x8, 9
      bn.lid x8, 320(x14)
      lw x4, 0(x3)
      srli x8, x21, 1
      andi x8, x8, -4
      add x4, x4, x8
      add x10, x0, x11
      loopi 32, 50
        lw x8, 0(x4)
        srl x8, x8, x20
        sw x8, 0(x24)
        li x8, 14
        bn.lid x8, 0(x24)
        li x8, 20
        bn.lid x8, 0(x10)
        bn.mov w0, w2
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w6
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w7
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w9
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        li x8, 20
        bn.sid x8, 0(x10)
        lw x8, 48(x4)
        srl x8, x8, x20
        sw x8, 0(x24)
        li x8, 14
        bn.lid x8, 0(x24)
        li x8, 20
        bn.lid x8, 320(x10)
        bn.mov w0, w2
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w6
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w7
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w9
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        li x8, 20
        bn.sid x8, 320(x10)
        addi x4, x4, 96
        addi x10, x10, 640
      addi x11, x11, 32
      addi x13, x13, 32
      addi x14, x14, 32
    bn.mov w0, w21
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160
    ret
#endif
