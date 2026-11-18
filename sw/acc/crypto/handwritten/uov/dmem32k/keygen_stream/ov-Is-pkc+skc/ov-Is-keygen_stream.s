/* ov-Is-keygen_stream.s - streamed UOV-Is keygen (32 KiB DMEM target).
 * Tiers (cpp-guarded like monolith P1O_P2.s): AES_INSTRUCTIONS -> bngfaes
 * inline AES; else bngfonly (KeySchedule_keygen/aes128_keygen via bn.gfmul;
 * helper IV in w18, P1 ctr in x24, consts below the bus boundary, ivb+frame
 * moved to top scratch - host-visible addresses unchanged).
 * ONE app, phase-dispatch, ctx in DMEM.
 *   phase 0 INIT  : expandsk(sk_seed@0x20) -> pk_seed@0x40 + O ctx (3,072B)
 *   phase 1 WINDOW(arg0=col_start, arg1=col_count EVEN <=12): slice[k][j] =
 *           sum_i O[i][k]*B[i][cs+j] over GF(16), B = P1*O+P2 restreamed.
 * Fixed slice layout: entry (k,j) at slice + k*384 + j*32 (32B exact, no
 * pad) for ALL windows incl. the short one (cs=60, wc=4); kernel zeroes the
 * full slice per WINDOW; host reads col_count cols out BEFORE the next call.
 * P1 stream: rows 0..95 in order, IV re-inited [ctr1|ctr0] per window (no
 * seek). P2 stream: entry p = 64*row+col at CTR 9,312 + 2p (9,312 = 2 x
 * 4,656 P1 entries); one bounce-seek per row, then the +2 increment rides.
 * mod1 = 0 on every phase exit. RKs re-derived from pk_seed per WINDOW.
 * clob: everything (phase app, no caller). INIT overlays slice (expandsk
 * 3,104B); WINDOW uses the static 32B frame only.
 */
.section .data
.balign 32
/* Address map (real 32 KiB part: bus window = 31,744, top 1,024 = ACC-only
 * scratchpad): host-visible objects end <= 24,672; group_buf is SPLIT into
 * two 768B halves so nothing straddles the bus boundary - gbuf23 sits in the
 * top scratch region (31,744..32,512). gbuf23 is an absolute symbol, not a
 * section: a .scratchpad section is charged to dmem_load (31,744) and will
 * not link once .data fills the window. */
ctrl:      .word 0, 0, 0, 0
           .zero 16
sk_seed:   .zero 32
pk_seed:   .zero 32
.globl slice
.globl slice_end
slice:     .zero 24576
slice_end:
o_ctx:     .zero 3072
p1buf:     .zero 3072
gbuf01:    .zero 768
#ifdef AES_INSTRUCTIONS
ivb:       .zero 32
frame:     .zero 32
           .zero 96
#else
/* bngfonly: AES consts (helpers reference by name; constants lib NOT
 * linked). Initialized data must stay below the NOLOAD scratch region, so
 * ivb+frame (runtime-only, written before read) move above gbuf23 instead.
 * 5x32 = 160B = the freed 64B + the 96B pad; gbuf23 stays at 31,744. */
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
#endif
/* ACC-private at fixed addresses above the bus window: never loaded, so these
 * get addresses, not linker objects. A section here would still claim load
 * space in dmem_load, which is sized to the 31,744 B window. */
.set gbuf23, 31744
#ifndef AES_INSTRUCTIONS
.set ivb, 32512
.set frame, 32544
#endif

.section .text.start
.balign 4
.global main
main:
    lw   x4, 0(x0)            /* phase */
    beq  x4, x0, _INIT
    li   x5, 1
    beq  x4, x5, _WINDOW
    csrrw x0, mod1, x0        /* pin mod1 = 0 on exit */
    li   x6, -2
    sw   x6, 12(x0)
    ecall

/* ============================ INIT ============================ */
_INIT:
    la x2, slice_end          /* expandsk overlays the slice (3,104B) */
    bn.xor w31, w31, w31
    la x11, sk_seed
    jal x1, expandsk_ret_O_pkseed   /* x2 -= 3104; pk_seed@x2, O@x2+32 */
    bn.ld w0, 0(x2)
    la x5, pk_seed
    bn.sd w0, 0(x5)           /* pk_seed ctx (low 16B valid) */
    addi x4, x2, 32           /* raw O (3,072B) -> ctx */
    la x5, o_ctx
    li x6, 96
    li x17, 0
    loop x6, 2
        bn.lid x17, 0(x4++)
        bn.sid x17, 0(x5++)
    csrrw x0, mod1, x0        /* pin mod1 = 0 on exit */
    sw x0, 12(x0)             /* status = 0 */
    ecall

/* ============================ WINDOW ============================ */
_WINDOW:
    la x3, frame
    lw x5, 4(x0)              /* col_start */
    lw x18, 8(x0)             /* col_count */
    sw x5, 4(x3)
    beq x18, x0, _bad_args
    andi x4, x18, 1
    bne x4, x0, _bad_args     /* col_count must be even (col-pairs) */
    /* bounds (beq/bne-only ISA: sub + srli sign trick) */
    li   x4, 12
    sub  x4, x4, x18
    srli x4, x4, 31
    bne  x4, x0, _bad_args    /* col_count <= 12 */
    andi x4, x5, 1
    bne  x4, x0, _bad_args    /* col_start even (48B col stride alignment) */
    li   x4, 62
    sub  x4, x4, x5
    srli x4, x4, 31
    bne  x4, x0, _bad_args    /* col_start <= 62 (also kills cs+wc wrap) */
    add  x4, x5, x18
    li   x6, 64
    sub  x6, x6, x4
    srli x6, x6, 31
    bne  x6, x0, _bad_args    /* col_start + col_count <= 64 */
    srli x19, x18, 1          /* pair count */
    bn.xor w31, w31, w31
    li x4, 0x13
    csrrw x0, mod0, x4
    la x6, o_ctx
    sw x6, 0(x3)              /* true O base (fold) */
    slli x4, x5, 5
    slli x7, x5, 4
    add  x4, x4, x7           /* col_start*48 */
    add  x6, x6, x4
    sw x6, 8(x3)              /* window O base (setup reloads per row) */
    /* RK schedule from pk_seed ctx + IV inc (per-window, no WDR persistence
     * across ecall) */
    la x4, pk_seed
    li x31, 30
    bn.lid x31, 0(x4)
#ifdef AES_INSTRUCTIONS
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
#else
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
    la x15, affine_value      /* stable const bases for in-loop reloads */
    la x16, msb_mask
    li x29, 9                 /* w9 idx (w9 reload sites) */
    li x24, 0                 /* P1 CTR (counter units), advances per row */
#endif
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160
#ifdef AES_INSTRUCTIONS
    /* P1 IV: fresh [ctr1@224 | ctr0@96] per window - no seek needed */
    bn.addi w1, w31, 1
    bn.rshi w1, w1, w31 >> 32
#endif
    /* WDR-index GPR constants */
    li x23, 6
    li x25, 8
    li x26, 3
    li x27, 4
    li x28, 5
    la x22, p1buf             /* resident P1 tmp base (setup contract) */
    /* zero the FULL slice (fixed layout, all windows): 768 stores */
    la x10, slice
    li x4, 768
    loop x4, 1
        bn.sd w31, 0(x10++)
    li x7, 0                  /* row */
    li x30, 96                /* 96 - r */
    /* ---- band A: 16 groups of 4 rows + fold ---- */
#ifdef AES_INSTRUCTIONS
    loopi 16, 320
#else
    loopi 16, 269             /* 320 - 4x13 + 1 reload; re-derive on body edit */
#endif
    jal x1, p1op2_rows1_94_setup
    addi x20, x30, -32
    slli x4, x7, 7
    lw   x5, 4(x3)
    slli x6, x5, 1
    add  x4, x4, x6
    li   x5, 9312
    add  x4, x4, x5
    la   x5, ivb
    bn.sd w31, 0(x5)
    sw   x4, 0(x5)
    bn.ld w14, 0(x5)
    bn.addi w15, w14, 1
    bn.rshi w2, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w2, w2, w15
#ifndef AES_INSTRUCTIONS
    bn.mov w18, w2            /* helper IV lives in w18 (advances by w19) */
#endif
    la x10, gbuf01
#ifdef AES_INSTRUCTIONS
    loop x19, 45
#else
    loop x19, 31
#endif
        add x9, x0, x22
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        bn.rshi w9, w5, w4 >> 128
        bn.rshi w10, w31, w5 >> 128
        csrrw x0, mod1, x7
        loop x20, 3
            bn.lid x23, 0(x9++)
            bn.gfmul.4.acc w8, w6, w3
            bn.gfmul.4.acch.inc w12, w6, w9
        loopi 32, 3
            bn.lid x23, 0(x9++)
            bn.gfmul.4.acc w8, w6, w4
            bn.gfmul.4.acch.inc w12, w6, w10
#ifdef AES_INSTRUCTIONS
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
        bn.sd w8, 0(x10++)
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
        bn.sd w12, 0(x10++)
#else
        bn.mov w6, w8             /* park ACC dot (helper wants w8=affine) */
        bn.mov w3, w12            /* park ACCH dot (helper clobbers w10-w17) */
        bn.lid x25, 0(x15)        /* w8 = affine_value (walk overwrote it) */
        bn.lid x29, 0(x16)        /* w9 = msb_mask (window build overwrote) */
        jal x1, aes128_keygen     /* w2 = keystream pair (IV in w18) */
        bn.add w18, w18, w19
        bn.xor w6, w6, w2
        bn.sd w6, 0(x10++)
        jal x1, aes128_keygen
        bn.add w18, w18, w19
        bn.xor w3, w3, w2
        bn.sd w3, 0(x10++)
        li x5, 0x13
        csrrw x0, mod0, x5        /* helper left 0x11B; walks need GF(16) */
#endif
    addi x7, x7, 1
    addi x30, x30, -1
    jal x1, p1op2_rows1_94_setup
    addi x20, x30, -32
    slli x4, x7, 7
    lw   x5, 4(x3)
    slli x6, x5, 1
    add  x4, x4, x6
    li   x5, 9312
    add  x4, x4, x5
    la   x5, ivb
    bn.sd w31, 0(x5)
    sw   x4, 0(x5)
    bn.ld w14, 0(x5)
    bn.addi w15, w14, 1
    bn.rshi w2, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w2, w2, w15
#ifndef AES_INSTRUCTIONS
    bn.mov w18, w2            /* helper IV lives in w18 (advances by w19) */
#endif
    la x10, gbuf01
    addi x10, x10, 384
#ifdef AES_INSTRUCTIONS
    loop x19, 45
#else
    loop x19, 31
#endif
        add x9, x0, x22
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        bn.rshi w9, w5, w4 >> 128
        bn.rshi w10, w31, w5 >> 128
        csrrw x0, mod1, x7
        loop x20, 3
            bn.lid x23, 0(x9++)
            bn.gfmul.4.acc w8, w6, w3
            bn.gfmul.4.acch.inc w12, w6, w9
        loopi 32, 3
            bn.lid x23, 0(x9++)
            bn.gfmul.4.acc w8, w6, w4
            bn.gfmul.4.acch.inc w12, w6, w10
#ifdef AES_INSTRUCTIONS
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
        bn.sd w8, 0(x10++)
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
        bn.sd w12, 0(x10++)
#else
        bn.mov w6, w8             /* park ACC dot (helper wants w8=affine) */
        bn.mov w3, w12            /* park ACCH dot (helper clobbers w10-w17) */
        bn.lid x25, 0(x15)        /* w8 = affine_value (walk overwrote it) */
        bn.lid x29, 0(x16)        /* w9 = msb_mask (window build overwrote) */
        jal x1, aes128_keygen     /* w2 = keystream pair (IV in w18) */
        bn.add w18, w18, w19
        bn.xor w6, w6, w2
        bn.sd w6, 0(x10++)
        jal x1, aes128_keygen
        bn.add w18, w18, w19
        bn.xor w3, w3, w2
        bn.sd w3, 0(x10++)
        li x5, 0x13
        csrrw x0, mod0, x5        /* helper left 0x11B; walks need GF(16) */
#endif
    addi x7, x7, 1
    addi x30, x30, -1
    jal x1, p1op2_rows1_94_setup
    addi x20, x30, -32
    slli x4, x7, 7
    lw   x5, 4(x3)
    slli x6, x5, 1
    add  x4, x4, x6
    li   x5, 9312
    add  x4, x4, x5
    la   x5, ivb
    bn.sd w31, 0(x5)
    sw   x4, 0(x5)
    bn.ld w14, 0(x5)
    bn.addi w15, w14, 1
    bn.rshi w2, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w2, w2, w15
#ifndef AES_INSTRUCTIONS
    bn.mov w18, w2            /* helper IV lives in w18 (advances by w19) */
#endif
    la x10, gbuf23
#ifdef AES_INSTRUCTIONS
    loop x19, 45
#else
    loop x19, 31
#endif
        add x9, x0, x22
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        bn.rshi w9, w5, w4 >> 128
        bn.rshi w10, w31, w5 >> 128
        csrrw x0, mod1, x7
        loop x20, 3
            bn.lid x23, 0(x9++)
            bn.gfmul.4.acc w8, w6, w3
            bn.gfmul.4.acch.inc w12, w6, w9
        loopi 32, 3
            bn.lid x23, 0(x9++)
            bn.gfmul.4.acc w8, w6, w4
            bn.gfmul.4.acch.inc w12, w6, w10
#ifdef AES_INSTRUCTIONS
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
        bn.sd w8, 0(x10++)
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
        bn.sd w12, 0(x10++)
#else
        bn.mov w6, w8             /* park ACC dot (helper wants w8=affine) */
        bn.mov w3, w12            /* park ACCH dot (helper clobbers w10-w17) */
        bn.lid x25, 0(x15)        /* w8 = affine_value (walk overwrote it) */
        bn.lid x29, 0(x16)        /* w9 = msb_mask (window build overwrote) */
        jal x1, aes128_keygen     /* w2 = keystream pair (IV in w18) */
        bn.add w18, w18, w19
        bn.xor w6, w6, w2
        bn.sd w6, 0(x10++)
        jal x1, aes128_keygen
        bn.add w18, w18, w19
        bn.xor w3, w3, w2
        bn.sd w3, 0(x10++)
        li x5, 0x13
        csrrw x0, mod0, x5        /* helper left 0x11B; walks need GF(16) */
#endif
    addi x7, x7, 1
    addi x30, x30, -1
    jal x1, p1op2_rows1_94_setup
    addi x20, x30, -32
    slli x4, x7, 7
    lw   x5, 4(x3)
    slli x6, x5, 1
    add  x4, x4, x6
    li   x5, 9312
    add  x4, x4, x5
    la   x5, ivb
    bn.sd w31, 0(x5)
    sw   x4, 0(x5)
    bn.ld w14, 0(x5)
    bn.addi w15, w14, 1
    bn.rshi w2, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w2, w2, w15
#ifndef AES_INSTRUCTIONS
    bn.mov w18, w2            /* helper IV lives in w18 (advances by w19) */
#endif
    la x10, gbuf23
    addi x10, x10, 384
#ifdef AES_INSTRUCTIONS
    loop x19, 45
#else
    loop x19, 31
#endif
        add x9, x0, x22
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        bn.rshi w9, w5, w4 >> 128
        bn.rshi w10, w31, w5 >> 128
        csrrw x0, mod1, x7
        loop x20, 3
            bn.lid x23, 0(x9++)
            bn.gfmul.4.acc w8, w6, w3
            bn.gfmul.4.acch.inc w12, w6, w9
        loopi 32, 3
            bn.lid x23, 0(x9++)
            bn.gfmul.4.acc w8, w6, w4
            bn.gfmul.4.acch.inc w12, w6, w10
#ifdef AES_INSTRUCTIONS
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
        bn.sd w8, 0(x10++)
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
        bn.sd w12, 0(x10++)
#else
        bn.mov w6, w8             /* park ACC dot (helper wants w8=affine) */
        bn.mov w3, w12            /* park ACCH dot (helper clobbers w10-w17) */
        bn.lid x25, 0(x15)        /* w8 = affine_value (walk overwrote it) */
        bn.lid x29, 0(x16)        /* w9 = msb_mask (window build overwrote) */
        jal x1, aes128_keygen     /* w2 = keystream pair (IV in w18) */
        bn.add w18, w18, w19
        bn.xor w6, w6, w2
        bn.sd w6, 0(x10++)
        jal x1, aes128_keygen
        bn.add w18, w18, w19
        bn.xor w3, w3, w2
        bn.sd w3, 0(x10++)
        li x5, 0x13
        csrrw x0, mod0, x5        /* helper left 0x11B; walks need GF(16) */
#endif
    addi x7, x7, 1
    addi x30, x30, -1
#ifndef AES_INSTRUCTIONS
    lw x18, 8(x0)             /* fold clusters clobbered x18/x19 (helper) */
#endif
    addi x21, x7, -4
    li x5, 13
    li x6, 16
    la x13, gbuf01
    la x14, gbuf23
    la x11, slice
    lw x9, 0(x3)
    loop x18, 34
      li x17, 0
      bn.lid x17, 0(x13)
      li x17, 2
      bn.lid x17, 384(x13)
      li x17, 6
      bn.lid x17, 0(x14)
      li x17, 7
      bn.lid x17, 384(x14)
      add x4, x0, x9
      add x10, x0, x11
      loopi 32, 20
        bn.lid x26, 0(x4++)
        bn.lid x27, 0(x4++)
        bn.lid x28, 0(x4++)
        bn.rshi w9, w5, w4 >> 128
        csrrw x0, mod1, x21
        bn.lid x5, 0(x10)
        bn.lid x6, 384(x10)
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
        bn.sd w8, 0(x10)
        bn.sd w12, 384(x10)
        addi x10, x10, 768
      addi x11, x11, 32
      addi x13, x13, 32
      addi x14, x14, 32
    nop
    /* ---- band B: 8 groups of 4 rows + fold ---- */
#ifdef AES_INSTRUCTIONS
    loopi 8, 304
#else
    loopi 8, 253              /* 304 - 4x13 + 1 reload; re-derive on body edit */
#endif
    jal x1, p1op2_rows1_94_setup
    addi x21, x7, -64
    add  x20, x0, x30
    slli x4, x7, 7
    lw   x5, 4(x3)
    slli x6, x5, 1
    add  x4, x4, x6
    li   x5, 9312
    add  x4, x4, x5
    la   x5, ivb
    bn.sd w31, 0(x5)
    sw   x4, 0(x5)
    bn.ld w14, 0(x5)
    bn.addi w15, w14, 1
    bn.rshi w2, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w2, w2, w15
#ifndef AES_INSTRUCTIONS
    bn.mov w18, w2            /* helper IV lives in w18 (advances by w19) */
#endif
    la x10, gbuf01
#ifdef AES_INSTRUCTIONS
    loop x19, 40
#else
    loop x19, 26
#endif
        add x9, x0, x22
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        addi x12, x12, 32
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        bn.rshi w10, w31, w5 >> 128
        csrrw x0, mod1, x21
        loop x20, 3
            bn.lid x23, 0(x9++)
            bn.gfmul.4.acc w8, w6, w4
            bn.gfmul.4.acch.inc w12, w6, w10
#ifdef AES_INSTRUCTIONS
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
        bn.sd w8, 0(x10++)
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
        bn.sd w12, 0(x10++)
#else
        bn.mov w6, w8             /* park ACC dot (helper wants w8=affine) */
        bn.mov w3, w12            /* park ACCH dot (helper clobbers w10-w17) */
        bn.lid x25, 0(x15)        /* w8 = affine_value (walk overwrote it) */
        bn.lid x29, 0(x16)        /* w9 = msb_mask (window build overwrote) */
        jal x1, aes128_keygen     /* w2 = keystream pair (IV in w18) */
        bn.add w18, w18, w19
        bn.xor w6, w6, w2
        bn.sd w6, 0(x10++)
        jal x1, aes128_keygen
        bn.add w18, w18, w19
        bn.xor w3, w3, w2
        bn.sd w3, 0(x10++)
        li x5, 0x13
        csrrw x0, mod0, x5        /* helper left 0x11B; walks need GF(16) */
#endif
    addi x7, x7, 1
    addi x30, x30, -1
    jal x1, p1op2_rows1_94_setup
    addi x21, x7, -64
    add  x20, x0, x30
    slli x4, x7, 7
    lw   x5, 4(x3)
    slli x6, x5, 1
    add  x4, x4, x6
    li   x5, 9312
    add  x4, x4, x5
    la   x5, ivb
    bn.sd w31, 0(x5)
    sw   x4, 0(x5)
    bn.ld w14, 0(x5)
    bn.addi w15, w14, 1
    bn.rshi w2, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w2, w2, w15
#ifndef AES_INSTRUCTIONS
    bn.mov w18, w2            /* helper IV lives in w18 (advances by w19) */
#endif
    la x10, gbuf01
    addi x10, x10, 384
#ifdef AES_INSTRUCTIONS
    loop x19, 40
#else
    loop x19, 26
#endif
        add x9, x0, x22
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        addi x12, x12, 32
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        bn.rshi w10, w31, w5 >> 128
        csrrw x0, mod1, x21
        loop x20, 3
            bn.lid x23, 0(x9++)
            bn.gfmul.4.acc w8, w6, w4
            bn.gfmul.4.acch.inc w12, w6, w10
#ifdef AES_INSTRUCTIONS
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
        bn.sd w8, 0(x10++)
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
        bn.sd w12, 0(x10++)
#else
        bn.mov w6, w8             /* park ACC dot (helper wants w8=affine) */
        bn.mov w3, w12            /* park ACCH dot (helper clobbers w10-w17) */
        bn.lid x25, 0(x15)        /* w8 = affine_value (walk overwrote it) */
        bn.lid x29, 0(x16)        /* w9 = msb_mask (window build overwrote) */
        jal x1, aes128_keygen     /* w2 = keystream pair (IV in w18) */
        bn.add w18, w18, w19
        bn.xor w6, w6, w2
        bn.sd w6, 0(x10++)
        jal x1, aes128_keygen
        bn.add w18, w18, w19
        bn.xor w3, w3, w2
        bn.sd w3, 0(x10++)
        li x5, 0x13
        csrrw x0, mod0, x5        /* helper left 0x11B; walks need GF(16) */
#endif
    addi x7, x7, 1
    addi x30, x30, -1
    jal x1, p1op2_rows1_94_setup
    addi x21, x7, -64
    add  x20, x0, x30
    slli x4, x7, 7
    lw   x5, 4(x3)
    slli x6, x5, 1
    add  x4, x4, x6
    li   x5, 9312
    add  x4, x4, x5
    la   x5, ivb
    bn.sd w31, 0(x5)
    sw   x4, 0(x5)
    bn.ld w14, 0(x5)
    bn.addi w15, w14, 1
    bn.rshi w2, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w2, w2, w15
#ifndef AES_INSTRUCTIONS
    bn.mov w18, w2            /* helper IV lives in w18 (advances by w19) */
#endif
    la x10, gbuf23
#ifdef AES_INSTRUCTIONS
    loop x19, 40
#else
    loop x19, 26
#endif
        add x9, x0, x22
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        addi x12, x12, 32
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        bn.rshi w10, w31, w5 >> 128
        csrrw x0, mod1, x21
        loop x20, 3
            bn.lid x23, 0(x9++)
            bn.gfmul.4.acc w8, w6, w4
            bn.gfmul.4.acch.inc w12, w6, w10
#ifdef AES_INSTRUCTIONS
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
        bn.sd w8, 0(x10++)
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
        bn.sd w12, 0(x10++)
#else
        bn.mov w6, w8             /* park ACC dot (helper wants w8=affine) */
        bn.mov w3, w12            /* park ACCH dot (helper clobbers w10-w17) */
        bn.lid x25, 0(x15)        /* w8 = affine_value (walk overwrote it) */
        bn.lid x29, 0(x16)        /* w9 = msb_mask (window build overwrote) */
        jal x1, aes128_keygen     /* w2 = keystream pair (IV in w18) */
        bn.add w18, w18, w19
        bn.xor w6, w6, w2
        bn.sd w6, 0(x10++)
        jal x1, aes128_keygen
        bn.add w18, w18, w19
        bn.xor w3, w3, w2
        bn.sd w3, 0(x10++)
        li x5, 0x13
        csrrw x0, mod0, x5        /* helper left 0x11B; walks need GF(16) */
#endif
    addi x7, x7, 1
    addi x30, x30, -1
    jal x1, p1op2_rows1_94_setup
    addi x21, x7, -64
    add  x20, x0, x30
    slli x4, x7, 7
    lw   x5, 4(x3)
    slli x6, x5, 1
    add  x4, x4, x6
    li   x5, 9312
    add  x4, x4, x5
    la   x5, ivb
    bn.sd w31, 0(x5)
    sw   x4, 0(x5)
    bn.ld w14, 0(x5)
    bn.addi w15, w14, 1
    bn.rshi w2, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w2, w2, w15
#ifndef AES_INSTRUCTIONS
    bn.mov w18, w2            /* helper IV lives in w18 (advances by w19) */
#endif
    la x10, gbuf23
    addi x10, x10, 384
#ifdef AES_INSTRUCTIONS
    loop x19, 40
#else
    loop x19, 26
#endif
        add x9, x0, x22
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        addi x12, x12, 32
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        bn.rshi w10, w31, w5 >> 128
        csrrw x0, mod1, x21
        loop x20, 3
            bn.lid x23, 0(x9++)
            bn.gfmul.4.acc w8, w6, w4
            bn.gfmul.4.acch.inc w12, w6, w10
#ifdef AES_INSTRUCTIONS
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
        bn.sd w8, 0(x10++)
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
        bn.sd w12, 0(x10++)
#else
        bn.mov w6, w8             /* park ACC dot (helper wants w8=affine) */
        bn.mov w3, w12            /* park ACCH dot (helper clobbers w10-w17) */
        bn.lid x25, 0(x15)        /* w8 = affine_value (walk overwrote it) */
        bn.lid x29, 0(x16)        /* w9 = msb_mask (window build overwrote) */
        jal x1, aes128_keygen     /* w2 = keystream pair (IV in w18) */
        bn.add w18, w18, w19
        bn.xor w6, w6, w2
        bn.sd w6, 0(x10++)
        jal x1, aes128_keygen
        bn.add w18, w18, w19
        bn.xor w3, w3, w2
        bn.sd w3, 0(x10++)
        li x5, 0x13
        csrrw x0, mod0, x5        /* helper left 0x11B; walks need GF(16) */
#endif
    addi x7, x7, 1
    addi x30, x30, -1
#ifndef AES_INSTRUCTIONS
    lw x18, 8(x0)             /* fold clusters clobbered x18/x19 (helper) */
#endif
    addi x21, x7, -68
    li x5, 13
    li x6, 16
    la x13, gbuf01
    la x14, gbuf23
    la x11, slice
    lw x9, 0(x3)
    loop x18, 34
      li x17, 0
      bn.lid x17, 0(x13)
      li x17, 2
      bn.lid x17, 384(x13)
      li x17, 6
      bn.lid x17, 0(x14)
      li x17, 7
      bn.lid x17, 384(x14)
      add x4, x0, x9
      add x10, x0, x11
      loopi 32, 20
        addi x4, x4, 32
        bn.lid x27, 0(x4++)
        bn.lid x28, 0(x4++)
        bn.rshi w10, w31, w5 >> 128
        csrrw x0, mod1, x21
        bn.lid x5, 0(x10)
        bn.lid x6, 384(x10)
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
        bn.sd w8, 0(x10)
        bn.sd w12, 384(x10)
        addi x10, x10, 768
      addi x11, x11, 32
      addi x13, x13, 32
      addi x14, x14, 32
    nop
    csrrw x0, mod1, x0        /* pin mod1 = 0 on exit */
    sw x0, 12(x0)             /* status = 0 */
    ecall

_bad_args:
    csrrw x0, mod1, x0        /* pin mod1 = 0 on exit */
    li x6, -2
    sw x6, 12(x0)
    ecall

/* ===== P1 row expand: (96-r) dual-block entries -> p1buf (per-tier).
 * in: x30 = 96-r, x22 = p1buf, w19 inc, w20-w30 RKs; out: x12 = window O
 * base. bngfaes: w1 = running P1 IV (verbatim monolith arm).
 * bngfonly: IV rebuilt in w18 from x24 (GPR P1 ctr, += 2*(96-r) here);
 * loads w7/w8/w9 consts (persist to the fold clusters); restores
 * mod0=0x13 and x18/x19 in the tail (helper clobbered them). ===== */
p1op2_rows1_94_setup:
#ifdef AES_INSTRUCTIONS
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
        bn.sd w0, 0(x9++)
        bn.add w1, w1, w19
    lw x12, 8(x3)
    ret
#else
    la x12, byte_swap_mask
    li x5, 7
    bn.lid x5, 0(x12)         /* w7 (fold walks never touch it) */
    bn.lid x25, 0(x15)        /* w8 = affine_value */
    bn.lid x29, 0(x16)        /* w9 = msb_mask */
    la x5, ivb
    bn.sd w31, 0(x5)
    sw x24, 0(x5)
    li x12, 14
    bn.lid x12, 0(x5)         /* w14 = P1 ctr */
    bn.addi w15, w14, 1
    bn.rshi w18, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w18, w18, w15      /* [ctr+1@224 | ctr@96] */
    add x9, x0, x22
    loop x30, 3
        jal x1, aes128_keygen
        bn.sd w2, 0(x9++)
        bn.add w18, w18, w19
    slli x5, x30, 1
    add x24, x24, x5          /* P1 ctr += 2*(96-r) */
    li x5, 0x13
    csrrw x0, mod0, x5        /* helper left 0x11B; walks need GF(16) */
    lw x18, 8(x0)             /* helper clobbered x18/x19 */
    srli x19, x18, 1
    lw x12, 8(x3)
    ret
#endif

