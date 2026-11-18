/* ov-Is-keygen_min.s - one-shot UOV-Is keygen, minimal DMEM
 * (77,248B bus-visible). WJ=2: 32 windows
 * re-expand P1 (more cycles, less DMEM). WJ=2 is the structural floor -
 * the GF16 pair reduce needs an even column count per window.
 * Host contract unchanged: write sk_seed, EXECUTE, read cpk 66,576B + csk.
 * Fold-scatter into the packed 32B-entry upper-tri accumulator in place;
 * pk_seed prefix at the end.
 * Frame ext: +4 col_start | +32 wc | +36 seg_c | +40 c.
 * Fold per slice col c: k >= c plain-stores to slot(c,k); k < c XOR-RMWs
 * slot(k,c). First touch each run = plain store -> re-EXECUTE clean.
 * mod1 = 0 on exit. clob: everything (app, no caller).
 * stack: INIT overlays slice (expandsk 3,104B); WINDOW uses the frame.
 */
.section .data
.balign 32
sk_seed:                      /* harness injects the KAT seed here */
csk:                          /* same buffer: csk == sk_seed, left in place */
    .zero 32
pk_seed:   .zero 32           /* INIT ctx (low 16B valid) */
           .zero 16           /* payload must land 32B-aligned */
cpk:       .zero 16           /* pk_seed prefix (written at the end) */
cpk_payload: .zero 66560      /* 2,080 x 32B packed upper-tri accumulator */
slice:     .zero 4096
slice_end:
o_ctx:     .zero 3072
p1buf:     .zero 3072
gbuf01:    .zero 128
#ifdef AES_INSTRUCTIONS
ivb:       .zero 32
frame:     .zero 64
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
gbuf23:    .zero 128
#ifndef AES_INSTRUCTIONS
ivb:       .zero 32
frame:     .zero 64
#endif

.section .text.start
.balign 4
.global main
main:
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

    /* window loop: runtime-init state in the frame extension */
    la   x3, frame
    sw   x0, 36(x3)           /* seg_c */
    sw   x0, 40(x3)           /* c = next col_start */
_wloop:
    la   x3, frame
    lw   x5, 40(x3)           /* col_start = c (stays even) */
    li   x18, 2               /* 64 % 2 == 0: 32 exact windows, no short one */
    sw   x5, 4(x3)
    sw   x18, 32(x3)          /* wc: body reloads + fold read this */
    /* falls into the spliced WINDOW body (post-validation) */
    srli x19, x18, 1          /* pair count */
    bn.xor w31, w31, w31
    li x4, 0x13
    csrrw x0, mod0, x4
    csrrw x0, mod1, x0
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
    li x4, 0x13
    csrrw x0, mod0, x4        /* KS left mod0=0x11B; Is walks are GF(16) */
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
    li x31, 31
    li x23, 6
    li x25, 8
    li x8,  12
    li x26, 3
    li x27, 4
    li x28, 5
    la x22, p1buf             /* resident P1 tmp base (setup contract) */
    /* zero the FULL slice (fixed layout, all windows): 128 stores */
    la x10, slice
    li x4, 128
    loop x4, 1
        bn.sid x31, 0(x10++)
    li x7, 0                  /* row */
    li x30, 96                /* 96 - r */
    /* ---- band A: 16 groups of 4 rows + fold ---- */
#ifdef AES_INSTRUCTIONS
    loopi 16, 324
#else
    loopi 16, 274             /* 4x56 + 2 + 46 + 2; re-derive on body edit */
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
    bn.sid x31, 0(x5)
    sw   x4, 0(x5)
    li   x6, 14
    bn.lid x6, 0(x5)
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
#else
        bn.mov w6, w8             /* park ACC dot (helper wants w8=affine) */
        bn.mov w3, w12            /* park ACCH dot (helper clobbers w10-w17) */
        bn.lid x25, 0(x15)        /* w8 = affine_value (walk overwrote it) */
        bn.lid x29, 0(x16)        /* w9 = msb_mask (window build overwrote) */
        jal x1, aes128_keygen     /* w2 = keystream pair (IV in w18) */
        bn.add w18, w18, w19
        bn.xor w6, w6, w2
        bn.sid x23, 0(x10++)
        jal x1, aes128_keygen
        bn.add w18, w18, w19
        bn.xor w3, w3, w2
        bn.sid x26, 0(x10++)
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
    bn.sid x31, 0(x5)
    sw   x4, 0(x5)
    li   x6, 14
    bn.lid x6, 0(x5)
    bn.addi w15, w14, 1
    bn.rshi w2, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w2, w2, w15
#ifndef AES_INSTRUCTIONS
    bn.mov w18, w2            /* helper IV lives in w18 (advances by w19) */
#endif
    la x10, gbuf01
    addi x10, x10, 64
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
#else
        bn.mov w6, w8             /* park ACC dot (helper wants w8=affine) */
        bn.mov w3, w12            /* park ACCH dot (helper clobbers w10-w17) */
        bn.lid x25, 0(x15)        /* w8 = affine_value (walk overwrote it) */
        bn.lid x29, 0(x16)        /* w9 = msb_mask (window build overwrote) */
        jal x1, aes128_keygen     /* w2 = keystream pair (IV in w18) */
        bn.add w18, w18, w19
        bn.xor w6, w6, w2
        bn.sid x23, 0(x10++)
        jal x1, aes128_keygen
        bn.add w18, w18, w19
        bn.xor w3, w3, w2
        bn.sid x26, 0(x10++)
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
    bn.sid x31, 0(x5)
    sw   x4, 0(x5)
    li   x6, 14
    bn.lid x6, 0(x5)
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
#else
        bn.mov w6, w8             /* park ACC dot (helper wants w8=affine) */
        bn.mov w3, w12            /* park ACCH dot (helper clobbers w10-w17) */
        bn.lid x25, 0(x15)        /* w8 = affine_value (walk overwrote it) */
        bn.lid x29, 0(x16)        /* w9 = msb_mask (window build overwrote) */
        jal x1, aes128_keygen     /* w2 = keystream pair (IV in w18) */
        bn.add w18, w18, w19
        bn.xor w6, w6, w2
        bn.sid x23, 0(x10++)
        jal x1, aes128_keygen
        bn.add w18, w18, w19
        bn.xor w3, w3, w2
        bn.sid x26, 0(x10++)
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
    bn.sid x31, 0(x5)
    sw   x4, 0(x5)
    li   x6, 14
    bn.lid x6, 0(x5)
    bn.addi w15, w14, 1
    bn.rshi w2, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w2, w2, w15
#ifndef AES_INSTRUCTIONS
    bn.mov w18, w2            /* helper IV lives in w18 (advances by w19) */
#endif
    la x10, gbuf23
    addi x10, x10, 64
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
#else
        bn.mov w6, w8             /* park ACC dot (helper wants w8=affine) */
        bn.mov w3, w12            /* park ACCH dot (helper clobbers w10-w17) */
        bn.lid x25, 0(x15)        /* w8 = affine_value (walk overwrote it) */
        bn.lid x29, 0(x16)        /* w9 = msb_mask (window build overwrote) */
        jal x1, aes128_keygen     /* w2 = keystream pair (IV in w18) */
        bn.add w18, w18, w19
        bn.xor w6, w6, w2
        bn.sid x23, 0(x10++)
        jal x1, aes128_keygen
        bn.add w18, w18, w19
        bn.xor w3, w3, w2
        bn.sid x26, 0(x10++)
        li x5, 0x13
        csrrw x0, mod0, x5        /* helper left 0x11B; walks need GF(16) */
#endif
    addi x7, x7, 1
    addi x30, x30, -1
#ifndef AES_INSTRUCTIONS
    lw x18, 32(x3)             /* fold clusters clobbered x18/x19 (helper) */
    srli x19, x18, 1
#endif
    addi x21, x7, -4
    li x5, 13
    li x6, 16
    la x13, gbuf01
    la x14, gbuf23
    la x11, slice
    loop x18, 35
      li x17, 0
      bn.lid x17, 0(x13)
      li x17, 2
      bn.lid x17, 64(x13)
      li x17, 6
      bn.lid x17, 0(x14)
      li x17, 7
      bn.lid x17, 64(x14)
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
        bn.lid x6, 64(x10)
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
        bn.sid x8, 64(x10)
        addi x10, x10, 128
      addi x11, x11, 32
      addi x13, x13, 32
      addi x14, x14, 32
    nop
    /* ---- band B: 8 groups of 4 rows + fold ---- */
#ifdef AES_INSTRUCTIONS
    loopi 8, 312
#else
    loopi 8, 262              /* 312 - 4x13 + 2 reload; re-derive on body edit */
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
    bn.sid x31, 0(x5)
    sw   x4, 0(x5)
    li   x6, 14
    bn.lid x6, 0(x5)
    bn.addi w15, w14, 1
    bn.rshi w2, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w2, w2, w15
#ifndef AES_INSTRUCTIONS
    bn.mov w18, w2            /* helper IV lives in w18 (advances by w19) */
#endif
    la x10, gbuf01
#ifdef AES_INSTRUCTIONS
    loop x19, 41
#else
    loop x19, 27
#endif
        add x9, x0, x22
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        bn.rshi w9, w5, w4 >> 128
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
#else
        bn.mov w6, w8             /* park ACC dot (helper wants w8=affine) */
        bn.mov w3, w12            /* park ACCH dot (helper clobbers w10-w17) */
        bn.lid x25, 0(x15)        /* w8 = affine_value (walk overwrote it) */
        bn.lid x29, 0(x16)        /* w9 = msb_mask (window build overwrote) */
        jal x1, aes128_keygen     /* w2 = keystream pair (IV in w18) */
        bn.add w18, w18, w19
        bn.xor w6, w6, w2
        bn.sid x23, 0(x10++)
        jal x1, aes128_keygen
        bn.add w18, w18, w19
        bn.xor w3, w3, w2
        bn.sid x26, 0(x10++)
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
    bn.sid x31, 0(x5)
    sw   x4, 0(x5)
    li   x6, 14
    bn.lid x6, 0(x5)
    bn.addi w15, w14, 1
    bn.rshi w2, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w2, w2, w15
#ifndef AES_INSTRUCTIONS
    bn.mov w18, w2            /* helper IV lives in w18 (advances by w19) */
#endif
    la x10, gbuf01
    addi x10, x10, 64
#ifdef AES_INSTRUCTIONS
    loop x19, 41
#else
    loop x19, 27
#endif
        add x9, x0, x22
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        bn.rshi w9, w5, w4 >> 128
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
#else
        bn.mov w6, w8             /* park ACC dot (helper wants w8=affine) */
        bn.mov w3, w12            /* park ACCH dot (helper clobbers w10-w17) */
        bn.lid x25, 0(x15)        /* w8 = affine_value (walk overwrote it) */
        bn.lid x29, 0(x16)        /* w9 = msb_mask (window build overwrote) */
        jal x1, aes128_keygen     /* w2 = keystream pair (IV in w18) */
        bn.add w18, w18, w19
        bn.xor w6, w6, w2
        bn.sid x23, 0(x10++)
        jal x1, aes128_keygen
        bn.add w18, w18, w19
        bn.xor w3, w3, w2
        bn.sid x26, 0(x10++)
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
    bn.sid x31, 0(x5)
    sw   x4, 0(x5)
    li   x6, 14
    bn.lid x6, 0(x5)
    bn.addi w15, w14, 1
    bn.rshi w2, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w2, w2, w15
#ifndef AES_INSTRUCTIONS
    bn.mov w18, w2            /* helper IV lives in w18 (advances by w19) */
#endif
    la x10, gbuf23
#ifdef AES_INSTRUCTIONS
    loop x19, 41
#else
    loop x19, 27
#endif
        add x9, x0, x22
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        bn.rshi w9, w5, w4 >> 128
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
#else
        bn.mov w6, w8             /* park ACC dot (helper wants w8=affine) */
        bn.mov w3, w12            /* park ACCH dot (helper clobbers w10-w17) */
        bn.lid x25, 0(x15)        /* w8 = affine_value (walk overwrote it) */
        bn.lid x29, 0(x16)        /* w9 = msb_mask (window build overwrote) */
        jal x1, aes128_keygen     /* w2 = keystream pair (IV in w18) */
        bn.add w18, w18, w19
        bn.xor w6, w6, w2
        bn.sid x23, 0(x10++)
        jal x1, aes128_keygen
        bn.add w18, w18, w19
        bn.xor w3, w3, w2
        bn.sid x26, 0(x10++)
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
    bn.sid x31, 0(x5)
    sw   x4, 0(x5)
    li   x6, 14
    bn.lid x6, 0(x5)
    bn.addi w15, w14, 1
    bn.rshi w2, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w2, w2, w15
#ifndef AES_INSTRUCTIONS
    bn.mov w18, w2            /* helper IV lives in w18 (advances by w19) */
#endif
    la x10, gbuf23
    addi x10, x10, 64
#ifdef AES_INSTRUCTIONS
    loop x19, 41
#else
    loop x19, 27
#endif
        add x9, x0, x22
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        bn.rshi w9, w5, w4 >> 128
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
#else
        bn.mov w6, w8             /* park ACC dot (helper wants w8=affine) */
        bn.mov w3, w12            /* park ACCH dot (helper clobbers w10-w17) */
        bn.lid x25, 0(x15)        /* w8 = affine_value (walk overwrote it) */
        bn.lid x29, 0(x16)        /* w9 = msb_mask (window build overwrote) */
        jal x1, aes128_keygen     /* w2 = keystream pair (IV in w18) */
        bn.add w18, w18, w19
        bn.xor w6, w6, w2
        bn.sid x23, 0(x10++)
        jal x1, aes128_keygen
        bn.add w18, w18, w19
        bn.xor w3, w3, w2
        bn.sid x26, 0(x10++)
        li x5, 0x13
        csrrw x0, mod0, x5        /* helper left 0x11B; walks need GF(16) */
#endif
    addi x7, x7, 1
    addi x30, x30, -1
#ifndef AES_INSTRUCTIONS
    lw x18, 32(x3)             /* fold clusters clobbered x18/x19 (helper) */
    srli x19, x18, 1
#endif
    addi x21, x7, -68
    li x5, 13
    li x6, 16
    la x13, gbuf01
    la x14, gbuf23
    la x11, slice
    loop x18, 35
      li x17, 0
      bn.lid x17, 0(x13)
      li x17, 2
      bn.lid x17, 64(x13)
      li x17, 6
      bn.lid x17, 0(x14)
      li x17, 7
      bn.lid x17, 64(x14)
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
        bn.lid x6, 64(x10)
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
        bn.sid x8, 64(x10)
        addi x10, x10, 128
      addi x11, x11, 32
      addi x13, x13, 32
      addi x14, x14, 32
    nop
    jal  x0, _fold


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
        bn.sid x0, 0(x9++)
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
    li x5, 0x13
    csrrw x0, mod0, x5        /* helper left 0x11B; walks need GF(16) */
    lw x18, 32(x3)             /* helper clobbered x18/x19 */
    srli x19, x18, 1
    lw x12, 8(x3)
    ret
#endif


/* ---- fold-scatter: slice window cols -> packed upper-tri accumulator ---- */
_fold:
    la   x3, frame
    lw   x14, 40(x3)          /* c = global col (cols strictly ascend) */
    lw   x15, 36(x3)          /* seg_c = payload offset of row-c segment */
    lw   x18, 32(x3)          /* col_count */
    la   x20, slice
    la   x21, cpk_payload
    li   x8, 0                /* WDR idx: w0 slice entry, w2 slot */
    li   x16, 2
_fold_j:
    beq  x14, x0, _fold_ge    /* c = 0: nothing above the diagonal */
    /* k < c: XOR into slot(k,c). Walk from slot(0,c) = payload + 32c;
     * stride 63*32 shrinking 32/step (row segments shorten). */
    slli x22, x14, 5
    add  x22, x21, x22
    add  x24, x20, x0
    li   x23, 2016
    loop x14, 7
        bn.lid x8, 0(x24)
        bn.lid x16, 0(x22)
        bn.xor w2, w2, w0
        bn.sid x16, 0(x22)
        addi x24, x24, 64
        add  x22, x22, x23
        addi x23, x23, -32
_fold_ge:
    /* k >= c: plain store to slot(c,k) - contiguous row-c segment */
    add  x22, x21, x15
    li   x25, 64
    sub  x25, x25, x14
    slli x26, x14, 6
    add  x24, x20, x26        /* slice + c*64 (this col) */
    loop x25, 4
        bn.lid x8, 0(x24)
        bn.sid x8, 0(x22)
        addi x24, x24, 64
        addi x22, x22, 32
    /* seg_{c+1} = seg_c + 32*(64-c); advance col */
    slli x26, x14, 5
    li   x27, 2048
    sub  x27, x27, x26
    add  x15, x15, x27
    addi x14, x14, 1
    addi x20, x20, 32
    addi x18, x18, -1
    bne  x18, x0, _fold_j
    sw   x14, 40(x3)          /* c == next col_start */
    sw   x15, 36(x3)
    li   x6, 64
    bne  x14, x6, _wloop
    /* cpk = pk_seed(16B) || payload (already packed in place) */
    la   x5, pk_seed
    la   x6, cpk
    lw   x7, 0(x5)
    sw   x7, 0(x6)
    lw   x7, 4(x5)
    sw   x7, 4(x6)
    lw   x7, 8(x5)
    sw   x7, 8(x6)
    lw   x7, 12(x5)
    sw   x7, 12(x6)
    csrrw x0, mod1, x0        /* pin mod1 = 0 on exit */
    ecall

/* host interface for C (ACC_DECLARE_SYMBOL_ADDR): seed in, csk == seed, cpk out */
.globl sk_seed
.globl csk
.globl cpk
