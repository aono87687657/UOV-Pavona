/* ov-Ip3-keygen_stream.s - streamed UOV-Ip3 keygen, phase-dispatch outer.
 * Streamed UOV-Ip3 keygen (v=74, o=45, WJ=6): phase-dispatch, ctx in DMEM.
 *   phase 0 INIT  : expandsk(sk_seed@0x20) -> pk_seed@0x40 + padded O ctx
 *   phase 1 WINDOW(arg0=col_start, arg1=1<=col_count<=6): slice[k][j] =
 *           sum_i O[i][k]*B[i][col_start+j], B = P1*O+P2 restreamed from AES.
 * WINDOW requires a prior INIT (pk_seed stored zero-extended to 32 B).
 * Fixed slice: entry (k,j) at slice + k*384 + j*64 (45B valid + 19B pad).
 * P2 stream: g = 2775 + 45*row + col; b=g>>3, slot=g&7; expand_360 seek
 * ctr=floor(45*b/2), phase=b&1. RKs re-derived from pk_seed per WINDOW.
 * mod1=0 on every phase exit. clob: everything (phase app, no caller).
 */
.section .data
.balign 32
ctrl:      .word 0, 0, 0, 0
           .zero 16
sk_seed:   .zero 32
pk_seed:   .zero 32
slice:     .zero 17280
slice_end:
o_aligned: .zero 4320
p1buf:     .zero 5120
group_buf: .zero 1536
frame:     .zero 32
#ifdef AES_INSTRUCTIONS
           .zero 768
#else
/* bngfonly locals in the pad: AES consts (aes128_sign/KeySchedule_sign and
 * expand_360 reference these by name; the constants lib is NOT linked so
 * they place here) + leaf stack. 5x32 consts + 152 slack + 456 stack
 * (448 expand_360 frame + 8 aes128_sign push) = 768; kg_stack_top and the
 * frame base land 32-aligned. */
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
           .zero 608
kg_stack_top:
#endif

.set p2buf, 31744
.global p2buf

.section .text.start
.balign 4
.global main
main:
    lw   x4, 0(x0)            /* phase */
    beq  x4, x0, _INIT
    li   x5, 1
    beq  x4, x5, _WINDOW
    jal  x0, _bad_args

/* ============================ INIT ============================ */
/* expandsk emits pk_seed(16B) || padded O(45x96); route its 4352B frame
 * through p1buf so it never overlaps o_aligned, then forward-copy down. */
_INIT:
    bn.xor w31, w31, w31
    la x2, group_buf          /* p1buf_end; expandsk frame grows down */
    la x11, sk_seed
    jal x1, expandsk_ret_O_pkseed
    li x6, 0
    bn.lid x6, 0(x2)
    la x5, pk_seed
    bn.sid x6, 0(x5)
    addi x12, x2, 32
    la x11, o_aligned
    loopi 135, 2
        bn.lid x6, 0(x12++)
        bn.sid x6, 0(x11++)
    csrrw x0, mod1, x0
    sw x0, 12(x0)
    ecall

/* ============================ WINDOW ============================ */
_WINDOW:
    la x3, frame
    lw x5, 4(x0)              /* col_start */
    lw x18, 8(x0)             /* col_count */
    sw x5, 4(x3)
    beq x18, x0, _bad_args
    or   x8, x5, x18          /* pre-gate cs|cc < 64: the signed-trick */
    srli x8, x8, 6            /* checks below wrap on huge inputs */
    bne  x8, x0, _bad_args
    addi x8, x18, -7     /* reject col_count > 6: group stores would */
    srli x8, x8, 31           /* run past group_buf into frame/pad */
    beq x8, x0, _bad_args
    li   x8, 44            /* col_start <= 44 */
    sub  x8, x8, x5
    srli x8, x8, 31
    bne  x8, x0, _bad_args
    add  x8, x5, x18
    li   x30, 45             /* col_start + col_count <= 45 */
    sub  x30, x30, x8
    srli x30, x30, 31
    bne  x30, x0, _bad_args
    bn.xor w31, w31, w31
    li x8, 0x11b
    csrrw x0, mod0, x8
    la x6, o_aligned
    sw x6, 0(x3)
    slli x7, x5, 6
    slli x8, x5, 5
    add  x7, x7, x8           /* col_start*96 */
    add  x6, x6, x7
    sw x6, 16(x3)
    la x6, p1buf
    sw x6, 20(x3)
    la x6, p2buf
    sw x6, 24(x3)
    la x8, pk_seed
    li x30, 30
    bn.lid x30, 0(x8)
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
    /* SW KS via KeySchedule_sign: RK1..RK10 dual-stored FORWARD in w20..w29
     * (aes128_sign layout), w30 = RK0 dual (pk_seed high half zero: INIT
     * precondition). KS clobbers w7, w11..w17, x5 - all dead here. */
    la x2, kg_stack_top
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
#endif
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160
    li x23, 6
    li x24, 7
    li x26, 3
    li x27, 4
    li x28, 5
    li x19, 12
    la x10, slice
    li x8, 540
    loop x8, 1
        bn.sd w31, 0(x10++)
    li x9, 0
    li x7, 0
    /* ---- band A: 8 group(s) of 4 rows + fold ---- */
    loopi 8, 376
    jal x1, phase4_row_setup
    addi x20, x8, -42
    /* g = 2775 + 45*row + col_start */
    slli x8,  x7, 5
    slli x30, x7, 3
    add  x8,  x8, x30
    slli x30, x7, 2
    add  x8,  x8, x30
    add  x8,  x8, x7
    lw   x30, 4(x3)
    add  x8,  x8, x30
    li   x30, 2775
    add  x8,  x8, x30
    srli x30, x8, 3
    andi x8,  x8, 7
    slli x8,  x8, 6
    sw   x8, 12(x3)
    andi x16, x30, 1
    slli x29, x30, 5
    slli x8,  x30, 3
    add  x29, x29, x8
    slli x8,  x30, 2
    add  x29, x29, x8
    add  x29, x29, x30
    srli x29, x29, 1
    lw   x8, 24(x3)
    bn.sd w31, 0(x8)
    sw   x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or   w18, w14, w18 << 128
    bn.rshi w18, w18, w31 >> 160
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_A_0
    jal x1, expand_batch
_bskip_A_0:
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    loop x18, 30
        bn.lid x26, 0(x13++)
        bn.lid x27, 0(x13++)
        bn.lid x28, 0(x13++)
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x14, x0, x5
        csrrw x0, mod1, x7
        loop x20, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w3
            bn.gfmul.8.acch.inc w9, w7, w3
        loopi 32, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w4
            bn.gfmul.8.acch.inc w9, w7, w4
        loopi 10, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w5
            bn.gfmul.8.acch.inc w9, w7, w5
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    addi x20, x8, -42
    /* g = 2775 + 45*row + col_start */
    slli x8,  x7, 5
    slli x30, x7, 3
    add  x8,  x8, x30
    slli x30, x7, 2
    add  x8,  x8, x30
    add  x8,  x8, x7
    lw   x30, 4(x3)
    add  x8,  x8, x30
    li   x30, 2775
    add  x8,  x8, x30
    srli x30, x8, 3
    andi x8,  x8, 7
    slli x8,  x8, 6
    sw   x8, 12(x3)
    andi x16, x30, 1
    slli x29, x30, 5
    slli x8,  x30, 3
    add  x29, x29, x8
    slli x8,  x30, 2
    add  x29, x29, x8
    add  x29, x29, x30
    srli x29, x29, 1
    lw   x8, 24(x3)
    bn.sd w31, 0(x8)
    sw   x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or   w18, w14, w18 << 128
    bn.rshi w18, w18, w31 >> 160
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_A_1
    jal x1, expand_batch
_bskip_A_1:
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 384
    loop x18, 30
        bn.lid x26, 0(x13++)
        bn.lid x27, 0(x13++)
        bn.lid x28, 0(x13++)
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x14, x0, x5
        csrrw x0, mod1, x7
        loop x20, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w3
            bn.gfmul.8.acch.inc w9, w7, w3
        loopi 32, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w4
            bn.gfmul.8.acch.inc w9, w7, w4
        loopi 10, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w5
            bn.gfmul.8.acch.inc w9, w7, w5
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    addi x20, x8, -42
    /* g = 2775 + 45*row + col_start */
    slli x8,  x7, 5
    slli x30, x7, 3
    add  x8,  x8, x30
    slli x30, x7, 2
    add  x8,  x8, x30
    add  x8,  x8, x7
    lw   x30, 4(x3)
    add  x8,  x8, x30
    li   x30, 2775
    add  x8,  x8, x30
    srli x30, x8, 3
    andi x8,  x8, 7
    slli x8,  x8, 6
    sw   x8, 12(x3)
    andi x16, x30, 1
    slli x29, x30, 5
    slli x8,  x30, 3
    add  x29, x29, x8
    slli x8,  x30, 2
    add  x29, x29, x8
    add  x29, x29, x30
    srli x29, x29, 1
    lw   x8, 24(x3)
    bn.sd w31, 0(x8)
    sw   x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or   w18, w14, w18 << 128
    bn.rshi w18, w18, w31 >> 160
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_A_2
    jal x1, expand_batch
_bskip_A_2:
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 768
    loop x18, 30
        bn.lid x26, 0(x13++)
        bn.lid x27, 0(x13++)
        bn.lid x28, 0(x13++)
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x14, x0, x5
        csrrw x0, mod1, x7
        loop x20, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w3
            bn.gfmul.8.acch.inc w9, w7, w3
        loopi 32, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w4
            bn.gfmul.8.acch.inc w9, w7, w4
        loopi 10, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w5
            bn.gfmul.8.acch.inc w9, w7, w5
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    addi x20, x8, -42
    /* g = 2775 + 45*row + col_start */
    slli x8,  x7, 5
    slli x30, x7, 3
    add  x8,  x8, x30
    slli x30, x7, 2
    add  x8,  x8, x30
    add  x8,  x8, x7
    lw   x30, 4(x3)
    add  x8,  x8, x30
    li   x30, 2775
    add  x8,  x8, x30
    srli x30, x8, 3
    andi x8,  x8, 7
    slli x8,  x8, 6
    sw   x8, 12(x3)
    andi x16, x30, 1
    slli x29, x30, 5
    slli x8,  x30, 3
    add  x29, x29, x8
    slli x8,  x30, 2
    add  x29, x29, x8
    add  x29, x29, x30
    srli x29, x29, 1
    lw   x8, 24(x3)
    bn.sd w31, 0(x8)
    sw   x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or   w18, w14, w18 << 128
    bn.rshi w18, w18, w31 >> 160
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_A_3
    jal x1, expand_batch
_bskip_A_3:
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 1152
    loop x18, 30
        bn.lid x26, 0(x13++)
        bn.lid x27, 0(x13++)
        bn.lid x28, 0(x13++)
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x14, x0, x5
        csrrw x0, mod1, x7
        loop x20, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w3
            bn.gfmul.8.acch.inc w9, w7, w3
        loopi 32, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w4
            bn.gfmul.8.acch.inc w9, w7, w4
        loopi 10, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w5
            bn.gfmul.8.acch.inc w9, w7, w5
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    addi x21, x7, -4
    li x30, 96
    li x29, 384
    la x12, group_buf
    la x11, slice
    lw x5, 0(x3)
    loop x18, 39
      li x8, 0
      bn.lid x8, 0(x12)
      addi x8, x8, 1
      bn.lid x8, 32(x12)
      addi x8, x8, 1
      bn.lid x8, 384(x12)
      addi x8, x8, 1
      bn.lid x8, 416(x12)
      addi x8, x8, 1
      bn.lid x8, 768(x12)
      addi x8, x8, 1
      bn.lid x8, 800(x12)
      addi x8, x8, 1
      bn.lid x8, 1152(x12)
      addi x8, x8, 1
      bn.lid x8, 1184(x12)
      add x4, x0, x5
      add x10, x0, x11
      loopi 45, 18
        bn.lid x19, 0(x4)
        csrrw x0, mod1, x21
        bn.ld w10, 0(x10)
        bn.ld w11, 32(x10)
        bn.wsrw acc, w10
        bn.wsrw acch, w11
        bn.gfmul.8.acc      w8, w0, w12
        bn.gfmul.8.acch.inc w9, w1, w12
        bn.gfmul.8.acc      w8, w2, w12
        bn.gfmul.8.acch.inc w9, w3, w12
        bn.gfmul.8.acc      w8, w4, w12
        bn.gfmul.8.acch.inc w9, w5, w12
        bn.gfmul.8.acc      w8, w6, w12
        bn.gfmul.8.acch.inc w9, w7, w12
        bn.sd w8, 0(x10)
        bn.sd w9, 32(x10)
        add x4, x4, x30
        add x10, x10, x29
      addi x11, x11, 64
      addi x12, x12, 64
    nop
    /* ---- band B: 8 group(s) of 4 rows + fold ---- */
    loopi 8, 361
    jal x1, phase4_row_setup
    addi x21, x7, -32
    addi x20, x8, -10
    /* g = 2775 + 45*row + col_start */
    slli x8,  x7, 5
    slli x30, x7, 3
    add  x8,  x8, x30
    slli x30, x7, 2
    add  x8,  x8, x30
    add  x8,  x8, x7
    lw   x30, 4(x3)
    add  x8,  x8, x30
    li   x30, 2775
    add  x8,  x8, x30
    srli x30, x8, 3
    andi x8,  x8, 7
    slli x8,  x8, 6
    sw   x8, 12(x3)
    andi x16, x30, 1
    slli x29, x30, 5
    slli x8,  x30, 3
    add  x29, x29, x8
    slli x8,  x30, 2
    add  x29, x29, x8
    add  x29, x29, x30
    srli x29, x29, 1
    lw   x8, 24(x3)
    bn.sd w31, 0(x8)
    sw   x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or   w18, w14, w18 << 128
    bn.rshi w18, w18, w31 >> 160
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_B_0
    jal x1, expand_batch
_bskip_B_0:
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    loop x18, 25
        addi x13, x13, 32
        bn.lid x27, 0(x13++)
        bn.lid x28, 0(x13++)
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x14, x0, x5
        csrrw x0, mod1, x21
        loop x20, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w4
            bn.gfmul.8.acch.inc w9, w7, w4
        loopi 10, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w5
            bn.gfmul.8.acch.inc w9, w7, w5
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    addi x21, x7, -32
    addi x20, x8, -10
    /* g = 2775 + 45*row + col_start */
    slli x8,  x7, 5
    slli x30, x7, 3
    add  x8,  x8, x30
    slli x30, x7, 2
    add  x8,  x8, x30
    add  x8,  x8, x7
    lw   x30, 4(x3)
    add  x8,  x8, x30
    li   x30, 2775
    add  x8,  x8, x30
    srli x30, x8, 3
    andi x8,  x8, 7
    slli x8,  x8, 6
    sw   x8, 12(x3)
    andi x16, x30, 1
    slli x29, x30, 5
    slli x8,  x30, 3
    add  x29, x29, x8
    slli x8,  x30, 2
    add  x29, x29, x8
    add  x29, x29, x30
    srli x29, x29, 1
    lw   x8, 24(x3)
    bn.sd w31, 0(x8)
    sw   x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or   w18, w14, w18 << 128
    bn.rshi w18, w18, w31 >> 160
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_B_1
    jal x1, expand_batch
_bskip_B_1:
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 384
    loop x18, 25
        addi x13, x13, 32
        bn.lid x27, 0(x13++)
        bn.lid x28, 0(x13++)
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x14, x0, x5
        csrrw x0, mod1, x21
        loop x20, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w4
            bn.gfmul.8.acch.inc w9, w7, w4
        loopi 10, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w5
            bn.gfmul.8.acch.inc w9, w7, w5
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    addi x21, x7, -32
    addi x20, x8, -10
    /* g = 2775 + 45*row + col_start */
    slli x8,  x7, 5
    slli x30, x7, 3
    add  x8,  x8, x30
    slli x30, x7, 2
    add  x8,  x8, x30
    add  x8,  x8, x7
    lw   x30, 4(x3)
    add  x8,  x8, x30
    li   x30, 2775
    add  x8,  x8, x30
    srli x30, x8, 3
    andi x8,  x8, 7
    slli x8,  x8, 6
    sw   x8, 12(x3)
    andi x16, x30, 1
    slli x29, x30, 5
    slli x8,  x30, 3
    add  x29, x29, x8
    slli x8,  x30, 2
    add  x29, x29, x8
    add  x29, x29, x30
    srli x29, x29, 1
    lw   x8, 24(x3)
    bn.sd w31, 0(x8)
    sw   x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or   w18, w14, w18 << 128
    bn.rshi w18, w18, w31 >> 160
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_B_2
    jal x1, expand_batch
_bskip_B_2:
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 768
    loop x18, 25
        addi x13, x13, 32
        bn.lid x27, 0(x13++)
        bn.lid x28, 0(x13++)
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x14, x0, x5
        csrrw x0, mod1, x21
        loop x20, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w4
            bn.gfmul.8.acch.inc w9, w7, w4
        loopi 10, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w5
            bn.gfmul.8.acch.inc w9, w7, w5
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    addi x21, x7, -32
    addi x20, x8, -10
    /* g = 2775 + 45*row + col_start */
    slli x8,  x7, 5
    slli x30, x7, 3
    add  x8,  x8, x30
    slli x30, x7, 2
    add  x8,  x8, x30
    add  x8,  x8, x7
    lw   x30, 4(x3)
    add  x8,  x8, x30
    li   x30, 2775
    add  x8,  x8, x30
    srli x30, x8, 3
    andi x8,  x8, 7
    slli x8,  x8, 6
    sw   x8, 12(x3)
    andi x16, x30, 1
    slli x29, x30, 5
    slli x8,  x30, 3
    add  x29, x29, x8
    slli x8,  x30, 2
    add  x29, x29, x8
    add  x29, x29, x30
    srli x29, x29, 1
    lw   x8, 24(x3)
    bn.sd w31, 0(x8)
    sw   x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or   w18, w14, w18 << 128
    bn.rshi w18, w18, w31 >> 160
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_B_3
    jal x1, expand_batch
_bskip_B_3:
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 1152
    loop x18, 25
        addi x13, x13, 32
        bn.lid x27, 0(x13++)
        bn.lid x28, 0(x13++)
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x14, x0, x5
        csrrw x0, mod1, x21
        loop x20, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w4
            bn.gfmul.8.acch.inc w9, w7, w4
        loopi 10, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w5
            bn.gfmul.8.acch.inc w9, w7, w5
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    addi x21, x7, -36
    li x30, 96
    li x29, 384
    la x12, group_buf
    la x11, slice
    lw x5, 0(x3)
    addi x5, x5, 32
    loop x18, 39
      li x8, 0
      bn.lid x8, 0(x12)
      addi x8, x8, 1
      bn.lid x8, 32(x12)
      addi x8, x8, 1
      bn.lid x8, 384(x12)
      addi x8, x8, 1
      bn.lid x8, 416(x12)
      addi x8, x8, 1
      bn.lid x8, 768(x12)
      addi x8, x8, 1
      bn.lid x8, 800(x12)
      addi x8, x8, 1
      bn.lid x8, 1152(x12)
      addi x8, x8, 1
      bn.lid x8, 1184(x12)
      add x4, x0, x5
      add x10, x0, x11
      loopi 45, 18
        bn.lid x19, 0(x4)
        csrrw x0, mod1, x21
        bn.ld w10, 0(x10)
        bn.ld w11, 32(x10)
        bn.wsrw acc, w10
        bn.wsrw acch, w11
        bn.gfmul.8.acc      w8, w0, w12
        bn.gfmul.8.acch.inc w9, w1, w12
        bn.gfmul.8.acc      w8, w2, w12
        bn.gfmul.8.acch.inc w9, w3, w12
        bn.gfmul.8.acc      w8, w4, w12
        bn.gfmul.8.acch.inc w9, w5, w12
        bn.gfmul.8.acc      w8, w6, w12
        bn.gfmul.8.acch.inc w9, w7, w12
        bn.sd w8, 0(x10)
        bn.sd w9, 32(x10)
        add x4, x4, x30
        add x10, x10, x29
      addi x11, x11, 64
      addi x12, x12, 64
    nop
    /* ---- band C: 2 group(s) of 4 rows + fold ---- */
    loopi 2, 337
    jal x1, phase4_row_setup
    addi x21, x7, -64
    add  x20, x0, x8
    /* g = 2775 + 45*row + col_start */
    slli x8,  x7, 5
    slli x30, x7, 3
    add  x8,  x8, x30
    slli x30, x7, 2
    add  x8,  x8, x30
    add  x8,  x8, x7
    lw   x30, 4(x3)
    add  x8,  x8, x30
    li   x30, 2775
    add  x8,  x8, x30
    srli x30, x8, 3
    andi x8,  x8, 7
    slli x8,  x8, 6
    sw   x8, 12(x3)
    andi x16, x30, 1
    slli x29, x30, 5
    slli x8,  x30, 3
    add  x29, x29, x8
    slli x8,  x30, 2
    add  x29, x29, x8
    add  x29, x29, x30
    srli x29, x29, 1
    lw   x8, 24(x3)
    bn.sd w31, 0(x8)
    sw   x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or   w18, w14, w18 << 128
    bn.rshi w18, w18, w31 >> 160
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_C_0
    jal x1, expand_batch
_bskip_C_0:
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    loop x18, 19
        addi x13, x13, 64
        bn.lid x28, 0(x13++)
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x14, x0, x5
        csrrw x0, mod1, x21
        loop x20, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w5
            bn.gfmul.8.acch.inc w9, w7, w5
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    addi x21, x7, -64
    add  x20, x0, x8
    /* g = 2775 + 45*row + col_start */
    slli x8,  x7, 5
    slli x30, x7, 3
    add  x8,  x8, x30
    slli x30, x7, 2
    add  x8,  x8, x30
    add  x8,  x8, x7
    lw   x30, 4(x3)
    add  x8,  x8, x30
    li   x30, 2775
    add  x8,  x8, x30
    srli x30, x8, 3
    andi x8,  x8, 7
    slli x8,  x8, 6
    sw   x8, 12(x3)
    andi x16, x30, 1
    slli x29, x30, 5
    slli x8,  x30, 3
    add  x29, x29, x8
    slli x8,  x30, 2
    add  x29, x29, x8
    add  x29, x29, x30
    srli x29, x29, 1
    lw   x8, 24(x3)
    bn.sd w31, 0(x8)
    sw   x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or   w18, w14, w18 << 128
    bn.rshi w18, w18, w31 >> 160
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_C_1
    jal x1, expand_batch
_bskip_C_1:
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 384
    loop x18, 19
        addi x13, x13, 64
        bn.lid x28, 0(x13++)
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x14, x0, x5
        csrrw x0, mod1, x21
        loop x20, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w5
            bn.gfmul.8.acch.inc w9, w7, w5
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    addi x21, x7, -64
    add  x20, x0, x8
    /* g = 2775 + 45*row + col_start */
    slli x8,  x7, 5
    slli x30, x7, 3
    add  x8,  x8, x30
    slli x30, x7, 2
    add  x8,  x8, x30
    add  x8,  x8, x7
    lw   x30, 4(x3)
    add  x8,  x8, x30
    li   x30, 2775
    add  x8,  x8, x30
    srli x30, x8, 3
    andi x8,  x8, 7
    slli x8,  x8, 6
    sw   x8, 12(x3)
    andi x16, x30, 1
    slli x29, x30, 5
    slli x8,  x30, 3
    add  x29, x29, x8
    slli x8,  x30, 2
    add  x29, x29, x8
    add  x29, x29, x30
    srli x29, x29, 1
    lw   x8, 24(x3)
    bn.sd w31, 0(x8)
    sw   x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or   w18, w14, w18 << 128
    bn.rshi w18, w18, w31 >> 160
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_C_2
    jal x1, expand_batch
_bskip_C_2:
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 768
    loop x18, 19
        addi x13, x13, 64
        bn.lid x28, 0(x13++)
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x14, x0, x5
        csrrw x0, mod1, x21
        loop x20, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w5
            bn.gfmul.8.acch.inc w9, w7, w5
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    addi x21, x7, -64
    add  x20, x0, x8
    /* g = 2775 + 45*row + col_start */
    slli x8,  x7, 5
    slli x30, x7, 3
    add  x8,  x8, x30
    slli x30, x7, 2
    add  x8,  x8, x30
    add  x8,  x8, x7
    lw   x30, 4(x3)
    add  x8,  x8, x30
    li   x30, 2775
    add  x8,  x8, x30
    srli x30, x8, 3
    andi x8,  x8, 7
    slli x8,  x8, 6
    sw   x8, 12(x3)
    andi x16, x30, 1
    slli x29, x30, 5
    slli x8,  x30, 3
    add  x29, x29, x8
    slli x8,  x30, 2
    add  x29, x29, x8
    add  x29, x29, x30
    srli x29, x29, 1
    lw   x8, 24(x3)
    bn.sd w31, 0(x8)
    sw   x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or   w18, w14, w18 << 128
    bn.rshi w18, w18, w31 >> 160
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_C_3
    jal x1, expand_batch
_bskip_C_3:
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 1152
    loop x18, 19
        addi x13, x13, 64
        bn.lid x28, 0(x13++)
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x14, x0, x5
        csrrw x0, mod1, x21
        loop x20, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w5
            bn.gfmul.8.acch.inc w9, w7, w5
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    addi x21, x7, -68
    li x30, 96
    li x29, 384
    la x12, group_buf
    la x11, slice
    lw x5, 0(x3)
    addi x5, x5, 64
    loop x18, 39
      li x8, 0
      bn.lid x8, 0(x12)
      addi x8, x8, 1
      bn.lid x8, 32(x12)
      addi x8, x8, 1
      bn.lid x8, 384(x12)
      addi x8, x8, 1
      bn.lid x8, 416(x12)
      addi x8, x8, 1
      bn.lid x8, 768(x12)
      addi x8, x8, 1
      bn.lid x8, 800(x12)
      addi x8, x8, 1
      bn.lid x8, 1152(x12)
      addi x8, x8, 1
      bn.lid x8, 1184(x12)
      add x4, x0, x5
      add x10, x0, x11
      loopi 45, 18
        bn.lid x19, 0(x4)
        csrrw x0, mod1, x21
        bn.ld w10, 0(x10)
        bn.ld w11, 32(x10)
        bn.wsrw acc, w10
        bn.wsrw acch, w11
        bn.gfmul.8.acc      w8, w0, w12
        bn.gfmul.8.acch.inc w9, w1, w12
        bn.gfmul.8.acc      w8, w2, w12
        bn.gfmul.8.acch.inc w9, w3, w12
        bn.gfmul.8.acc      w8, w4, w12
        bn.gfmul.8.acch.inc w9, w5, w12
        bn.gfmul.8.acc      w8, w6, w12
        bn.gfmul.8.acch.inc w9, w7, w12
        bn.sd w8, 0(x10)
        bn.sd w9, 32(x10)
        add x4, x4, x30
        add x10, x10, x29
      addi x11, x11, 64
      addi x12, x12, 64
    nop
    /* ---- tail: rows 72,73 (2-row fold) ---- */
    jal x1, phase4_row_setup
    addi x21, x7, -64
    add  x20, x0, x8
    /* g = 2775 + 45*row + col_start */
    slli x8,  x7, 5
    slli x30, x7, 3
    add  x8,  x8, x30
    slli x30, x7, 2
    add  x8,  x8, x30
    add  x8,  x8, x7
    lw   x30, 4(x3)
    add  x8,  x8, x30
    li   x30, 2775
    add  x8,  x8, x30
    srli x30, x8, 3
    andi x8,  x8, 7
    slli x8,  x8, 6
    sw   x8, 12(x3)
    andi x16, x30, 1
    slli x29, x30, 5
    slli x8,  x30, 3
    add  x29, x29, x8
    slli x8,  x30, 2
    add  x29, x29, x8
    add  x29, x29, x30
    srli x29, x29, 1
    lw   x8, 24(x3)
    bn.sd w31, 0(x8)
    sw   x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or   w18, w14, w18 << 128
    bn.rshi w18, w18, w31 >> 160
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_C_T0
    jal x1, expand_batch
_bskip_C_T0:
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    loop x18, 19
        addi x13, x13, 64
        bn.lid x28, 0(x13++)
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x14, x0, x5
        csrrw x0, mod1, x21
        loop x20, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w5
            bn.gfmul.8.acch.inc w9, w7, w5
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    addi x21, x7, -64
    add  x20, x0, x8
    /* g = 2775 + 45*row + col_start */
    slli x8,  x7, 5
    slli x30, x7, 3
    add  x8,  x8, x30
    slli x30, x7, 2
    add  x8,  x8, x30
    add  x8,  x8, x7
    lw   x30, 4(x3)
    add  x8,  x8, x30
    li   x30, 2775
    add  x8,  x8, x30
    srli x30, x8, 3
    andi x8,  x8, 7
    slli x8,  x8, 6
    sw   x8, 12(x3)
    andi x16, x30, 1
    slli x29, x30, 5
    slli x8,  x30, 3
    add  x29, x29, x8
    slli x8,  x30, 2
    add  x29, x29, x8
    add  x29, x29, x30
    srli x29, x29, 1
    lw   x8, 24(x3)
    bn.sd w31, 0(x8)
    sw   x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or   w18, w14, w18 << 128
    bn.rshi w18, w18, w31 >> 160
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_C_T1
    jal x1, expand_batch
_bskip_C_T1:
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 384
    loop x18, 19
        addi x13, x13, 64
        bn.lid x28, 0(x13++)
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x14, x0, x5
        csrrw x0, mod1, x21
        loop x20, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w5
            bn.gfmul.8.acch.inc w9, w7, w5
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    addi x7, x7, 1
    addi x21, x7, -66
    li x30, 96
    li x29, 384
    la x12, group_buf
    la x11, slice
    lw x5, 0(x3)
    addi x5, x5, 64
    loop x18, 27
      li x8, 0
      bn.lid x8, 0(x12)
      addi x8, x8, 1
      bn.lid x8, 32(x12)
      addi x8, x8, 1
      bn.lid x8, 384(x12)
      addi x8, x8, 1
      bn.lid x8, 416(x12)
      add x4, x0, x5
      add x10, x0, x11
      loopi 45, 14
        bn.lid x19, 0(x4)
        csrrw x0, mod1, x21
        bn.ld w10, 0(x10)
        bn.ld w11, 32(x10)
        bn.wsrw acc, w10
        bn.wsrw acch, w11
        bn.gfmul.8.acc      w8, w0, w12
        bn.gfmul.8.acch.inc w9, w1, w12
        bn.gfmul.8.acc      w8, w2, w12
        bn.gfmul.8.acch.inc w9, w3, w12
        bn.sd w8, 0(x10)
        bn.sd w9, 32(x10)
        add x4, x4, x30
        add x10, x10, x29
      addi x11, x11, 64
      addi x12, x12, 64
    csrrw x0, mod1, x0
    sw x0, 12(x0)
    ecall

_bad_args:
    li x6, -2
    sw x6, 12(x0)
    ecall

/* expand_360 store-wrapper (W1): leaf -> 8 x 64B slots in p1buf. */
expand_batch:
    jal x1, expand_360
    bn.sd w0, 0(x11)
    bn.sd w1, 32(x11)
    bn.sd w2, 64(x11)
    bn.sd w3, 96(x11)
    bn.sd w4, 128(x11)
    bn.sd w5, 160(x11)
    bn.sd w6, 192(x11)
    bn.sd w7, 224(x11)
    bn.sd w8, 256(x11)
    bn.sd w9, 288(x11)
    bn.sd w10, 320(x11)
    bn.sd w11, 352(x11)
    bn.sd w12, 384(x11)
    bn.sd w13, 416(x11)
    bn.sd w14, 448(x11)
    bn.sd w15, 480(x11)
    addi x11, x11, 512
    ret

/* phase4_row_setup (W4): P1 seek + restream a row into p1buf. */
phase4_row_setup:
    srli x29, x9, 3
    andi x15, x9, 7
    andi x16, x29, 1
    slli x30, x29, 5
    slli x8,  x29, 3
    add  x30, x30, x8
    slli x8,  x29, 2
    add  x30, x30, x8
    add  x30, x30, x29
    srli x30, x30, 1
    lw   x29, 24(x3)
    bn.sd w31, 0(x29)
    sw   x30, 0(x29)
    bn.ld w14, 0(x29)
    bn.addi w18, w14, 1
    bn.or   w18, w14, w18 << 128
    bn.rshi w18, w18, w31 >> 160
    li   x8, 74
    sub  x8, x8, x7
    add  x8, x8, x15
    addi x8, x8, 7
    srli x8, x8, 3
    lw   x11, 20(x3)
    loop x8, 2
        jal x1, expand_batch
        nop
    lw   x14, 20(x3)
    slli x29, x15, 6
    add  x14, x14, x29
    add  x5, x0, x14
    li   x8, 74
    sub  x8, x8, x7
    lw x13, 16(x3)
    ret
