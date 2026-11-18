/* ov-Ip-keygen_stream.s - streamed UOV-Ip keygen (32 KiB DMEM target).
 * Tiers (cpp-guarded like monolith P1O_P2.s): AES_INSTRUCTIONS -> bngfaes
 * inline AES; else bngfonly (KeySchedule_keygen/aes128_keygen via bn.gfmul,
 * consts + 352B stage in the .data pad, same map).
 * ONE app, phase-dispatch, ctx in DMEM.
 *   phase 0 INIT  : expandsk(sk_seed@0x20) -> pk_seed@0x40 + o_aligned ctx
 *   phase 1 WINDOW(arg0=col_start, arg1=col_count<=7): slice[k][j] =
 *           sum_i O[i][k]*B[i][col_start+j], B = P1*O+P2 restreamed from AES.
 * Fixed-448 slice layout: entry (k,j) at slice + k*448 + j*64 (44B valid +
 * 20B zero pad) for ALL windows incl. the short last one; kernel zeroes the
 * full slice per WINDOW; host reads col_count cols out BEFORE the next call.
 * Host assembles P3full, folds upper (j<k XOR), packs cpk = pk_seed||P3.
 * P2 stream: entry p = 44*row+col is global CTR entry g = 2346+p; batch =
 * g>>3, CTR = 22*batch, 2 batches expanded, read at p2buf + (g&7)*64.
 * mod1 = 0 on every phase exit. RKs re-derived from pk_seed per WINDOW.
 * clob: everything (phase app, no caller). stack: INIT overlays slice
 * (expandsk 3,040B); WINDOW uses the static 32B frame only.
 */
.section .data
.balign 32
/* Address map (real 32 KiB part: bus window = 31,744, top 1,024 = ACC-only
 * scratchpad): host-visible objects first (all end <= 19,808), ACC-private
 * after; p2buf sits exactly in the top 1,024 (31,744..32,768) and nothing
 * straddles the bus boundary. p2buf is an absolute symbol, not a section: a
 * .scratchpad section is charged to dmem_load (31,744) and will not link once
 * .data fills the window. */
ctrl:      .word 0, 0, 0, 0
           .zero 16
sk_seed:   .zero 32
pk_seed:   .zero 32
.globl slice
.globl slice_end
slice:     .zero 19712
slice_end:
o_aligned: .zero 4224
p1buf:     .zero 5120
group_buf: .zero 1792
frame:     .zero 32
#ifdef AES_INSTRUCTIONS
           .zero 768
#else
/* bngfonly locals in the pad: AES consts (aes128_keygen/KeySchedule_keygen
 * reference these by name; the constants lib is NOT linked so they place
 * here, below p2buf) + 352B expand staging. 5x32 + 352 + 256 = 768. */
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
aes_stage: .zero 352
           .zero 256
#endif
/* p2buf is ACC-private at a fixed 31,744 - above the bus window, never loaded,
 * so it gets an address, not a linker object. A section here would still claim
 * load space in dmem_load, which is sized to the 31,744 B window. */
.set p2buf, 31744

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
    sw   x6, 12(x0)           /* invalid phase */
    ecall

/* ============================ INIT ============================ */
_INIT:
    la x2, slice_end          /* expandsk overlays the slice (3,040B) */
    bn.xor w31, w31, w31
    la x11, sk_seed
    jal x1, expandsk_ret_O_pkseed   /* x2 -= 3040; pk_seed@x2, O@x2+32 */
    bn.ld w0, 0(x2)
    la x5, pk_seed
    bn.sd w0, 0(x5)           /* pk_seed ctx (low 16B valid, high zero) */
    addi x12, x2, 32          /* raw O source */
    /* ---- O-align (P3_cal Phase 1 verbatim) ---- */
    # Copy 44 O columns from 68B stride to 96B-padded (32B-aligned) layout.
    # Batch: load 8 cols (17 WDRs = 544B), extract with rshi, store 3 WDRs/col.
    # x12 = O source (advances), x11 = O aligned dest (advances)
    la x11, o_aligned               # O aligned dest base
    li x9, 17                       # WDR idx for w17 (temp)
    li x29, 1                       # WDR idx for w1
    li x30, 2                       # WDR idx for w2

    loopi 5, 57                     # 5 full batches x 8 cols = 40 cols
        li x8, 0                    # WDR load idx
        loopi 17, 2                 # load 17 WDRs -> w0..w16
            bn.lid x8, 0(x12++)
            addi x8, x8, 1
        # Col +0 (shift=0): w0, w1, w2 direct
        bn.sid x0, 0(x11)           # w0
        bn.sid x29, 32(x11)         # w1
        bn.sid x30, 64(x11)         # w2
        addi x11, x11, 96
        # Col +1 (shift=32)
        bn.rshi w17, w3, w2 >> 32   # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w4, w3 >> 32   # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w5, w4 >> 32   # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +2 (shift=64)
        bn.rshi w17, w5, w4 >> 64   # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w6, w5 >> 64   # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w7, w6 >> 64   # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +3 (shift=96)
        bn.rshi w17, w7, w6 >> 96   # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w8, w7 >> 96   # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w9, w8 >> 96   # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +4 (shift=128)
        bn.rshi w17, w9, w8 >> 128  # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w10, w9 >> 128 # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w11, w10 >> 128 # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +5 (shift=160)
        bn.rshi w17, w11, w10 >> 160 # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w12, w11 >> 160 # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w13, w12 >> 160 # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +6 (shift=192)
        bn.rshi w17, w13, w12 >> 192 # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w14, w13 >> 192 # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w15, w14 >> 192 # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +7 (shift=224)
        bn.rshi w17, w15, w14 >> 224 # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w16, w15 >> 224 # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w31, w16 >> 224 # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96

    # Last batch: 4 remaining columns (cols 40-43)
    li x8, 0                        # WDR load idx
    loopi 9, 2                      # load 9 WDRs (272B + padding)
        bn.lid x8, 0(x12++)
        addi x8, x8, 1
    # Col 40 (shift=0)
    bn.sid x0, 0(x11)               # w0
    bn.sid x29, 32(x11)             # w1
    bn.sid x30, 64(x11)             # w2
    addi x11, x11, 96
    # Col 41 (shift=32)
    bn.rshi w17, w3, w2 >> 32       # lo
    bn.sid x9, 0(x11)
    bn.rshi w17, w4, w3 >> 32       # mid
    bn.sid x9, 32(x11)
    bn.rshi w17, w5, w4 >> 32       # hi
    bn.sid x9, 64(x11)
    addi x11, x11, 96
    # Col 42 (shift=64)
    bn.rshi w17, w5, w4 >> 64       # lo
    bn.sid x9, 0(x11)
    bn.rshi w17, w6, w5 >> 64       # mid
    bn.sid x9, 32(x11)
    bn.rshi w17, w7, w6 >> 64       # hi
    bn.sid x9, 64(x11)
    addi x11, x11, 96
    # Col 43 (shift=96)
    bn.rshi w17, w7, w6 >> 96       # lo
    bn.sid x9, 0(x11)
    bn.rshi w17, w8, w7 >> 96       # mid
    bn.sid x9, 32(x11)
    bn.rshi w17, w9, w8 >> 96       # hi
    bn.sid x9, 64(x11)

    csrrw x0, mod1, x0        /* pin mod1 = 0 on exit */
    sw x0, 12(x0)             /* status = 0 */
    ecall

/* ============================ WINDOW ============================ */
_WINDOW:
    la x3, frame
    lw x5, 4(x0)              /* col_start */
    lw x18, 8(x0)             /* col_count */
    sw x5, 4(x3)
    beq x18, x0, _bad_args    /* zero-col window: reject (loop-0 traps) */
    /* bounds (beq/bne-only ISA: sub + srli sign trick) */
    li   x6, 7
    sub  x6, x6, x18
    srli x6, x6, 31
    bne  x6, x0, _bad_args    /* col_count <= 7 */
    li   x6, 43
    sub  x6, x6, x5
    srli x6, x6, 31
    bne  x6, x0, _bad_args    /* col_start <= 43 (also kills cs+wc wrap) */
    add  x6, x5, x18
    li   x7, 44
    sub  x7, x7, x6
    srli x7, x7, 31
    bne  x7, x0, _bad_args    /* col_start + col_count <= 44 */
    bn.xor w31, w31, w31
    li x8, 0x11b
    csrrw x0, mod0, x8
    la x6, o_aligned
    sw x6, 0(x3)              /* true O base (fold) */
    slli x7, x5, 6
    slli x8, x5, 5
    add  x7, x7, x8           /* col_start*96 */
    add  x6, x6, x7
    sw x6, 16(x3)             /* window O base (B-build via setup) */
    la x6, p1buf
    sw x6, 20(x3)
    la x6, p2buf
    sw x6, 24(x3)
    /* RK schedule from pk_seed ctx + stream consts (per-window, no WDR
     * persistence across ecall) */
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
#endif
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160
    bn.not w13, w31
    bn.rshi w13, w31, w13 >> 160
    li x23, 6
    li x24, 7
    li x26, 3
    li x27, 4
    li x28, 5
    li x16, 11
    li x19, 12
    li x17, 10
    /* zero the FULL 7-wide slice (fixed-448 layout, all windows) */
    la x10, slice
    li x8, 616
    loop x8, 1
        bn.sd w31, 0(x10++)
    li x9, 0
    li x7, 0
    /* ---- band A: 8 group(s) of 4 rows + fold ---- */
    loopi 8, 360
    jal x1, phase4_row_setup
    addi x20, x8, -36
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2346
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    slli x29, x30, 2
    add  x29, x29, x30
    slli x29, x29, 1
    add  x29, x29, x30
    slli x29, x29, 1
    lw x8, 24(x3)
    bn.sd w31, 0(x8)
    sw x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or w18, w14, w18 << 128
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
        loopi 4, 4
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
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    addi x20, x8, -36
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2346
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    slli x29, x30, 2
    add  x29, x29, x30
    slli x29, x29, 1
    add  x29, x29, x30
    slli x29, x29, 1
    lw x8, 24(x3)
    bn.sd w31, 0(x8)
    sw x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or w18, w14, w18 << 128
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
    addi x22, x22, 448
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
        loopi 4, 4
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
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    addi x20, x8, -36
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2346
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    slli x29, x30, 2
    add  x29, x29, x30
    slli x29, x29, 1
    add  x29, x29, x30
    slli x29, x29, 1
    lw x8, 24(x3)
    bn.sd w31, 0(x8)
    sw x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or w18, w14, w18 << 128
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
    addi x22, x22, 896
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
        loopi 4, 4
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
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    addi x20, x8, -36
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2346
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    slli x29, x30, 2
    add  x29, x29, x30
    slli x29, x29, 1
    add  x29, x29, x30
    slli x29, x29, 1
    lw x8, 24(x3)
    bn.sd w31, 0(x8)
    sw x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or w18, w14, w18 << 128
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
    addi x22, x22, 1344
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
        loopi 4, 4
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
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    addi x21, x7, -4
    li x30, 96
    li x29, 448
    la x12, group_buf
    la x11, slice
    lw x5, 0(x3)
    loop x18, 39
      li x8, 0
      bn.lid x8, 0(x12)
      addi x8, x8, 1
      bn.lid x8, 32(x12)
      addi x8, x8, 1
      bn.lid x8, 448(x12)
      addi x8, x8, 1
      bn.lid x8, 480(x12)
      addi x8, x8, 1
      bn.lid x8, 896(x12)
      addi x8, x8, 1
      bn.lid x8, 928(x12)
      addi x8, x8, 1
      bn.lid x8, 1344(x12)
      addi x8, x8, 1
      bn.lid x8, 1376(x12)
      add x4, x0, x5
      add x10, x0, x11
      loopi 44, 18
        bn.lid x19, 0(x4)
        csrrw x0, mod1, x21
        bn.lid x17, 0(x10)
        bn.lid x16, 32(x10)
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
    loopi 8, 345
    jal x1, phase4_row_setup
    addi x21, x7, -32
    addi x20, x8, -4
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2346
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    slli x29, x30, 2
    add  x29, x29, x30
    slli x29, x29, 1
    add  x29, x29, x30
    slli x29, x29, 1
    lw x8, 24(x3)
    bn.sd w31, 0(x8)
    sw x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or w18, w14, w18 << 128
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
        loopi 4, 4
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
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    addi x21, x7, -32
    addi x20, x8, -4
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2346
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    slli x29, x30, 2
    add  x29, x29, x30
    slli x29, x29, 1
    add  x29, x29, x30
    slli x29, x29, 1
    lw x8, 24(x3)
    bn.sd w31, 0(x8)
    sw x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or w18, w14, w18 << 128
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
    addi x22, x22, 448
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
        loopi 4, 4
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
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    addi x21, x7, -32
    addi x20, x8, -4
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2346
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    slli x29, x30, 2
    add  x29, x29, x30
    slli x29, x29, 1
    add  x29, x29, x30
    slli x29, x29, 1
    lw x8, 24(x3)
    bn.sd w31, 0(x8)
    sw x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or w18, w14, w18 << 128
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
    addi x22, x22, 896
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
        loopi 4, 4
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
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    addi x21, x7, -32
    addi x20, x8, -4
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2346
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    slli x29, x30, 2
    add  x29, x29, x30
    slli x29, x29, 1
    add  x29, x29, x30
    slli x29, x29, 1
    lw x8, 24(x3)
    bn.sd w31, 0(x8)
    sw x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or w18, w14, w18 << 128
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
    addi x22, x22, 1344
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
        loopi 4, 4
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
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    addi x21, x7, -36
    li x30, 96
    li x29, 448
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
      bn.lid x8, 448(x12)
      addi x8, x8, 1
      bn.lid x8, 480(x12)
      addi x8, x8, 1
      bn.lid x8, 896(x12)
      addi x8, x8, 1
      bn.lid x8, 928(x12)
      addi x8, x8, 1
      bn.lid x8, 1344(x12)
      addi x8, x8, 1
      bn.lid x8, 1376(x12)
      add x4, x0, x5
      add x10, x0, x11
      loopi 44, 18
        bn.lid x19, 0(x4)
        csrrw x0, mod1, x21
        bn.lid x17, 0(x10)
        bn.lid x16, 32(x10)
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
    /* ---- band C: 1 group(s) of 4 rows + fold ---- */
    jal x1, phase4_row_setup
    addi x21, x7, -64
    add  x20, x0, x8
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2346
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    slli x29, x30, 2
    add  x29, x29, x30
    slli x29, x29, 1
    add  x29, x29, x30
    slli x29, x29, 1
    lw x8, 24(x3)
    bn.sd w31, 0(x8)
    sw x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or w18, w14, w18 << 128
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
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    addi x21, x7, -64
    add  x20, x0, x8
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2346
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    slli x29, x30, 2
    add  x29, x29, x30
    slli x29, x29, 1
    add  x29, x29, x30
    slli x29, x29, 1
    lw x8, 24(x3)
    bn.sd w31, 0(x8)
    sw x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or w18, w14, w18 << 128
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
    addi x22, x22, 448
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
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    addi x21, x7, -64
    add  x20, x0, x8
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2346
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    slli x29, x30, 2
    add  x29, x29, x30
    slli x29, x29, 1
    add  x29, x29, x30
    slli x29, x29, 1
    lw x8, 24(x3)
    bn.sd w31, 0(x8)
    sw x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or w18, w14, w18 << 128
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
    addi x22, x22, 896
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
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    addi x21, x7, -64
    add  x20, x0, x8
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2346
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    slli x29, x30, 2
    add  x29, x29, x30
    slli x29, x29, 1
    add  x29, x29, x30
    slli x29, x29, 1
    lw x8, 24(x3)
    bn.sd w31, 0(x8)
    sw x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or w18, w14, w18 << 128
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
    addi x22, x22, 1344
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
    addi x21, x7, -68
    li x30, 96
    li x29, 448
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
      bn.lid x8, 448(x12)
      addi x8, x8, 1
      bn.lid x8, 480(x12)
      addi x8, x8, 1
      bn.lid x8, 896(x12)
      addi x8, x8, 1
      bn.lid x8, 928(x12)
      addi x8, x8, 1
      bn.lid x8, 1344(x12)
      addi x8, x8, 1
      bn.lid x8, 1376(x12)
      add x4, x0, x5
      add x10, x0, x11
      loopi 44, 18
        bn.lid x19, 0(x4)
        csrrw x0, mod1, x21
        bn.lid x17, 0(x10)
        bn.lid x16, 32(x10)
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
    csrrw x0, mod1, x0        /* pin mod1 = 0 on exit */
    sw x0, 12(x0)             /* status = 0 */
    ecall

_bad_args:
    csrrw x0, mod1, x0        /* pin mod1 = 0 on exit */
    li x6, -2
    sw x6, 12(x0)
    ecall

/* ===== expand_batch: 8x64B entries from AES-CTR (per-tier generation,
 * shared repack). in: w18 IV, w19 inc, x11 write ptr, w31=0.
 * bngfaes: verbatim monolith bngfaes arm; clob w0-w11 (w13 preserved).
 * bngfonly: 11x aes128_keygen staged via aes_stage; clob w0-w17, x12, x14;
 * rebuilds w13, restores x19=12/x18=col_count in the tail. ===== */
expand_batch:
#ifdef AES_INSTRUCTIONS
    # AES-CTR: 11 parallel blocks
    bn.aes128.encz.swap w0, w18, w30        # block 0
    bn.add w18, w18, w19                    # IV += 2
    bn.aes128.encz.swap w1, w18, w30        # block 1
    bn.add w18, w18, w19
    bn.aes128.encz.swap w2, w18, w30        # block 2
    bn.add w18, w18, w19
    bn.aes128.encz.swap w3, w18, w30        # block 3
    bn.add w18, w18, w19
    bn.aes128.encz.swap w4, w18, w30        # block 4
    bn.add w18, w18, w19
    bn.aes128.encz.swap w5, w18, w30        # block 5
    bn.add w18, w18, w19
    bn.aes128.encz.swap w6, w18, w30        # block 6
    bn.add w18, w18, w19
    bn.aes128.encz.swap w7, w18, w30        # block 7
    bn.add w18, w18, w19
    bn.aes128.encz.swap w8, w18, w30        # block 8
    bn.add w18, w18, w19
    bn.aes128.encz.swap w9, w18, w30        # block 9
    bn.add w18, w18, w19
    bn.aes128.encz.swap w10, w18, w30       # block 10
    bn.add w18, w18, w19
    # Round 1
    bn.aes128.encm w0, w0, w29
    bn.aes128.encm w1, w1, w29
    bn.aes128.encm w2, w2, w29
    bn.aes128.encm w3, w3, w29
    bn.aes128.encm w4, w4, w29
    bn.aes128.encm w5, w5, w29
    bn.aes128.encm w6, w6, w29
    bn.aes128.encm w7, w7, w29
    bn.aes128.encm w8, w8, w29
    bn.aes128.encm w9, w9, w29
    bn.aes128.encm w10, w10, w29
    # Round 2
    bn.aes128.encm w0, w0, w28
    bn.aes128.encm w1, w1, w28
    bn.aes128.encm w2, w2, w28
    bn.aes128.encm w3, w3, w28
    bn.aes128.encm w4, w4, w28
    bn.aes128.encm w5, w5, w28
    bn.aes128.encm w6, w6, w28
    bn.aes128.encm w7, w7, w28
    bn.aes128.encm w8, w8, w28
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w10, w10, w28
    # Round 3
    bn.aes128.encm w0, w0, w27
    bn.aes128.encm w1, w1, w27
    bn.aes128.encm w2, w2, w27
    bn.aes128.encm w3, w3, w27
    bn.aes128.encm w4, w4, w27
    bn.aes128.encm w5, w5, w27
    bn.aes128.encm w6, w6, w27
    bn.aes128.encm w7, w7, w27
    bn.aes128.encm w8, w8, w27
    bn.aes128.encm w9, w9, w27
    bn.aes128.encm w10, w10, w27
    # Round 4
    bn.aes128.encm w0, w0, w26
    bn.aes128.encm w1, w1, w26
    bn.aes128.encm w2, w2, w26
    bn.aes128.encm w3, w3, w26
    bn.aes128.encm w4, w4, w26
    bn.aes128.encm w5, w5, w26
    bn.aes128.encm w6, w6, w26
    bn.aes128.encm w7, w7, w26
    bn.aes128.encm w8, w8, w26
    bn.aes128.encm w9, w9, w26
    bn.aes128.encm w10, w10, w26
    # Round 5
    bn.aes128.encm w0, w0, w25
    bn.aes128.encm w1, w1, w25
    bn.aes128.encm w2, w2, w25
    bn.aes128.encm w3, w3, w25
    bn.aes128.encm w4, w4, w25
    bn.aes128.encm w5, w5, w25
    bn.aes128.encm w6, w6, w25
    bn.aes128.encm w7, w7, w25
    bn.aes128.encm w8, w8, w25
    bn.aes128.encm w9, w9, w25
    bn.aes128.encm w10, w10, w25
    # Round 6
    bn.aes128.encm w0, w0, w24
    bn.aes128.encm w1, w1, w24
    bn.aes128.encm w2, w2, w24
    bn.aes128.encm w3, w3, w24
    bn.aes128.encm w4, w4, w24
    bn.aes128.encm w5, w5, w24
    bn.aes128.encm w6, w6, w24
    bn.aes128.encm w7, w7, w24
    bn.aes128.encm w8, w8, w24
    bn.aes128.encm w9, w9, w24
    bn.aes128.encm w10, w10, w24
    # Round 7
    bn.aes128.encm w0, w0, w23
    bn.aes128.encm w1, w1, w23
    bn.aes128.encm w2, w2, w23
    bn.aes128.encm w3, w3, w23
    bn.aes128.encm w4, w4, w23
    bn.aes128.encm w5, w5, w23
    bn.aes128.encm w6, w6, w23
    bn.aes128.encm w7, w7, w23
    bn.aes128.encm w8, w8, w23
    bn.aes128.encm w9, w9, w23
    bn.aes128.encm w10, w10, w23
    # Round 8
    bn.aes128.encm w0, w0, w22
    bn.aes128.encm w1, w1, w22
    bn.aes128.encm w2, w2, w22
    bn.aes128.encm w3, w3, w22
    bn.aes128.encm w4, w4, w22
    bn.aes128.encm w5, w5, w22
    bn.aes128.encm w6, w6, w22
    bn.aes128.encm w7, w7, w22
    bn.aes128.encm w8, w8, w22
    bn.aes128.encm w9, w9, w22
    bn.aes128.encm w10, w10, w22
    # Round 9
    bn.aes128.encm w0, w0, w21
    bn.aes128.encm w1, w1, w21
    bn.aes128.encm w2, w2, w21
    bn.aes128.encm w3, w3, w21
    bn.aes128.encm w4, w4, w21
    bn.aes128.encm w5, w5, w21
    bn.aes128.encm w6, w6, w21
    bn.aes128.encm w7, w7, w21
    bn.aes128.encm w8, w8, w21
    bn.aes128.encm w9, w9, w21
    bn.aes128.encm w10, w10, w21
    # Final round
    bn.aes128.encf w0, w0, w20
    bn.aes128.encf w1, w1, w20
    bn.aes128.encf w2, w2, w20
    bn.aes128.encf w3, w3, w20
    bn.aes128.encf w4, w4, w20
    bn.aes128.encf w5, w5, w20
    bn.aes128.encf w6, w6, w20
    bn.aes128.encf w7, w7, w20
    bn.aes128.encf w8, w8, w20
    bn.aes128.encf w9, w9, w20
    bn.aes128.encf w10, w10, w20
#else
    # bngfonly AES-CTR: 11 aes128_keygen calls (dual-block w2 out) staged to
    # aes_stage, reloaded to w0..w10 for the shared repack. Helper clobbers
    # w1, w10-w17, x18, x19; needs w7/w8/w9 consts (loaded here) + w18 IV.
    la x12, byte_swap_mask
    li x14, 7
    bn.lid x14, 0(x12)
    la x12, affine_value
    li x14, 8
    bn.lid x14, 0(x12)
    la x12, msb_mask
    li x14, 9
    bn.lid x14, 0(x12)
    la x12, aes_stage
    loopi 11, 3
        jal x1, aes128_keygen
        bn.sd w2, 0(x12++)
        bn.add w18, w18, w19
    la x12, aes_stage
    li x14, 0
    loopi 11, 2
        bn.lid x14, 0(x12++)
        addi x14, x14, 1
    # Rebuild w13 = mask96 (helper scratch killed it)
    bn.not w13, w31
    bn.rshi w13, w31, w13 >> 160
    # Tail-restore caller invariants (keeps every call site edit-free):
    li x19, 12                # w12 load idx (group-folds)
    lw x18, 8(x0)             # col_count (batch-skip reads it post-return)
#endif

    # Repack 11 WDRs -> 8 x 64B-padded entries
    # 11 WDRs (352B) = 8 entries of 44B. Extract with rshi, mask hi, store.
    # Entry 0 (bytes 0-43, shift=0)
    bn.sd w0, 0(x11++)                      # lo = w0, x11+=32
    bn.and w11, w1, w13                     # hi = w1 & mask96
    bn.sd w11, 0(x11++)                     # store hi, x11+=32
    # Entry 1 (bytes 44-87, shift=96)
    bn.rshi w11, w2, w1 >> 96              # lo
    bn.sd w11, 0(x11++)
    bn.rshi w11, w3, w2 >> 96              # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sd w11, 0(x11++)
    # Entry 2 (bytes 88-131, shift=192)
    bn.rshi w11, w3, w2 >> 192             # lo
    bn.sd w11, 0(x11++)
    bn.rshi w11, w4, w3 >> 192             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sd w11, 0(x11++)
    # Entry 3 (bytes 132-175, shift=32)
    bn.rshi w11, w5, w4 >> 32              # lo
    bn.sd w11, 0(x11++)
    bn.rshi w11, w6, w5 >> 32              # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sd w11, 0(x11++)
    # Entry 4 (bytes 176-219, shift=128)
    bn.rshi w11, w6, w5 >> 128             # lo
    bn.sd w11, 0(x11++)
    bn.rshi w11, w7, w6 >> 128             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sd w11, 0(x11++)
    # Entry 5 (bytes 220-263, shift=224)
    bn.rshi w11, w7, w6 >> 224             # lo
    bn.sd w11, 0(x11++)
    bn.rshi w11, w8, w7 >> 224             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sd w11, 0(x11++)
    # Entry 6 (bytes 264-307, shift=64)
    bn.rshi w11, w9, w8 >> 64              # lo
    bn.sd w11, 0(x11++)
    bn.rshi w11, w10, w9 >> 64             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sd w11, 0(x11++)
    # Entry 7 (bytes 308-351, shift=160)
    bn.rshi w11, w10, w9 >> 160            # lo
    bn.sd w11, 0(x11++)
    bn.rshi w11, w31, w10 >> 160           # hi (upper already 0)
    bn.sd w11, 0(x11++)

    ret

phase4_row_setup:
    srli x29, x9, 3                    # batch_idx = x9 / 8
    andi x15, x9, 7                    # offset = x9 % 8
    slli x30, x29, 4                   # batch*16
    slli x8, x29, 2                    # batch*4
    add x30, x30, x8                   # batch*20
    slli x8, x29, 1                    # batch*2
    add x30, x30, x8                   # x30 = batch*22
    lw x29, 24(x3)                     # P2 buf addr (32B aligned)
    bn.sd w31, 0(x29)                  # zero 32 bytes
    sw x30, 0(x29)                     # write counter low bytes
    li x8, 14
    bn.lid x8, 0(x29)                  # w14 = batch*22
    bn.addi w18, w14, 1                # w18 = batch*22 + 1
    bn.or w18, w14, w18 << 128         # [odd | even]
    bn.rshi w18, w18, w31 >> 160       # position IV
    li x8, 68
    sub x8, x8, x7                     # elements = 68-r
    add x8, x8, x15                    # elements + offset
    addi x8, x8, 7
    srli x8, x8, 3                     # num batches
    lw x11, 20(x3)                     # reset P1 buf write ptr
    loop x8, 2
        jal x1, expand_batch
        nop
    lw x14, 20(x3)                     # buf base
    slli x29, x15, 6                   # offset * 64
    add x14, x14, x29                  # adjusted read start
    add x5, x0, x14                    # adjusted P1 read ptr, kept in x5
    li x8, 68
    sub x8, x8, x7                     # x8 = 68-r (element count for the bands)
    lw x13, 16(x3)                     # reset O aligned base
    ret

