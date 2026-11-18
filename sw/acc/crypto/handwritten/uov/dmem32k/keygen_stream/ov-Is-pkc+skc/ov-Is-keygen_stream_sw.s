/* ov-Is-keygen_stream_sw.s - streamed UOV-Is keygen (sw tier, 32 KiB DMEM
 * target). T-table AES (aes128_dual_table, DMEM RKs derived once in INIT,
 * x18 = RK base) + gf16_macc_sw dots. No PQC insns.
 *   phase 0 INIT  : expandsk -> pk_seed ctx + RK buf + O ctx
 *   phase 1 WINDOW(arg0=col_start, arg1=col_count EVEN <=10): slice[k][j] =
 *           sum_i O[i][k]*B[i][cs+j] over GF(16), B = P1*O+P2 restreamed.
 * Fixed slice layout: entry (k,j) at slice + k*320 + j*32; kernel zeroes the
 * full slice per WINDOW; host reads col_count cols out BEFORE the next call.
 * 7 windows (6x10+4). P1 counter rides w0 across rows (w18 during P1); P2 re-seeked per
 * row (c = 9,312 + 128r + 2cs). mod1 = 0 pinned on every exit (never set).
 * clob: everything. stack: INIT overlays slice (expandsk 3,104B); WINDOW
 * uses the static frame + swframe (aes128_dual_table 32B).
 */
.section .data
.balign 32
/* Map: bus-side objects first; in the SW arm, the AES table ends at 31,744.
 * gbuf23/ivb/frame/swframe are runtime-only
 * and live in the top scratch (31,744..32,768). */
ctrl:      .word 0, 0, 0, 0
           .zero 16
sk_seed:   .zero 32
pk_seed:   .zero 32
.globl slice
.globl slice_end
slice:     .zero 20480
slice_end:
o_ctx:     .zero 3072
p1buf:     .zero 3072
gbuf01:    .zero 640
rkbuf:     .zero 192
           .zero 96
/* ACC-private at fixed addresses above the bus window: never loaded, so these
 * get addresses, not linker objects. A section here would still claim load
 * space in dmem_load, which is sized to the 31,744 B window. */
.set gbuf23, 31744
.set ivb, 32384
.set frame, 32416
.set swframe, 32448
.set swframe_end, 32480

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
    la x2, slice_end          /* expandsk overlays the slice (3,104B) */
    bn.xor w31, w31, w31
    la x11, sk_seed
    jal x1, expandsk_ret_O_pkseed   /* x2 -= 3104; pk_seed@x2, O@x2+32 */
    bn.ld w0, 0(x2)
    la x5, pk_seed
    bn.sd w0, 0(x5)           /* pk_seed ctx (low 16B valid) */
    /* SW AES key schedule once: pk_seed -> rkbuf (DMEM persists).
     * Clobbers x5-x8, x11-x18, x29-x31 -> runs BEFORE the O copy. */
    la x10, pk_seed
    la x11, rkbuf
    jal x1, AES_128_keyschedule
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
    li   x4, 10
    sub  x4, x4, x18
    srli x4, x4, 31
    bne  x4, x0, _bad_args    /* col_count <= 10 */
    andi x4, x5, 1
    bne  x4, x0, _bad_args    /* col_start even (48B stride alignment) */
    li   x4, 62
    sub  x4, x4, x5
    srli x4, x4, 31
    bne  x4, x0, _bad_args    /* col_start <= 62 (kills cs+wc wrap) */
    add  x4, x5, x18
    li   x6, 64
    sub  x6, x6, x4
    srli x6, x6, 31
    bne  x6, x0, _bad_args    /* col_start + col_count <= 64 */
    bn.xor w31, w31, w31
    la x6, o_ctx
    sw x6, 0(x3)              /* true O base (fold) */
    slli x4, x5, 5
    slli x7, x5, 4
    add  x4, x4, x7           /* col_start*48 */
    add  x6, x6, x4
    sw x6, 8(x3)              /* window O base */
    la x6, p1buf
    sw x6, 12(x3)             /* P1 row buffer */
    la x18, rkbuf             /* x18 = RK base, required by dual_table */
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
    li x23, 6
    li x26, 3
    li x27, 4
    li x28, 5
    /* zero the FULL slice */
    la x10, slice
    li x4, 640
    loop x4, 1
        bn.sd w31, 0(x10++)
    li x7, 0                  /* row */
    li x30, 96                /* 96 - r */
    loopi 24, 459
    bn.mov w18, w0
    lw x9, 12(x3)
    sw x7, 28(x3)
    loop x30, 3
        jal x1, aes128_dual_table
        bn.sd w2, 0(x9++)
        bn.add w18, w18, w19
    lw x7, 28(x3)
    bn.mov w0, w18
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
    bn.rshi w18, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w18, w18, w15
    lw x12, 8(x3)
    la x10, gbuf01
    lw x19, 8(x0)
    srli x19, x19, 1
    loop x19, 62
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
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        sw x10, 20(x3)
        sw x12, 24(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        lw x7,  28(x3)
        bn.add w18, w18, w19
        bn.xor w8, w20, w2
        bn.sd w8, 0(x10++)
        bn.mov w22, w18
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
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        sw x10, 20(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        lw x7,  28(x3)
        bn.add w18, w18, w19
        bn.xor w8, w20, w2
        bn.sd w8, 0(x10++)
    addi x7, x7, 1
    addi x30, x30, -1
    bn.mov w18, w0
    lw x9, 12(x3)
    sw x7, 28(x3)
    loop x30, 3
        jal x1, aes128_dual_table
        bn.sd w2, 0(x9++)
        bn.add w18, w18, w19
    lw x7, 28(x3)
    bn.mov w0, w18
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
    bn.rshi w18, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w18, w18, w15
    lw x12, 8(x3)
    la x10, gbuf01
    addi x10, x10, 320
    lw x19, 8(x0)
    srli x19, x19, 1
    loop x19, 62
        lw x9, 12(x3)
        bn.mov w21, w0
        bn.mov w22, w18
        bn.mov w23, w19
        bn.xor w20, w20, w20
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        beq x7, x0, _nsa_1
        loop x7, 3
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w5, w4 >> 4
            bn.rshi w5, w31, w5 >> 4
_nsa_1:
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
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        sw x10, 20(x3)
        sw x12, 24(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        lw x7,  28(x3)
        bn.add w18, w18, w19
        bn.xor w8, w20, w2
        bn.sd w8, 0(x10++)
        bn.mov w22, w18
        bn.xor w20, w20, w20
        lw x9, 12(x3)
        beq x7, x0, _nsb_1
        loop x7, 2
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
_nsb_1:
        li x8, 96
        sub x8, x8, x7
        loop x8, 6
            bn.lid x23, 0(x9++)
            bn.mov w0, w6
            bn.mov w19, w3
            jal x1, gf16_macc_sw
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        sw x10, 20(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        lw x7,  28(x3)
        bn.add w18, w18, w19
        bn.xor w8, w20, w2
        bn.sd w8, 0(x10++)
    addi x7, x7, 1
    addi x30, x30, -1
    bn.mov w18, w0
    lw x9, 12(x3)
    sw x7, 28(x3)
    loop x30, 3
        jal x1, aes128_dual_table
        bn.sd w2, 0(x9++)
        bn.add w18, w18, w19
    lw x7, 28(x3)
    bn.mov w0, w18
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
    bn.rshi w18, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w18, w18, w15
    lw x12, 8(x3)
    la x10, gbuf23
    lw x19, 8(x0)
    srli x19, x19, 1
    loop x19, 62
        lw x9, 12(x3)
        bn.mov w21, w0
        bn.mov w22, w18
        bn.mov w23, w19
        bn.xor w20, w20, w20
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        beq x7, x0, _nsa_2
        loop x7, 3
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w5, w4 >> 4
            bn.rshi w5, w31, w5 >> 4
_nsa_2:
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
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        sw x10, 20(x3)
        sw x12, 24(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        lw x7,  28(x3)
        bn.add w18, w18, w19
        bn.xor w8, w20, w2
        bn.sd w8, 0(x10++)
        bn.mov w22, w18
        bn.xor w20, w20, w20
        lw x9, 12(x3)
        beq x7, x0, _nsb_2
        loop x7, 2
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
_nsb_2:
        li x8, 96
        sub x8, x8, x7
        loop x8, 6
            bn.lid x23, 0(x9++)
            bn.mov w0, w6
            bn.mov w19, w3
            jal x1, gf16_macc_sw
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        sw x10, 20(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        lw x7,  28(x3)
        bn.add w18, w18, w19
        bn.xor w8, w20, w2
        bn.sd w8, 0(x10++)
    addi x7, x7, 1
    addi x30, x30, -1
    bn.mov w18, w0
    lw x9, 12(x3)
    sw x7, 28(x3)
    loop x30, 3
        jal x1, aes128_dual_table
        bn.sd w2, 0(x9++)
        bn.add w18, w18, w19
    lw x7, 28(x3)
    bn.mov w0, w18
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
    bn.rshi w18, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w18, w18, w15
    lw x12, 8(x3)
    la x10, gbuf23
    addi x10, x10, 320
    lw x19, 8(x0)
    srli x19, x19, 1
    loop x19, 62
        lw x9, 12(x3)
        bn.mov w21, w0
        bn.mov w22, w18
        bn.mov w23, w19
        bn.xor w20, w20, w20
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        beq x7, x0, _nsa_3
        loop x7, 3
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w5, w4 >> 4
            bn.rshi w5, w31, w5 >> 4
_nsa_3:
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
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        sw x10, 20(x3)
        sw x12, 24(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        lw x7,  28(x3)
        bn.add w18, w18, w19
        bn.xor w8, w20, w2
        bn.sd w8, 0(x10++)
        bn.mov w22, w18
        bn.xor w20, w20, w20
        lw x9, 12(x3)
        beq x7, x0, _nsb_3
        loop x7, 2
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
_nsb_3:
        li x8, 96
        sub x8, x8, x7
        loop x8, 6
            bn.lid x23, 0(x9++)
            bn.mov w0, w6
            bn.mov w19, w3
            jal x1, gf16_macc_sw
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        sw x10, 20(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        lw x7,  28(x3)
        bn.add w18, w18, w19
        bn.xor w8, w20, w2
        bn.sd w8, 0(x10++)
    addi x7, x7, 1
    addi x30, x30, -1
    bn.mov w21, w0
    addi x21, x7, -4
    srli x20, x21, 1
    andi x20, x20, 2
    slli x20, x20, 3
    la x24, ivb
    la x13, gbuf01
    la x14, gbuf23
    la x11, slice
    lw x5, 8(x0)
    lw x9, 0(x3)
    srli x8, x21, 1
    andi x8, x8, -4
    add x9, x9, x8
    loop x5, 54
      bn.ld w2, 0(x13)
      bn.ld w6, 320(x13)
      bn.ld w7, 0(x14)
      bn.ld w9, 320(x14)
      add x4, x0, x9
      add x10, x0, x11
      loopi 32, 44
        lw x8, 0(x4)
        srl x8, x8, x20
        sw x8, 0(x24)
        bn.ld w14, 0(x24)
        bn.ld w20, 0(x10)
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
        bn.sd w20, 0(x10)
        lw x8, 48(x4)
        srl x8, x8, x20
        sw x8, 0(x24)
        bn.ld w14, 0(x24)
        bn.ld w20, 320(x10)
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
        bn.sd w20, 320(x10)
        addi x4, x4, 96
        addi x10, x10, 640
      addi x11, x11, 32
      addi x13, x13, 32
      addi x14, x14, 32
    bn.mov w0, w21
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160
    csrrw x0, mod1, x0        /* pin mod1 = 0 on exit */
    sw x0, 12(x0)             /* status = 0 */
    ecall

_bad_args:
    csrrw x0, mod1, x0        /* pin mod1 = 0 on exit */
    li x6, -2
    sw x6, 12(x0)
    ecall
