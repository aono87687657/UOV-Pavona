/* ov-Ip-pkc_verify_streamed_gfsw.s - streamed UOV-Ip verify, software GF(256).
 * Two tiers from one body: swonly (T-table AES) and, with -DAES_INSTRUCTIONS,
 * bnaesonly (aes128hw_352). Only the AES leaf, its prologue and the T-table are
 * behind the arm; GF(256) dots are gf256_mul = bn.mulv.l either way, so PQC
 * mode stays required for both.
 * Host contract = ov-Ip-pkc_verify_streamed_gfhw.s (window 22,368, 13/31 split, 16 B
 * prefix). acc = w21/w22, spilled to 0x20/0x40. INIT rejects msg_len > 22,368,
 * UPDATE gates shape + caprows, FINAL/UPDATE before a completed INIT reject -3.
 * clob: everything.
 * stack: 576 B swonly / 384 B bnaesonly, ACC-private scratch (x2 descends).
 */
#ifdef GF_INSTRUCTIONS
#error "gfsw source: GF is always software here, so -DGF_INSTRUCTIONS is never correct on it -- a _bngfonly target aimed at this file reports swonly cycles under a hardware-GF name. Build _gfhw.s for that tier."
#endif
.section .data
.balign 32
ctrl:      .zero 32              /* 0x000 phase, arg0, arg1, status; 0x10 = init_done */
accctx:    .zero 64              /* 0x020 acc lo/hi ctx */
oil:       .zero 64              /* 0x060 host-rewritten per UPDATE */
target:    .zero 64              /* 0x0A0 ctx */
sig:       .zero 128             /* 0x0E0 */
seed:      .zero 32              /* 0x160 */
/* msg / P3-window overlay. Sized to the MAX admissible UPDATE read end: the
 * sw loader reads 384 B per 352 B advance, worst case 22,208 B - inside the
 * shared 22,368 B reservation, which stays for ABI uniformity across arms. */
.global msgwin
msgwin:    .zero 22368           /* 0x180 .. 0x58e0 */
.global winend
winend:
/* Largest row_count per row_start that still fits msgwin (same table as the
 * bngfonly arm: its load_p3 overshoot bound is >= the sw loader's). UPDATE
 * rejects rc > caprows[rs] with -2. */
caprows:
    .word 13, 13, 14, 14, 15, 16, 16, 17
    .word 18, 19, 21, 22, 25, 31, 30, 29
    .word 28, 27, 26, 25, 24, 23, 22, 21
    .word 20, 19, 18, 17, 16, 15, 14, 13
    .word 12, 11, 10, 9, 8, 7, 6, 5
    .word 4, 3, 2, 1
.balign 32
sfk_upper12: .word 0xffffffff, 0xffffffff, 0xffffffff
             .zero 20
.balign 32
sfk_msb:     .word 0x80808080, 0x80808080, 0x80808080, 0x80808080
             .word 0x80808080, 0x80808080, 0x80808080, 0x80808080
/* The software-AES target links its table after these bus-side objects. */

/* ACC-private scratch above the 31,744 B bus window: addresses only, all
 * written before read, never host-read. x2 descends from sfk_stack_end:
 * 32 B frame | 192 B rk (176 + 16 align, swonly only) | 352 B P1 batch buffer. */
.set sfk_stack,     31744
.set sfk_stack_end, 32320

.section .text.start
.balign 4
.global main
main:
    li   x3, 0x00
    lw   x4, 0(x3)            /* phase */
    beq  x4, x0, _INIT
    li   x5, 1
    beq  x4, x5, _UPDATE
    li   x5, 2
    beq  x4, x5, _FINAL
    li   x6, -2              /* invalid phase -> error status */
    sw   x6, 12(x3)
    ecall

_FINAL:
    /* acc/target come up as loader-written .data zeros, so FINAL before INIT
     * would compare 0 == 0 and ACCEPT. Sentinel, set by INIT. */
    lw   x5, 16(x0)
    li   x6, 0x517
    bne  x5, x6, _f_noinit
    li   x3, 0x020
    bn.ld w0, 0(x3)          /* acc_lo */
    li   x3, 0x040
    bn.ld w1, 0(x3)          /* acc_hi */
    li   x3, 0x0A0
    bn.ld w13, 0(x3)         /* target_lo */
    li   x3, 0x0C0
    bn.ld w14, 0(x3)         /* target_hi */
    bn.cmp w0, w13, FG0
    bn.cmp w1, w14, FG1
    csrrs x5, 0x7c0, x0
    csrrs x6, 0x7c1, x0
    and  x5, x5, x6
    srli x5, x5, 3
    andi x5, x5, 1
    li   x3, 0x000
    beq  x5, x0, _F_fail
    li   x6, 0
    sw   x6, 12(x3)          /* status = 0 (accept) */
    ecall
_F_fail:
    li   x6, -1
    sw   x6, 12(x3)          /* status = -1 (reject) */
    ecall

/* ============================ INIT ============================ */
_INIT:
    li   x3, 0x00
    lw   x14, 4(x3)           /* msg_len */
    sw   x0, 16(x3)           /* invalidate init_done up-front (stale-guard) */
    /* Early, wrap-safe msg bound: sign-bit test alone wraps on huge lengths
     * after the absorb has already walked DMEM. len >= 2^15 first. */
    srli x5, x14, 15
    bne  x5, x0, _msgbad
    li   x5, 22368            /* msg past this would sit under the constants */
    sub  x5, x5, x14
    srli x5, x5, 31
    bne  x5, x0, _msgbad
    li   x10, 0x0E0          /* sig */
    li   x12, 0x160          /* seed */
    li   x13, 0x180          /* msg */

    /* ---------------- KMAC SHAKE256 over (msg || salt) ---------------- */
    bn.xor w31, w31, w31
    bn.xor w1, w1, w1
    addi x5, x14, 16
    slli x5, x5, 5
    ori  x5, x5, 0xA
    csrrw x0, kmac_cfg, x5
    bn.ld w1, 96(x10)         /* salt: 32B from sig+96; upper 128b = bytes 112..127 */
    bn.rshi w1, w31, w1 >> 128
    beq  x14, x0, _ipi_msg_zero
    srli x5, x14, 5
    andi x6, x14, 0x1f
    beq  x5, x0, _ipi_msg_short
    loop x5, 27
        bn.lid x0, 0(x13++)
        bn.wsrw kmac_msg, w0
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
    beq  x6, x0, _ipi_msg_zero
_ipi_msg_short:
    csrrw x0, kmac_partial_write, x6
    bn.lid x0, 0(x13++)
    bn.wsrw kmac_msg, w0
_ipi_msg_zero:
    li   x5, 16
    csrrw x0, kmac_partial_write, x5
    bn.wsrw kmac_msg, w1

    /* p1p2 fold, from ov-Ip-verify_backend.s sw arm (inline: no x1 save) */
    la x2, sfk_stack_end      /* private 576B stack (monolith convention) */
    la x5, sfk_msb
    li x6, 17
    bn.lid x6, 0(x5)          /* w17 = msb_mask (gf256_mul precondition) */
    la x5, sfk_upper12
    li x6, 29
    bn.lid x6, 0(x5)          /* w29 = upper12B_mask (col-hi12) */
    li x10, 0xE0              /* sig */
    li x11, 0x20             /* acc-out (unused; p1p2 spills to 0x20/0x40) */
    li x12, 0x160            /* seed = AES key (cpk[0..15] in the monolith) */
    li x13, 0
    li x14, 0
    addi x2, x2, -32
    add x3, x0, x2
    sw x10, 0(x2)
    sw x11, 4(x2)
    sw x12, 8(x2)
    sw x13, 12(x2)
    sw x14, 16(x2)

    bn.xor w31, w31, w31
    bn.xor w21, w21, w21
    bn.xor w22, w22, w22
    bn.xor w20, w20, w20

    bn.wsrw acc, w31

#ifdef AES_INSTRUCTIONS
    add x18, x0, x12            # x18 = AES key survivor; bn.aes128 expands per call
#else
    addi x2, x2, -192            # 176 B rk + 16 B pad (keeps stack 32-aligned for P1 below)

    #AES key schedule: pk_seed (cpk[0..15]) to 176-byte round-key buffer
    add x10, x0, x12            # x10 = pk_seed pointer (= cpk pointer)
    add x11, x0, x2            # x11 = rkb base
    jal x1, AES_128_keyschedule
    add x18, x0, x2             #x18 = rkb survivor, set AFTER KS, KS clobbers x18
#endif

    #AES-CTR counter init; threads through the AES leaf via x13
    addi x13, x0, 0

    # preserve 352 bytes for P1 expansion
    addi x2, x2, -352
    add x4, x0, x2 # x4 point for P1 tmp space for 352 bytes
    sw x4, 20(x3)   # store 352 bytes starting adddress
    li x31, 23
    lw x25, 0(x3)
    # VxV,  Only load V part first
    bn.lid x31++, 0(x25)            # w23 = sig[0..31]   = v[0..31]
    bn.lid x31++, 32(x25)           # w24 = sig[32..63]  = v[32..63]
    bn.lid x31++, 64(x25)           # w25 = sig[64..95]  (only v[64..67] valid)
    bn.rshi w25, w25, w31 >> 32     # trim w25 to 4 valid vinegar bytes (low 4B)
    bn.rshi w25, w31, w25 >> 224

    li x17, 0                   # col countdown (relocated from x25 to free contiguous block)
    li x26, 68                  # row size
    li x23, 7                   # WDR idx 7 (was x23)
    li x24, 8                   # WDR idx 8 (was x24)
    li x25, 9                   # WDR idx 9 (was x25; now part of x23-x24-x25 contiguous block)
    addi x10, x10, -320
    #setup first batch of VxV Elements
    jal x1, gen_newVxV_element
    VxV_mul_loop:
        lw x4, 20(x3)
        # AES-CTR expand 22 blocks (352 B) into P1 buffer; counter chains via x13
        add x10, x0, x18              #rk base / AES key survivor from setup
        lw  x11, 20(x3)               # P1 buffer base from frame slot 20
#ifdef AES_INSTRUCTIONS
        jal x1, aes128hw_352reg   /* duals returned in WDRs */
#else
        jal x1, aes128table_352
        lw  x4, 20(x3)
        li  x28, 7
        bn.lid x28++, 0(x4)
        bn.lid x28++, 32(x4)
        bn.lid x28++, 64(x4)
        bn.lid x28++, 96(x4)
        li  x28, 13
        bn.lid x28++, 128(x4)
        bn.lid x28++, 160(x4)
        bn.lid x28++, 192(x4)
        li  x28, 18
        bn.lid x28++, 224(x4)
        bn.lid x28++, 256(x4)
        bn.lid x28++, 288(x4)
        li  x28, 30
        bn.lid x28, 320(x4)
#endif
        lw x4, 20(x3)                    #col 0
        bn.mov w2, w26
        bn.mov w1, w7                  /* lo32 = whole dual */
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.and w1, w8, w29             /* hi12 */
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8      # advance coef buffer
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_col1
        jal x1, gen_newVxV_element
        VxV_col1:
        bn.rshi w1, w9, w8 >> 96
        bn.mov w2, w26
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w9 >> 96
        bn.and w1, w1, w29
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_col2
        beq x0, x26, VxV_END
        jal x1, gen_newVxV_element
        VxV_col2:
        bn.rshi w1, w10, w9 >> 192
        bn.mov w2, w26
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w13, w10 >> 192
        bn.and w1, w1, w29
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_col3
        jal x1, gen_newVxV_element
        VxV_col3:
        bn.rshi w1, w14, w13 >> 32
        bn.mov w2, w26
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w14 >> 32
        bn.and w1, w1, w29
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_col4
        jal x1, gen_newVxV_element
        VxV_col4:
        bn.rshi w1, w15, w14 >> 128
        bn.mov w2, w26
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w15 >> 128
        bn.and w1, w1, w29
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_col5
        jal x1, gen_newVxV_element
        VxV_col5:
        bn.rshi w1, w18, w15 >> 224
        bn.mov w2, w26
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w19, w18 >> 224
        bn.and w1, w1, w29
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_col6
        jal x1, gen_newVxV_element
        VxV_col6:
        bn.rshi w1, w20, w19 >> 64
        bn.mov w2, w26
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w20 >> 64
        bn.and w1, w1, w29
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_col7
        jal x1, gen_newVxV_element
        VxV_col7:
        bn.rshi w1, w30, w20 >> 160
        bn.mov w2, w26
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w30 >> 160
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_mul_loop
        jal x1, gen_newVxV_element
        beq x0, x0, VxV_mul_loop
    VxV_END:    #start VxO init continue from VxV end of VxVcol2
    li x31, 23                  #x23..x27 still hold prior state, x28..x31 clobbered by aes128table_352 not used here
    lw x5, 0(x3)                #reload sig ptr
    li x17, 0                   # current VxO elements
    li x26, 68                  # V elements remaining; x26=0 marks P2 done
    # VxO, load all sig = V(68B) || O(44B) || salt (16B), need V[0..67] + O[0..43]
    bn.lid x31++, 0(x5)         #w23 V[0..31]
    bn.lid x31++, 32(x5)        #w24 V[32..63]
    bn.lid x31++, 64(x5)        #w25 V[64..67] + O[0..27]
    bn.lid x31++, 96(x5)        #w26 O[28..43] + 16B junk
    bn.and w27, w29, w26 >> 32  #w27 = O[32..43] low 12B, mask12 wipe junk
    bn.rshi w26, w26, w25 >> 32 # w26 = O[0..31] = w25[4..31] || w26[0..3]
    bn.and w25, w25, w29 >> 64  # w25 = V[64..67] low 4B, rest 0
    jal x1, gen_newVxO_element  # row 0 coefs in w11/w12, v slid for row 1
    beq x0, x0,  VxO_col2       # last VxV batch col2..col7 = first 6 P2 entries
    VxO_mul_loop:
        lw x4, 20(x3)
        # AES-CTR expand 22 blocks (352 B) into P1 buffer; counter chains via x13
        add x10, x0, x18              #rk base / AES key survivor from setup
        lw  x11, 20(x3)               # P1 buffer base from frame slot 20
#ifdef AES_INSTRUCTIONS
        jal x1, aes128hw_352reg   /* duals returned in WDRs */
#else
        jal x1, aes128table_352
        lw  x4, 20(x3)
        li  x28, 7
        bn.lid x28++, 0(x4)
        bn.lid x28++, 32(x4)
        bn.lid x28++, 64(x4)
        bn.lid x28++, 96(x4)
        li  x28, 13
        bn.lid x28++, 128(x4)
        bn.lid x28++, 160(x4)
        bn.lid x28++, 192(x4)
        li  x28, 18
        bn.lid x28++, 224(x4)
        bn.lid x28++, 256(x4)
        bn.lid x28++, 288(x4)
        li  x28, 30
        bn.lid x28, 320(x4)
#endif
        lw x4, 20(x3)                    #col 0
        bn.mov w2, w11
        bn.mov w1, w7                  /* lo32 = whole dual */
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.and w1, w8, w29             /* hi12 */
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_col1
        jal x1, gen_newVxO_element
        VxO_col1:
        bn.rshi w1, w9, w8 >> 96
        bn.mov w2, w11
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w9 >> 96
        bn.and w1, w1, w29
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        # gate order: row 67 = 44 entries so x26=0 stays across many col1
        # visits. bne x17 first so beq fires only when x17=0 AND x26=0
        bne x17, x0, VxO_col2     # row not done, continue
        beq x0, x26, VxO_END      # row done, no more rows, exit
        jal x1, gen_newVxO_element  # row done, prep next row
        VxO_col2:
        bn.rshi w1, w10, w9 >> 192
        bn.mov w2, w11
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w13, w10 >> 192
        bn.and w1, w1, w29
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_col3
        jal x1, gen_newVxO_element
        VxO_col3:
        bn.rshi w1, w14, w13 >> 32
        bn.mov w2, w11
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w14 >> 32
        bn.and w1, w1, w29
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_col4
        jal x1, gen_newVxO_element
        VxO_col4:
        bn.rshi w1, w15, w14 >> 128
        bn.mov w2, w11
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w15 >> 128
        bn.and w1, w1, w29
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_col5
        jal x1, gen_newVxO_element
        VxO_col5:
        bn.rshi w1, w18, w15 >> 224
        bn.mov w2, w11
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w19, w18 >> 224
        bn.and w1, w1, w29
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_col6
        jal x1, gen_newVxO_element
        VxO_col6:
        bn.rshi w1, w20, w19 >> 64
        bn.mov w2, w11
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w20 >> 64
        bn.and w1, w1, w29
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_col7
        jal x1, gen_newVxO_element
        VxO_col7:
        bn.rshi w1, w30, w20 >> 160
        bn.mov w2, w11
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w30 >> 160
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_mul_loop
        jal x1, gen_newVxO_element
        beq x0, x0, VxO_mul_loop
    VxO_END:    # start P3 init
    /* acc (w21/w22) complete after VxO; spill to ctx */
    li x5, 0x20
    bn.sd w21, 0(x5)
    li x5, 0x40
    bn.sd w22, 0(x5)

    /* ---------------- read 44B digest -> ctx.target ----------------- */
    bn.wsrr w13, 0xA
    bn.wsrr w14, 0xA
    bn.rshi w14, w14, w31 >> 96
    bn.rshi w14, w31, w14 >> 160
    li   x3, 0x0A0
    bn.sd w13, 0(x3)         /* target lo */
    bn.sd w14, 32(x3)        /* target hi */
    li   x5, 0x517
    sw   x5, 16(x0)           /* init_done: FINAL/UPDATE reject -3 without it */
    ecall

/* ============================ UPDATE ============================ */
_UPDATE:
    li   x3, 0x00
    lw   x9, 4(x3)            /* row_start */
    lw   x8, 8(x3)            /* row_count */

    lw   x5, 16(x3)
    li   x6, 0x517
    bne  x5, x6, _u_noinit    /* UPDATE before a completed INIT */
    /* Capacity gate: past winend a fold would eat caprows and the T-table -
     * wrong verdict, nothing corrupted. Gate BEFORE the zero-row skip. */
    or   x5, x9, x8
    srli x5, x5, 6
    bne  x5, x0, _U_bad       /* row_start or row_count >= 64 */
    li   x5, 43
    sub  x5, x5, x9
    srli x5, x5, 31
    bne  x5, x0, _U_bad       /* row_start > 43 */
    add  x5, x9, x8
    li   x6, 44
    sub  x6, x6, x5
    srli x6, x6, 31
    bne  x6, x0, _U_bad       /* row_start + row_count > 44 */
    slli x6, x9, 2
    la   x5, caprows
    add  x5, x5, x6
    lw   x5, 0(x5)
    sub  x5, x5, x8
    srli x5, x5, 31
    bne  x5, x0, _U_bad       /* row_count > caprows[row_start] */

    beq  x8, x0, _U_done      /* zero-row window -> no-op */

    /* P3 row fold, from ov-Ip-verify_backend.s sw arm (inline) */
    la x2, sfk_stack_end
    la x5, sfk_msb
    li x6, 17
    bn.lid x6, 0(x5)          /* w17 = msb_mask */
    la x5, sfk_upper12
    li x6, 30
    bn.lid x6, 0(x5)          /* w30 = 12B mask for the fold hi half */
    bn.xor w31, w31, w31
    li x5, 0x20
    bn.ld w21, 0(x5)          /* acc lo <- ctx */
    li x5, 0x40
    bn.ld w22, 0(x5)          /* acc hi */
    li x5, 0x60
    bn.ld w26, 0(x5)          /* oil[0..31] (host-shifted: byte0 = O[row_start]) */
    li x5, 0x80
    bn.ld w27, 0(x5)          /* oil[32..43] (junk above ok) */
    li x4, 0x180             /* P3 window (16B prefix + packed entries) */
    li x26, 44
    sub x26, x26, x9         /* geometry rows: 44 - row_start */
    /* x8 = row_count (from outer) is the independent terminator */
    jal x1, gen_newP3_element  /* row-0 coefs w28/w29, x17 = 44-row_start */
    P3_outer_loop:
        #load 12 aligned WDRs cpk[352N..352N+383] into w7..w16,w18,w19
        li x6, 7
        bn.lid x6++, 0(x4)          #w7
        bn.lid x6++, 32(x4)         #w8
        bn.lid x6++, 64(x4)         #w9
        bn.lid x6++, 96(x4)         #w10
        bn.lid x6++, 128(x4)        #w11
        bn.lid x6++, 160(x4)        #w12
        bn.lid x6++, 192(x4)        #w13
        bn.lid x6++, 224(x4)        #w14
        bn.lid x6++, 256(x4)        #w15
        bn.lid x6, 288(x4)          # w16 (skip w17 = msb mask)
        li x6, 18
        bn.lid x6++, 320(x4)        #w18
        bn.lid x6, 352(x4)          #w19
        addi x4, x4, 352
        P3_col0:                  #entry 0 bytes [16..59]
        bn.mov w2, w28
        bn.rshi w1, w8, w7 >> 128
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w8 >> 128
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_col1
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_col1:                  #entry 1 bytes [60..103]
        bn.mov w2, w28
        bn.rshi w1, w9, w8 >> 224
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w10, w9 >> 224
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_col2
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_col2:                  #entry 2 bytes [104..147]
        bn.mov w2, w28
        bn.rshi w1, w11, w10 >> 64
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w11 >> 64
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_col3
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_col3:                  #entry 3 bytes [148..191]
        bn.mov w2, w28
        bn.rshi w1, w12, w11 >> 160
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w12 >> 160
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_col4
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_col4:                  #entry 4 bytes [192..235]
        bn.mov w2, w28
        bn.mov w1, w13
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.and w1, w14, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_col5
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_col5:                  #entry 5 bytes [236..279]
        bn.mov w2, w28
        bn.rshi w1, w15, w14 >> 96
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w15 >> 96
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_col6
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_col6:                  #entry 6 bytes [280..323]
        bn.mov w2, w28
        bn.rshi w1, w16, w15 >> 192
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w18, w16 >> 192
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_col7
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_col7:                  #entry 7 bytes [324..367]
        bn.mov w2, w28
        bn.rshi w1, w19, w18 >> 32
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w19 >> 32
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_outer_loop
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        beq x0, x0, P3_outer_loop
    P3_done:
    li x5, 0x20
    bn.sd w21, 0(x5)          /* acc lo -> ctx */
    li x5, 0x40
    bn.sd w22, 0(x5)
_U_done:
    ecall

_U_bad:
    li   x6, -2
    li   x3, 0x00
    sw   x6, 12(x3)           /* bad UPDATE args */
    ecall
_msgbad:
    li   x6, -2
    li   x3, 0x00
    sw   x6, 12(x3)           /* msg would overrun the window */
    ecall
_f_noinit:
    li   x6, -3
    sw   x6, 12(x0)           /* FINAL before a completed INIT */
    ecall
_u_noinit:
    li   x6, -3
    sw   x6, 12(x0)           /* UPDATE before a completed INIT */
    ecall

/* ---- internal helpers from the backend sw arm (ret-terminated, jal x1) ---- */
# gen_newVxV_element: prep one VxV row coefs (upper-tri, row size = V-i)
# in:  w23..w25 V window, byte 0 = v[i]
#      x26 = row size for current row (= V-i), caller gates so x26 != 0 here
# out: w26 = v[i]*v[i..i+31], w27 = v[i]*v[i+32..i+63], w28 = v[i]*v[i+64..i+95]
#      x17 = x26 (row size for col countdown)
#      v slid 1B (byte 0 = v[i+1]), x26-- (next row size = V-(i+1))
gen_newVxV_element:
    bn.mov w1, w23
    bn.mov w2, w23
    jal x1, gf256_mul
    bn.mov w26, w0                       # 32 coefs v[i]*v[i..i+31]
    bn.mov w1, w24
    jal x1, gf256_mul
    bn.mov w27, w0                       # 32 coefs v[i]*v[i+32..i+63]
    bn.mov w1, w25
    jal x1, gf256_mul
    bn.mov w28, w0                       # tail v[i]*v[i+64..i+95] (bytes past V[67] = junk)
    add x17, x0, x26                     # row size = V-i (shrinks per row)
    beq x26, x0, gen_newVxV_element_ret  #x26=0 skip slide
    bn.rshi w23, w24, w23 >> 8
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8           # v window v[i] to v[i+1]
    addi x26, x26, -1
gen_newVxV_element_ret:
    ret


# gen_newVxO_element: prep one VxO row coefs
# in:  w23..w25 V window, byte 0 = v[i]
#      w26 = O[0..31], w27 = O[32..43] low 12B
#      x26 = rows left, caller gates so x26 != 0 here
# out: w11 = v[i]*O[0..31], w12 = v[i]*O[32..43] low 12B
#      x17 = 44, v slid 1B (byte 0 = v[i+1]), x26--
gen_newVxO_element:
    bn.mov w2, w23
    bn.mov w1, w26
    jal x1, gf256_mul
    bn.mov w11, w0                       # 32 coefs v[i]*O[0..31]
    bn.mov w1, w27
    jal x1, gf256_mul
    bn.mov w12, w0                       # 12 valid coefs v[i]*O[32..43]
    li x17, 44                           # row size const for VxO (vs V-i in VxV)
    beq x26, x0, gen_newVxO_element_ret  #x26=0 skip slide
    bn.rshi w23, w24, w23 >> 8
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8           # v window v[i] to v[i+1]
    addi x26, x26, -1
gen_newVxO_element_ret:
    ret


# gen_newP3_element: prep one P3 row coefs (oil x oil upper-tri)
# in:  w26 = O[i..i+31], w27 = O[i+32..i+43] low 12B (junk above)
#      x26 = rows-left BEFORE this row (= 44-i; caller gates so x26 != 0 here)
# out: w28 = O[i]*O[i..i+31]              (32B; first 44-i meaningful)
#      w29 = O[i]*O[i+32..i+43] low 12B   (first max(0,12-i) meaningful)
#      x17 = row size for col countdown (= 44-i)
#      O window slid 1B (byte 0 = O[i+1]); x26 decremented
gen_newP3_element:
    bn.mov w2, w26                       # scalar = O[i] (low byte)
    bn.mov w1, w26
    jal x1, gf256_mul
    bn.mov w28, w0                       # 32 coefs O[i]*O[i..i+31]
    bn.mov w1, w27
    jal x1, gf256_mul
    bn.mov w29, w0                       # 12 valid coefs O[i]*O[i+32..i+43]
    add x17, x0, x26                     # row size = 44-i (shrinks per row)
    beq x26, x0, gen_newP3_element_ret   #x26=0 skip slide
    bn.rshi w26, w27, w26 >> 8
    bn.rshi w27, w31, w27 >> 8           # O window O[i] to O[i+1]
    addi x26, x26, -1
gen_newP3_element_ret:
    ret
