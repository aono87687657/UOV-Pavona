/* ov-Ip3-pkc_verify_full_sw.s - one-shot UOV-Ip3 verify, software-GF arms
 * (swonly = T-table AES; -DAES_INSTRUCTIONS = bnaesonly via aes128hw_384),
 * whole cpk resident: host writes cpk (46,591B + 225B zero padding the P3
 * loader over-reads), msg_len, msg, sig (135B in a 160B zero-tailed slot);
 * ONE EXECUTE; reads result: 0 accept, -1 reject, -2 msg_len > 1,024, -5
 * while running. Bodies are the streamed kernel's INIT (KMAC target + P1/P2
 * -> acc in w21/w22), UPDATE (P3 fold, one pass over all 45 rows) and FINAL;
 * the seed is copied from the cpk prefix and the oil vector from sig[74..118]
 * by the kernel. Host contract = ov-Ip3-pkc_verify_full.s.
 * Map: hdr@0 acc@0x20 oil@0x60 target@0xA0 sig@0xE0 seed@0x180 msg@0x1A0
 * cpk@0x5A0, then the fold masks and the private stack (608B swonly /
 * 416B bnaesonly, x2 descends from sfk_stack_end).
 * clob: everything (app, no caller). call depth 2 (gen_new* helpers -> gf256_mul).
 */
#ifdef GF_INSTRUCTIONS
#error "gfsw source: GF is always software here, so -DGF_INSTRUCTIONS is never correct on it -- a _bngfonly target aimed at this file reports swonly cycles under a hardware-GF name. Build _gfhw.s for that tier."
#endif
.section .data
.balign 32
hdr:       .zero 32              /* 0x000: +4 msg_len (host), +12 result (kernel) */
accctx:    .zero 64              /* 0x020 acc lo/hi, INIT -> P3 pass -> FINAL */
oil:       .zero 64              /* 0x060 sig[74..118] zero-padded, written by INIT's tail */
target:    .zero 64              /* 0x0A0 KMAC digest, INIT -> FINAL */
sig:       .zero 160             /* 0x0E0: 135B sig + zero tail (host writes 160 B) */
seed:      .zero 32              /* 0x180: cpk[0:16] zero-extended, written at entry */
msg:       .zero 1024            /* 0x1A0: 32B granules, zero tail */
cpk:       .zero 46816           /* 0x5A0: 46,591B key + 225B readable padding */
.balign 32
sfk_upper13: .word 0xffffffff, 0xffffffff, 0xffffffff
             .byte 0xff
             .zero 19
.balign 32
sfk_msb:     .word 0x80808080, 0x80808080, 0x80808080, 0x80808080
             .word 0x80808080, 0x80808080, 0x80808080, 0x80808080
/* private stack, in the image: 32B frame | 192B rk (swonly only) | 384B batch buffer */
.balign 32
sfk_stack:
#ifndef AES_INSTRUCTIONS
    .zero 608
#else
    .zero 416
#endif
sfk_stack_end:

.section .text.start
.balign 4
.global main
main:
    li   x3, 0x00
    li   x6, -5
    sw   x6, 12(x3)           /* result = running */
    lw   x14, 4(x3)           /* msg_len */
    srli x5, x14, 15          /* wrap-safe: len >= 2^15 first */
    bne  x5, x0, _len_bad
    li   x5, 1024
    sub  x5, x5, x14
    srli x5, x5, 31
    bne  x5, x0, _len_bad     /* len > 1,024 */
    /* seed := cpk[0:16], zero-extended to the 32B word the bodies read */
    la   x10, cpk
    li   x12, 0x180
    lw   x5, 0(x10)
    sw   x5, 0(x12)
    lw   x5, 4(x10)
    sw   x5, 4(x12)
    lw   x5, 8(x10)
    sw   x5, 8(x12)
    lw   x5, 12(x10)
    sw   x5, 12(x12)
    sw   x0, 16(x12)
    sw   x0, 20(x12)
    sw   x0, 24(x12)
    sw   x0, 28(x12)
    jal  x0, _INIT
_len_bad:
    li   x6, -2
    jal  x0, _done

/* ============================ INIT ============================ */
_INIT:
    li   x3, 0x00
    lw   x14, 4(x3)           /* msg_len */
    li   x10, 0x0E0          /* sig */
    li   x12, 0x160          /* seed */
    li   x13, 0x1A0          /* msg */

    /* ---------------- KMAC SHAKE256 over (msg || salt) ---------------- */
    bn.xor w31, w31, w31
    bn.xor w1, w1, w1
    addi x5, x14, 16
    slli x5, x5, 5
    ori  x5, x5, 0xA
    csrrw x0, kmac_cfg, x5
    bn.ld w1, 96(x10)         /* sig bytes 96..127 */
    bn.ld w2, 128(x10)        /* sig bytes 128..159 (135-B sig: 128..134 live) */
    bn.rshi w1, w2, w1 >> 184 /* salt = bytes 119..134 */
    bn.rshi w1, w1, w31 >> 128
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
    la x2, sfk_stack_end      /* private stack label: 32 frame + 192 rk (swonly) + 384 buf */
    la x5, sfk_msb
    li x6, 17
    bn.lid x6, 0(x5)          /* w17 = msb_mask (gf256_mul precondition) */
    la x5, sfk_upper13
    li x6, 29
    bn.lid x6, 0(x5)          /* w29 = upper12B_mask (col-hi12) */
    li x10, 0xE0              /* sig */
    li x11, 0x20             /* acc-out (unused; p1p2 spills to 0x20/0x40) */
    li x12, 0x180            /* seed = AES key (cpk[0..15] in the monolith) */
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

    #AES-CTR counter init; threads through the 384-B leaf calls via x13
    addi x13, x0, 0

    # preserve 384 bytes for P1 expansion (12 duals)
    addi x2, x2, -384
    add x4, x0, x2 # x4 point for P1 tmp space for 384 bytes
    sw x4, 20(x3)   # store 384 bytes starting adddress
    li x31, 23
    lw x25, 0(x3)
    # VxV,  Only load V part first
    bn.lid x31++, 0(x25)            # w23 = sig[0..31]   = v[0..31]
    bn.lid x31++, 32(x25)           # w24 = sig[32..63]  = v[32..63]
    bn.lid x31++, 64(x25)           # w25 = sig[64..95]  (only v[64..67] valid)
    bn.rshi w25, w25, w31 >> 80     # trim w25 to 10 valid vinegar bytes
    bn.rshi w25, w31, w25 >> 176

    li x17, 0                   # col countdown (relocated from x25 to free contiguous block)
    li x26, 74                  # row size
    li x23, 7                   # WDR idx 7 (was x23)
    li x24, 8                   # WDR idx 8 (was x24)
    li x25, 9                   # WDR idx 9 (was x25; now part of x23-x24-x25 contiguous block)
    addi x10, x10, -320
    #setup first batch of VxV Elements
    jal x1, gen_newVxV_element
    VxV_p0_head:
        lw x4, 20(x3)
        add x10, x0, x18              #rk base / AES key survivor
        lw  x11, 20(x3)               # 384-B batch buffer
#ifdef AES_INSTRUCTIONS
        jal x1, aes128hw_384
#else
        jal x1, aes128table_384
#endif
        addi x13, x13, -2          # net +22 blocks
        lw x4, 20(x3)
        bn.lid x23, 0(x4)
        bn.lid x24, 32(x4)
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p0_col1
        jal x1, gen_newVxV_element
        VxV_p0_col1:
        bn.lid x23, 32(x4)
        bn.lid x24, 64(x4)
        bn.rshi w7, w8, w7 >> 104
        bn.rshi w8, w31, w8 >> 104
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p0_col2
        jal x1, gen_newVxV_element
        VxV_p0_col2:
        bn.lid x23, 64(x4)
        bn.lid x24, 96(x4)
        bn.lid x25, 128(x4)
        bn.rshi w7, w8, w7 >> 208
        bn.rshi w8, w9, w8 >> 208
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p0_col3
        jal x1, gen_newVxV_element
        VxV_p0_col3:
        bn.lid x23, 128(x4)
        bn.lid x24, 160(x4)
        bn.rshi w7, w8, w7 >> 56
        bn.rshi w8, w31, w8 >> 56
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p0_col4
        jal x1, gen_newVxV_element
        VxV_p0_col4:
        bn.lid x23, 160(x4)
        bn.lid x24, 192(x4)
        bn.lid x25, 224(x4)
        bn.rshi w7, w8, w7 >> 160
        bn.rshi w8, w9, w8 >> 160
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p0_col5
        jal x1, gen_newVxV_element
        VxV_p0_col5:
        bn.lid x23, 224(x4)
        bn.lid x24, 256(x4)
        bn.rshi w7, w8, w7 >> 8
        bn.rshi w8, w31, w8 >> 8
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p0_col6
        jal x1, gen_newVxV_element
        VxV_p0_col6:
        bn.lid x23, 256(x4)
        bn.lid x24, 288(x4)
        bn.rshi w7, w8, w7 >> 112
        bn.rshi w8, w31, w8 >> 112
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p0_col7
        beq x0, x26, VxV_END
        jal x1, gen_newVxV_element
        VxV_p0_col7:
        bn.lid x23, 288(x4)
        bn.lid x24, 320(x4)
        bn.lid x25, 352(x4)
        bn.rshi w7, w8, w7 >> 216
        bn.rshi w8, w9, w8 >> 216
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p1_head
        jal x1, gen_newVxV_element
        beq x0, x0, VxV_p1_head
    VxV_p1_head:
        lw x4, 20(x3)
        add x10, x0, x18              #rk base / AES key survivor
        lw  x11, 20(x3)               # 384-B batch buffer
#ifdef AES_INSTRUCTIONS
        jal x1, aes128hw_384
#else
        jal x1, aes128table_384
#endif
        addi x13, x13, -1          # net +23 blocks
        lw x4, 20(x3)
        bn.lid x23, 0(x4)
        bn.lid x24, 32(x4)
        bn.rshi w7, w8, w7 >> 64
        bn.rshi w8, w31, w8 >> 64
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p1_col1
        jal x1, gen_newVxV_element
        VxV_p1_col1:
        bn.lid x23, 32(x4)
        bn.lid x24, 64(x4)
        bn.lid x25, 96(x4)
        bn.rshi w7, w8, w7 >> 168
        bn.rshi w8, w9, w8 >> 168
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p1_col2
        jal x1, gen_newVxV_element
        VxV_p1_col2:
        bn.lid x23, 96(x4)
        bn.lid x24, 128(x4)
        bn.rshi w7, w8, w7 >> 16
        bn.rshi w8, w31, w8 >> 16
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p1_col3
        jal x1, gen_newVxV_element
        VxV_p1_col3:
        bn.lid x23, 128(x4)
        bn.lid x24, 160(x4)
        bn.rshi w7, w8, w7 >> 120
        bn.rshi w8, w31, w8 >> 120
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p1_col4
        jal x1, gen_newVxV_element
        VxV_p1_col4:
        bn.lid x23, 160(x4)
        bn.lid x24, 192(x4)
        bn.lid x25, 224(x4)
        bn.rshi w7, w8, w7 >> 224
        bn.rshi w8, w9, w8 >> 224
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p1_col5
        jal x1, gen_newVxV_element
        VxV_p1_col5:
        bn.lid x23, 224(x4)
        bn.lid x24, 256(x4)
        bn.rshi w7, w8, w7 >> 72
        bn.rshi w8, w31, w8 >> 72
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p1_col6
        jal x1, gen_newVxV_element
        VxV_p1_col6:
        bn.lid x23, 256(x4)
        bn.lid x24, 288(x4)
        bn.lid x25, 320(x4)
        bn.rshi w7, w8, w7 >> 176
        bn.rshi w8, w9, w8 >> 176
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p1_col7
        beq x0, x26, VxV_END
        jal x1, gen_newVxV_element
        VxV_p1_col7:
        bn.lid x23, 320(x4)
        bn.lid x24, 352(x4)
        bn.rshi w7, w8, w7 >> 24
        bn.rshi w8, w31, w8 >> 24
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p0_head
        jal x1, gen_newVxV_element
        beq x0, x0, VxV_p0_head
    VxV_END:    #start VxO init continue from VxV end of VxVcol2
    li x31, 23                  #x23..x27 still hold prior state, x28..x31 clobbered by aes128table_352 not used here
    lw x5, 0(x3)                #reload sig ptr
    li x17, 0                   # current VxO elements
    li x26, 74                  # V elements remaining; x26=0 marks P2 done
    # VxO, load all sig = V(68B) || O(44B) || salt (16B), need V[0..67] + O[0..43]
    bn.lid x31++, 0(x5)         #w23 V[0..31]
    bn.lid x31++, 32(x5)        #w24 V[32..63]
    bn.lid x31++, 64(x5)        #w25 V[64..67] + O[0..27]
    bn.lid x31++, 96(x5)        #w26 O[28..43] + 16B junk
    bn.rshi w27, w31, w26 >> 80 #w27 = O[32..44] = sig[106..118]
    bn.and w27, w27, w29        #  mask to 13B, wipe salt junk
    bn.rshi w26, w26, w25 >> 80 # w26 = O[0..31] = sig[74..105]
    bn.and w25, w25, w29 >> 24  # w25 = V[64..73] low 10B, rest 0
    jal x1, gen_newVxO_element  # row 0 coefs in w11/w12, v slid for row 1
    beq x0, x0, VxO_p0_col7   # continue mid-batch: entry 2775 is col 7
    VxO_p0_head:
        lw x4, 20(x3)
        add x10, x0, x18              #rk base / AES key survivor
        lw  x11, 20(x3)               # 384-B batch buffer
#ifdef AES_INSTRUCTIONS
        jal x1, aes128hw_384
#else
        jal x1, aes128table_384
#endif
        addi x13, x13, -2          # net +22 blocks
        lw x4, 20(x3)
        bn.lid x23, 0(x4)
        bn.lid x24, 32(x4)
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p0_col1
        beq x0, x26, VxO_END
        jal x1, gen_newVxO_element
        VxO_p0_col1:
        bn.lid x23, 32(x4)
        bn.lid x24, 64(x4)
        bn.rshi w7, w8, w7 >> 104
        bn.rshi w8, w31, w8 >> 104
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p0_col2
        jal x1, gen_newVxO_element
        VxO_p0_col2:
        bn.lid x23, 64(x4)
        bn.lid x24, 96(x4)
        bn.lid x25, 128(x4)
        bn.rshi w7, w8, w7 >> 208
        bn.rshi w8, w9, w8 >> 208
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p0_col3
        jal x1, gen_newVxO_element
        VxO_p0_col3:
        bn.lid x23, 128(x4)
        bn.lid x24, 160(x4)
        bn.rshi w7, w8, w7 >> 56
        bn.rshi w8, w31, w8 >> 56
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p0_col4
        jal x1, gen_newVxO_element
        VxO_p0_col4:
        bn.lid x23, 160(x4)
        bn.lid x24, 192(x4)
        bn.lid x25, 224(x4)
        bn.rshi w7, w8, w7 >> 160
        bn.rshi w8, w9, w8 >> 160
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p0_col5
        jal x1, gen_newVxO_element
        VxO_p0_col5:
        bn.lid x23, 224(x4)
        bn.lid x24, 256(x4)
        bn.rshi w7, w8, w7 >> 8
        bn.rshi w8, w31, w8 >> 8
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p0_col6
        jal x1, gen_newVxO_element
        VxO_p0_col6:
        bn.lid x23, 256(x4)
        bn.lid x24, 288(x4)
        bn.rshi w7, w8, w7 >> 112
        bn.rshi w8, w31, w8 >> 112
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p0_col7
        jal x1, gen_newVxO_element
        VxO_p0_col7:
        bn.lid x23, 288(x4)
        bn.lid x24, 320(x4)
        bn.lid x25, 352(x4)
        bn.rshi w7, w8, w7 >> 216
        bn.rshi w8, w9, w8 >> 216
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p1_head
        jal x1, gen_newVxO_element
        beq x0, x0, VxO_p1_head
    VxO_p1_head:
        lw x4, 20(x3)
        add x10, x0, x18              #rk base / AES key survivor
        lw  x11, 20(x3)               # 384-B batch buffer
#ifdef AES_INSTRUCTIONS
        jal x1, aes128hw_384
#else
        jal x1, aes128table_384
#endif
        addi x13, x13, -1          # net +23 blocks
        lw x4, 20(x3)
        bn.lid x23, 0(x4)
        bn.lid x24, 32(x4)
        bn.rshi w7, w8, w7 >> 64
        bn.rshi w8, w31, w8 >> 64
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p1_col1
        beq x0, x26, VxO_END
        jal x1, gen_newVxO_element
        VxO_p1_col1:
        bn.lid x23, 32(x4)
        bn.lid x24, 64(x4)
        bn.lid x25, 96(x4)
        bn.rshi w7, w8, w7 >> 168
        bn.rshi w8, w9, w8 >> 168
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p1_col2
        jal x1, gen_newVxO_element
        VxO_p1_col2:
        bn.lid x23, 96(x4)
        bn.lid x24, 128(x4)
        bn.rshi w7, w8, w7 >> 16
        bn.rshi w8, w31, w8 >> 16
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p1_col3
        jal x1, gen_newVxO_element
        VxO_p1_col3:
        bn.lid x23, 128(x4)
        bn.lid x24, 160(x4)
        bn.rshi w7, w8, w7 >> 120
        bn.rshi w8, w31, w8 >> 120
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p1_col4
        jal x1, gen_newVxO_element
        VxO_p1_col4:
        bn.lid x23, 160(x4)
        bn.lid x24, 192(x4)
        bn.lid x25, 224(x4)
        bn.rshi w7, w8, w7 >> 224
        bn.rshi w8, w9, w8 >> 224
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p1_col5
        jal x1, gen_newVxO_element
        VxO_p1_col5:
        bn.lid x23, 224(x4)
        bn.lid x24, 256(x4)
        bn.rshi w7, w8, w7 >> 72
        bn.rshi w8, w31, w8 >> 72
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p1_col6
        jal x1, gen_newVxO_element
        VxO_p1_col6:
        bn.lid x23, 256(x4)
        bn.lid x24, 288(x4)
        bn.lid x25, 320(x4)
        bn.rshi w7, w8, w7 >> 176
        bn.rshi w8, w9, w8 >> 176
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p1_col7
        jal x1, gen_newVxO_element
        VxO_p1_col7:
        bn.lid x23, 320(x4)
        bn.lid x24, 352(x4)
        bn.rshi w7, w8, w7 >> 24
        bn.rshi w8, w31, w8 >> 24
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p0_head
        jal x1, gen_newVxO_element
        beq x0, x0, VxO_p0_head
    VxO_END:    # start P3 init
    /* acc (w21/w22) complete after VxO; spill to ctx */
    li x5, 0x20
    bn.sd w21, 0(x5)
    li x5, 0x40
    bn.sd w22, 0(x5)

    /* ---------------- read 44B digest -> ctx.target ----------------- */
    bn.wsrr w13, 0xA
    bn.wsrr w14, 0xA
    bn.rshi w14, w14, w31 >> 104
    bn.rshi w14, w31, w14 >> 152
    li   x3, 0x0A0
    bn.sd w13, 0(x3)         /* target lo */
    bn.sd w14, 32(x3)        /* target hi */
    /* oil := sig[74..118] zero-padded to 64B: what the host wrote per window */
    li   x3, 0x0E0
    bn.ld w5, 64(x3)          /* sig 64..95 */
    bn.ld w6, 96(x3)          /* sig 96..127 */
    bn.ld w7, 128(x3)         /* sig 128..159 (zero tail) */
    bn.rshi w5, w6, w5 >> 80  /* bytes 74..105 */
    bn.rshi w6, w7, w6 >> 80  /* bytes 106..137 */
    bn.rshi w6, w6, w31 >> 104
    bn.rshi w6, w31, w6 >> 152 /* keep 13 bytes: 106..118 */
    li   x3, 0x060
    bn.sd w5, 0(x3)
    bn.sd w6, 32(x3)

/* ---------------- P3 pass: the UPDATE body, rows 0..44 in one go ---------------- */
    li   x3, 0x00
    li   x9, 0                /* row_start */
    li   x8, 45               /* row_count */
    /* P3 row fold, from ov-Ip-verify_backend.s sw arm (inline) */
    la x2, sfk_stack_end
    la x5, sfk_msb
    li x6, 17
    bn.lid x6, 0(x5)          /* w17 = msb_mask */
    la x5, sfk_upper13
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
    la x4, cpk              /* resident cpk: 16B prefix + 1,035 entries + padding */
    li x26, 45
    sub x26, x26, x9         /* geometry rows: 45 - row_start */
    /* x8 = row_count (from outer) is the independent terminator */
    jal x1, gen_newP3_element  /* row-0 coefs w28/w29, x17 = 45-row_start */
    P3_p0_head:
        li x6, 7
        bn.lid x6++, 0(x4)
        bn.lid x6++, 32(x4)
        bn.lid x6++, 64(x4)
        bn.lid x6++, 96(x4)
        bn.lid x6++, 128(x4)
        bn.lid x6++, 160(x4)
        bn.lid x6++, 192(x4)
        bn.lid x6++, 224(x4)
        bn.lid x6++, 256(x4)
        bn.lid x6, 288(x4)          # w16 (skip w17 = msb mask)
        li x6, 18
        bn.lid x6++, 320(x4)
        bn.lid x6++, 352(x4)
        addi x4, x4, 352
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
        bne x17, x0, P3_p0_col1
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p0_col1:
        bn.mov w2, w28
        bn.rshi w1, w9, w8 >> 232
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w10, w9 >> 232
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p0_col2
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p0_col2:
        bn.mov w2, w28
        bn.rshi w1, w11, w10 >> 80
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w11 >> 80
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p0_col3
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p0_col3:
        bn.mov w2, w28
        bn.rshi w1, w12, w11 >> 184
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w13, w12 >> 184
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p0_col4
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p0_col4:
        bn.mov w2, w28
        bn.rshi w1, w14, w13 >> 32
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w14 >> 32
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p0_col5
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p0_col5:
        bn.mov w2, w28
        bn.rshi w1, w15, w14 >> 136
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w15 >> 136
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p0_col6
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p0_col6:
        bn.mov w2, w28
        bn.rshi w1, w16, w15 >> 240
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w18, w16 >> 240
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p0_col7
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p0_col7:
        bn.mov w2, w28
        bn.rshi w1, w19, w18 >> 88
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w19 >> 88
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p1_head
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        beq x0, x0, P3_p1_head
    P3_p1_head:
        li x6, 7
        bn.lid x6++, 0(x4)
        bn.lid x6++, 32(x4)
        bn.lid x6++, 64(x4)
        bn.lid x6++, 96(x4)
        bn.lid x6++, 128(x4)
        bn.lid x6++, 160(x4)
        bn.lid x6++, 192(x4)
        bn.lid x6++, 224(x4)
        bn.lid x6++, 256(x4)
        bn.lid x6, 288(x4)          # w16 (skip w17 = msb mask)
        li x6, 18
        bn.lid x6++, 320(x4)
        bn.lid x6++, 352(x4)
        addi x4, x4, 384
        bn.mov w2, w28
        bn.rshi w1, w8, w7 >> 192
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w9, w8 >> 192
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p1_col1
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p1_col1:
        bn.mov w2, w28
        bn.rshi w1, w10, w9 >> 40
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w10 >> 40
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p1_col2
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p1_col2:
        bn.mov w2, w28
        bn.rshi w1, w11, w10 >> 144
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w11 >> 144
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p1_col3
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p1_col3:
        bn.mov w2, w28
        bn.rshi w1, w12, w11 >> 248
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w13, w12 >> 248
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p1_col4
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p1_col4:
        bn.mov w2, w28
        bn.rshi w1, w14, w13 >> 96
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w14 >> 96
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p1_col5
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p1_col5:
        bn.mov w2, w28
        bn.rshi w1, w15, w14 >> 200
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w16, w15 >> 200
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p1_col6
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p1_col6:
        bn.mov w2, w28
        bn.rshi w1, w18, w16 >> 48
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w18 >> 48
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p1_col7
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p1_col7:
        bn.mov w2, w28
        bn.rshi w1, w19, w18 >> 152
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w19 >> 152
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p2_head
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        beq x0, x0, P3_p2_head
    P3_p2_head:
        li x6, 7
        bn.lid x6++, 0(x4)
        bn.lid x6++, 32(x4)
        bn.lid x6++, 64(x4)
        bn.lid x6++, 96(x4)
        bn.lid x6++, 128(x4)
        bn.lid x6++, 160(x4)
        bn.lid x6++, 192(x4)
        bn.lid x6++, 224(x4)
        bn.lid x6++, 256(x4)
        bn.lid x6, 288(x4)          # w16 (skip w17 = msb mask)
        li x6, 18
        bn.lid x6++, 320(x4)
        bn.lid x6++, 352(x4)
        addi x4, x4, 352
        bn.mov w2, w28
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.and w1, w8, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p2_col1
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p2_col1:
        bn.mov w2, w28
        bn.rshi w1, w9, w8 >> 104
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w9 >> 104
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p2_col2
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p2_col2:
        bn.mov w2, w28
        bn.rshi w1, w10, w9 >> 208
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w11, w10 >> 208
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p2_col3
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p2_col3:
        bn.mov w2, w28
        bn.rshi w1, w12, w11 >> 56
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w12 >> 56
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p2_col4
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p2_col4:
        bn.mov w2, w28
        bn.rshi w1, w13, w12 >> 160
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w14, w13 >> 160
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p2_col5
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p2_col5:
        bn.mov w2, w28
        bn.rshi w1, w15, w14 >> 8
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w15 >> 8
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p2_col6
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p2_col6:
        bn.mov w2, w28
        bn.rshi w1, w16, w15 >> 112
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w16 >> 112
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p2_col7
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p2_col7:
        bn.mov w2, w28
        bn.rshi w1, w18, w16 >> 216
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w19, w18 >> 216
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p3_head
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        beq x0, x0, P3_p3_head
    P3_p3_head:
        li x6, 7
        bn.lid x6++, 0(x4)
        bn.lid x6++, 32(x4)
        bn.lid x6++, 64(x4)
        bn.lid x6++, 96(x4)
        bn.lid x6++, 128(x4)
        bn.lid x6++, 160(x4)
        bn.lid x6++, 192(x4)
        bn.lid x6++, 224(x4)
        bn.lid x6++, 256(x4)
        bn.lid x6, 288(x4)          # w16 (skip w17 = msb mask)
        li x6, 18
        bn.lid x6++, 320(x4)
        bn.lid x6++, 352(x4)
        addi x4, x4, 352
        bn.mov w2, w28
        bn.rshi w1, w8, w7 >> 64
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w8 >> 64
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p3_col1
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p3_col1:
        bn.mov w2, w28
        bn.rshi w1, w9, w8 >> 168
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w10, w9 >> 168
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p3_col2
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p3_col2:
        bn.mov w2, w28
        bn.rshi w1, w11, w10 >> 16
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w11 >> 16
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p3_col3
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p3_col3:
        bn.mov w2, w28
        bn.rshi w1, w12, w11 >> 120
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w12 >> 120
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p3_col4
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p3_col4:
        bn.mov w2, w28
        bn.rshi w1, w13, w12 >> 224
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w14, w13 >> 224
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p3_col5
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p3_col5:
        bn.mov w2, w28
        bn.rshi w1, w15, w14 >> 72
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w15 >> 72
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p3_col6
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p3_col6:
        bn.mov w2, w28
        bn.rshi w1, w16, w15 >> 176
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w18, w16 >> 176
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p3_col7
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p3_col7:
        bn.mov w2, w28
        bn.rshi w1, w19, w18 >> 24
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w19 >> 24
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p0_head
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        beq x0, x0, P3_p0_head
    P3_done:
    li x5, 0x20
    bn.sd w21, 0(x5)          /* acc lo -> ctx */
    li x5, 0x40
    bn.sd w22, 0(x5)

/* ============================ FINAL ============================ */
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
    jal  x0, _done
_F_fail:
    li   x6, -1
_done:
    li   x3, 0x000
    sw   x6, 12(x3)           /* result: 0 accept, -1 reject, -2 bad msg_len */
    csrrw x0, mod1, x0
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
    li x17, 45                           # row size const for VxO (vs V-i in VxV)
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
