/*
 * partial_expandP1_table — aestable equivalent of bngfonly's partial_expandP1.
 *
 * Encrypts a col-specific subset of the 22-block AES-CTR stream and packs
 * the result into col-specific WDRs via rshi-reorder. The rshi pattern is
 * preserved verbatim from bngfonly partial_expandP1 (byte-identical AES
 * output between bngfonly aes128_sign and aes128_dualblock).
 *
 * Calling convention:
 *   x18 = rk-base survivor register (caller-managed: caller's local stack
 *         frame holding RKs derived via AES_128_keyschedule; this kernel
 *         reloads x10 from x18 per call and never writes x18)
 *   x25 = col index (0..7)
 *   stack arg at 32(x2) = col_arg (value used to derive starting counter
 *                                  N = 22 * col_arg; caller-conformant with
 *                                  bngfonly contract — caller pre-decrements
 *                                  x2 by 32 and stores col_arg via sw)
 *   x1  = link
 *
 * Output:
 *   WDRs per col path (same as bngfonly partial_expandP1):
 *     col0 -> w1
 *     col1 -> w2, w3 (with w1 also touched)
 *     col2 -> w4, w5 (with w2, w3 also touched)
 *     col3 -> w6, w7
 *     col4 -> w8, w9
 *     col5 -> w10, w11 (with w6, w7 also touched)
 *     col6 -> w12, w13
 *     col7 -> w14, w15
 *
 * Stack: 32 B internal (+ 32 B caller's col_arg = 64 B total reclaimed at ret).
 *
 * Counter layout per col (starting from N = 22 * col_arg):
 *   col0: skip 0,  encrypt 4 counters {N..N+3}
 *   col1: skip 2,  encrypt 4 counters {N+2..N+5}
 *   col2: skip 4,  encrypt 6 counters {N+4..N+9}
 *   col3: skip 8,  encrypt 4 counters {N+8..N+11}
 *   col4: skip 10, encrypt 4 counters {N+10..N+13}
 *   col5: skip 12, encrypt 6 counters {N+12..N+17}
 *   col6: skip 16, encrypt 4 counters {N+16..N+19}
 *   col7: skip 18, encrypt 4 counters {N+18..N+21}
 *
 * Total counter range across all cols matches expand_352_table's 22 blocks.
 */
.section .text
.balign 4
.global partial_expandP1_table
partial_expandP1_table:
    /* Save all AES-clobbered GPRs that gf256trimat depends on.
     * aes128_dualblock internally calls AES_128_encrypt (clobbers x5..x8,
     * x13..x16, x19..x22, x29, x31) and itself uses x9 as counter snapshot.
     * gf256trimat needs preserved: x5, x6, x7, x8, x9, x20, x21, x31.
     * (x11, x12 are preserved by aes128_dualblock itself.) */
    addi x2, x2, -32
    sw x5, 0(x2)
    sw x6, 4(x2)
    sw x7, 8(x2)
    sw x8, 12(x2)
    sw x9, 16(x2)
    sw x20, 20(x2)
    sw x21, 24(x2)
    sw x31, 28(x2)

    /* Compute starting counter N = 22 * col_arg (col_arg at 32(x2)). */
    lw x6, 32(x2)
    slli x7, x6, 4                  /* 16 * col_arg */
    slli x13, x6, 1                 /* 2 * col_arg */
    add x13, x13, x7                /* 18 * col_arg */
    slli x7, x6, 2                  /* 4 * col_arg */
    add x13, x13, x7                /* x13 = 22 * col_arg = N */

    /* Restore rk base into x10 (aes128_dualblock expects x10 = rk). */
    addi x10, x18, 0

    /* Col dispatch */
    beq x0, x25, col0_t
    li x6, 1
    beq x6, x25, col1_t
    li x6, 2
    beq x6, x25, col2_t
    li x6, 3
    beq x6, x25, col3_t
    li x6, 4
    beq x6, x25, col4_t
    li x6, 5
    beq x6, x25, col5_t
    li x6, 6
    beq x6, x25, col6_t

col7_t:
    /* skip to IV(9): N+18; encrypt ct(N+18,N+19) and ct(N+20,N+21) -> w14, w15 */
    addi x13, x13, 18
    addi x10, x18, 0
    jal x1, aes128_dualblock        /* w2 = ct(9) */
    bn.mov w3, w2                   /* temp */
    addi x10, x18, 0
    jal x1, aes128_dualblock        /* w2 = ct(10) */
    bn.mov w10, w2                  /* w10 = ct(10) */
    bn.mov w9, w3                   /* w9 = ct(9) */
    bn.rshi w15, w31, w10 >> 160
    bn.rshi w14, w10, w9 >> 160
    beq x0, x0, partial_expandP1_table_epilogue

col6_t:
    /* skip 16; encrypt ct(8) and ct(9) -> w12, w13 */
    addi x13, x13, 16
    addi x10, x18, 0
    jal x1, aes128_dualblock        /* w2 = ct(8) */
    bn.mov w3, w2
    addi x10, x18, 0
    jal x1, aes128_dualblock        /* w2 = ct(9) */
    bn.mov w9, w2                   /* w9 = ct(9) */
    bn.mov w8, w3                   /* w8 = ct(8) */
    bn.rshi w13, w9, w31 >> 160
    bn.rshi w13, w31, w13 >> 160
    bn.rshi w12, w9, w8 >> 64
    beq x0, x0, partial_expandP1_table_epilogue

col5_t:
    /* skip 12; encrypt ct(6), ct(7), ct(8) -> w10, w11 */
    addi x13, x13, 12
    addi x10, x18, 0
    jal x1, aes128_dualblock        /* w2 = ct(6) */
    bn.mov w3, w2
    addi x10, x18, 0
    jal x1, aes128_dualblock        /* w2 = ct(7) */
    bn.mov w4, w2
    addi x10, x18, 0
    jal x1, aes128_dualblock        /* w2 = ct(8) */
    bn.mov w8, w2                   /* w8 = ct(8) */
    bn.mov w7, w4                   /* w7 = ct(7) */
    bn.mov w6, w3                   /* w6 = ct(6) */
    bn.rshi w11, w8, w7 >> 64
    bn.rshi w11, w31, w11 >> 160
    bn.rshi w10, w7, w6 >> 224
    beq x0, x0, partial_expandP1_table_epilogue

col4_t:
    /* skip 10; encrypt ct(5) and ct(6) -> w8, w9 */
    addi x13, x13, 10
    addi x10, x18, 0
    jal x1, aes128_dualblock        /* w2 = ct(5) */
    bn.mov w3, w2
    addi x10, x18, 0
    jal x1, aes128_dualblock        /* w2 = ct(6) */
    bn.mov w6, w2                   /* w6 = ct(6) */
    bn.mov w5, w3                   /* w5 = ct(5) */
    bn.rshi w9, w6, w31 >> 224
    bn.rshi w9, w31, w9 >> 160
    bn.rshi w8, w6, w5 >> 128
    beq x0, x0, partial_expandP1_table_epilogue

col3_t:
    /* skip 8; encrypt ct(4) and ct(5) -> w6, w7 */
    addi x13, x13, 8
    addi x10, x18, 0
    jal x1, aes128_dualblock        /* w2 = ct(4) */
    bn.mov w3, w2
    addi x10, x18, 0
    jal x1, aes128_dualblock        /* w2 = ct(5) */
    bn.mov w5, w2                   /* w5 = ct(5) */
    bn.mov w4, w3                   /* w4 = ct(4) */
    bn.rshi w7, w5, w31 >> 128
    bn.rshi w7, w31, w7 >> 160
    bn.rshi w6, w5, w4 >> 32
    beq x0, x0, partial_expandP1_table_epilogue

col2_t:
    /* skip 4; encrypt ct(2), ct(3), ct(4) -> w4, w5 (with w2, w3 also set) */
    addi x13, x13, 4
    addi x10, x18, 0
    jal x1, aes128_dualblock        /* w2 = ct(2) */
    bn.mov w3, w2
    addi x10, x18, 0
    jal x1, aes128_dualblock        /* w2 = ct(3) */
    bn.mov w5, w2
    addi x10, x18, 0
    jal x1, aes128_dualblock        /* w2 = ct(4) */
    bn.mov w4, w2                   /* w4 = ct(4) */
    bn.mov w2, w3                   /* w2 = ct(2) */
    bn.mov w3, w5                   /* w3 = ct(3) */
    bn.rshi w5, w4, w3 >> 32
    bn.rshi w5, w31, w5 >> 160
    bn.rshi w4, w3, w2 >> 192
    beq x0, x0, partial_expandP1_table_epilogue

col1_t:
    /* skip 2; encrypt ct(1) and ct(2) -> w2, w3 (with w1 also set) */
    addi x13, x13, 2
    addi x10, x18, 0
    jal x1, aes128_dualblock        /* w2 = ct(1) */
    bn.mov w3, w2
    addi x10, x18, 0
    jal x1, aes128_dualblock        /* w2 = ct(2) */
    /* w2 = ct(2), w3 = ct(1) */
    bn.mov w1, w3                   /* w1 = ct(1) */
    bn.rshi w3, w2, w31 >> 192
    bn.rshi w3, w31, w3 >> 160
    bn.rshi w2, w2, w1 >> 96
    beq x0, x0, partial_expandP1_table_epilogue

col0_t:
    /* no skip; encrypt ct(0) and ct(1) -> w1 */
    addi x10, x18, 0
    jal x1, aes128_dualblock        /* w2 = ct(0) */
    bn.mov w0, w2                   /* w0 = ct(0) (used by rshi reorder) */
    addi x10, x18, 0
    jal x1, aes128_dualblock        /* w2 = ct(1) */
    bn.mov w1, w2                   /* w1 = ct(1) */
    bn.rshi w1, w1, w31 >> 96
    bn.rshi w1, w31, w1 >> 160
    /* fall through */

partial_expandP1_table_epilogue:
    lw x5, 0(x2)
    lw x6, 4(x2)
    lw x7, 8(x2)
    lw x8, 12(x2)
    lw x9, 16(x2)
    lw x20, 20(x2)
    lw x21, 24(x2)
    lw x31, 28(x2)
    addi x2, x2, 64                 /* 32 internal + 32 caller's col_arg slot */
    ret
