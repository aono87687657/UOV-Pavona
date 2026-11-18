.section .text
.global P1O_P2
.balign 4
/* P1O_P2 (Ip3, bngfaes): B = P1*O + P2 over GF(256), V=74, O=M=45.
 * P2 is streamed straight into B, then each P1 row r is re-expanded and
 * B[r][j] ^= sum_{k>=r} P1[r][k] * O[k][j] in place. Lo 32B in ACC (.acc),
 * hi 13B in ACCH (.acch.inc); .acc reads the mod1 cursor before .acch.inc
 * advances it.
 * in:  x10 = B out, 74x45 cells of 64B (213,120B), cell (i,j) at 64*(45i+j)
 *      x11 = pk_seed (AES-128 key, 32B-aligned, high half zero)
 *      x12 = O, 45 cols x 96B (3 WDRs, rows 74..95 zero)
 * out: B; every cell 45B + 19 zero bytes
 * clob: x3, x6-x11, x13-x16, x20, x21, x23-x31; w0-w31 except w16, w17;
 *   ACC, ACCH, FG0; mod0 = 0x11b, mod1 = 0 on exit. x2 restored.
 * stack: 5,664B = frame 32 | p1buf 5120 (10 batches) | p2buf 512 (1 batch).
 * frame: 16 O, 20 p1buf, 24 p2buf, 28 P1 row read ptr. call depth 3 below
 *   this one (phase4_row_setup > expand_batch > expand_360).
 */
P1O_P2:
    bn.xor w31, w31, w31
    li x31, 0x11b
    csrrw x0, mod0, x31

    addi x2, x2, -32
    add x3, x0, x2
    sw x12, 16(x3)
    li x30, 5120
    sub x2, x2, x30
    sw x2, 20(x3)                           # p1buf
    addi x2, x2, -512
    sw x2, 24(x3)                           # p2buf

    # AES-128 key schedule: w30 = RK0, w29..w20 = RK1..RK10
    li x31, 30
    bn.lid x31, 0(x11)
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

    # IV increment (w19): +2 blocks per dual
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160

    li x23, 6                               # w6 P1 lo
    li x24, 7                               # w7 P1 hi
    li x25, 8                               # w8 result lo
    li x6,  9                               # w9 result hi
    li x26, 3                               # w3 O col [0:31]
    li x27, 4                               # w4 O col [32:63]
    li x28, 5                               # w5 O col [64:73]

    # P2 into B. Stream entry 2775 + 45i + j is cell (i,j): batch 346 slot 7
    # is cell 0, batches 347..762 are cells 1..3328 in place, batch 763 slot 0
    # is cell 3329. One seek; IV and phase carry through the rest.
    lw   x8, 24(x3)
    li   x29, 7785                          # block counter of batch 346 = 346*45/2
    bn.sd w31, 0(x8)
    sw   x29, 0(x8)
    bn.ld w14, 0(x8)
    bn.addi w18, w14, 1
    bn.or   w18, w14, w18 << 128
    bn.rshi w18, w18, w31 >> 160
    li   x16, 0                             # window phase = batch & 1
    add  x11, x0, x8
    jal  x1, expand_batch
    bn.ld w0, 448(x8)
    bn.ld w1, 480(x8)
    bn.sd w0, 0(x10)
    bn.sd w1, 32(x10)
    addi x11, x10, 64
    loopi 416, 2
        jal x1, expand_batch
        nop
    add  x29, x0, x11                       # B + 213056 = cell 3329
    add  x11, x0, x8
    jal  x1, expand_batch
    bn.ld w0, 0(x8)
    bn.ld w1, 32(x8)
    bn.sd w0, 0(x29)
    bn.sd w1, 32(x29)

    # P1*O, one row per iteration; row r starts its dot product at O[r].
    # x7 = row, x9 = running P1 entry index, x10 = B[r][0] (walks all of B).
    li x9, 0
    li x7, 0

    # rows 0..31: w3[r..31], w4, w5[0..9]
    loopi 32, 37
        jal  x1, phase4_row_setup           # x8 = 74-r, x13 = O, 28(x3) = P1 row
        lw   x15, 28(x3)
        addi x20, x8, -42                   # 32-r
        loopi 45, 29
            bn.lid x26, 0(x13++)
            bn.lid x27, 0(x13++)
            bn.lid x28, 0(x13++)
            bn.wsrw acc, w31
            bn.wsrw acch, w31
            add x14, x0, x15
            csrrw x0, mod1, x7
            loop x20, 4
                bn.lid x23, 0(x14++)
                bn.lid x24, 0(x14++)
                bn.gfmul.8.acc w8, w6, w3
                bn.gfmul.8.acch.inc w9, w7, w3
            loopi 32, 4                     # cursor wrapped to 0
                bn.lid x23, 0(x14++)
                bn.lid x24, 0(x14++)
                bn.gfmul.8.acc w8, w6, w4
                bn.gfmul.8.acch.inc w9, w7, w4
            loopi 10, 4
                bn.lid x23, 0(x14++)
                bn.lid x24, 0(x14++)
                bn.gfmul.8.acc w8, w6, w5
                bn.gfmul.8.acch.inc w9, w7, w5
            bn.lid x23, 0(x10)              # B ^= P1*O, in place
            bn.lid x24, 32(x10)
            bn.xor w8, w8, w6
            bn.xor w9, w9, w7
            bn.sid x25, 0(x10)
            bn.sid x6, 32(x10)
            addi x10, x10, 64
        li   x8, 74
        sub  x8, x8, x7
        add  x9, x9, x8
        addi x7, x7, 1

    # rows 32..63: w4[r-32..31], w5[0..9]
    loopi 32, 33
        jal  x1, phase4_row_setup
        lw   x15, 28(x3)
        addi x21, x7, -32
        addi x20, x8, -10                   # 64-r
        loopi 45, 24
            bn.lid x26, 0(x13++)
            bn.lid x27, 0(x13++)
            bn.lid x28, 0(x13++)
            bn.wsrw acc, w31
            bn.wsrw acch, w31
            add x14, x0, x15
            csrrw x0, mod1, x21
            loop x20, 4
                bn.lid x23, 0(x14++)
                bn.lid x24, 0(x14++)
                bn.gfmul.8.acc w8, w6, w4
                bn.gfmul.8.acch.inc w9, w7, w4
            loopi 10, 4                     # cursor wrapped to 0
                bn.lid x23, 0(x14++)
                bn.lid x24, 0(x14++)
                bn.gfmul.8.acc w8, w6, w5
                bn.gfmul.8.acch.inc w9, w7, w5
            bn.lid x23, 0(x10)
            bn.lid x24, 32(x10)
            bn.xor w8, w8, w6
            bn.xor w9, w9, w7
            bn.sid x25, 0(x10)
            bn.sid x6, 32(x10)
            addi x10, x10, 64
        li   x8, 74
        sub  x8, x8, x7
        add  x9, x9, x8
        addi x7, x7, 1

    # rows 64..73: w5[r-64..9]
    loopi 10, 27
        jal  x1, phase4_row_setup
        lw   x15, 28(x3)
        addi x21, x7, -64
        loopi 45, 19
            bn.lid x26, 0(x13++)
            bn.lid x27, 0(x13++)
            bn.lid x28, 0(x13++)
            bn.wsrw acc, w31
            bn.wsrw acch, w31
            add x14, x0, x15
            csrrw x0, mod1, x21
            loop x8, 4                      # 74-r
                bn.lid x23, 0(x14++)
                bn.lid x24, 0(x14++)
                bn.gfmul.8.acc w8, w6, w5
                bn.gfmul.8.acch.inc w9, w7, w5
            bn.lid x23, 0(x10)
            bn.lid x24, 32(x10)
            bn.xor w8, w8, w6
            bn.xor w9, w9, w7
            bn.sid x25, 0(x10)
            bn.sid x6, 32(x10)
            addi x10, x10, 64
        li   x8, 74
        sub  x8, x8, x7
        add  x9, x9, x8
        addi x7, x7, 1

    csrrw x0, mod1, x0

    addi x2, x3, 32
    ret

/* expand_batch: expand_360 -> 8 x 64B entries at x11.
 * in: w18 IV, w19 inc, w20..w30 RKs, w31 = 0, x16 phase, x11 dst.
 * out: x11 += 512, w18/x16 advanced. clob: w0-w15, FG0. */
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

/* phase4_row_setup: seek the P1 stream to entry x9 and expand row x7
 * (74-r entries) into p1buf. out: x8 = 74-r, x13 = O base,
 * 28(x3) = first entry of the row in p1buf.
 * clob: x8, x11, x13-x16, x29, x30; w0-w15, w18, FG0. */
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
    srli x30, x30, 1                        # block counter = batch*45/2
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
    srli x8, x8, 3                          # batches covering the row
    lw   x11, 20(x3)
    loop x8, 2
        jal x1, expand_batch
        nop
    lw   x14, 20(x3)
    slli x29, x15, 6
    add  x14, x14, x29
    sw   x14, 28(x3)
    li   x8, 74
    sub  x8, x8, x7
    lw   x13, 16(x3)
    ret
