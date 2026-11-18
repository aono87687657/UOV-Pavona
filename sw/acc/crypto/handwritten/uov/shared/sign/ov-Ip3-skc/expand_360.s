/* expand_360 (Ip3) - 8 P1 entries (45 B each) for the P1 expansion stream.
 *
 *   variant     cpp flag                                  body
 *   bngfonly    -DGF_INSTRUCTIONS                         12 sequential aes128_sign jal calls + stack buffer
 *   bngfaes     -DAES_INSTRUCTIONS|GF_INSTRUCTIONS        12 inline bn.aes128.encz/encm/encf streams
 *
 * Swonly tier uses a separately-named kernel `expand_360_table.s` (different signature).
 *
 * 8 x 45 B = 360 B is not a whole number of dual blocks, so a call encrypts 12
 * duals (384 B) and takes its 360-B window at byte 8*phase. Phases run 0,8,16,24
 * and the IV advances 11,11,11,12 duals, so four calls cover 45 duals with no
 * drift and every call is self-contained: nothing but the phase crosses a call.
 *
 * Caller pre-loads w18=IV, w19=IV-inc, w30=RK0, w31=0, x16=phase, and RK1..RK10 in
 * the order its arm consumes them: bngfaes w29..w20 (descending, as the caller's kf
 * chain assigns them), bngfonly w20..w29 forward AND every key dual-stored K|K -
 * aes128_sign XORs all 256 bits, so a low-half-only key silently corrupts the
 * second block.
 * Output: w0..w15 = 8 P1 entries, entry k = (w2k, w2k+1) with the top 19 B of the
 * odd WDR zero; w18 advanced; x16 = next phase.
 */

.section .text
.balign 4
.global expand_360
#if defined(AES_INSTRUCTIONS)

/* =============== bngfaes (inline HW bn.aes128.*) =============== */
expand_360:
    # Assumes: w30 = RK0, w29..w20 = RK1..RK10 (descending, per the caller's kf chain)
    #          w19 = IV increment, w18 = current IV, w31 = zero, x16 = phase 0..3
    # Output: 8 entries in w0/w1..w14/w15, Clobbers: w0-w15, w18, x16

    bn.mov w0, w18
    bn.add w1, w0, w19
    bn.add w2, w1, w19
    bn.add w3, w2, w19
    bn.add w4, w3, w19
    bn.add w5, w4, w19
    bn.add w6, w5, w19
    bn.add w7, w6, w19
    bn.add w8, w7, w19
    bn.add w9, w8, w19
    bn.add w10, w9, w19
    bn.add w11, w10, w19
    bn.add w18, w11, w19             # IV + 12 duals; phases 0-2 give one back

    bn.aes128.encz.swap w0, w0, w30
    bn.aes128.encz.swap w1, w1, w30
    bn.aes128.encz.swap w2, w2, w30
    bn.aes128.encz.swap w3, w3, w30
    bn.aes128.encz.swap w4, w4, w30
    bn.aes128.encz.swap w5, w5, w30
    bn.aes128.encz.swap w6, w6, w30
    bn.aes128.encz.swap w7, w7, w30
    bn.aes128.encz.swap w8, w8, w30
    bn.aes128.encz.swap w9, w9, w30
    bn.aes128.encz.swap w10, w10, w30
    bn.aes128.encz.swap w11, w11, w30
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
    bn.aes128.encm w11, w11, w29
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
    bn.aes128.encm w11, w11, w28
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
    bn.aes128.encm w11, w11, w27
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
    bn.aes128.encm w11, w11, w26
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
    bn.aes128.encm w11, w11, w25
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
    bn.aes128.encm w11, w11, w24
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
    bn.aes128.encm w11, w11, w23
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
    bn.aes128.encm w11, w11, w22
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
    bn.aes128.encm w11, w11, w21
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
    bn.aes128.encf w11, w11, w20

    # phase dispatch: x16 = 0..3 in, next phase out
    beq x16, x0, exp360_p0
    addi x16, x16, -1
    beq x16, x0, exp360_p1
    addi x16, x16, -1
    beq x16, x0, exp360_p2

    # phase 3: window at buffer byte 24
    # entry 7 @ buf 339 (wdr 10 byte 19)
    bn.rshi w15, w31, w11 >> 152
    bn.rshi w14, w11, w10 >> 152
    # entry 6 @ buf 294 (wdr 9 byte 6)
    bn.rshi w13, w10, w31 >> 152
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w12, w10, w9 >> 48
    # entry 5 @ buf 249 (wdr 7 byte 25)
    bn.rshi w11, w9, w8 >> 48
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w10, w8, w7 >> 200
    # entry 4 @ buf 204 (wdr 6 byte 12)
    bn.rshi w9, w7, w31 >> 200
    bn.rshi w9, w31, w9 >> 152
    bn.rshi w8, w7, w6 >> 96
    # entry 3 @ buf 159 (wdr 4 byte 31)
    bn.rshi w7, w6, w5 >> 96
    bn.rshi w7, w31, w7 >> 152
    bn.rshi w6, w5, w4 >> 248
    # entry 2 @ buf 114 (wdr 3 byte 18)
    bn.rshi w5, w4, w31 >> 248
    bn.rshi w5, w31, w5 >> 152
    bn.rshi w4, w4, w3 >> 144
    # entry 0 @ buf 24 (wdr 0 byte 24)
    bn.rshi w0, w1, w0 >> 192
    bn.rshi w1, w2, w1 >> 40
    bn.rshi w1, w31, w1 >> 152
    # entry 1 @ buf 69 (wdr 2 byte 5)
    bn.rshi w2, w3, w2 >> 40
    bn.rshi w3, w3, w31 >> 144
    bn.rshi w3, w31, w3 >> 152
    li x16, 0
    ret

exp360_p0:
    # phase 0: window at buffer byte 0
    bn.sub w18, w18, w19
    # entry 7 @ buf 315 (wdr 9 byte 27)
    bn.rshi w15, w11, w10 >> 64
    bn.rshi w15, w31, w15 >> 152
    bn.rshi w14, w10, w9 >> 216
    # entry 6 @ buf 270 (wdr 8 byte 14)
    bn.rshi w13, w9, w31 >> 216
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w12, w9, w8 >> 112
    # entry 5 @ buf 225 (wdr 7 byte 1)
    bn.rshi w11, w8, w31 >> 112
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w10, w8, w7 >> 8
    # entry 4 @ buf 180 (wdr 5 byte 20)
    bn.rshi w9, w7, w6 >> 8
    bn.rshi w9, w31, w9 >> 152
    bn.rshi w8, w6, w5 >> 160
    # entry 3 @ buf 135 (wdr 4 byte 7)
    bn.rshi w7, w5, w31 >> 160
    bn.rshi w7, w31, w7 >> 152
    bn.rshi w6, w5, w4 >> 56
    # entry 2 @ buf 90 (wdr 2 byte 26)
    bn.rshi w5, w4, w3 >> 56
    bn.rshi w5, w31, w5 >> 152
    bn.rshi w4, w3, w2 >> 208
    # entry 1 @ buf 45 (wdr 1 byte 13)
    bn.rshi w3, w2, w31 >> 208
    bn.rshi w3, w31, w3 >> 152
    bn.rshi w2, w2, w1 >> 104
    # entry 0 @ buf 0 (wdr 0 byte 0)
    bn.rshi w1, w1, w31 >> 104
    bn.rshi w1, w31, w1 >> 152
    li x16, 1
    ret

exp360_p1:
    # phase 1: window at buffer byte 8
    bn.sub w18, w18, w19
    # entry 7 @ buf 323 (wdr 10 byte 3)
    bn.rshi w15, w11, w31 >> 128
    bn.rshi w15, w31, w15 >> 152
    bn.rshi w14, w11, w10 >> 24
    # entry 6 @ buf 278 (wdr 8 byte 22)
    bn.rshi w13, w10, w9 >> 24
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w12, w9, w8 >> 176
    # entry 5 @ buf 233 (wdr 7 byte 9)
    bn.rshi w11, w8, w31 >> 176
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w10, w8, w7 >> 72
    # entry 4 @ buf 188 (wdr 5 byte 28)
    bn.rshi w9, w7, w6 >> 72
    bn.rshi w9, w31, w9 >> 152
    bn.rshi w8, w6, w5 >> 224
    # entry 3 @ buf 143 (wdr 4 byte 15)
    bn.rshi w7, w5, w31 >> 224
    bn.rshi w7, w31, w7 >> 152
    bn.rshi w6, w5, w4 >> 120
    # entry 2 @ buf 98 (wdr 3 byte 2)
    bn.rshi w5, w4, w31 >> 120
    bn.rshi w5, w31, w5 >> 152
    bn.rshi w4, w4, w3 >> 16
    # entry 1 @ buf 53 (wdr 1 byte 21)
    bn.rshi w3, w3, w2 >> 16
    bn.rshi w3, w31, w3 >> 152
    bn.rshi w2, w2, w1 >> 168
    # entry 0 @ buf 8 (wdr 0 byte 8)
    bn.rshi w0, w1, w0 >> 64
    bn.rshi w1, w1, w31 >> 168
    bn.rshi w1, w31, w1 >> 152
    li x16, 2
    ret

exp360_p2:
    # phase 2: window at buffer byte 16
    bn.sub w18, w18, w19
    # entry 7 @ buf 331 (wdr 10 byte 11)
    bn.rshi w15, w11, w31 >> 192
    bn.rshi w15, w31, w15 >> 152
    bn.rshi w14, w11, w10 >> 88
    # entry 6 @ buf 286 (wdr 8 byte 30)
    bn.rshi w13, w10, w9 >> 88
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w12, w9, w8 >> 240
    # entry 5 @ buf 241 (wdr 7 byte 17)
    bn.rshi w11, w8, w31 >> 240
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w10, w8, w7 >> 136
    # entry 4 @ buf 196 (wdr 6 byte 4)
    bn.rshi w9, w7, w31 >> 136
    bn.rshi w9, w31, w9 >> 152
    bn.rshi w8, w7, w6 >> 32
    # entry 3 @ buf 151 (wdr 4 byte 23)
    bn.rshi w7, w6, w5 >> 32
    bn.rshi w7, w31, w7 >> 152
    bn.rshi w6, w5, w4 >> 184
    # entry 2 @ buf 106 (wdr 3 byte 10)
    bn.rshi w5, w4, w31 >> 184
    bn.rshi w5, w31, w5 >> 152
    bn.rshi w4, w4, w3 >> 80
    # entry 1 @ buf 61 (wdr 1 byte 29)
    bn.rshi w3, w3, w2 >> 80
    bn.rshi w3, w31, w3 >> 152
    bn.rshi w2, w2, w1 >> 232
    # entry 0 @ buf 16 (wdr 0 byte 16)
    bn.rshi w0, w1, w0 >> 128
    bn.rshi w1, w1, w31 >> 232
    bn.rshi w1, w31, w1 >> 152
    li x16, 3
    ret


#else

/* =============== bngfonly (jal aes128_sign + stack buffer) =============== */
expand_360:
    # Save caller's x5, x6 (clobbered by la/li below; gf256trimat needs both).
    # AES buffer at offsets 0..383 (12 x 32 B), x5/x6 saved at 384/388.
    addi x2, x2, -448
    sw x5, 384(x2)
    sw x6, 388(x2)

    # Reload the AES constants: the extraction blocks below leave P1-entry
    # data in w7/w8/w9, and the caller invokes expand_360 many times.
    la x5, byte_swap_mask
    li x6, 7
    bn.lid x6, 0(x5)
    la x5, affine_value
    li x6, 8
    bn.lid x6, 0(x5)
    la x5, msb_mask
    li x6, 9
    bn.lid x6, 0(x5)

    # x17 for bn.sid/lid: x8 belongs to the gf256trimat caller, x6 to
    # several others; batch_quad reloads x17 after expand_360 returns.
    li x17, 2                        # w2 = aes128_sign output

    # ---- 12 sequential AES-CTR ciphertexts to stack ----
    jal x1, aes128_sign
    bn.sid x17, 0(x2)
    bn.add w18, w18, w19
    jal x1, aes128_sign
    bn.sid x17, 32(x2)
    bn.add w18, w18, w19
    jal x1, aes128_sign
    bn.sid x17, 64(x2)
    bn.add w18, w18, w19
    jal x1, aes128_sign
    bn.sid x17, 96(x2)
    bn.add w18, w18, w19
    jal x1, aes128_sign
    bn.sid x17, 128(x2)
    bn.add w18, w18, w19
    jal x1, aes128_sign
    bn.sid x17, 160(x2)
    bn.add w18, w18, w19
    jal x1, aes128_sign
    bn.sid x17, 192(x2)
    bn.add w18, w18, w19
    jal x1, aes128_sign
    bn.sid x17, 224(x2)
    bn.add w18, w18, w19
    jal x1, aes128_sign
    bn.sid x17, 256(x2)
    bn.add w18, w18, w19
    jal x1, aes128_sign
    bn.sid x17, 288(x2)
    bn.add w18, w18, w19
    jal x1, aes128_sign
    bn.sid x17, 320(x2)
    bn.add w18, w18, w19
    jal x1, aes128_sign
    bn.sid x17, 352(x2)
    bn.add w18, w18, w19

    # ---- load the 12 CTs back into w0..w11 ----
    li x17, 0
    bn.lid x17, 0(x2)
    addi x17, x17, 1
    bn.lid x17, 32(x2)
    addi x17, x17, 1
    bn.lid x17, 64(x2)
    addi x17, x17, 1
    bn.lid x17, 96(x2)
    addi x17, x17, 1
    bn.lid x17, 128(x2)
    addi x17, x17, 1
    bn.lid x17, 160(x2)
    addi x17, x17, 1
    bn.lid x17, 192(x2)
    addi x17, x17, 1
    bn.lid x17, 224(x2)
    addi x17, x17, 1
    bn.lid x17, 256(x2)
    addi x17, x17, 1
    bn.lid x17, 288(x2)
    addi x17, x17, 1
    bn.lid x17, 320(x2)
    addi x17, x17, 1
    bn.lid x17, 352(x2)

    # Restore caller's x5, x6 and free stack before the phase blocks
    lw x5, 384(x2)
    lw x6, 388(x2)
    addi x2, x2, 448

    # phase dispatch: x16 = 0..3 in, next phase out
    beq x16, x0, exp360_p0
    addi x16, x16, -1
    beq x16, x0, exp360_p1
    addi x16, x16, -1
    beq x16, x0, exp360_p2

    # phase 3: window at buffer byte 24
    # entry 7 @ buf 339 (wdr 10 byte 19)
    bn.rshi w15, w31, w11 >> 152
    bn.rshi w14, w11, w10 >> 152
    # entry 6 @ buf 294 (wdr 9 byte 6)
    bn.rshi w13, w10, w31 >> 152
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w12, w10, w9 >> 48
    # entry 5 @ buf 249 (wdr 7 byte 25)
    bn.rshi w11, w9, w8 >> 48
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w10, w8, w7 >> 200
    # entry 4 @ buf 204 (wdr 6 byte 12)
    bn.rshi w9, w7, w31 >> 200
    bn.rshi w9, w31, w9 >> 152
    bn.rshi w8, w7, w6 >> 96
    # entry 3 @ buf 159 (wdr 4 byte 31)
    bn.rshi w7, w6, w5 >> 96
    bn.rshi w7, w31, w7 >> 152
    bn.rshi w6, w5, w4 >> 248
    # entry 2 @ buf 114 (wdr 3 byte 18)
    bn.rshi w5, w4, w31 >> 248
    bn.rshi w5, w31, w5 >> 152
    bn.rshi w4, w4, w3 >> 144
    # entry 0 @ buf 24 (wdr 0 byte 24)
    bn.rshi w0, w1, w0 >> 192
    bn.rshi w1, w2, w1 >> 40
    bn.rshi w1, w31, w1 >> 152
    # entry 1 @ buf 69 (wdr 2 byte 5)
    bn.rshi w2, w3, w2 >> 40
    bn.rshi w3, w3, w31 >> 144
    bn.rshi w3, w31, w3 >> 152
    li x16, 0
    ret

exp360_p0:
    # phase 0: window at buffer byte 0
    bn.sub w18, w18, w19
    # entry 7 @ buf 315 (wdr 9 byte 27)
    bn.rshi w15, w11, w10 >> 64
    bn.rshi w15, w31, w15 >> 152
    bn.rshi w14, w10, w9 >> 216
    # entry 6 @ buf 270 (wdr 8 byte 14)
    bn.rshi w13, w9, w31 >> 216
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w12, w9, w8 >> 112
    # entry 5 @ buf 225 (wdr 7 byte 1)
    bn.rshi w11, w8, w31 >> 112
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w10, w8, w7 >> 8
    # entry 4 @ buf 180 (wdr 5 byte 20)
    bn.rshi w9, w7, w6 >> 8
    bn.rshi w9, w31, w9 >> 152
    bn.rshi w8, w6, w5 >> 160
    # entry 3 @ buf 135 (wdr 4 byte 7)
    bn.rshi w7, w5, w31 >> 160
    bn.rshi w7, w31, w7 >> 152
    bn.rshi w6, w5, w4 >> 56
    # entry 2 @ buf 90 (wdr 2 byte 26)
    bn.rshi w5, w4, w3 >> 56
    bn.rshi w5, w31, w5 >> 152
    bn.rshi w4, w3, w2 >> 208
    # entry 1 @ buf 45 (wdr 1 byte 13)
    bn.rshi w3, w2, w31 >> 208
    bn.rshi w3, w31, w3 >> 152
    bn.rshi w2, w2, w1 >> 104
    # entry 0 @ buf 0 (wdr 0 byte 0)
    bn.rshi w1, w1, w31 >> 104
    bn.rshi w1, w31, w1 >> 152
    li x16, 1
    ret

exp360_p1:
    # phase 1: window at buffer byte 8
    bn.sub w18, w18, w19
    # entry 7 @ buf 323 (wdr 10 byte 3)
    bn.rshi w15, w11, w31 >> 128
    bn.rshi w15, w31, w15 >> 152
    bn.rshi w14, w11, w10 >> 24
    # entry 6 @ buf 278 (wdr 8 byte 22)
    bn.rshi w13, w10, w9 >> 24
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w12, w9, w8 >> 176
    # entry 5 @ buf 233 (wdr 7 byte 9)
    bn.rshi w11, w8, w31 >> 176
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w10, w8, w7 >> 72
    # entry 4 @ buf 188 (wdr 5 byte 28)
    bn.rshi w9, w7, w6 >> 72
    bn.rshi w9, w31, w9 >> 152
    bn.rshi w8, w6, w5 >> 224
    # entry 3 @ buf 143 (wdr 4 byte 15)
    bn.rshi w7, w5, w31 >> 224
    bn.rshi w7, w31, w7 >> 152
    bn.rshi w6, w5, w4 >> 120
    # entry 2 @ buf 98 (wdr 3 byte 2)
    bn.rshi w5, w4, w31 >> 120
    bn.rshi w5, w31, w5 >> 152
    bn.rshi w4, w4, w3 >> 16
    # entry 1 @ buf 53 (wdr 1 byte 21)
    bn.rshi w3, w3, w2 >> 16
    bn.rshi w3, w31, w3 >> 152
    bn.rshi w2, w2, w1 >> 168
    # entry 0 @ buf 8 (wdr 0 byte 8)
    bn.rshi w0, w1, w0 >> 64
    bn.rshi w1, w1, w31 >> 168
    bn.rshi w1, w31, w1 >> 152
    li x16, 2
    ret

exp360_p2:
    # phase 2: window at buffer byte 16
    bn.sub w18, w18, w19
    # entry 7 @ buf 331 (wdr 10 byte 11)
    bn.rshi w15, w11, w31 >> 192
    bn.rshi w15, w31, w15 >> 152
    bn.rshi w14, w11, w10 >> 88
    # entry 6 @ buf 286 (wdr 8 byte 30)
    bn.rshi w13, w10, w9 >> 88
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w12, w9, w8 >> 240
    # entry 5 @ buf 241 (wdr 7 byte 17)
    bn.rshi w11, w8, w31 >> 240
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w10, w8, w7 >> 136
    # entry 4 @ buf 196 (wdr 6 byte 4)
    bn.rshi w9, w7, w31 >> 136
    bn.rshi w9, w31, w9 >> 152
    bn.rshi w8, w7, w6 >> 32
    # entry 3 @ buf 151 (wdr 4 byte 23)
    bn.rshi w7, w6, w5 >> 32
    bn.rshi w7, w31, w7 >> 152
    bn.rshi w6, w5, w4 >> 184
    # entry 2 @ buf 106 (wdr 3 byte 10)
    bn.rshi w5, w4, w31 >> 184
    bn.rshi w5, w31, w5 >> 152
    bn.rshi w4, w4, w3 >> 80
    # entry 1 @ buf 61 (wdr 1 byte 29)
    bn.rshi w3, w3, w2 >> 80
    bn.rshi w3, w31, w3 >> 152
    bn.rshi w2, w2, w1 >> 232
    # entry 0 @ buf 16 (wdr 0 byte 16)
    bn.rshi w0, w1, w0 >> 128
    bn.rshi w1, w1, w31 >> 232
    bn.rshi w1, w31, w1 >> 152
    li x16, 3
    ret

#endif

