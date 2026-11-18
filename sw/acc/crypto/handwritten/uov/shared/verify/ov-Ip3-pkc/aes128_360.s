/* aes128_360 (Ip3 verify, bngfaes): 12 dual-block AES-128-CTR fetch (384B
 * keystream) via bn.aes128 encz.swap/encm/encf with on-the-fly kf key schedule
 * in w28. 8 entries x 45 B = 360 B is not a whole number of dual blocks, so a
 * call fetches 12 duals and takes its 360-B window at byte 8*phase; phases run
 * 0,8,16,24 and the IV advances 11,11,11,12 duals, so four calls cover 45 duals
 * with no drift and nothing but the phase crosses a call.
 * in    : w27 counter increment, w30 base key, w31 zero, x16 phase 0..3
 * in-out: w29 IV base -> advanced past this call; x16 -> next phase
 * out   : w8-w23 keystream realigned to 45B columns
 * clob  : w8-w23, w28, FG0 (bn.add); no WSR/CSR writes
 * stack : none (leaf)
 */
.section .text
.balign 4
.global aes128_360
aes128_360:
    /* Prepare 12 IV blocks in w8-w19 */
    bn.mov w8, w29
    bn.add w9, w8, w27
    bn.add w10, w9, w27
    bn.add w11, w10, w27
    bn.add w12, w11, w27
    bn.add w13, w12, w27
    bn.add w14, w13, w27
    bn.add w15, w14, w27
    bn.add w16, w15, w27
    bn.add w17, w16, w27
    bn.add w18, w17, w27
    bn.add w19, w18, w27
    bn.add w29, w19, w27      /* IV + 12 duals; phases 0-2 give one back */

    /* Zero round: byte-swap counters + XOR with base key */
    bn.aes128.encz.swap w8, w8, w30
    bn.aes128.encz.swap w9, w9, w30
    bn.aes128.encz.swap w10, w10, w30
    bn.aes128.encz.swap w11, w11, w30
    bn.aes128.encz.swap w12, w12, w30
    bn.aes128.encz.swap w13, w13, w30
    bn.aes128.encz.swap w14, w14, w30
    bn.aes128.encz.swap w15, w15, w30
    bn.aes128.encz.swap w16, w16, w30
    bn.aes128.encz.swap w17, w17, w30
    bn.aes128.encz.swap w18, w18, w30
    bn.aes128.encz.swap w19, w19, w30

    /* Rounds 1-9: on-the-fly key schedule in w28 */
    bn.aes128.kf w28, w30, 1
    bn.aes128.encm w8, w8, w28
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w10, w10, w28
    bn.aes128.encm w11, w11, w28
    bn.aes128.encm w12, w12, w28
    bn.aes128.encm w13, w13, w28
    bn.aes128.encm w14, w14, w28
    bn.aes128.encm w15, w15, w28
    bn.aes128.encm w16, w16, w28
    bn.aes128.encm w17, w17, w28
    bn.aes128.encm w18, w18, w28
    bn.aes128.encm w19, w19, w28

    bn.aes128.kf w28, w28, 2
    bn.aes128.encm w8, w8, w28
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w10, w10, w28
    bn.aes128.encm w11, w11, w28
    bn.aes128.encm w12, w12, w28
    bn.aes128.encm w13, w13, w28
    bn.aes128.encm w14, w14, w28
    bn.aes128.encm w15, w15, w28
    bn.aes128.encm w16, w16, w28
    bn.aes128.encm w17, w17, w28
    bn.aes128.encm w18, w18, w28
    bn.aes128.encm w19, w19, w28

    bn.aes128.kf w28, w28, 3
    bn.aes128.encm w8, w8, w28
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w10, w10, w28
    bn.aes128.encm w11, w11, w28
    bn.aes128.encm w12, w12, w28
    bn.aes128.encm w13, w13, w28
    bn.aes128.encm w14, w14, w28
    bn.aes128.encm w15, w15, w28
    bn.aes128.encm w16, w16, w28
    bn.aes128.encm w17, w17, w28
    bn.aes128.encm w18, w18, w28
    bn.aes128.encm w19, w19, w28

    bn.aes128.kf w28, w28, 4
    bn.aes128.encm w8, w8, w28
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w10, w10, w28
    bn.aes128.encm w11, w11, w28
    bn.aes128.encm w12, w12, w28
    bn.aes128.encm w13, w13, w28
    bn.aes128.encm w14, w14, w28
    bn.aes128.encm w15, w15, w28
    bn.aes128.encm w16, w16, w28
    bn.aes128.encm w17, w17, w28
    bn.aes128.encm w18, w18, w28
    bn.aes128.encm w19, w19, w28

    bn.aes128.kf w28, w28, 5
    bn.aes128.encm w8, w8, w28
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w10, w10, w28
    bn.aes128.encm w11, w11, w28
    bn.aes128.encm w12, w12, w28
    bn.aes128.encm w13, w13, w28
    bn.aes128.encm w14, w14, w28
    bn.aes128.encm w15, w15, w28
    bn.aes128.encm w16, w16, w28
    bn.aes128.encm w17, w17, w28
    bn.aes128.encm w18, w18, w28
    bn.aes128.encm w19, w19, w28

    bn.aes128.kf w28, w28, 6
    bn.aes128.encm w8, w8, w28
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w10, w10, w28
    bn.aes128.encm w11, w11, w28
    bn.aes128.encm w12, w12, w28
    bn.aes128.encm w13, w13, w28
    bn.aes128.encm w14, w14, w28
    bn.aes128.encm w15, w15, w28
    bn.aes128.encm w16, w16, w28
    bn.aes128.encm w17, w17, w28
    bn.aes128.encm w18, w18, w28
    bn.aes128.encm w19, w19, w28

    bn.aes128.kf w28, w28, 7
    bn.aes128.encm w8, w8, w28
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w10, w10, w28
    bn.aes128.encm w11, w11, w28
    bn.aes128.encm w12, w12, w28
    bn.aes128.encm w13, w13, w28
    bn.aes128.encm w14, w14, w28
    bn.aes128.encm w15, w15, w28
    bn.aes128.encm w16, w16, w28
    bn.aes128.encm w17, w17, w28
    bn.aes128.encm w18, w18, w28
    bn.aes128.encm w19, w19, w28

    bn.aes128.kf w28, w28, 8
    bn.aes128.encm w8, w8, w28
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w10, w10, w28
    bn.aes128.encm w11, w11, w28
    bn.aes128.encm w12, w12, w28
    bn.aes128.encm w13, w13, w28
    bn.aes128.encm w14, w14, w28
    bn.aes128.encm w15, w15, w28
    bn.aes128.encm w16, w16, w28
    bn.aes128.encm w17, w17, w28
    bn.aes128.encm w18, w18, w28
    bn.aes128.encm w19, w19, w28

    bn.aes128.kf w28, w28, 9
    bn.aes128.encm w8, w8, w28
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w10, w10, w28
    bn.aes128.encm w11, w11, w28
    bn.aes128.encm w12, w12, w28
    bn.aes128.encm w13, w13, w28
    bn.aes128.encm w14, w14, w28
    bn.aes128.encm w15, w15, w28
    bn.aes128.encm w16, w16, w28
    bn.aes128.encm w17, w17, w28
    bn.aes128.encm w18, w18, w28
    bn.aes128.encm w19, w19, w28

    bn.aes128.kf w28, w28, 10
    bn.aes128.encf w8, w8, w28
    bn.aes128.encf w9, w9, w28
    bn.aes128.encf w10, w10, w28
    bn.aes128.encf w11, w11, w28
    bn.aes128.encf w12, w12, w28
    bn.aes128.encf w13, w13, w28
    bn.aes128.encf w14, w14, w28
    bn.aes128.encf w15, w15, w28
    bn.aes128.encf w16, w16, w28
    bn.aes128.encf w17, w17, w28
    bn.aes128.encf w18, w18, w28
    bn.aes128.encf w19, w19, w28

    # phase dispatch: x16 = 0..3 in, next phase out
    beq x16, x0, exp360_p0
    addi x16, x16, -1
    beq x16, x0, exp360_p1
    addi x16, x16, -1
    beq x16, x0, exp360_p2

    # phase 3: window at buffer byte 24
    # entry 7 @ buf 339 (wdr 18 byte 19)
    bn.rshi w23, w31, w19 >> 152
    bn.rshi w22, w19, w18 >> 152
    # entry 6 @ buf 294 (wdr 17 byte 6)
    bn.rshi w21, w18, w31 >> 152
    bn.rshi w21, w31, w21 >> 152
    bn.rshi w20, w18, w17 >> 48
    # entry 5 @ buf 249 (wdr 15 byte 25)
    bn.rshi w19, w17, w16 >> 48
    bn.rshi w19, w31, w19 >> 152
    bn.rshi w18, w16, w15 >> 200
    # entry 4 @ buf 204 (wdr 14 byte 12)
    bn.rshi w17, w15, w31 >> 200
    bn.rshi w17, w31, w17 >> 152
    bn.rshi w16, w15, w14 >> 96
    # entry 3 @ buf 159 (wdr 12 byte 31)
    bn.rshi w15, w14, w13 >> 96
    bn.rshi w15, w31, w15 >> 152
    bn.rshi w14, w13, w12 >> 248
    # entry 2 @ buf 114 (wdr 11 byte 18)
    bn.rshi w13, w12, w31 >> 248
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w12, w12, w11 >> 144
    # entry 0 @ buf 24 (wdr 8 byte 24)
    bn.rshi w8, w9, w8 >> 192
    bn.rshi w9, w10, w9 >> 40
    bn.rshi w9, w31, w9 >> 152
    # entry 1 @ buf 69 (wdr 10 byte 5)
    bn.rshi w10, w11, w10 >> 40
    bn.rshi w11, w11, w31 >> 144
    bn.rshi w11, w31, w11 >> 152
    li x16, 0
    ret

exp360_p0:
    # phase 0: window at buffer byte 0
    bn.sub w29, w29, w27
    # entry 7 @ buf 315 (wdr 17 byte 27)
    bn.rshi w23, w19, w18 >> 64
    bn.rshi w23, w31, w23 >> 152
    bn.rshi w22, w18, w17 >> 216
    # entry 6 @ buf 270 (wdr 16 byte 14)
    bn.rshi w21, w17, w31 >> 216
    bn.rshi w21, w31, w21 >> 152
    bn.rshi w20, w17, w16 >> 112
    # entry 5 @ buf 225 (wdr 15 byte 1)
    bn.rshi w19, w16, w31 >> 112
    bn.rshi w19, w31, w19 >> 152
    bn.rshi w18, w16, w15 >> 8
    # entry 4 @ buf 180 (wdr 13 byte 20)
    bn.rshi w17, w15, w14 >> 8
    bn.rshi w17, w31, w17 >> 152
    bn.rshi w16, w14, w13 >> 160
    # entry 3 @ buf 135 (wdr 12 byte 7)
    bn.rshi w15, w13, w31 >> 160
    bn.rshi w15, w31, w15 >> 152
    bn.rshi w14, w13, w12 >> 56
    # entry 2 @ buf 90 (wdr 10 byte 26)
    bn.rshi w13, w12, w11 >> 56
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w12, w11, w10 >> 208
    # entry 1 @ buf 45 (wdr 9 byte 13)
    bn.rshi w11, w10, w31 >> 208
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w10, w10, w9 >> 104
    # entry 0 @ buf 0 (wdr 8 byte 0)
    bn.rshi w9, w9, w31 >> 104
    bn.rshi w9, w31, w9 >> 152
    li x16, 1
    ret

exp360_p1:
    # phase 1: window at buffer byte 8
    bn.sub w29, w29, w27
    # entry 7 @ buf 323 (wdr 18 byte 3)
    bn.rshi w23, w19, w31 >> 128
    bn.rshi w23, w31, w23 >> 152
    bn.rshi w22, w19, w18 >> 24
    # entry 6 @ buf 278 (wdr 16 byte 22)
    bn.rshi w21, w18, w17 >> 24
    bn.rshi w21, w31, w21 >> 152
    bn.rshi w20, w17, w16 >> 176
    # entry 5 @ buf 233 (wdr 15 byte 9)
    bn.rshi w19, w16, w31 >> 176
    bn.rshi w19, w31, w19 >> 152
    bn.rshi w18, w16, w15 >> 72
    # entry 4 @ buf 188 (wdr 13 byte 28)
    bn.rshi w17, w15, w14 >> 72
    bn.rshi w17, w31, w17 >> 152
    bn.rshi w16, w14, w13 >> 224
    # entry 3 @ buf 143 (wdr 12 byte 15)
    bn.rshi w15, w13, w31 >> 224
    bn.rshi w15, w31, w15 >> 152
    bn.rshi w14, w13, w12 >> 120
    # entry 2 @ buf 98 (wdr 11 byte 2)
    bn.rshi w13, w12, w31 >> 120
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w12, w12, w11 >> 16
    # entry 1 @ buf 53 (wdr 9 byte 21)
    bn.rshi w11, w11, w10 >> 16
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w10, w10, w9 >> 168
    # entry 0 @ buf 8 (wdr 8 byte 8)
    bn.rshi w8, w9, w8 >> 64
    bn.rshi w9, w9, w31 >> 168
    bn.rshi w9, w31, w9 >> 152
    li x16, 2
    ret

exp360_p2:
    # phase 2: window at buffer byte 16
    bn.sub w29, w29, w27
    # entry 7 @ buf 331 (wdr 18 byte 11)
    bn.rshi w23, w19, w31 >> 192
    bn.rshi w23, w31, w23 >> 152
    bn.rshi w22, w19, w18 >> 88
    # entry 6 @ buf 286 (wdr 16 byte 30)
    bn.rshi w21, w18, w17 >> 88
    bn.rshi w21, w31, w21 >> 152
    bn.rshi w20, w17, w16 >> 240
    # entry 5 @ buf 241 (wdr 15 byte 17)
    bn.rshi w19, w16, w31 >> 240
    bn.rshi w19, w31, w19 >> 152
    bn.rshi w18, w16, w15 >> 136
    # entry 4 @ buf 196 (wdr 14 byte 4)
    bn.rshi w17, w15, w31 >> 136
    bn.rshi w17, w31, w17 >> 152
    bn.rshi w16, w15, w14 >> 32
    # entry 3 @ buf 151 (wdr 12 byte 23)
    bn.rshi w15, w14, w13 >> 32
    bn.rshi w15, w31, w15 >> 152
    bn.rshi w14, w13, w12 >> 184
    # entry 2 @ buf 106 (wdr 11 byte 10)
    bn.rshi w13, w12, w31 >> 184
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w12, w12, w11 >> 80
    # entry 1 @ buf 61 (wdr 9 byte 29)
    bn.rshi w11, w11, w10 >> 80
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w10, w10, w9 >> 232
    # entry 0 @ buf 16 (wdr 8 byte 16)
    bn.rshi w8, w9, w8 >> 128
    bn.rshi w9, w9, w31 >> 232
    bn.rshi w9, w31, w9 >> 152
    li x16, 3
    ret


