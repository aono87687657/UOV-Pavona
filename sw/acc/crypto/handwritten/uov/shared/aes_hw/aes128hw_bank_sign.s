/* AES-128 for the Is AES-only sign kernel, round keys held in WDRs: each AES_128_keyschedule call expands the
 * key into the bank and the packed 176 B schedule; aes128_dual_table then only encrypts. The bank stays valid
 * to the end of the EXECUTE (the end-of-run wipe clears it).
 * bank: K0..K10 = w11 w12 w13 w9 w24 w25 w26 w27 w28 w29 w30; each the round key, zero-extended.
 */
.section .text
.balign 4

/* in: x10 key[16], x11 round_keys[176] (both 4-byte aligned); out: x11 += 160, the bank.
 * clob: x5-x8, x11, x29; wdr: the bank. flags/WSRs preserved. data: 32 B private slot. stack: none.
 */
.global AES_128_keyschedule
.global aes128hw_keyschedule
AES_128_keyschedule:
aes128hw_keyschedule:
    la x29, aes128hw_bank_sign_slot
    lw x5, 0(x10)
    lw x6, 4(x10)
    lw x7, 8(x10)
    lw x8, 12(x10)
    sw x5, 0(x29)
    sw x6, 4(x29)
    sw x7, 8(x29)
    sw x8, 12(x29)
    sw x0, 16(x29)
    sw x0, 20(x29)
    sw x0, 24(x29)
    sw x0, 28(x29)
    bn.ld w11, 0(x29)
    addi x11, x11, -16
    lw x5, 0(x29)
    lw x6, 4(x29)
    lw x7, 8(x29)
    lw x8, 12(x29)
    addi x11, x11, 16
    sw x5, 0(x11)
    sw x6, 4(x11)
    sw x7, 8(x11)
    sw x8, 12(x11)
    bn.aes128.kf w12, w11, 1
    bn.sd w12, 0(x29)
    lw x5, 0(x29)
    lw x6, 4(x29)
    lw x7, 8(x29)
    lw x8, 12(x29)
    addi x11, x11, 16
    sw x5, 0(x11)
    sw x6, 4(x11)
    sw x7, 8(x11)
    sw x8, 12(x11)
    bn.aes128.kf w13, w12, 2
    bn.sd w13, 0(x29)
    lw x5, 0(x29)
    lw x6, 4(x29)
    lw x7, 8(x29)
    lw x8, 12(x29)
    addi x11, x11, 16
    sw x5, 0(x11)
    sw x6, 4(x11)
    sw x7, 8(x11)
    sw x8, 12(x11)
    bn.aes128.kf w9, w13, 3
    bn.sd w9, 0(x29)
    lw x5, 0(x29)
    lw x6, 4(x29)
    lw x7, 8(x29)
    lw x8, 12(x29)
    addi x11, x11, 16
    sw x5, 0(x11)
    sw x6, 4(x11)
    sw x7, 8(x11)
    sw x8, 12(x11)
    bn.aes128.kf w24, w9, 4
    bn.sd w24, 0(x29)
    lw x5, 0(x29)
    lw x6, 4(x29)
    lw x7, 8(x29)
    lw x8, 12(x29)
    addi x11, x11, 16
    sw x5, 0(x11)
    sw x6, 4(x11)
    sw x7, 8(x11)
    sw x8, 12(x11)
    bn.aes128.kf w25, w24, 5
    bn.sd w25, 0(x29)
    lw x5, 0(x29)
    lw x6, 4(x29)
    lw x7, 8(x29)
    lw x8, 12(x29)
    addi x11, x11, 16
    sw x5, 0(x11)
    sw x6, 4(x11)
    sw x7, 8(x11)
    sw x8, 12(x11)
    bn.aes128.kf w26, w25, 6
    bn.sd w26, 0(x29)
    lw x5, 0(x29)
    lw x6, 4(x29)
    lw x7, 8(x29)
    lw x8, 12(x29)
    addi x11, x11, 16
    sw x5, 0(x11)
    sw x6, 4(x11)
    sw x7, 8(x11)
    sw x8, 12(x11)
    bn.aes128.kf w27, w26, 7
    bn.sd w27, 0(x29)
    lw x5, 0(x29)
    lw x6, 4(x29)
    lw x7, 8(x29)
    lw x8, 12(x29)
    addi x11, x11, 16
    sw x5, 0(x11)
    sw x6, 4(x11)
    sw x7, 8(x11)
    sw x8, 12(x11)
    bn.aes128.kf w28, w27, 8
    bn.sd w28, 0(x29)
    lw x5, 0(x29)
    lw x6, 4(x29)
    lw x7, 8(x29)
    lw x8, 12(x29)
    addi x11, x11, 16
    sw x5, 0(x11)
    sw x6, 4(x11)
    sw x7, 8(x11)
    sw x8, 12(x11)
    bn.aes128.kf w29, w28, 9
    bn.sd w29, 0(x29)
    lw x5, 0(x29)
    lw x6, 4(x29)
    lw x7, 8(x29)
    lw x8, 12(x29)
    addi x11, x11, 16
    sw x5, 0(x11)
    sw x6, 4(x11)
    sw x7, 8(x11)
    sw x8, 12(x11)
    bn.aes128.kf w30, w29, 10
    bn.sd w30, 0(x29)
    lw x5, 0(x29)
    lw x6, 4(x29)
    lw x7, 8(x29)
    lw x8, 12(x29)
    addi x11, x11, 16
    sw x5, 0(x11)
    sw x6, 4(x11)
    sw x7, 8(x11)
    sw x8, 12(x11)
    ret

/* in: w18 = two IVs (12 zero bytes + LE counter at bytes 12..15 in each 128-bit lane); the bank of this
 * EXECUTE. out: w2 = AES(lane 0) || AES(lane 1). clob: w2; every other register, flags and WSRs preserved.
 * stack: none. The .swap form of the first round turns the LE counter field big-endian.
 */
.global aes128_dual_table
aes128_dual_table:
    bn.aes128.encz.swap w2, w18, w11
    bn.aes128.encm w2, w2, w12
    bn.aes128.encm w2, w2, w13
    bn.aes128.encm w2, w2, w9
    bn.aes128.encm w2, w2, w24
    bn.aes128.encm w2, w2, w25
    bn.aes128.encm w2, w2, w26
    bn.aes128.encm w2, w2, w27
    bn.aes128.encm w2, w2, w28
    bn.aes128.encm w2, w2, w29
    bn.aes128.encf w2, w2, w30
    ret

.section .data
.balign 32
aes128hw_bank_sign_slot: .zero 32
