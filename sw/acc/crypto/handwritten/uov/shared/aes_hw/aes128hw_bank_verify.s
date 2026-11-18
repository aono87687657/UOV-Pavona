/* AES-128 for the Is AES-only verifiers (full, stream, stream_uniform), round keys held in WDRs: each AES_128_keyschedule call expands the
 * key into the bank and the packed 176 B schedule; aes128_col_is then only encrypts. The bank stays valid
 * to the end of the EXECUTE (the end-of-run wipe clears it).
 * bank: K0..K10 = w9 w10 w14 w15 w16 w17 w18 w19 w20 w21 w22; each the round key, zero-extended.
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
    la x29, aes128hw_bank_verify_slot
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
    bn.ld w9, 0(x29)
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
    bn.aes128.kf w10, w9, 1
    bn.sd w10, 0(x29)
    lw x5, 0(x29)
    lw x6, 4(x29)
    lw x7, 8(x29)
    lw x8, 12(x29)
    addi x11, x11, 16
    sw x5, 0(x11)
    sw x6, 4(x11)
    sw x7, 8(x11)
    sw x8, 12(x11)
    bn.aes128.kf w14, w10, 2
    bn.sd w14, 0(x29)
    lw x5, 0(x29)
    lw x6, 4(x29)
    lw x7, 8(x29)
    lw x8, 12(x29)
    addi x11, x11, 16
    sw x5, 0(x11)
    sw x6, 4(x11)
    sw x7, 8(x11)
    sw x8, 12(x11)
    bn.aes128.kf w15, w14, 3
    bn.sd w15, 0(x29)
    lw x5, 0(x29)
    lw x6, 4(x29)
    lw x7, 8(x29)
    lw x8, 12(x29)
    addi x11, x11, 16
    sw x5, 0(x11)
    sw x6, 4(x11)
    sw x7, 8(x11)
    sw x8, 12(x11)
    bn.aes128.kf w16, w15, 4
    bn.sd w16, 0(x29)
    lw x5, 0(x29)
    lw x6, 4(x29)
    lw x7, 8(x29)
    lw x8, 12(x29)
    addi x11, x11, 16
    sw x5, 0(x11)
    sw x6, 4(x11)
    sw x7, 8(x11)
    sw x8, 12(x11)
    bn.aes128.kf w17, w16, 5
    bn.sd w17, 0(x29)
    lw x5, 0(x29)
    lw x6, 4(x29)
    lw x7, 8(x29)
    lw x8, 12(x29)
    addi x11, x11, 16
    sw x5, 0(x11)
    sw x6, 4(x11)
    sw x7, 8(x11)
    sw x8, 12(x11)
    bn.aes128.kf w18, w17, 6
    bn.sd w18, 0(x29)
    lw x5, 0(x29)
    lw x6, 4(x29)
    lw x7, 8(x29)
    lw x8, 12(x29)
    addi x11, x11, 16
    sw x5, 0(x11)
    sw x6, 4(x11)
    sw x7, 8(x11)
    sw x8, 12(x11)
    bn.aes128.kf w19, w18, 7
    bn.sd w19, 0(x29)
    lw x5, 0(x29)
    lw x6, 4(x29)
    lw x7, 8(x29)
    lw x8, 12(x29)
    addi x11, x11, 16
    sw x5, 0(x11)
    sw x6, 4(x11)
    sw x7, 8(x11)
    sw x8, 12(x11)
    bn.aes128.kf w20, w19, 8
    bn.sd w20, 0(x29)
    lw x5, 0(x29)
    lw x6, 4(x29)
    lw x7, 8(x29)
    lw x8, 12(x29)
    addi x11, x11, 16
    sw x5, 0(x11)
    sw x6, 4(x11)
    sw x7, 8(x11)
    sw x8, 12(x11)
    bn.aes128.kf w21, w20, 9
    bn.sd w21, 0(x29)
    lw x5, 0(x29)
    lw x6, 4(x29)
    lw x7, 8(x29)
    lw x8, 12(x29)
    addi x11, x11, 16
    sw x5, 0(x11)
    sw x6, 4(x11)
    sw x7, 8(x11)
    sw x8, 12(x11)
    bn.aes128.kf w22, w21, 10
    bn.sd w22, 0(x29)
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

/* AES-128 CTR column: two blocks in w13.
 * in: x13 counter; the bank of this EXECUTE; w31 = 0; 20(x3) = 32 B aligned scratch.
 * out: w13 low/high lanes = AES(counter)/AES(counter+1); x13 += 2 modulo 2^32.
 * clob: x5, x6, scratch contents; wdr: w13. flags/WSRs preserved. stack: none.
 */
.global aes128hw_col_is
.global aes128_col_is
.type aes128hw_col_is, @function
.type aes128_col_is, @function
aes128hw_col_is:
aes128_col_is:
    lw x6, 20(x3)
    bn.sd w31, 0(x6)
    sw x13, 12(x6)
    addi x5, x13, 1
    sw x5, 28(x6)
    bn.ld w13, 0(x6)
    bn.aes128.encz.swap w13, w13, w9
    bn.aes128.encm w13, w13, w10
    bn.aes128.encm w13, w13, w14
    bn.aes128.encm w13, w13, w15
    bn.aes128.encm w13, w13, w16
    bn.aes128.encm w13, w13, w17
    bn.aes128.encm w13, w13, w18
    bn.aes128.encm w13, w13, w19
    bn.aes128.encm w13, w13, w20
    bn.aes128.encm w13, w13, w21
    bn.aes128.encf w13, w13, w22
    addi x13, x13, 2
    ret
.size aes128hw_col_is, .-aes128hw_col_is
.size aes128_col_is, .-aes128_col_is

.section .data
.balign 32
aes128hw_bank_verify_slot: .zero 32
