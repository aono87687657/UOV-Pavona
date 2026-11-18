/*
 * aes128_sign_zerokey_test encrypt counters 2 and 3 with zero key using
 * the SIGN-kernel IV setup (counter at byte 12 of low half, byte 28 of high half).
 *
 * Expected:
 *   block 0 (counter=2 in BE pos byte 15): 03 88 da ce 60 b6 a3 92 f3 28 c2 b9 71 b2 fe 78
 *   block 1 (counter=3): f7 95 aa ab 49 4b 59 23 f7 fd 89 ff 94 8b c1 e0
 */
.section .data
.balign 32
ct_out:
    .zero 32

.section .text.start
.global main
.balign 4
main:
    bn.xor w31, w31, w31

    /* Pre-load constants */
    la x5, affine_value
    li x6, 8
    bn.lid x6, 0(x5)
    la x5, msb_mask
    li x6, 9
    bn.lid x6, 0(x5)
    la x5, rcon
    li x6, 11
    bn.lid x6, 0(x5)

    /* Zero key into w30, dual-stored (already zero from w31, but be explicit) */
    bn.xor w30, w30, w30
    /* Already dual-stored as 0 | 0 = 0 */

    /* SW key schedule x 10 (forward layout) */
    bn.mov w17, w30
    jal x1, KeySchedule_sign
    bn.mov w20, w17
    bn.or  w20, w20, w20 << 128
    jal x1, KeySchedule_sign
    bn.mov w21, w17
    bn.or  w21, w21, w21 << 128
    jal x1, KeySchedule_sign
    bn.mov w22, w17
    bn.or  w22, w22, w22 << 128
    jal x1, KeySchedule_sign
    bn.mov w23, w17
    bn.or  w23, w23, w23 << 128
    jal x1, KeySchedule_sign
    bn.mov w24, w17
    bn.or  w24, w24, w24 << 128
    jal x1, KeySchedule_sign
    bn.mov w25, w17
    bn.or  w25, w25, w25 << 128
    jal x1, KeySchedule_sign
    bn.mov w26, w17
    bn.or  w26, w26, w26 << 128
    jal x1, KeySchedule_sign
    bn.mov w27, w17
    bn.or  w27, w27, w27 << 128
    jal x1, KeySchedule_sign
    bn.mov w28, w17
    bn.or  w28, w28, w28 << 128
    jal x1, KeySchedule_sign
    bn.mov w29, w17
    bn.or  w29, w29, w29 << 128

    /* Re-load byte_swap_mask */
    la x5, byte_swap_mask
    li x6, 7
    bn.lid x6, 0(x5)

    /* Set mod0 = 0x13 (matches kernel caller convention) */
    li x5, 0x13
    csrrw x0, mod0, x5

    /* Build IV: low half byte 12 = 02 (LE), high half byte 28 = 03 (LE).
       After aes128_sign byte-swap, BE-counter = 02 at byte 15 (low), 03 at byte 31 (high). */
    bn.xor w18, w18, w18                # clear w18
    bn.addi w17, w31, 0x02              # tmp = 0x02
    bn.or w18, w18, w17 << 96           # w18 bit 96..103 = 0x02 (= byte 12 low half)
    bn.addi w17, w31, 0x03              # tmp = 0x03
    bn.or w18, w18, w17 << 224          # w18 bit 224..231 = 0x03 (= byte 28 high half)

    /* Encrypt */
    jal x1, aes128_sign

    /* Store ciphertext */
    la x5, ct_out
    li x6, 2
    bn.sid x6, 0(x5)

    ecall
