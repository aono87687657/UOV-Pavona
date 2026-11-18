/*
 * aes128_sign_nistkey_sign_iv_test NIST AES key + SIGN-kernel IV setup.
 *
 * Key: 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
 * IV after first kernel-add: low half CTR=2 (byte 12 = 02), high half CTR=3 (byte 28 = 03)
 *
 * Expected (computed via Python AES with NIST key):
 *   block 0 (CTR=2 BE at byte 15): AES_NISTkey([0...0, 0x02])
 *   block 1 (CTR=3 BE at byte 31): AES_NISTkey([0...0, 0x03])
 */
.section .data
.balign 32
test_key:
    .word 0x16157e2b, 0xa6d2ae28, 0x8815f7ab, 0x3c4fcf09
    .zero 16
.balign 32
ct_out:
    .zero 32

.section .text.start
.global main
.balign 4
main:
    bn.xor w31, w31, w31

    /* Pre-load AES constants */
    la x5, affine_value
    li x6, 8
    bn.lid x6, 0(x5)
    la x5, msb_mask
    li x6, 9
    bn.lid x6, 0(x5)
    la x5, rcon
    li x6, 11
    bn.lid x6, 0(x5)

    /* Load NIST key into w30, dual-store */
    la x5, test_key
    li x6, 30
    bn.lid x6, 0(x5)
    bn.or w30, w30, w30 << 128

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

    /* Set mod0 = 0x13 */
    li x5, 0x13
    csrrw x0, mod0, x5

    /* Build IV: byte 12 = 02 (low half CTR), byte 28 = 03 (high half CTR) */
    bn.xor w18, w18, w18
    bn.addi w17, w31, 0x02
    bn.or w18, w18, w17 << 96
    bn.addi w17, w31, 0x03
    bn.or w18, w18, w17 << 224

    /* Encrypt */
    jal x1, aes128_sign

    /* Store ciphertext */
    la x5, ct_out
    li x6, 2
    bn.sid x6, 0(x5)

    ecall
