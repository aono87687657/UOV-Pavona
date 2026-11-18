/*
 * aes128_sign_test standalone single-block AES-128 test using NIST FIPS-197
 * Appendix B example.
 *
 *   Key (RK0): 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
 *   PT (AES input after byte-swap): 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
 *   Expected CT: 39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32
 *
 * aes128_sign byte-swaps w18 within every 4-byte group; we encode the IV
 * pre-byte-swapped so the AES input is the NIST plaintext after swap.
 *
 * Flow:
 *   1. load key into w30 (dual-stored)
 *   2. pre-load constants
 *   3. KSx10 to w20..w29 (each dual-stored)
 *   4. load IV pre-byte-swap into w18 (dual-half)
 *   5. set mod0=0x13 (caller convention)
 *   6. jal aes128_sign
 *   7. store w2 (ciphertext) to DMEM ct_out
 */
.section .data
.balign 32
test_key:
    .word 0x16157e2b, 0xa6d2ae28, 0x8815f7ab, 0x3c4fcf09
    .zero 16
.balign 32
test_iv_preswap:
    /* AES input after byte-swap: 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
       Pre-byte-swap (reverse each 4-byte group): a8 f6 43 32 8d 30 5a 88 a2 98 31 31 34 07 37 e0
       In .word LE: 0x3243f6a8, 0x885a308d, 0x313198a2, 0xe0370734 */
    .word 0x3243f6a8, 0x885a308d, 0x313198a2, 0xe0370734
    /* high half = same (both blocks encrypt the same plaintext) */
    .word 0x3243f6a8, 0x885a308d, 0x313198a2, 0xe0370734
.balign 32
ct_out:
    .zero 32          /* low half = ciphertext block 0; high half = block 1 */

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

    /* Load AES key to w30, dual-store */
    la x5, test_key
    li x6, 30
    bn.lid x6, 0(x5)
    bn.or w30, w30, w30 << 128

    /* SW key schedule x 10 (forward layout: RK1=w20, ..., RK10=w29) */
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

    /* Re-load byte_swap_mask (KS clobbered it) */
    la x5, byte_swap_mask
    li x6, 7
    bn.lid x6, 0(x5)

    /* Set mod0 = 0x13 (caller convention for sign kernel) */
    li x5, 0x13
    csrrw x0, mod0, x5

    /* Load IV pre-byte-swap into w18 */
    la x5, test_iv_preswap
    li x6, 18
    bn.lid x6, 0(x5)

    /* Encrypt */
    jal x1, aes128_sign

    /* Store ciphertext */
    la x5, ct_out
    li x6, 2
    bn.sid x6, 0(x5)

    ecall
