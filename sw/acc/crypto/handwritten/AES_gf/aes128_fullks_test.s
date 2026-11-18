/* Cycle measurement: full AES-128 key schedule (compute-AES path).
 * Expands the 16-byte key into 11 round keys (w5..w14 + w28) via 10
 * KeySchedule calls, exactly as aes128_test drives it. Encryption is
 * measured separately (aes128_encrypt_only_test). Read with --dump-stats.
 */
.section .data
.balign 32
.global key
key:
    .zero 16
    .zero 16
.balign 32
.global rcon
rcon:
    .word 0x08040201, 0x80402010, 0x361b
    .zero 26
.balign 32
.global msb_mask
msb_mask:
    .word 0x80808080, 0x80808080, 0x80808080, 0x80808080
    .word 0x80808080, 0x80808080, 0x80808080, 0x80808080
.balign 32
.global affine_value
affine_value:
    .word 0x63636363, 0x63636363, 0x63636363, 0x63636363
    .word 0x63636363, 0x63636363, 0x63636363, 0x63636363

.section .text.start
.balign 4
.global main
main:
    bn.xor w31, w31, w31
    la x5, key
    li x6, 28
    bn.lid x6, 0(x5)             /* w28 = master key */

    la x5, rcon
    li x6, 26
    bn.lid x6, 0(x5)            /* w26 = rcon stream */
    la x5, affine_value
    li x6, 23
    bn.lid x6, 0(x5)           /* w23 = affine */
    la x5, msb_mask
    li x6, 24
    bn.lid x6, 0(x5)           /* w24 = msb mask */

    li x5, 5
    li x6, 28
    loopi 10, 2                 /* 10 rounds -> w5..w14 */
        jal x1, KeySchedule
        bn.movr x5++, x6

    ecall
