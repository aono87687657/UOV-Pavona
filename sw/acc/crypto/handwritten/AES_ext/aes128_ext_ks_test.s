/* Cycle measurement: AES-128 key schedule via the ISE (bn.aes128.kf).
 * Expands a 16-byte key into round keys 1..10 in w1..w10 (rk0 = w0), all
 * resident in WDRs; UOV kernels use other key-schedule strategies.
 * Key values do not affect the cycle count. Read with --dump-stats.
 */
.section .data
.balign 32
key0:
    .zero 32

.section .text.start
.balign 4
.global main
main:
    li x5, 0
    la x6, key0
    bn.lid x5, 0(x6)          /* w0 = rk0 (master key) */

    bn.aes128.kf w1,  w0,  1
    bn.aes128.kf w2,  w1,  2
    bn.aes128.kf w3,  w2,  3
    bn.aes128.kf w4,  w3,  4
    bn.aes128.kf w5,  w4,  5
    bn.aes128.kf w6,  w5,  6
    bn.aes128.kf w7,  w6,  7
    bn.aes128.kf w8,  w7,  8
    bn.aes128.kf w9,  w8,  9
    bn.aes128.kf w10, w9,  10

    ecall
