/*
 * KeySchedule_sign_all10_test calls KS 10 times, dumps RK1..RK10 to DMEM
 * for full NIST FIPS-197 cross-check.
 *
 * Expected (NIST key 2b 7e 15 16 ...):
 *   RK1:  a0 fa fe 17 88 54 2c b1 23 a3 39 39 2a 6c 76 05
 *   RK2:  f2 c2 95 f2 7a 96 b9 43 59 35 80 7a 73 59 f6 7f
 *   RK3:  3d 80 47 7d 47 16 fe 3e 1e 23 7e 44 6d 7a 88 3b
 *   RK4:  ef 44 a5 41 a8 52 5b 7f b6 71 25 3b db 0b ad 00
 *   RK5:  d4 d1 c6 f8 7c 83 9d 87 ca f2 b8 bc 11 f9 15 bc
 *   RK6:  6d 88 a3 7a 11 0b 3e fd db f9 86 41 ca 00 93 fd
 *   RK7:  4e 54 f7 0e 5f 5f c9 f3 84 a6 4f b2 4e a6 dc 4f
 *   RK8:  ea d2 73 21 b5 8d ba d2 31 2b f5 60 7f 8d 29 2f
 *   RK9:  ac 77 66 f3 19 fa dc 21 28 d1 29 41 57 5c 00 6e
 *   RK10: d0 14 f9 a8 c9 ee 25 89 e1 3f 0c c8 b6 63 0c a6
 */
.section .data
.balign 32
test_key:
    .word 0x16157e2b, 0xa6d2ae28, 0x8815f7ab, 0x3c4fcf09
    .zero 16

.balign 32
rk_buf:
    .zero 320          /* 10 round keys x 32 bytes per WDR */

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

    /* Load test key into w17 (RK0) */
    la x5, test_key
    li x6, 17
    bn.lid x6, 0(x5)

    /* Setup output cursor: x10 = &rk_buf, x6 = 17 (source WDR for bn.sid) */
    la x10, rk_buf
    li x6, 17

    /* 10 iterations: jal KS, bn.sid w17 to rk_buf[i*32] */
    jal x1, KeySchedule_sign
    bn.sid x6, 0(x10)
    jal x1, KeySchedule_sign
    bn.sid x6, 32(x10)
    jal x1, KeySchedule_sign
    bn.sid x6, 64(x10)
    jal x1, KeySchedule_sign
    bn.sid x6, 96(x10)
    jal x1, KeySchedule_sign
    bn.sid x6, 128(x10)
    jal x1, KeySchedule_sign
    bn.sid x6, 160(x10)
    jal x1, KeySchedule_sign
    bn.sid x6, 192(x10)
    jal x1, KeySchedule_sign
    bn.sid x6, 224(x10)
    jal x1, KeySchedule_sign
    bn.sid x6, 256(x10)
    jal x1, KeySchedule_sign
    bn.sid x6, 288(x10)

    ecall
