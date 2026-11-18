/*
 * KeySchedule_sign_test single-call smoke test.
 *
 * Loads the NIST FIPS-197 example AES-128 key (2b 7e 15 16 28 ae d2 a6 ab f7
 * 15 88 09 cf 4f 3c) into w17, pre-loads the SW-AES constants, calls
 * KeySchedule_sign once, and dumps w17 (= RK1) to DMEM at label `rk_out`.
 *
 * Expected RK1: a0 fa fe 17 88 54 2c b1 23 a3 39 39 2a 6c 76 05
 *
 * To validate: assemble + run via standalone.py --pqc true --dump-dmem - <elf>
 * and compare bytes 0..15 of rk_out region.
 */
.section .data
.balign 32
test_key:
    .word 0x16157e2b, 0xa6d2ae28, 0x8815f7ab, 0x3c4fcf09       /* NIST key, low half */
    .zero 16                                                    /* high half = 0 (KS reads low half only) */

.balign 32
rk_out:
    .zero 32                                                    /* output RK1, 16 bytes used + 16 pad */

.section .text.start
.global main
.balign 4
main:
    bn.xor w31, w31, w31

    /* Pre-load SW-AES constants */
    la x5, affine_value
    li x6, 8
    bn.lid x6, 0(x5)              /* w8 = 0x63..63 */
    la x5, msb_mask
    li x6, 9
    bn.lid x6, 0(x5)              /* w9 = 0x80..80 */
    la x5, rcon
    li x6, 11
    bn.lid x6, 0(x5)              /* w11 = rcon stream */

    /* Load test key into w17 (RK0). KS reads low half only no need to dual-store. */
    la x5, test_key
    li x6, 17
    bn.lid x6, 0(x5)

    /* One round of key schedule: w17 = RK0 to w17 = RK1 */
    jal x1, KeySchedule_sign

    /* Store RK1 to DMEM */
    la x5, rk_out
    li x6, 17
    bn.sid x6, 0(x5)

    ecall
