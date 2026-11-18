/* Cycle measurement: AES-128 encrypt (dual-block, 32 B) via the ISE, with
 * round keys already resident in WDRs: the encrypt cost alone, without a key
 * schedule (bn.aes128.encz.swap + 9x encm + encf).
 * Round-key and message values do not affect the cycle count; the key
 * schedule is measured separately (aes128_ext_ks_test).
 */
.section .data
.balign 32
msg:
    .zero 32                 /* two 128-bit CTR-style blocks packed in one WDR */

.section .text.start
.balign 4
.global main
main:
    /* round keys rk0..rk10 resident in w20..w30 (values do not affect the
     * cycle count; nothing writes them here). */
    li x5, 1
    la x6, msg
    bn.lid x5, 0(x6)         /* w1 = dual-block input */

    bn.aes128.encz.swap w0, w1, w20   /* zero round + AddRoundKey0 */
    bn.aes128.encm w0, w0, w21
    bn.aes128.encm w0, w0, w22
    bn.aes128.encm w0, w0, w23
    bn.aes128.encm w0, w0, w24
    bn.aes128.encm w0, w0, w25
    bn.aes128.encm w0, w0, w26
    bn.aes128.encm w0, w0, w27
    bn.aes128.encm w0, w0, w28
    bn.aes128.encm w0, w0, w29
    bn.aes128.encf w0, w0, w30        /* final round */

    ecall
