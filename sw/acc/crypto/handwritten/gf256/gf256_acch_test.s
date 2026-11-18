/* gf256_acch_test.s — bn.gfmul .acch (ACCH accumulator-select) test.
 * Proves ACC and ACCH are two independent GF-MAC accumulators:
 * interleaved .acc/.acch chains, .acch.z zeroing, .acch.inc mod1 wrap.
 * Expected values: test_scripts/gf256_acch_expectgen.py
 */

.section .data
.balign 32
val_a:
    .word 0x12345678, 0x9ABCDEF0, 0x12345678, 0x9ABCDEF0
    .word 0x12345678, 0x9ABCDEF0, 0x12345678, 0x9ABCDEF0
.balign 32
val_b2:
    .word 0x00000002, 0, 0, 0, 0, 0, 0, 0
.balign 32
val_b3:
    .word 0x00000003, 0, 0, 0, 0, 0, 0, 0
.balign 32
val_b7:
    .word 0x00000007, 0, 0, 0, 0, 0, 0, 0

.section .text.start
.balign 4
.global main
main:
    /* mod0 = GF(256) AES polynomial 0x11b; mod1 = 0 (scalar = byte 0 of wrs2) */
    li x23, 0x0000011b
    csrrw x0, mod0, x23
    csrrw x0, mod1, x0

    la x5, val_a
    li x6, 1
    bn.lid x6, 0(x5)
    la x5, val_b2
    li x6, 2
    bn.lid x6, 0(x5)
    la x5, val_b3
    li x6, 3
    bn.lid x6, 0(x5)
    la x5, val_b7
    li x6, 4
    bn.lid x6, 0(x5)

    /* ACC = a*2 */
    bn.gfmul.8.acc.z w10, w1, w2
    /* ACCH = a*3 — must not disturb ACC */
    bn.gfmul.8.acch.z w11, w1, w3
    /* ACCH ^= a*7 — accumulation happens in ACCH */
    bn.gfmul.8.acch w12, w1, w4
    /* readback: ACC still a*2, ACCH = a*3 ^ a*7 */
    bn.wsrr w20, acc
    bn.wsrr w21, acch
    /* ACC ^= a*3 — ACC chain unaffected by ACCH use */
    bn.gfmul.8.acc w13, w1, w3
    /* ACCH must still hold a*3 ^ a*7 — .acc must not write ACCH */
    bn.wsrr w23, acch
    /* ACCH = a*2 (zeroed) while ACC keeps its value */
    bn.gfmul.8.acch.z w14, w1, w2
    bn.wsrr w22, acc
    /* .acch.inc: mod1=31 -> scalar byte 31 of w2 is 0 -> ACCH unchanged;
     * mod1 wraps 31 -> 0 (field size 8) */
    li x7, 31
    csrrw x0, mod1, x7
    csrrs x8, mod1, x0
    bn.gfmul.8.acch.inc w15, w1, w2
    csrrs x9, mod1, x0

    bn.xor w0, w0, w0
    ecall
