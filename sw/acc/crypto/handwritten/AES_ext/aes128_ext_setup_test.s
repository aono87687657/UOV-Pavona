/* Baseline for the ISE ks/enc drivers: identical scaffold
 * (li/la/bn.lid), no AES op. Op cost = op-driver run - this run.
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


    ecall
