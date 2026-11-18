/* Test driver: AES-128 key schedule only.
 * Caller can inject `key` and read `round_keys` from DMEM.
 */

.section .data
.balign 4
.globl key
key:
    .zero 16
.balign 4
.globl round_keys
round_keys:
    .zero 176

.section .text.start
.globl _start
_start:
    la x10, key
    la x11, round_keys
    jal x1, AES_128_keyschedule
    ecall
