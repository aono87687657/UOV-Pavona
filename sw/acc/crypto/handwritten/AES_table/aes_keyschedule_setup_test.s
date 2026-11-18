/* Baseline for aes_keyschedule_test: identical pointer setup, no
 * call. Op cost = keyschedule run - this run.
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
    ecall
