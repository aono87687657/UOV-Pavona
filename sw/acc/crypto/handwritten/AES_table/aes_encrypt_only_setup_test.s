/* Baseline for aes_encrypt_only_test: identical pointer setup, no
 * call. Op cost = encrypt run - this run.
 */

.section .data
.balign 4
.globl round_keys
round_keys:
    .zero 176
.balign 4
.globl plaintext
plaintext:
    .zero 16
.balign 4
.globl ciphertext
ciphertext:
    .zero 16

.section .text.start
.globl _start
_start:
    la x10, round_keys
    la x11, plaintext
    la x12, ciphertext
    ecall
