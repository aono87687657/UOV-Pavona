/* Test driver: AES-128 encrypt only.
 * Caller should preload `round_keys` and `plaintext` in DMEM.
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
    jal x1, AES_128_encrypt
    ecall
