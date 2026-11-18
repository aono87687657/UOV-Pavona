/* Test driver for AES-128 T-table (key schedule + encrypt).
 *
 * Flow:
 *   1. Expand 16-byte `key` into 176-byte `round_keys` buffer.
 *   2. Encrypt 16-byte `plaintext` into 16-byte `ciphertext` using those
 *      round keys.
 *   3. ecall to halt.
 *
 * Caller (Python harness) injects `key` and `plaintext`, then reads
 * `round_keys` and `ciphertext` back from DMEM.
 */

.section .data
.balign 4
.globl key
key:
    .zero 16
.balign 4
.globl plaintext
plaintext:
    .zero 16
.balign 32
.globl ciphertext
ciphertext:
    .zero 16
.balign 4
.globl round_keys
round_keys:
    .zero 176

.section .text.start
.globl _start
_start:
    /* --- Key schedule --- */
    la   x10, key
    la   x11, round_keys
    jal  x1, AES_128_keyschedule

    /* --- Encrypt --- */
    la   x10, round_keys
    la   x11, plaintext
    la   x12, ciphertext
    jal  x1, AES_128_encrypt

    ecall


