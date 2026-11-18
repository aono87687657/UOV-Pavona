/* Test driver for AES-128-CTR keystream (T-table flavour).
 *
 * Flow:
 *   1. Expand `key` (16 B) into `round_keys` (176 B) via AES_128_keyschedule.
 *   2. Read `num_rounds` from DMEM (Python harness injects; default 1).
 *   3. Loop num_rounds times: call aes128table_352 with chaining via x13.
 *      Each round overwrites ctr_keystream with the next 352 B; final round
 *      wins. Counter persists across rounds, so total bytes generated =
 *      num_rounds * 352, but only the LAST 352 are kept.
 *   4. ecall to halt.
 */
.section .data

.balign 4
.globl key
key:
    .zero 16

.balign 4
.globl ctr_keystream
ctr_keystream:
    .zero 352                    /* 16 * NUM_BLOCKS = 22 * 16 */

.balign 4
.globl round_keys
round_keys:
    .zero 176

.balign 4
.globl num_rounds
num_rounds:
    .word 1                      /* default 1 round; Python harness overrides */


.section .text.start
.globl _start
_start:
    la   x10, key
    la   x11, round_keys
    jal  x1, AES_128_keyschedule

    la   x14, num_rounds
    lw   x14, 0(x14)             # x14 = number of 352-byte rounds (>=1)
    la   x18, round_keys         # rk base, hoisted (must survive encrypt's x13..x16 clobber)
    la   x17, ctr_keystream      # output buf, hoisted (also outside encrypt's clobber set)
    addi x13, x0, 0              # counter starts at 0; threads through rounds via x13

    loop x14, 4                  # body = 4 insn (jal + nop trailing per ISA rule)
      addi x10, x18, 0
      addi x11, x17, 0
      jal  x1, aes128table_352
      nop                        # jal must not be last insn of loop body

    ecall


