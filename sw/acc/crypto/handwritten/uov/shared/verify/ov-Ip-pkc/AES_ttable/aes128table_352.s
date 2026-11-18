/* AES-128-CTR PRG: encrypts 22 counter blocks (= 352 bytes) into caller's buffer.
 * For UOV pk_seed P1/P2 expansion (no plaintext, no XOR keystream IS output).
 *
 * Calling convention:
 *   x10 (a0) = pointer to 176-byte pre-expanded round-key buffer (input)
 *   x11 (a1) = pointer to 352-byte output buffer (also used as per-block IV scratch)
 *   x13 (a3) = IN: starting LE counter (0 for first call)
 *              OUT: ending LE counter = start + 22 (caller chains back for next call)
 *   x1  (ra) = link
 *
 * Block count is fixed (22) by the routine name; no N argument.
 *
 * Clobbers:  x6, x7, x9, x10..x12, x28, x30, plus everything AES_128_encrypt clobbers
 *            (x13 written at exit)
 * Preserves: every other GPR and all WDRs/WSRs/CSRs.
 */

.section .text
.globl aes128table_352
aes128table_352:
    addi x28, x10, 0             # save rk base (encrypt clobbers x10)
    addi x30, x11, 0             # output ptr (advances per block, doubles as IV slot)

    addi x9, x13, 0              # load LE counter from caller (a3); 0 for first call, prev-end for chained

    loopi 22, 22                 # 22 blocks of 22 insn each
      andi x6, x9, 0xff            # bswap32(counter) -> x6 ; byte 0 of counter
      slli x6, x6, 24              # to byte 3 of x6
      srli x7, x9, 8
      andi x7, x7, 0xff            # byte 1 of counter
      slli x7, x7, 16              # to byte 2
      or   x6, x6, x7
      srli x7, x9, 16
      andi x7, x7, 0xff            # byte 2 of counter
      slli x7, x7, 8               # to byte 1
      or   x6, x6, x7
      srli x7, x9, 24              # byte 3 of counter (no mask, high bits zero)
      or   x6, x6, x7
      sw   x0,  0(x30)             # IV nonce[0..3]   = 0
      sw   x0,  4(x30)             # IV nonce[4..7]   = 0
      sw   x0,  8(x30)             # IV nonce[8..11]  = 0
      sw   x6, 12(x30)             # IV[12..15] = BE(counter)
      addi x10, x28, 0             # rk base for this call
      addi x11, x30, 0             # encrypt input ptr  = current output slot
      addi x12, x30, 0             # encrypt output ptr = same slot (in-place encrypt)
      jal  x1, AES_128_encrypt
      addi x9,  x9,  1             # counter++
      addi x30, x30, 16            # output += 16

    addi x13, x9, 0              # return updated counter (for chaining)
    ret                          # pops original caller's PC from x1 call stack
