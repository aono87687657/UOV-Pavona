/* aes128_col_is single Is-pkc col (32 B = 2 AES-128 blocks) via T-table.
 *
 * Wraps two AES-128-CTR blocks back-to-back, building IV in registers
 * (no DMEM round-trip for nonce), running AES_128_encrypt for each block
 * into a 32 B scratch buffer, then bn.lid'ing the result into w13.
 *
 * Equivalent to "1 dual-block aes128 call = 1 col" in ov-verify/ov-Is-pkc
 * (which uses HW bn.aes128.encf). For the gf-only / aestable SW path
 * AES_128_encrypt is a single-block T-table function, so 2 calls per col.
 *
 * Calling convention:
 *   x13   IN/OUT: LE counter, chained across calls (0,2,4,...)
 *   x18   rk base, survivor reg set by publicmap setup
 *   x3    frame ptr (= initial-x2 - 32); 20(x3) = 32 B scratch buf base
 *   AES128_TABLE symbol must resolve
 *
 * Output:
 *   w13   = 32 B = 64 GF16 nibbles = 1 P column (2 AES blocks concat)
 *
 * Clobbers GPR: x5..x16, x19..x22, x29..x31 (= AES_128_encrypt clobber +
 *                own scratch: x6, x7, x9, x10..x12, x30)
 * Clobbers WDR: w13
 * Preserves:    x0..x4, x17, x18, x23..x28; all WDRs except w13.
 */

.section .text
.balign 4
.global aes128_col_is
aes128_col_is:
    lw   x30, 20(x3)             # x30 = 32 B scratch buf base (P1-buf slot, alignment OK)
    addi x9,  x13, 0             # local LE counter (preserves caller's x13 across the loop)

    loopi 2, 22                  # 2 blocks = 32 B = 1 col
      andi x6, x9, 0xff
      slli x6, x6, 24
      srli x7, x9, 8
      andi x7, x7, 0xff
      slli x7, x7, 16
      or   x6, x6, x7
      srli x7, x9, 16
      andi x7, x7, 0xff
      slli x7, x7, 8
      or   x6, x6, x7
      srli x7, x9, 24
      or   x6, x6, x7
      sw   x0,  0(x30)
      sw   x0,  4(x30)
      sw   x0,  8(x30)
      sw   x6, 12(x30)           #IV: 12B nonce(0) || BE counter
      addi x10, x18, 0           #rk base
      addi x11, x30, 0           #encrypt input  = scratch slot
      addi x12, x30, 0           #encrypt output = same slot (in-place)
      jal  x1, AES_128_encrypt
      addi x9,  x9,  1
      addi x30, x30, 16

    addi x13, x9, 0              #return updated counter to caller

    lw   x30, 20(x3)             #reload scratch base for bn.lid (advanced inside loop)
    li   x6, 13
    bn.lid x6, 0(x30)            #w13 = full 32 B col (both blocks concat)
    ret
