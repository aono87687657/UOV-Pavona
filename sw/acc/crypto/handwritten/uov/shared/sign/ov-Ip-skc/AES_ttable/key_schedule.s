/* AES-128 Key Schedule (T-table flavour) for ACC.
 *
 * Expands a 16-byte master key into 11 round keys (176 bytes packed) using
 * AES128_TABLE for the SubWord lookup. Pure GPR — no WDR/WSR/CSR usage.
 *
 * Calling convention:
 *   x10 (a0) = pointer to 16-byte input key         (read, preserved)
 *   x11 (a1) = pointer to 176-byte round-key buffer (advanced; final value
 *              points at the LAST round key = base + 160)
 *   x1  (ra) = link
 *
 * Assumes:
 *   - AES128_TABLE symbol resolvable (provides 4 KiB interleaved T-table;
 *     each entry's offset +0 holds Te2 whose LSB = S[x], so `lw + andi 0xff`
 *     returns the S-box value with no extra table)
 *
 * Clobbers:  x5..x8, x12..x18, x29, x30, x31
 * Preserves: every other GPR (x0..x4, x9, x10, x19..x28) and all
 *            WDRs/WSRs/CSRs.
 *
 * Output round-key layout at *x11 (caller's input pointer):
 *   offset  0..15   = round key 0  (= input key, copied verbatim)
 *   offset 16..31   = round key 1
 *   ...
 *   offset 160..175 = round key 10
 */

.section .text
.globl AES_128_keyschedule
AES_128_keyschedule:

    #round 0: copy key into rk[0] (col0..col3 of rk[0] = input key bytes 0..15)
    lw   x5,  0(x10)             # col0 = key[0..3]
    lw   x6,  4(x10)             # col1
    lw   x7,  8(x10)             # col2
    lw   x8, 12(x10)             # col3
    sw   x5,  0(x11)
    sw   x6,  4(x11)
    sw   x7,  8(x11)
    sw   x8, 12(x11)

    la   x29, AES128_TABLE       # T-table base (offset +0 of each entry holds S[x] in byte 0)
    li   x31, 0xff0              # byte index pre-multiplied by 16 (entry size)
    addi x18, x0, 1              # Rcon = 0x01 (round 1 init)

    #10 rounds. each iter: prev rk in x5..x8 (col0..col3) -> new rk in x5..x8
    loopi 10, 43
      slli x30, x8,  4              # Pass: extract 4 bytes from col3 (last word of prev rk)
      and  x15, x30, x31            # x15 = byte0(col3) *16
      srli x30, x8,  4
      and  x12, x30, x31            # x12 = byte1(col3) *16
      srli x30, x8, 12
      and  x13, x30, x31            # x13 = byte2(col3) *16
      srli x30, x8, 20
      and  x14, x30, x31            # x14 = byte3(col3) *16
      add  x30, x12, x29            # SubWord via Te2 LSB; S-box from AES128_TABLE
      lw   x12, 0(x30)
      andi x12, x12, 0xff           # x12 = S[byte1(col3)]
      add  x30, x13, x29
      lw   x13, 0(x30)
      andi x13, x13, 0xff           # x13 = S[byte2(col3)]
      add  x30, x14, x29
      lw   x14, 0(x30)
      andi x14, x14, 0xff           # x14 = S[byte3(col3)]
      add  x30, x15, x29
      lw   x15, 0(x30)
      andi x15, x15, 0xff           # x15 = S[byte0(col3)]
      xor  x5, x5,  x18             # new col0 XOR Rcon  (in byte 0)
      xor  x5, x5,  x12             # new col0 XOR S[byte1(col3)] in byte 0  (= RotWord+SubWord)
      slli x13, x13, 8
      xor  x5, x5,  x13             # new col0 XOR S[byte2(col3)] in byte 1
      slli x14, x14, 16
      xor  x5, x5,  x14             # new col0 XOR S[byte3(col3)] in byte 2
      slli x15, x15, 24
      xor  x5, x5,  x15             # new col0 XOR S[byte0(col3)] in byte 3  (RotWord wrap)
      xor  x6, x6,  x5              # new col1 = prev col1 XOR new col0
      xor  x7, x7,  x6              # new col2 = prev col2 XOR new col1
      xor  x8, x8,  x7              # new col3 = prev col3 XOR new col2
      addi x11, x11, 16             # advance buf to next rk slot
      sw   x5,  0(x11)
      sw   x6,  4(x11)
      sw   x7,  8(x11)
      sw   x8, 12(x11)
      slli x16, x18, 1              # Rcon update (xtime, branchless): low 8 bits
      andi x16, x16, 0xff
      andi x17, x18, 0x80           # mask MSB of prev Rcon
      srli x17, x17, 7              # 0 or 1
      sub  x17, x0,  x17            # 0 or 0xffffffff (sign-extend)
      andi x17, x17, 0x1b           # 0x1b iff prev MSB set (GF reduction poly)
      xor  x18, x16, x17            # new Rcon = (prev*x) mod 0x11b

    ret
