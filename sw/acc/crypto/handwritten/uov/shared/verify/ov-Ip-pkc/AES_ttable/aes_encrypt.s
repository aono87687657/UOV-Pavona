/* AES-128 Encrypt (T-table flavour) for ACC.
 *
 * Encrypts one 16-byte plaintext block to ciphertext using 11 pre-expanded
 * round keys. Pure GPR no WDR/WSR/CSR usage.
 *
 * Calling convention:
 *   x10 (a0)  = pointer to 176-byte round-key buffer (input, advanced past end)
 *   x11 (a1)  = pointer to 16-byte plaintext         (input, preserved)
 *   x12 (a2)  = pointer to 16-byte ciphertext        (output, preserved)
 *   x1  (ra)  = link register                        (preserved)
 *
 * Assumes:
 *   - 11 round keys (176 B) already expanded at *x10 by AES_128_keyschedule
 *   - AES128_TABLE symbol resolvable (provides 4 KiB interleaved T-table)
 *
 * Clobbers:  x5..x8, x13..x16, x19..x22, x29, x31
 * Preserves: every other GPR (x0, x1, x2..x4, x9, x11, x12, x17, x18,
 *            x23..x28, x30) and all WDRs/WSRs/CSRs.
 */

.section .text
.globl AES_128_encrypt
AES_128_encrypt:

    #load plaintext (4 LE words = 4 columns)
    lw   x5,  0(x11)
    lw   x6,  4(x11)
    lw   x7,  8(x11)
    lw   x8, 12(x11)

    #initial AddRoundKey with RK[0], advance to RK[1]
    lw   x13,  0(x10)
    lw   x14,  4(x10)
    lw   x15,  8(x10)
    lw   x16, 12(x10)
    addi x10, x10, 16
    xor  x5, x5, x13
    xor  x6, x6, x14
    xor  x7, x7, x15
    xor  x8, x8, x16

    la   x29, AES128_TABLE       # T-table base
    li   x31, 0xff0              # byte index pre-multiplied by 16 (entry size)

    loopi 9, 89
      lw   x13,  0(x10)              # load RK[j=0]
      lw   x14,  4(x10)              # RK[j=1]
      lw   x15,  8(x10)              # RK[j=2]
      lw   x16, 12(x10)              # RK[j=3]
      addi x10, x10, 16              # rk advance
      andi x19, x5, 0xff             # Pass 1: byte0 of col[j], Te0 lookup (offset +4)
      andi x20, x6, 0xff             # byte0(col1)
      andi x21, x7, 0xff             # byte0(col2)
      andi x22, x8, 0xff             # byte0(col3)
      slli x19, x19, 4               # *16 = entry off
      slli x20, x20, 4
      slli x21, x21, 4
      slli x22, x22, 4
      add  x19, x19, x29
      lw   x19, 4(x19)               # Te0[byte0(col0)]   0x03010102
      add  x20, x20, x29
      lw   x20, 4(x20)               # Te0[byte0(col1)]
      add  x21, x21, x29
      lw   x21, 4(x21)               # Te0[byte0(col2)]
      add  x22, x22, x29
      lw   x22, 4(x22)               # Te0[byte0(col3)]
      xor  x13, x13, x19             # Y0 XOR Te0
      xor  x14, x14, x20             # Y1 XOR Te0
      xor  x15, x15, x21             # Y2 XOR Te0
      xor  x16, x16, x22             # Y3 XOR Te0
      srli x5, x5, 4                 # Pass 2: byte1 of col[(j+1)%4], Te1 lookup (offset +12)
      srli x6, x6, 4
      srli x7, x7, 4
      srli x8, x8, 4
      and  x19, x6, x31              # byte1(col1) *16
      and  x20, x7, x31              # byte1(col2)
      and  x21, x8, x31              # byte1(col3)
      and  x22, x5, x31              # byte1(col0) wrap
      add  x19, x19, x29
      lw   x19, 12(x19)              # Te1[byte1(col1)]   0x01010203
      add  x20, x20, x29
      lw   x20, 12(x20)              # Te1[byte1(col2)]
      add  x21, x21, x29
      lw   x21, 12(x21)              # Te1[byte1(col3)]
      add  x22, x22, x29
      lw   x22, 12(x22)              # Te1[byte1(col0)] wrap
      xor  x13, x13, x19             # Y0 XOR Te1
      xor  x14, x14, x20             # Y1 XOR Te1
      xor  x15, x15, x21             # Y2 XOR Te1
      xor  x16, x16, x22             # Y3 XOR Te1
      srli x5, x5, 8                 # Pass 3: byte2 of col[(j+2)%4], Te2 lookup (offset +0)
      srli x6, x6, 8
      srli x7, x7, 8
      srli x8, x8, 8
      and  x19, x7, x31              # byte2(col2) *16
      and  x20, x8, x31              # byte2(col3)
      and  x21, x5, x31              # byte2(col0) wrap
      and  x22, x6, x31              # byte2(col1) wrap
      add  x19, x19, x29
      lw   x19, 0(x19)               # Te2[byte2(col2)]   0x01020301
      add  x20, x20, x29
      lw   x20, 0(x20)               # Te2[byte2(col3)]
      add  x21, x21, x29
      lw   x21, 0(x21)               # Te2[byte2(col0)] wrap
      add  x22, x22, x29
      lw   x22, 0(x22)               # Te2[byte2(col1)] wrap
      xor  x13, x13, x19             # Y0 XOR Te2
      xor  x14, x14, x20             # Y1 XOR Te2
      xor  x15, x15, x21             # Y2 XOR Te2
      xor  x16, x16, x22             # Y3 XOR Te2
      srli x5, x5, 8                 # Pass 4: byte3 of col[(j+3)%4], Te3 lookup (offset +8)
      srli x6, x6, 8
      srli x7, x7, 8
      srli x8, x8, 8
      and  x19, x8, x31              # byte3(col3) *16
      and  x20, x5, x31              # byte3(col0) wrap
      and  x21, x6, x31              # byte3(col1) wrap
      and  x22, x7, x31              # byte3(col2) wrap
      add  x19, x19, x29
      lw   x19, 8(x19)               # Te3[byte3(col3)]   0x02030101
      add  x20, x20, x29
      lw   x20, 8(x20)               # Te3[byte3(col0)] wrap
      add  x21, x21, x29
      lw   x21, 8(x21)               # Te3[byte3(col1)] wrap
      add  x22, x22, x29
      lw   x22, 8(x22)               # Te3[byte3(col2)] wrap
      xor  x13, x13, x19             # Y0 XOR Te3
      xor  x14, x14, x20             # Y1 XOR Te3
      xor  x15, x15, x21             # Y2 XOR Te3
      xor  x16, x16, x22             # Y3 XOR Te3
      addi x5,  x13, 0               # col <- Y, ready for next round
      addi x6,  x14, 0
      addi x7,  x15, 0
      addi x8,  x16, 0

    #final round: no MixColumns, S-box only via lw + andi 0xff
    lw   x13,  0(x10)            # load RK[10]
    lw   x14,  4(x10)
    lw   x15,  8(x10)
    lw   x16, 12(x10)

    #Pass 1: byte0 of col[j], no shift, lands in byte 0 of Y[j]
    andi x19, x5, 0xff           # byte0(col0)
    andi x20, x6, 0xff           # byte0(col1)
    andi x21, x7, 0xff           # byte0(col2)
    andi x22, x8, 0xff           # byte0(col3)
    slli x19, x19, 4             # *16 = entry off
    slli x20, x20, 4
    slli x21, x21, 4
    slli x22, x22, 4
    add  x19, x19, x29
    lw   x19, 0(x19)
    andi x19, x19, 0xff          # S[byte0(col0)]
    add  x20, x20, x29
    lw   x20, 0(x20)
    andi x20, x20, 0xff          # S[byte0(col1)]
    add  x21, x21, x29
    lw   x21, 0(x21)
    andi x21, x21, 0xff          # S[byte0(col2)]
    add  x22, x22, x29
    lw   x22, 0(x22)
    andi x22, x22, 0xff          # S[byte0(col3)]
    xor  x13, x13, x19           # Y0 XOR S
    xor  x14, x14, x20           # Y1 XOR S
    xor  x15, x15, x21           # Y2 XOR S
    xor  x16, x16, x22           # Y3 XOR S

    #Pass 2: byte1 of col[(j+1)%4], shift result <<8
    srli x5, x5, 4
    srli x6, x6, 4
    srli x7, x7, 4
    srli x8, x8, 4
    and  x19, x6, x31            # byte1(col1) *16
    and  x20, x7, x31            # byte1(col2)
    and  x21, x8, x31            # byte1(col3)
    and  x22, x5, x31            # byte1(col0) wrap
    add  x19, x19, x29
    lw   x19, 0(x19)
    andi x19, x19, 0xff          # S[byte1(col1)]
    add  x20, x20, x29
    lw   x20, 0(x20)
    andi x20, x20, 0xff          # S[byte1(col2)]
    add  x21, x21, x29
    lw   x21, 0(x21)
    andi x21, x21, 0xff          # S[byte1(col3)]
    add  x22, x22, x29
    lw   x22, 0(x22)
    andi x22, x22, 0xff          # S[byte1(col0)] wrap
    slli x19, x19, 8             # << 8 to byte 1
    slli x20, x20, 8
    slli x21, x21, 8
    slli x22, x22, 8
    xor  x13, x13, x19           # Y0 XOR S<<8
    xor  x14, x14, x20           # Y1 XOR S<<8
    xor  x15, x15, x21           # Y2 XOR S<<8
    xor  x16, x16, x22           # Y3 XOR S<<8

    #Pass 3: byte2 of col[(j+2)%4], shift result <<16
    srli x5, x5, 8
    srli x6, x6, 8
    srli x7, x7, 8
    srli x8, x8, 8
    and  x19, x7, x31            # byte2(col2) *16
    and  x20, x8, x31            # byte2(col3)
    and  x21, x5, x31            # byte2(col0) wrap
    and  x22, x6, x31            # byte2(col1) wrap
    add  x19, x19, x29
    lw   x19, 0(x19)
    andi x19, x19, 0xff          # S[byte2(col2)]
    add  x20, x20, x29
    lw   x20, 0(x20)
    andi x20, x20, 0xff          # S[byte2(col3)]
    add  x21, x21, x29
    lw   x21, 0(x21)
    andi x21, x21, 0xff          # S[byte2(col0)] wrap
    add  x22, x22, x29
    lw   x22, 0(x22)
    andi x22, x22, 0xff          # S[byte2(col1)] wrap
    slli x19, x19, 16            # << 16 to byte 2
    slli x20, x20, 16
    slli x21, x21, 16
    slli x22, x22, 16
    xor  x13, x13, x19           # Y0 XOR S<<16
    xor  x14, x14, x20           # Y1 XOR S<<16
    xor  x15, x15, x21           # Y2 XOR S<<16
    xor  x16, x16, x22           # Y3 XOR S<<16

    #Pass 4: byte3 of col[(j+3)%4], shift result <<24
    srli x5, x5, 8
    srli x6, x6, 8
    srli x7, x7, 8
    srli x8, x8, 8
    and  x19, x8, x31            # byte3(col3) *16
    and  x20, x5, x31            # byte3(col0) wrap
    and  x21, x6, x31            # byte3(col1) wrap
    and  x22, x7, x31            # byte3(col2) wrap
    add  x19, x19, x29
    lw   x19, 0(x19)
    andi x19, x19, 0xff          # S[byte3(col3)]
    add  x20, x20, x29
    lw   x20, 0(x20)
    andi x20, x20, 0xff          # S[byte3(col0)] wrap
    add  x21, x21, x29
    lw   x21, 0(x21)
    andi x21, x21, 0xff          # S[byte3(col1)] wrap
    add  x22, x22, x29
    lw   x22, 0(x22)
    andi x22, x22, 0xff          # S[byte3(col2)] wrap
    slli x19, x19, 24            # << 24 to byte 3
    slli x20, x20, 24
    slli x21, x21, 24
    slli x22, x22, 24
    xor  x13, x13, x19           # Y0 XOR S<<24
    xor  x14, x14, x20           # Y1 XOR S<<24
    xor  x15, x15, x21           # Y2 XOR S<<24
    xor  x16, x16, x22           # Y3 XOR S<<24

    #store ciphertext
    sw   x13,  0(x12)
    sw   x14,  4(x12)
    sw   x15,  8(x12)
    sw   x16, 12(x12)

    ret
