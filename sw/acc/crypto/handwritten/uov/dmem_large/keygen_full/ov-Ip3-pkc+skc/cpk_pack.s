.section .text
.global cpk_pack
.balign 4
/* cpk_pack (Ip3): cpk = pk_seed (16B) || 1,035 x 45B P3 slots = 46,591B.
 * Each 64B tri cell goes to its 45B slot through the masked slot writer.
 * in:  x10 = cpk out base, 32B-aligned; 46,592B writable and initialized
 *            (the last slot's tail word ends at byte 46,591)
 *      x11 = tri (1,035 x 64B cells) ; x12 = pk_seed (16B)
 * out: cpk at the entry value of x10
 * clob: x8, x10, x16, x17, x19, x21-x30. leaf apart from _slot_write.
 */
cpk_pack:
    lw   x8, 0(x12)
    sw   x8, 0(x10)
    lw   x8, 4(x12)
    sw   x8, 4(x10)
    lw   x8, 8(x12)
    sw   x8, 8(x10)
    lw   x8, 12(x12)
    sw   x8, 12(x10)

    addi x22, x10, 16
    add  x24, x0, x11
    li   x16, -1                # plain mode
    li   x8, 1035
    loop x8, 3
        jal  x1, _slot_write    # x24 += 48
        addi x22, x22, 45
        addi x24, x24, 16
    ret

/* Write one 45B entry. in: x22 = dst byte address (any alignment), x24 = src
 * (4B-aligned, 48B readable), x16 = -1 plain / 0 XOR. out: x24 += 48.
 * clob: x10, x17, x19, x21, x23, x25-x30. 12 dst words: head (mask ~0 << 8a),
 * 10 full, tail (mask ~0 >> (24-8a)); v_i = u_{i-1} >> (32-8a) | u_i << 8a,
 * the >>32 case split as >>(31-8a) >>1. d ^= ((d & mode) ^ v) & mask:
 * mode -1 replaces the owned bytes, mode 0 XORs them; neighbours' bytes in
 * the shared head/tail words are never touched. */
_slot_write:
    andi x17, x22, 3
    slli x17, x17, 3          /* s = 8a */
    li   x19, 31
    sub  x19, x19, x17        /* 31 - s */
    andi x10, x22, -4         /* aligned write cursor */
    li   x21, -1
    sll  x21, x21, x17        /* head mask */
    li   x23, 24
    sub  x23, x23, x17
    li   x25, -1
    srl  x25, x25, x23        /* tail mask */
    lw   x27, 0(x24)          /* u0 */
    sll  x28, x27, x17        /* v0 (no carry-in) */
    lw   x29, 0(x10)
    and  x30, x29, x16
    xor  x30, x30, x28
    and  x30, x30, x21
    xor  x29, x29, x30
    sw   x29, 0(x10)
    addi x10, x10, 4
    addi x24, x24, 4
    add  x26, x27, x0         /* prev = u0 */
    loopi 10, 13
        lw   x27, 0(x24)
        srl  x28, x26, x19
        srli x28, x28, 1
        sll  x30, x27, x17
        or   x28, x28, x30    /* v_i */
        lw   x29, 0(x10)
        and  x30, x29, x16
        xor  x30, x30, x28
        xor  x29, x29, x30
        sw   x29, 0(x10)
        addi x10, x10, 4
        addi x24, x24, 4
        add  x26, x27, x0
    lw   x27, 0(x24)          /* u11: byte 44 + pad (masked) */
    srl  x28, x26, x19
    srli x28, x28, 1
    sll  x30, x27, x17
    or   x28, x28, x30
    lw   x29, 0(x10)
    and  x30, x29, x16
    xor  x30, x30, x28
    and  x30, x30, x25
    xor  x29, x29, x30
    sw   x29, 0(x10)
    addi x24, x24, 4
    ret
