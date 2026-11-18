.section .text
.global cpk_pack
.balign 4
/* cpk_pack (Is): cpk = pk_seed(16B) || P3(2080 x 32B = 66,560B) = 66,576B.
 * Is P3 already compact -> straight GPR word-copy.
 * in:  x10 = cpk out base ; x11 = P3 src (66,560B) ; x12 = pk_seed src (16B)
 * out: cpk at x10
 * overlap: forward copy, needs x11 >= x10+16 (not a general memmove)
 * clobber: x13..x17. leaf.
 */
cpk_pack:
    # Phase 1: copy P3 block: 66,560B = 16,640 words, contiguous
    addi x13, x10, 16            # dst = cpk + 16
    add  x14, x0,  x11           # src = P3 base
    li   x15, 16640              # total words (66,560 / 4)
    loop x15, 4
        lw   x17, 0(x14)
        sw   x17, 0(x13)
        addi x14, x14, 4
        addi x13, x13, 4
    # Phase 2: prepend pk_seed (4 words = 16B)
    add  x13, x0, x10            # dst = cpk base
    add  x14, x0, x12            # src = pk_seed
    li   x16, 4
    loop x16, 4
        lw   x17, 0(x14)
        sw   x17, 0(x13)
        addi x14, x14, 4
        addi x13, x13, 4
    ret
