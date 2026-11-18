.section .text
.global cpk_pack
.balign 4
/* cpk_pack (Ip): cpk = pk_seed(16B) || compact_P3(990 x 44B = 43,560B) = 43,576B.
 * On-ACC P3 is 64B-padded/entry; this compacts 64->44 and prepends pk_seed (GPR copy).
 * in:  x10 = cpk out base ; x11 = padded P3 src (990 x 64B) ; x12 = pk_seed src (16B)
 * out: cpk at x10
 * overlap: forward copy (dst stride 44 < src 64), needs x11 >= x10+16 (not a memmove)
 * clobber: x13..x17. leaf.
 */
cpk_pack:
    # Phase 1: compact P3 ; 990 entries: copy 11 words (44B), skip 5 (20B)
    addi x13, x10, 16            # dst = cpk + 16
    add  x14, x0,  x11           # src = padded P3 base
    li   x15, 990                # entry counter
    li   x16, 11                 # 11 words per compact entry (inner loop preserves x16)
    loop x15, 6
        loop x16, 4
            lw   x17, 0(x14)
            sw   x17, 0(x13)
            addi x14, x14, 4
            addi x13, x13, 4
        addi x14, x14, 20        # skip 5 pad words: src -> next 64B entry
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
