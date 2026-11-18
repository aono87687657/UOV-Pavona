/* ov-Is-pkc_verify_full_sw.s - one-shot UOV-Is verify, software-GF arms
 * (swonly = T-table AES; -DAES_INSTRUCTIONS = bnaesonly: the same body linked
 * with aes128hw_col_is and the AES_ext key schedule), whole cpk resident: host
 * writes cpk (66,576B at 16 mod 32), msg_len, msg, sig; ONE EXECUTE; reads
 * result: 0 accept, -1 reject, -2 msg_len > 1,024, -5 while running. Bodies
 * are the streamed kernel's INIT (KMAC target + P1/P2 -> acc in w25), UPDATE
 * (P3 fold, one pass over all 64 rows) and FINAL; the seed is copied from the
 * cpk prefix and the oil vector from sig[48..79] by the kernel. Host contract
 * = ov-Is-pkc_verify_full.s.
 * Map: hdr@0 acc@0x20 oil@0x40 target@0x60 sig@0x80 seed@0xE0 msg@0x100
 * cpk@0x510, then the gf16 mask and sfk_stack (32B frame | 192B rk | 32B
 * column buffer).
 * clob: everything (app, no caller).
 * stack: 256B at sfk_stack, both arms (x2 descends from sfk_stack_end); call
 * depth 2 (aes128_col_is -> AES_128_encrypt; the AES_ext key schedule -> its
 * round store).
 */
#ifdef GF_INSTRUCTIONS
#error "gfsw source: GF is always software here, so -DGF_INSTRUCTIONS is never correct on it -- a _bngfonly target aimed at this file reports swonly cycles under a hardware-GF name. Build ov-Is-pkc_verify_full.s for that tier."
#endif
.section .data
.balign 32
hdr:       .zero 32              /* 0x000: +4 msg_len (host), +12 result (kernel) */
accctx:    .zero 32              /* 0x020 acc, INIT -> P3 pass -> FINAL */
oil:       .zero 32              /* 0x040 sig[48..79], written by INIT's tail */
target:    .zero 32              /* 0x060 KMAC digest, INIT -> FINAL */
sig:       .zero 96              /* 0x080: 96B sig (host) */
seed:      .zero 32              /* 0x0E0: cpk[0:16] zero-extended, written at entry */
msg:       .zero 1024            /* 0x100: 32B granules, zero tail */
           .zero 16              /* 0x500: puts the P3 entries on 32B */
cpk:       .zero 16              /* 0x510: 66,576B key = 16B seed + P3 */
cpk_p3:    .zero 66560           /* 0x520: 2,080 entries of 32B */
/* gf16_mul msb mask (loaded to w3) */
.balign 32
sfk_msb:
    .word 0x88888888,0x88888888,0x88888888,0x88888888
    .word 0x88888888,0x88888888,0x88888888,0x88888888
/* private stack, in the image: 32B frame | 192B rk | 32B column buffer */
.balign 32
sfk_stack:
    .zero 256
sfk_stack_end:

.section .text.start
.balign 4
.global main
main:
    li   x3, 0x00
    li   x6, -5
    sw   x6, 12(x3)           /* result = running */
    lw   x14, 4(x3)           /* msg_len */
    srli x5, x14, 15          /* wrap-safe: len >= 2^15 first */
    bne  x5, x0, _len_bad
    li   x5, 1024
    sub  x5, x5, x14
    srli x5, x5, 31
    bne  x5, x0, _len_bad     /* len > 1,024 */
    /* seed := cpk[0:16], zero-extended to the 32B word the bodies read */
    la   x10, cpk
    li   x12, 0x0E0
    lw   x5, 0(x10)
    sw   x5, 0(x12)
    lw   x5, 4(x10)
    sw   x5, 4(x12)
    lw   x5, 8(x10)
    sw   x5, 8(x12)
    lw   x5, 12(x10)
    sw   x5, 12(x12)
    sw   x0, 16(x12)
    sw   x0, 20(x12)
    sw   x0, 24(x12)
    sw   x0, 28(x12)
    jal  x0, _INIT
_len_bad:
    li   x6, -2
    jal  x0, _done

/* ============================ INIT ============================ */
_INIT:
    li   x3, 0x00
    lw   x14, 4(x3)          /* msg_len */
    li   x10, 0x080          /* sig */
    li   x12, 0x0E0          /* seed */
    li   x13, 0x100          /* msg */

    bn.xor w31, w31, w31
    addi x5, x14, 16
    slli x5, x5, 5
    ori  x5, x5, 0xA
    csrrw x0, kmac_cfg, x5

    bn.ld w1, 64(x10)         /* salt */
    bn.rshi w1, w31, w1 >> 128

    beq  x14, x0, _msg_zero
    srli x5, x14, 5
    andi x6, x14, 0x1f
    beq  x5, x0, _msg_short
    loop x5, 27
        bn.lid x0, 0(x13++)
        bn.wsrw kmac_msg, w0
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
    beq  x6, x0, _msg_zero
_msg_short:
    csrrw x0, kmac_partial_write, x6
    bn.lid x0, 0(x13++)
    bn.wsrw kmac_msg, w0
_msg_zero:
    li   x5, 16
    csrrw x0, kmac_partial_write, x5
    bn.wsrw kmac_msg, w1

    /* p1p2 fold, from ov-Is-verify_backend.s sw arm (inline: no x1 save) */
    la   x2, sfk_stack_end    /* private stack, descending */
    la   x5, sfk_msb
    li   x6, 3
    bn.lid x6, 0(x5)          /* w3 = gf16_mul msb mask */
    li   x10, 0x80            /* sig */
    li   x11, 0x20            /* acc out */
    li   x12, 0xE0            /* seed = AES key */
    addi x2, x2, -32
    add  x3, x0, x2
    sw   x10,  0(x3)
    sw   x11,  4(x3)
    sw   x12,  8(x3)
    sw   x13, 12(x3)
    sw   x14, 16(x3)

    bn.xor w31, w31, w31           # zero const
    bn.xor w25, w25, w25            # accumulator = 0

    /* Packed AES key schedule, 176 B. */
    addi x2, x2, -192              # 176 B rk + 16 B align pad
    add  x10, x0, x12              # x10 = pk_seed pointer
    add  x11, x0, x2               # x11 = rk buffer base
    jal  x1, AES_128_keyschedule
    add  x18, x0, x2               # x18 = rk base survivor, set AFTER KS

    /* CTR + 32 B scratch buf for aes128_col_is (2 AES blocks = 1 col) */
    addi x13, x0, 0                # AES-CTR LE counter starts at 0
    addi x2, x2, -32
    add  x4, x0, x2
    sw   x4, 20(x3)                # buf base for helper to lw

    /* sig load + v / o window extract */
    li   x31, 5
    lw   x5, 0(x3)                 # x5 = sig base
    bn.lid x31++, 0(x5)            # w5 = bytes [0..31]   = v[0..63]
    bn.lid x31++, 32(x5)           # w6 = v[64..95] || o[0..31]
    bn.lid x31++, 64(x5)           # w7 = o[32..63] || salt
    bn.mov  w23, w5                # v-window lo (full 64 nibbles)
    bn.rshi w26, w7, w6 >> 128     # o-window = o[0..63]
    bn.rshi w24, w6, w31 >> 128
    bn.rshi w24, w31, w24 >> 128   # w24 = v[64..95] lo, 0 hi

    /* VxV. 96 rows, row i has 96-i entries. x17 = row ctr (survivor). */
    li x17, 96
    loopi 96, 18
        bn.mov w1, w23
        bn.mov w2, w23                   #scalar = v[i]
        jal x1, gf16_mul
        bn.mov w11, w0                   #coef lo = v[i]*v_window[0..63]
        bn.mov w1, w24
        jal x1, gf16_mul                  #w2 still = v[i]
        bn.mov w12, w0                   #coef hi
        loop x17, 7
            jal x1, aes128_col_is        #w13 = 1 col (32 B), x13 += 2
            bn.mov w1, w13
            bn.mov w2, w11
            jal x1, gf16_mul
            bn.xor  w25, w25, w0
            bn.rshi w11, w12, w11 >> 4
            bn.rshi w12, w31, w12 >> 4
        bn.rshi w23, w24, w23 >> 4
        bn.rshi w24, w31, w24 >> 4
        addi x17, x17, -1

    /* VxO setup: reload sig + rebuild windows */
    li   x31, 5
    lw   x6, 0(x3)
    bn.lid x31++, 0(x6)
    bn.lid x31++, 32(x6)
    bn.lid x31++, 64(x6)
    bn.mov  w23, w5
    bn.rshi w26, w7, w6 >> 128
    bn.rshi w24, w6, w31 >> 128
    bn.rshi w24, w31, w24 >> 128

    /* VxO. 96 rows x 64 cols, const inner. */
    loopi 96, 13
        bn.mov w1, w26
        bn.mov w2, w23                   #scalar = v[i]
        jal x1, gf16_mul
        bn.mov w11, w0                   #coef = v[i]*o[0..63]
        loopi 64, 6
            jal x1, aes128_col_is
            bn.mov w1, w13
            bn.mov w2, w11
            jal x1, gf16_mul
            bn.xor  w25, w25, w0
            bn.rshi w11, w31, w11 >> 4
        bn.rshi w23, w24, w23 >> 4
        bn.rshi w24, w31, w24 >> 4

    bn.wsrr w8, 0xA           /* 32B digest -> ctx.target */
    li   x3, 0x60
    bn.sd w8, 0(x3)
    li   x3, 0x20
    li   x6, 25
    bn.sid x6, 0(x3)          /* acc (w25) -> ctx */
    /* oil := sig[48..79], the 64 oil nibbles the P3 body reads */
    li   x3, 0x080
    bn.ld w5, 32(x3)          /* sig 32..63 */
    bn.ld w6, 64(x3)          /* sig 64..95 */
    bn.rshi w5, w6, w5 >> 128 /* bytes 48..79 */
    li   x3, 0x040
    bn.sd w5, 0(x3)

/* ---------------- P3 pass: the UPDATE body, rows 0..63 in one go ---------------- */
    li   x3, 0x00
    li   x9, 0                /* row_start */
    li   x8, 64               /* row_count */
    /* P3 row fold, from ov-Is-verify_backend.s sw arm (inline) */
    bn.xor w31, w31, w31
    la   x5, sfk_msb
    li   x6, 3
    bn.lid x6, 0(x5)          /* w3 = gf16_mul msb mask */
    li   x5, 0x20
    li   x6, 25
    bn.lid x6, 0(x5)          /* w25 = acc <- ctx */
    li   x5, 0x40
    li   x6, 26
    bn.lid x6, 0(x5)          /* w26 = o[0..63] */
    li   x23, 1               /* bn.lid dest w1: entries are aligned */
    la   x4, cpk_p3           /* resident P3: 2,080 aligned 32B entries */
    li   x7, 64
    sub  x7, x7, x9           /* first row size */
    loop x8, 13
    bn.mov w1, w26
    bn.mov w2, w26            # scalar = O[row]
    jal x1, gf16_mul
    bn.mov w11, w0            # coef = O[row]*o_window
    loop x7, 6
        bn.lid x23, 0(x4)     # w1 = entry (aligned)
        bn.mov w2, w11
        jal x1, gf16_mul
        bn.xor w25, w25, w0
        bn.rshi w11, w31, w11 >> 4
        addi x4, x4, 32
    bn.rshi w26, w31, w26 >> 4
    addi x7, x7, -1
    li   x5, 0x20
    li   x6, 25
    bn.sid x6, 0(x5)          /* acc -> ctx */

/* ============================ FINAL ============================ */
    li   x3, 0x20
    bn.ld w0, 0(x3)          /* acc */
    li   x3, 0x60
    bn.ld w8, 0(x3)          /* target */
    bn.cmp w0, w8, FG0
    csrrs x5, 0x7c0, x0
    srli x5, x5, 3
    andi x5, x5, 1           /* Z flag: 1 if acc == target */
    li   x3, 0x00
    beq  x5, x0, _F_fail
    li   x6, 0
    jal  x0, _done
_F_fail:
    li   x6, -1
_done:
    li   x3, 0x000
    sw   x6, 12(x3)           /* result: 0 accept, -1 reject, -2 bad msg_len */
    csrrw x0, mod1, x0
    ecall
