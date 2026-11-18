.section .text
.balign 4
.global ov_keygen
/* ov_keygen (Ip3): on-ACC UOV pkc+skc keygen, single binary.
 *   sk_seed -> expandsk -> P1O_P2 -> P3_cal -> cpk_pack -> cpk ; csk = seed in place.
 * in:  x10 = cpk out base (46,591B + 1 pad, 32B-aligned, initialized: cpk_pack
 *            reads the last word before it writes it)
 *      x11 = sk_seed buffer (32B, 32B-aligned); read-only, left in place as csk
 *      x2  = stack top, 32B-aligned; peak 413,376B (P3_cal step: 283,744 own
 *            + the 129,632 P3_cal frame with its P3_full temp)
 * stack (below x2, high->low): frame 32 | expandsk 4352 (pk_seed, padded O) |
 *   B 213120 | tri 66240 (= 283744 own reserve). callees restore x2. exact peak.
 * clob: x3-x31, w0-w31, ACC, ACCH, FG0, kmac_msg, kmac_partial_write; mod0 = 0x11b,
 *   mod1 = 0, kmac_cfg off on exit.
 */
ov_keygen:
    # prologue: 32B frame; only the cpk base needs saving
    addi x2, x2, -32
    sw x10, 0(x2)

    bn.xor w31, w31, w31           # w31 = 0 for expandsk's zero fill
    # step 1: expandsk(x11 = sk_seed) -> x2 -= 4352 ; pk_seed @ x2, padded O @ x2+32
    jal x1, expandsk_ret_O_pkseed

    # reserve B 213120 + tri 66240 = 279360
    #   now: tri @ x2 ; B @ x2+66240 ; pk_seed @ x2+279360 ;
    #        O @ x2+279392 ; frame @ x2+283712
    li   x13, 279360
    sub  x2, x2, x13

    # step 2: P1O_P2(x10 = B, x11 = pk_seed, x12 = O) -> B
    li   x10, 66240
    add  x10, x2, x10
    li   x11, 279360
    add  x11, x2, x11
    addi x12, x11, 32
    jal  x1, P1O_P2

    # step 3: P3_cal(x10 = tri, x11 = B, x12 = O) -> tri
    addi x10, x2, 0
    li   x11, 66240
    add  x11, x2, x11
    li   x12, 279392
    add  x12, x2, x12
    jal  x1, P3_cal

    # step 4: cpk_pack(x10 = cpk, x11 = tri, x12 = pk_seed) -> cpk
    li   x13, 283712
    add  x13, x2, x13
    lw   x10, 0(x13)
    addi x11, x2, 0
    li   x12, 279360
    add  x12, x2, x12
    jal  x1, cpk_pack

    # csk = sk_seed, no copy: the pipeline only reads the seed buffer.

    # epilogue: B + tri 279360 + expandsk 4352 + frame 32 = 283744
    li   x13, 283744
    add  x2, x2, x13
    ret
