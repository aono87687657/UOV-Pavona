.section .text
.balign 4
.global ov_keygen
/* ov_keygen (Ip): on-ACC UOV pkc+skc keygen, single binary.
 *   sk_seed -> expandsk -> P1O_P2 -> P3_cal -> cpk_pack -> cpk ; csk = seed in-place.
 * in:  x10 = cpk out base (43,576B, 32B-aligned)
 *      x11 = sk_seed buffer (32B); read-only, left in place as csk
 *      x2  = stack top, 32B-aligned; peak 386,080B in every tier (P3_cal step:
 *            257,920 own + the 128,160 P3_cal frame with its P3_full temp)
 * stack (below x2, high->low): frame 32 | expandsk 3040 | P1O_P2 buf 191488 | padded-P3 63360
 *   (= 257920 own reserve; x2-rel offsets at each step below). callees restore x2.
 *   x1 = HW call stack. exact peak, no slack.
 */
ov_keygen:
    # prologue: 32B frame (32B-aligned for downstream bn.sid x2); only B needs saving
    addi x2, x2, -32
    sw x10, 0(x2)                  # [0] B = cpk base (re-read at step 4)

    bn.xor w31, w31, w31           # w31=0 for expandsk bn.rshi zero-fill (RTL inits WDR random)
    # step 1: expandsk(x11=sk_seed) -> x2 -= 3040 ; pk_seed@x2 , O@x2+32
    jal x1, expandsk_ret_O_pkseed

    # reserve both bufs on stack
    #   254848 = P1O_P2 buffer 191488 + padded-P3 63360
    #   now: padded_P3 @ x2 ; P1O_P2_buf @ x2+63360 ; pk_seed @ x2+254848 ;
    #        O @ x2+254880 ; frame(B) @ x2+257888
    li   x13, 254848
    sub  x2, x2, x13

    # step 2: P1O_P2(x10=P1O_P2_buf, x11=pk_seed, x12=O) -> buffer
    li   x10, 63360
    add  x10, x2, x10            # P1O_P2 buffer
    li   x11, 254848
    add  x11, x2, x11            # pk_seed
    addi x12, x11, 32            # O = pk_seed+32
    jal  x1, P1O_P2             # private frame below x2 ; restores x2

    # step 3: P3_cal(x10=padded_P3, x11=P1O_P2_buf, x12=O) -> padded P3 at x2
    addi x10, x2, 0             # padded-P3 scratch
    li   x11, 63360
    add  x11, x2, x11            # P1O_P2 buffer
    li   x12, 254880
    add  x12, x2, x12            # O
    jal  x1, P3_cal             # restores x2

    # step 4: cpk_pack(x10=B, x11=padded_P3, x12=pk_seed) -> cpk at B
    li   x13, 257888
    add  x13, x2, x13           # frame_ptr
    lw   x10, 0(x13)            # B = cpk base
    addi x11, x2, 0            # padded-P3 source
    li   x12, 254848
    add  x12, x2, x12           # pk_seed
    jal  x1, cpk_pack

    # csk = sk_seed, no copy: seed buffer is also the csk output, pipeline never
    # writes it (expandsk only reads it; all scratch is x2-relative).

    # epilogue: undo buffers(254848) + expandsk(3040) + frame(32) = 257920
    li   x13, 257920
    add  x2, x2, x13
    ret
