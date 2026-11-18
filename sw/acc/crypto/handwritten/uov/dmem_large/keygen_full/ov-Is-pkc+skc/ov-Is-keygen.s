.section .text
.balign 4
.global ov_keygen
/* ov_keygen (Is): on-ACC UOV pkc+skc keygen, single binary.
 *   sk_seed -> expandsk -> P1O_P2 -> P3_cal -> cpk_pack -> cpk ; csk = seed in-place.
 * in:  x10 = cpk out base (66,576B, 32B-aligned)
 *      x11 = sk_seed buffer (32B); read-only, left in place as csk
 *      x2  = stack top, 32B-aligned; peak: HW tiers 269,408B (P1O_P2 step:
 *            266,304 own + 3,104 P1O_P2 frame; P3_cal frame is only 32),
 *            sw 397,408B (P3_cal keeps the 131,104 P3_full frame)
 * stack (below x2, high->low): frame 32 | expandsk 3104 | P1O_P2 buf 196608 | P3 66560.
 *   x2-rel after reserve: P3@x2, P1O_P2_buf@x2+66560, pk_seed@x2+263168, O@x2+263200,
 *   frame@x2+266272. callees restore x2. x1 = HW call stack. exact peak, no slack.
 */
ov_keygen:
    # prologue: 32B frame (32B-aligned for downstream bn.sid x2); only B needs saving
    addi x2, x2, -32
    sw x10, 0(x2)                  # [0] B = cpk base (re-read at step 4)

    bn.xor w31, w31, w31           # w31=0 for expandsk bn.rshi zero-fill (RTL inits WDR random)
    # step 1: expandsk(x11=sk_seed) -> x2 -= 3104 ; pk_seed@x2 , O@x2+32
    jal x1, expandsk_ret_O_pkseed

    # reserve both bufs on stack
    #   263168 = P1O_P2 buffer 196608 + P3 scratch 66560
    #   now: P3 @ x2 ; P1O_P2_buf @ x2+66560 ; pk_seed @ x2+263168 ;
    #        O @ x2+263200 ; frame(B) @ x2+266272
    li   x13, 263168
    sub  x2, x2, x13

    # step 2: P1O_P2(x10=P1O_P2_buf, x11=pk_seed, x12=O) -> buffer
    li   x10, 66560
    add  x10, x2, x10            # P1O_P2 buffer
    li   x11, 263168
    add  x11, x2, x11            # pk_seed
    addi x12, x11, 32            # O = pk_seed+32
    jal  x1, P1O_P2             # private frame below x2 ; restores x2

    # step 3: P3_cal(x10=P3, x11=P1O_P2_buf, x12=O) -> P3 at x2
    addi x10, x2, 0             # P3 scratch
    li   x11, 66560
    add  x11, x2, x11            # P1O_P2 buffer
    li   x12, 263200
    add  x12, x2, x12            # O
    jal  x1, P3_cal             # restores x2

    # step 4: cpk_pack(x10=B, x11=P3, x12=pk_seed) -> cpk at B
    li   x13, 266272
    add  x13, x2, x13           # frame_ptr
    lw   x10, 0(x13)            # B = cpk base
    addi x11, x2, 0            # P3 source
    li   x12, 263168
    add  x12, x2, x12           # pk_seed
    jal  x1, cpk_pack

    # csk = sk_seed, no copy: seed buffer is also the csk output, pipeline never
    # writes it (expandsk only reads it; all scratch is x2-relative).

    # epilogue: undo buffers(263168) + expandsk(3104) + frame(32) = 266304
    li   x13, 266304
    add  x2, x2, x13
    ret
