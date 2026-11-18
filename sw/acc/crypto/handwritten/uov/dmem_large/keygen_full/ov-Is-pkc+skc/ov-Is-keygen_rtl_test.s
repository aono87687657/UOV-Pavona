# RTL self-test for ov_keygen (Is). RTL cant inject from Python, so seed baked in.
# One buffer csk = seed in and output out (same buffer, written in place). Seed = KAT case-0.
# Tier from BUILD dep. Entry in .text.start so code at PC 0 (sim starts there).
# Check: ISS first proves baked cpk == KAT and csk not changed. Then RTL == ISS.

.section .data
.balign 32
csk:
    .word 0xb3604d93, 0x40d72456, 0x227f0ab3, 0x7caef27a   /* KAT case-0 csk (= seed), baked */
    .word 0x044e8e67, 0x505f3ce1, 0xb7e2ad9e, 0xe277ea9a
cpk:
    .zero 66592             /* output base B: the cpk only (66,576B); +16 to 32-align stack_end */
stack:
    .zero 397408            /* exact peak, no guard: 32 frame + 3104 expandsk
                               + 196608 P1O_P2 buf + 66560 P3 scratch + 131104 P3_cal frame */
stack_end:

.section .text.start
.balign 4
.global main
main:
    la x2,  stack_end
    la x10, cpk
    la x11, csk             /* seed buffer = csk: read by expandsk, left in-place as output */
    jal x1, ov_keygen
    ecall
