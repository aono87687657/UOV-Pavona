.section .data
.balign 32
sk_seed:                   /* harness injects the KAT seed here */
csk:                       /* same buffer: csk == sk_seed (skc), left in-place by keygen */
    .zero 32
cpk:
    .zero 66592             /* output base B: the cpk only (66,576B); +16 to 32-align stack_end */
stack:
    .zero 397408            /* exact peak, no guard: 32 frame + 3104 expandsk
                               + 196608 P1O_P2 buf + 66560 P3 scratch + 131104 P3_cal frame */
stack_end:

.section .text.start
.balign 4
.global ov_keygen_test
ov_keygen_test:
    la x2,  stack_end
    la x10, cpk
    la x11, sk_seed         /* seed buffer = csk output (same address) */
    jal x1, ov_keygen
    ecall
