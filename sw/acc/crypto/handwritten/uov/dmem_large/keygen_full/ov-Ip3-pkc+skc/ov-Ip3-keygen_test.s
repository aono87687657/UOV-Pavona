.section .data
.balign 32
sk_seed:                   /* harness injects the KAT seed here */
csk:                       /* same buffer: csk == sk_seed, left in place by keygen */
    .zero 32
cpk:
    .zero 46592             /* cpk 46,591B; +1 so the last slot's tail word stays inside */
stack:
    .zero 413376            /* exact peak, no guard: 32 frame + 4352 expandsk
                               + 213120 B + 66240 tri + 129632 P3_cal frame */
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

.globl sk_seed
.globl csk
.globl cpk
