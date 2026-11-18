.section .data
.balign 32
cpk:
    .zero 32
.balign 32
v:
    .zero 96
.balign 32
result:
    .zero 64
arguement:
    .zero 512                       # kernel needs 352 B (10 WDR save + GPR saves)
stack_end:
.section .text.start
.global batch_quad_trimat_eval_gf256_test
batch_quad_trimat_eval_gf256_test:
    la x2, stack_end
    la x10, cpk
    la x11, v
    la x12, result
    jal x1, batch_quad_trimat_eval_gf256
    ecall