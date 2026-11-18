.section .data
.global bswap32_mask
.balign 32
bswap32_mask:
.word 0x000000ff
.word 0x000000ff
.word 0x000000ff
.word 0x000000ff
.word 0x000000ff
.word 0x000000ff
.word 0x000000ff
.word 0x000000ff
.balign 32
cpk:
    .zero 32
.balign 32
v:
    .zero 64
.balign 32
result:
    .zero 32
arguement:
    .zero 32
stack_end:
.section .text.start
.global batch_quad_trimat_eval_gf16_test
batch_quad_trimat_eval_gf16_test:
    la x2, stack_end
    la x10, cpk
    la x11, v
    la x12, result
    jal x1, batch_quad_trimat_eval_gf16

ecall


