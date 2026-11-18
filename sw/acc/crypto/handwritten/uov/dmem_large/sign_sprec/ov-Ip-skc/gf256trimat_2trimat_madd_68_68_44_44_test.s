.section .data
.balign 32
AES_KEY:
    .zero 32
.balign 32 
O:
    .zero 3008
.balign 32 
result:
    .zero 191488
.balign 32
P1_cache:
    .zero 150144
.balign 32
val:
    .zero 32
stack:
    .zero 4352
argument:    
    .zero 32
stack_end:
.section .text.start
.global main
.balign 4
main:
    la x2, stack_end
    la x10, AES_KEY
    la x11, O
    la x12, result
    la x13, P1_cache
    jal x1, gf256trimat_2trimat_madd_68_68_44_44
    ecall