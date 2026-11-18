.section .data
.balign 32
sk_seed:
    .zero 32
pk_seed:
    .zero 32
O:
    .zero 3072
stack_end:

.section .text.start
.balign 4
.global main
main:
    # Initialize stack pointer
    la x2, stack_end
    
    # Load sk_seed address into x11
    la x11, sk_seed
    
    # Call expandsk_ret_O_pkseed
    jal x1, expandsk_ret_O_pkseed

ecall
