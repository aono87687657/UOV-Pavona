/* Hardware AES-128 with packed memory keys; preserves WDRs, WSRs and flags.
 * data: 96 B private scratch; calls are non-reentrant. stack: none.
 */
.section .text
.balign 4

/* in: x10 key[16], x11 round_keys[176]; out: x11 += 160.
 * clob: x5-x8, x11, x29. wdr: none. stack: none; call depth 2.
 */
.global AES_128_keyschedule
.global aes128hw_keyschedule
AES_128_keyschedule:
aes128hw_keyschedule:
    la x29, aes128hw_mem_scratch
    bn.sd w0, 0(x29)
    lw x5, 0(x10)
    lw x6, 4(x10)
    lw x7, 8(x10)
    lw x8, 12(x10)
    sw x5, 64(x29)
    sw x6, 68(x29)
    sw x7, 72(x29)
    sw x8, 76(x29)
    sw x0, 80(x29)
    sw x0, 84(x29)
    sw x0, 88(x29)
    sw x0, 92(x29)
    bn.ld w0, 64(x29)
    addi x11, x11, -16
    jal x1, aes128hw_store_round
    bn.aes128.kf w0, w0, 1
    jal x1, aes128hw_store_round
    bn.aes128.kf w0, w0, 2
    jal x1, aes128hw_store_round
    bn.aes128.kf w0, w0, 3
    jal x1, aes128hw_store_round
    bn.aes128.kf w0, w0, 4
    jal x1, aes128hw_store_round
    bn.aes128.kf w0, w0, 5
    jal x1, aes128hw_store_round
    bn.aes128.kf w0, w0, 6
    jal x1, aes128hw_store_round
    bn.aes128.kf w0, w0, 7
    jal x1, aes128hw_store_round
    bn.aes128.kf w0, w0, 8
    jal x1, aes128hw_store_round
    bn.aes128.kf w0, w0, 9
    jal x1, aes128hw_store_round
    bn.aes128.kf w0, w0, 10
    jal x1, aes128hw_store_round
    bn.ld w0, 0(x29)
    ret

/* in: w0 round key, x11 previous slot, x29 scratch; out: x11 += 16.
 * clob: x5-x8, x11. wdr: none. stack: none.
 */
aes128hw_store_round:
    bn.sd w0, 64(x29)
    lw x5, 64(x29)
    lw x6, 68(x29)
    lw x7, 72(x29)
    lw x8, 76(x29)
    addi x11, x11, 16
    sw x5, 0(x11)
    sw x6, 4(x11)
    sw x7, 8(x11)
    sw x8, 12(x11)
    ret

/* in: x10 round_keys[176], x11 plaintext[16], x12 ciphertext[16].
 * out: x10 += 160; input/output may alias. clob: x5-x8, x10, x29.
 * wdr: none. stack: none. All pointers need only 4-byte alignment.
 */
.global AES_128_encrypt
.global aes128hw_encrypt
AES_128_encrypt:
aes128hw_encrypt:
    la x29, aes128hw_mem_scratch
    bn.sd w0, 0(x29)
    bn.sd w1, 32(x29)
    lw x5, 0(x11)
    lw x6, 4(x11)
    lw x7, 8(x11)
    lw x8, 12(x11)
    sw x5, 64(x29)
    sw x6, 68(x29)
    sw x7, 72(x29)
    sw x8, 76(x29)
    sw x0, 80(x29)
    sw x0, 84(x29)
    sw x0, 88(x29)
    sw x0, 92(x29)
    bn.ld w0, 64(x29)

    lw x5, 0(x10)
    lw x6, 4(x10)
    lw x7, 8(x10)
    lw x8, 12(x10)
    sw x5, 64(x29)
    sw x6, 68(x29)
    sw x7, 72(x29)
    sw x8, 76(x29)
    bn.ld w1, 64(x29)
    bn.aes128.encz w0, w0, w1
    addi x10, x10, 16

    loopi 9, 11
        lw x5, 0(x10)
        lw x6, 4(x10)
        lw x7, 8(x10)
        lw x8, 12(x10)
        sw x5, 64(x29)
        sw x6, 68(x29)
        sw x7, 72(x29)
        sw x8, 76(x29)
        bn.ld w1, 64(x29)
        bn.aes128.encm w0, w0, w1
        addi x10, x10, 16

    lw x5, 0(x10)
    lw x6, 4(x10)
    lw x7, 8(x10)
    lw x8, 12(x10)
    sw x5, 64(x29)
    sw x6, 68(x29)
    sw x7, 72(x29)
    sw x8, 76(x29)
    bn.ld w1, 64(x29)
    bn.aes128.encf w0, w0, w1
    bn.sd w0, 64(x29)
    lw x5, 64(x29)
    lw x6, 68(x29)
    lw x7, 72(x29)
    lw x8, 76(x29)
    sw x5, 0(x12)
    sw x6, 4(x12)
    sw x7, 8(x12)
    sw x8, 12(x12)
    bn.ld w0, 0(x29)
    bn.ld w1, 32(x29)
    ret

.section .data
.balign 32
aes128hw_mem_scratch: .zero 96
