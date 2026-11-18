/* AES-128 CTR column: two blocks in w13, with software-GF state preserved.
 * in: x13 counter, x18 packed keys (first 16 B = key), w31=0.
 *     x18 is 32 B aligned; first 32 B initialized by key schedule.
 *     20(x3) = 32 B aligned scratch, separate from keys and frame.
 * out: w13 low/high lanes = counter/counter+1; x13 += 2 modulo 2^32.
 * clob: x5, x6, scratch contents. wdr: w13; w14 restored.
 * flags/WSRs preserved. stack: none; one return entry, no nested calls.
 */
.section .text
.balign 4
.global aes128hw_col_is
.global aes128_col_is
.type aes128hw_col_is, @function
.type aes128_col_is, @function
aes128hw_col_is:
aes128_col_is:
    lw x6, 20(x3)
    bn.sd w31, 0(x6)
    sw x13, 12(x6)
    addi x5, x13, 1
    sw x5, 28(x6)
    bn.ld w13, 0(x6)
    bn.sd w14, 0(x6)             /* IVs consumed; save original key scratch WDR. */
    bn.ld w14, 0(x18)
    bn.aes128.encz.swap w13, w13, w14
    bn.aes128.kf w14, w14, 1
    bn.aes128.encm w13, w13, w14
    bn.aes128.kf w14, w14, 2
    bn.aes128.encm w13, w13, w14
    bn.aes128.kf w14, w14, 3
    bn.aes128.encm w13, w13, w14
    bn.aes128.kf w14, w14, 4
    bn.aes128.encm w13, w13, w14
    bn.aes128.kf w14, w14, 5
    bn.aes128.encm w13, w13, w14
    bn.aes128.kf w14, w14, 6
    bn.aes128.encm w13, w13, w14
    bn.aes128.kf w14, w14, 7
    bn.aes128.encm w13, w13, w14
    bn.aes128.kf w14, w14, 8
    bn.aes128.encm w13, w13, w14
    bn.aes128.kf w14, w14, 9
    bn.aes128.encm w13, w13, w14
    bn.aes128.kf w14, w14, 10
    bn.aes128.encf w13, w13, w14
    addi x13, x13, 2
    bn.ld w14, 0(x6)
    ret
.size aes128hw_col_is, .-aes128hw_col_is
.size aes128_col_is, .-aes128_col_is
