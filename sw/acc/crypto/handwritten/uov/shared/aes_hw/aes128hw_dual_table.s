/* aes128_dual_table, hardware: two AES-128-CTR blocks with bn.aes128 behind the contract
 * of the dual T-table wrapper of the same name, for the Round-2 Is AES-only sign and
 * keygen kernels.
 * in    : w18 = dual IV (12 zero bytes + LE counter at bytes 12..15 in each 128-bit lane)
 *         x18 = round-key buffer, 32-byte aligned (bytes 0..15, the key, are read)
 * out   : w2 = AES(block 1) || AES(block 2); x18 and w18 unchanged
 * clob  : x5 (saved FLAGS), x6 (scratch base); w2. Every other wide register preserved
 *         (w14 carries the round keys and is saved); FLAGS saved and restored.
 * data  : 32 B private scratch; non-reentrant. stack: none; no nested call.
 * The .swap form of the first round turns the LE counter field big-endian, which the
 * T-table wrapper did with twelve shift-and-or instructions per block.
 */
.section .text
.balign 4
.globl aes128_dual_table
aes128_dual_table:
    la x6, aes128hw_dual_scratch
    csrrs x5, flags, x0
    bn.sd w14, 0(x6)
    bn.ld w14, 0(x18)
    bn.aes128.encz.swap w2, w18, w14
    bn.aes128.kf w14, w14, 1
    bn.aes128.encm w2, w2, w14
    bn.aes128.kf w14, w14, 2
    bn.aes128.encm w2, w2, w14
    bn.aes128.kf w14, w14, 3
    bn.aes128.encm w2, w2, w14
    bn.aes128.kf w14, w14, 4
    bn.aes128.encm w2, w2, w14
    bn.aes128.kf w14, w14, 5
    bn.aes128.encm w2, w2, w14
    bn.aes128.kf w14, w14, 6
    bn.aes128.encm w2, w2, w14
    bn.aes128.kf w14, w14, 7
    bn.aes128.encm w2, w2, w14
    bn.aes128.kf w14, w14, 8
    bn.aes128.encm w2, w2, w14
    bn.aes128.kf w14, w14, 9
    bn.aes128.encm w2, w2, w14
    bn.aes128.kf w14, w14, 10
    bn.aes128.encf w2, w2, w14
    bn.ld w14, 0(x6)
    csrrw x0, flags, x5
    ret

.section .data
.balign 32
aes128hw_dual_scratch: .zero 32
