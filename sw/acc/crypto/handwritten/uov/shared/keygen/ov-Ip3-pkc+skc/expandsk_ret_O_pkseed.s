/* expandsk_ret_O_pkseed - SHAKE256(sk_seed) -> pk_seed || padded O (UOV-Ip3).
 * Squeezes 105 blocks, parks the 16B pk_seed prefix at the frame base, then
 * repacks O in place (descending) so each of the 45 columns lands in a 96-B
 * slot (3 WDRs; low 74 B are the column, the 22 slack bytes are ZEROED --
 * consumers may multiply the slack, so it must not carry squeeze data).
 * The frame is NOT freed: x2 stays at the frame base on return, and the
 * caller reads pk_seed at 0(x2) (low 16B) and padded O at 32(x2) (45x96 B).
 * pk_seed is stored zero-extended to the full 32B word; the bngfonly sign
 * tier depends on it (KeySchedule_sign reads w17[255:96] for RotWord; the
 * bn.aes128.* insns mask the key to 128 bits and do not care).
 * in:    x11 = sk_seed addr (32B), x2 = 32B-aligned stack, w31 = 0
 * clob:  x2 (-4352), x5, x6, x7, x8, x31; w0-w4; kmac_cfg (disabled on exit)
 * stack: 4352 B, kept live for the caller
 */
.section .text
.balign 4
.global expandsk_ret_O_pkseed
expandsk_ret_O_pkseed:
    # Assume sk_seed address in x11
    bn.lid x0, 0(x11)
    li x5, 0xA                       # KMAC Config 010(L256)_10(SHAKE256):0xA
    addi x31, x0, 0x20
    slli x31, x31, 5
    or x31, x31, x5
    csrrw x0, kmac_cfg, x31
    bn.wsrw 0x9, w0
    # Assume stack is 32 balign
    li x31, 4352
    sub x2, x2, x31
    addi x5, x2, 32
    loopi 105, 27
        bn.wsrr w0, 0xa
        bn.sid x0, 0(x5++)
        .rept 25
            NOP
        .endr
    li x31, 3360
    sub x5, x5, x31
    bn.lid x0, 0(x5)            #pk_seed(16)||O(16)
    bn.rshi w0, w0, w31 >> 128
    bn.rshi w0, w31, w0 >> 128
    bn.sid x0, 0(x2)
    # in-place repack, col 44 down to 0: packed col c sits at 48+74c(x2),
    # its slot at 32+96c(x2). Ladder shift = 8*((16+10c)%32) bits; a 4th
    # cover WDR is needed when the 74-B span crosses one (11 of 45 cols);
    # the 3 aligned cols (c=8,24,40) skip the shifts. w4 = keep-10 mask for
    # the slot's third WDR (zeroes the slack).
    li x6, 1
    li x7, 2
    li x8, 3
    bn.not w4, w31
    bn.rshi w4, w31, w4 >> 176
    # c=44 a=8
    bn.lid x0, 3296(x2)
    bn.lid x6, 3328(x2)
    bn.lid x7, 3360(x2)
    bn.rshi w0, w1, w0 >> 64
    bn.rshi w1, w2, w1 >> 64
    bn.rshi w2, w31, w2 >> 64
    bn.and w2, w2, w4
    bn.sid x0, 4256(x2)
    bn.sid x6, 4288(x2)
    bn.sid x7, 4320(x2)
    # c=43 a=30
    bn.lid x0, 3200(x2)
    bn.lid x6, 3232(x2)
    bn.lid x7, 3264(x2)
    bn.lid x8, 3296(x2)
    bn.rshi w0, w1, w0 >> 240
    bn.rshi w1, w2, w1 >> 240
    bn.rshi w2, w3, w2 >> 240
    bn.and w2, w2, w4
    bn.sid x0, 4160(x2)
    bn.sid x6, 4192(x2)
    bn.sid x7, 4224(x2)
    # c=42 a=20
    bn.lid x0, 3136(x2)
    bn.lid x6, 3168(x2)
    bn.lid x7, 3200(x2)
    bn.rshi w0, w1, w0 >> 160
    bn.rshi w1, w2, w1 >> 160
    bn.rshi w2, w31, w2 >> 160
    bn.and w2, w2, w4
    bn.sid x0, 4064(x2)
    bn.sid x6, 4096(x2)
    bn.sid x7, 4128(x2)
    # c=41 a=10
    bn.lid x0, 3072(x2)
    bn.lid x6, 3104(x2)
    bn.lid x7, 3136(x2)
    bn.rshi w0, w1, w0 >> 80
    bn.rshi w1, w2, w1 >> 80
    bn.rshi w2, w31, w2 >> 80
    bn.and w2, w2, w4
    bn.sid x0, 3968(x2)
    bn.sid x6, 4000(x2)
    bn.sid x7, 4032(x2)
    # c=40 a=0
    bn.lid x0, 3008(x2)
    bn.lid x6, 3040(x2)
    bn.lid x7, 3072(x2)
    bn.and w2, w2, w4
    bn.sid x0, 3872(x2)
    bn.sid x6, 3904(x2)
    bn.sid x7, 3936(x2)
    # c=39 a=22
    bn.lid x0, 2912(x2)
    bn.lid x6, 2944(x2)
    bn.lid x7, 2976(x2)
    bn.rshi w0, w1, w0 >> 176
    bn.rshi w1, w2, w1 >> 176
    bn.rshi w2, w31, w2 >> 176
    bn.and w2, w2, w4
    bn.sid x0, 3776(x2)
    bn.sid x6, 3808(x2)
    bn.sid x7, 3840(x2)
    # c=38 a=12
    bn.lid x0, 2848(x2)
    bn.lid x6, 2880(x2)
    bn.lid x7, 2912(x2)
    bn.rshi w0, w1, w0 >> 96
    bn.rshi w1, w2, w1 >> 96
    bn.rshi w2, w31, w2 >> 96
    bn.and w2, w2, w4
    bn.sid x0, 3680(x2)
    bn.sid x6, 3712(x2)
    bn.sid x7, 3744(x2)
    # c=37 a=2
    bn.lid x0, 2784(x2)
    bn.lid x6, 2816(x2)
    bn.lid x7, 2848(x2)
    bn.rshi w0, w1, w0 >> 16
    bn.rshi w1, w2, w1 >> 16
    bn.rshi w2, w31, w2 >> 16
    bn.and w2, w2, w4
    bn.sid x0, 3584(x2)
    bn.sid x6, 3616(x2)
    bn.sid x7, 3648(x2)
    # c=36 a=24
    bn.lid x0, 2688(x2)
    bn.lid x6, 2720(x2)
    bn.lid x7, 2752(x2)
    bn.lid x8, 2784(x2)
    bn.rshi w0, w1, w0 >> 192
    bn.rshi w1, w2, w1 >> 192
    bn.rshi w2, w3, w2 >> 192
    bn.and w2, w2, w4
    bn.sid x0, 3488(x2)
    bn.sid x6, 3520(x2)
    bn.sid x7, 3552(x2)
    # c=35 a=14
    bn.lid x0, 2624(x2)
    bn.lid x6, 2656(x2)
    bn.lid x7, 2688(x2)
    bn.rshi w0, w1, w0 >> 112
    bn.rshi w1, w2, w1 >> 112
    bn.rshi w2, w31, w2 >> 112
    bn.and w2, w2, w4
    bn.sid x0, 3392(x2)
    bn.sid x6, 3424(x2)
    bn.sid x7, 3456(x2)
    # c=34 a=4
    bn.lid x0, 2560(x2)
    bn.lid x6, 2592(x2)
    bn.lid x7, 2624(x2)
    bn.rshi w0, w1, w0 >> 32
    bn.rshi w1, w2, w1 >> 32
    bn.rshi w2, w31, w2 >> 32
    bn.and w2, w2, w4
    bn.sid x0, 3296(x2)
    bn.sid x6, 3328(x2)
    bn.sid x7, 3360(x2)
    # c=33 a=26
    bn.lid x0, 2464(x2)
    bn.lid x6, 2496(x2)
    bn.lid x7, 2528(x2)
    bn.lid x8, 2560(x2)
    bn.rshi w0, w1, w0 >> 208
    bn.rshi w1, w2, w1 >> 208
    bn.rshi w2, w3, w2 >> 208
    bn.and w2, w2, w4
    bn.sid x0, 3200(x2)
    bn.sid x6, 3232(x2)
    bn.sid x7, 3264(x2)
    # c=32 a=16
    bn.lid x0, 2400(x2)
    bn.lid x6, 2432(x2)
    bn.lid x7, 2464(x2)
    bn.rshi w0, w1, w0 >> 128
    bn.rshi w1, w2, w1 >> 128
    bn.rshi w2, w31, w2 >> 128
    bn.and w2, w2, w4
    bn.sid x0, 3104(x2)
    bn.sid x6, 3136(x2)
    bn.sid x7, 3168(x2)
    # c=31 a=6
    bn.lid x0, 2336(x2)
    bn.lid x6, 2368(x2)
    bn.lid x7, 2400(x2)
    bn.rshi w0, w1, w0 >> 48
    bn.rshi w1, w2, w1 >> 48
    bn.rshi w2, w31, w2 >> 48
    bn.and w2, w2, w4
    bn.sid x0, 3008(x2)
    bn.sid x6, 3040(x2)
    bn.sid x7, 3072(x2)
    # c=30 a=28
    bn.lid x0, 2240(x2)
    bn.lid x6, 2272(x2)
    bn.lid x7, 2304(x2)
    bn.lid x8, 2336(x2)
    bn.rshi w0, w1, w0 >> 224
    bn.rshi w1, w2, w1 >> 224
    bn.rshi w2, w3, w2 >> 224
    bn.and w2, w2, w4
    bn.sid x0, 2912(x2)
    bn.sid x6, 2944(x2)
    bn.sid x7, 2976(x2)
    # c=29 a=18
    bn.lid x0, 2176(x2)
    bn.lid x6, 2208(x2)
    bn.lid x7, 2240(x2)
    bn.rshi w0, w1, w0 >> 144
    bn.rshi w1, w2, w1 >> 144
    bn.rshi w2, w31, w2 >> 144
    bn.and w2, w2, w4
    bn.sid x0, 2816(x2)
    bn.sid x6, 2848(x2)
    bn.sid x7, 2880(x2)
    # c=28 a=8
    bn.lid x0, 2112(x2)
    bn.lid x6, 2144(x2)
    bn.lid x7, 2176(x2)
    bn.rshi w0, w1, w0 >> 64
    bn.rshi w1, w2, w1 >> 64
    bn.rshi w2, w31, w2 >> 64
    bn.and w2, w2, w4
    bn.sid x0, 2720(x2)
    bn.sid x6, 2752(x2)
    bn.sid x7, 2784(x2)
    # c=27 a=30
    bn.lid x0, 2016(x2)
    bn.lid x6, 2048(x2)
    bn.lid x7, 2080(x2)
    bn.lid x8, 2112(x2)
    bn.rshi w0, w1, w0 >> 240
    bn.rshi w1, w2, w1 >> 240
    bn.rshi w2, w3, w2 >> 240
    bn.and w2, w2, w4
    bn.sid x0, 2624(x2)
    bn.sid x6, 2656(x2)
    bn.sid x7, 2688(x2)
    # c=26 a=20
    bn.lid x0, 1952(x2)
    bn.lid x6, 1984(x2)
    bn.lid x7, 2016(x2)
    bn.rshi w0, w1, w0 >> 160
    bn.rshi w1, w2, w1 >> 160
    bn.rshi w2, w31, w2 >> 160
    bn.and w2, w2, w4
    bn.sid x0, 2528(x2)
    bn.sid x6, 2560(x2)
    bn.sid x7, 2592(x2)
    # c=25 a=10
    bn.lid x0, 1888(x2)
    bn.lid x6, 1920(x2)
    bn.lid x7, 1952(x2)
    bn.rshi w0, w1, w0 >> 80
    bn.rshi w1, w2, w1 >> 80
    bn.rshi w2, w31, w2 >> 80
    bn.and w2, w2, w4
    bn.sid x0, 2432(x2)
    bn.sid x6, 2464(x2)
    bn.sid x7, 2496(x2)
    # c=24 a=0
    bn.lid x0, 1824(x2)
    bn.lid x6, 1856(x2)
    bn.lid x7, 1888(x2)
    bn.and w2, w2, w4
    bn.sid x0, 2336(x2)
    bn.sid x6, 2368(x2)
    bn.sid x7, 2400(x2)
    # c=23 a=22
    bn.lid x0, 1728(x2)
    bn.lid x6, 1760(x2)
    bn.lid x7, 1792(x2)
    bn.rshi w0, w1, w0 >> 176
    bn.rshi w1, w2, w1 >> 176
    bn.rshi w2, w31, w2 >> 176
    bn.and w2, w2, w4
    bn.sid x0, 2240(x2)
    bn.sid x6, 2272(x2)
    bn.sid x7, 2304(x2)
    # c=22 a=12
    bn.lid x0, 1664(x2)
    bn.lid x6, 1696(x2)
    bn.lid x7, 1728(x2)
    bn.rshi w0, w1, w0 >> 96
    bn.rshi w1, w2, w1 >> 96
    bn.rshi w2, w31, w2 >> 96
    bn.and w2, w2, w4
    bn.sid x0, 2144(x2)
    bn.sid x6, 2176(x2)
    bn.sid x7, 2208(x2)
    # c=21 a=2
    bn.lid x0, 1600(x2)
    bn.lid x6, 1632(x2)
    bn.lid x7, 1664(x2)
    bn.rshi w0, w1, w0 >> 16
    bn.rshi w1, w2, w1 >> 16
    bn.rshi w2, w31, w2 >> 16
    bn.and w2, w2, w4
    bn.sid x0, 2048(x2)
    bn.sid x6, 2080(x2)
    bn.sid x7, 2112(x2)
    # c=20 a=24
    bn.lid x0, 1504(x2)
    bn.lid x6, 1536(x2)
    bn.lid x7, 1568(x2)
    bn.lid x8, 1600(x2)
    bn.rshi w0, w1, w0 >> 192
    bn.rshi w1, w2, w1 >> 192
    bn.rshi w2, w3, w2 >> 192
    bn.and w2, w2, w4
    bn.sid x0, 1952(x2)
    bn.sid x6, 1984(x2)
    bn.sid x7, 2016(x2)
    # c=19 a=14
    bn.lid x0, 1440(x2)
    bn.lid x6, 1472(x2)
    bn.lid x7, 1504(x2)
    bn.rshi w0, w1, w0 >> 112
    bn.rshi w1, w2, w1 >> 112
    bn.rshi w2, w31, w2 >> 112
    bn.and w2, w2, w4
    bn.sid x0, 1856(x2)
    bn.sid x6, 1888(x2)
    bn.sid x7, 1920(x2)
    # c=18 a=4
    bn.lid x0, 1376(x2)
    bn.lid x6, 1408(x2)
    bn.lid x7, 1440(x2)
    bn.rshi w0, w1, w0 >> 32
    bn.rshi w1, w2, w1 >> 32
    bn.rshi w2, w31, w2 >> 32
    bn.and w2, w2, w4
    bn.sid x0, 1760(x2)
    bn.sid x6, 1792(x2)
    bn.sid x7, 1824(x2)
    # c=17 a=26
    bn.lid x0, 1280(x2)
    bn.lid x6, 1312(x2)
    bn.lid x7, 1344(x2)
    bn.lid x8, 1376(x2)
    bn.rshi w0, w1, w0 >> 208
    bn.rshi w1, w2, w1 >> 208
    bn.rshi w2, w3, w2 >> 208
    bn.and w2, w2, w4
    bn.sid x0, 1664(x2)
    bn.sid x6, 1696(x2)
    bn.sid x7, 1728(x2)
    # c=16 a=16
    bn.lid x0, 1216(x2)
    bn.lid x6, 1248(x2)
    bn.lid x7, 1280(x2)
    bn.rshi w0, w1, w0 >> 128
    bn.rshi w1, w2, w1 >> 128
    bn.rshi w2, w31, w2 >> 128
    bn.and w2, w2, w4
    bn.sid x0, 1568(x2)
    bn.sid x6, 1600(x2)
    bn.sid x7, 1632(x2)
    # c=15 a=6
    bn.lid x0, 1152(x2)
    bn.lid x6, 1184(x2)
    bn.lid x7, 1216(x2)
    bn.rshi w0, w1, w0 >> 48
    bn.rshi w1, w2, w1 >> 48
    bn.rshi w2, w31, w2 >> 48
    bn.and w2, w2, w4
    bn.sid x0, 1472(x2)
    bn.sid x6, 1504(x2)
    bn.sid x7, 1536(x2)
    # c=14 a=28
    bn.lid x0, 1056(x2)
    bn.lid x6, 1088(x2)
    bn.lid x7, 1120(x2)
    bn.lid x8, 1152(x2)
    bn.rshi w0, w1, w0 >> 224
    bn.rshi w1, w2, w1 >> 224
    bn.rshi w2, w3, w2 >> 224
    bn.and w2, w2, w4
    bn.sid x0, 1376(x2)
    bn.sid x6, 1408(x2)
    bn.sid x7, 1440(x2)
    # c=13 a=18
    bn.lid x0, 992(x2)
    bn.lid x6, 1024(x2)
    bn.lid x7, 1056(x2)
    bn.rshi w0, w1, w0 >> 144
    bn.rshi w1, w2, w1 >> 144
    bn.rshi w2, w31, w2 >> 144
    bn.and w2, w2, w4
    bn.sid x0, 1280(x2)
    bn.sid x6, 1312(x2)
    bn.sid x7, 1344(x2)
    # c=12 a=8
    bn.lid x0, 928(x2)
    bn.lid x6, 960(x2)
    bn.lid x7, 992(x2)
    bn.rshi w0, w1, w0 >> 64
    bn.rshi w1, w2, w1 >> 64
    bn.rshi w2, w31, w2 >> 64
    bn.and w2, w2, w4
    bn.sid x0, 1184(x2)
    bn.sid x6, 1216(x2)
    bn.sid x7, 1248(x2)
    # c=11 a=30
    bn.lid x0, 832(x2)
    bn.lid x6, 864(x2)
    bn.lid x7, 896(x2)
    bn.lid x8, 928(x2)
    bn.rshi w0, w1, w0 >> 240
    bn.rshi w1, w2, w1 >> 240
    bn.rshi w2, w3, w2 >> 240
    bn.and w2, w2, w4
    bn.sid x0, 1088(x2)
    bn.sid x6, 1120(x2)
    bn.sid x7, 1152(x2)
    # c=10 a=20
    bn.lid x0, 768(x2)
    bn.lid x6, 800(x2)
    bn.lid x7, 832(x2)
    bn.rshi w0, w1, w0 >> 160
    bn.rshi w1, w2, w1 >> 160
    bn.rshi w2, w31, w2 >> 160
    bn.and w2, w2, w4
    bn.sid x0, 992(x2)
    bn.sid x6, 1024(x2)
    bn.sid x7, 1056(x2)
    # c=9 a=10
    bn.lid x0, 704(x2)
    bn.lid x6, 736(x2)
    bn.lid x7, 768(x2)
    bn.rshi w0, w1, w0 >> 80
    bn.rshi w1, w2, w1 >> 80
    bn.rshi w2, w31, w2 >> 80
    bn.and w2, w2, w4
    bn.sid x0, 896(x2)
    bn.sid x6, 928(x2)
    bn.sid x7, 960(x2)
    # c=8 a=0
    bn.lid x0, 640(x2)
    bn.lid x6, 672(x2)
    bn.lid x7, 704(x2)
    bn.and w2, w2, w4
    bn.sid x0, 800(x2)
    bn.sid x6, 832(x2)
    bn.sid x7, 864(x2)
    # c=7 a=22
    bn.lid x0, 544(x2)
    bn.lid x6, 576(x2)
    bn.lid x7, 608(x2)
    bn.rshi w0, w1, w0 >> 176
    bn.rshi w1, w2, w1 >> 176
    bn.rshi w2, w31, w2 >> 176
    bn.and w2, w2, w4
    bn.sid x0, 704(x2)
    bn.sid x6, 736(x2)
    bn.sid x7, 768(x2)
    # c=6 a=12
    bn.lid x0, 480(x2)
    bn.lid x6, 512(x2)
    bn.lid x7, 544(x2)
    bn.rshi w0, w1, w0 >> 96
    bn.rshi w1, w2, w1 >> 96
    bn.rshi w2, w31, w2 >> 96
    bn.and w2, w2, w4
    bn.sid x0, 608(x2)
    bn.sid x6, 640(x2)
    bn.sid x7, 672(x2)
    # c=5 a=2
    bn.lid x0, 416(x2)
    bn.lid x6, 448(x2)
    bn.lid x7, 480(x2)
    bn.rshi w0, w1, w0 >> 16
    bn.rshi w1, w2, w1 >> 16
    bn.rshi w2, w31, w2 >> 16
    bn.and w2, w2, w4
    bn.sid x0, 512(x2)
    bn.sid x6, 544(x2)
    bn.sid x7, 576(x2)
    # c=4 a=24
    bn.lid x0, 320(x2)
    bn.lid x6, 352(x2)
    bn.lid x7, 384(x2)
    bn.lid x8, 416(x2)
    bn.rshi w0, w1, w0 >> 192
    bn.rshi w1, w2, w1 >> 192
    bn.rshi w2, w3, w2 >> 192
    bn.and w2, w2, w4
    bn.sid x0, 416(x2)
    bn.sid x6, 448(x2)
    bn.sid x7, 480(x2)
    # c=3 a=14
    bn.lid x0, 256(x2)
    bn.lid x6, 288(x2)
    bn.lid x7, 320(x2)
    bn.rshi w0, w1, w0 >> 112
    bn.rshi w1, w2, w1 >> 112
    bn.rshi w2, w31, w2 >> 112
    bn.and w2, w2, w4
    bn.sid x0, 320(x2)
    bn.sid x6, 352(x2)
    bn.sid x7, 384(x2)
    # c=2 a=4
    bn.lid x0, 192(x2)
    bn.lid x6, 224(x2)
    bn.lid x7, 256(x2)
    bn.rshi w0, w1, w0 >> 32
    bn.rshi w1, w2, w1 >> 32
    bn.rshi w2, w31, w2 >> 32
    bn.and w2, w2, w4
    bn.sid x0, 224(x2)
    bn.sid x6, 256(x2)
    bn.sid x7, 288(x2)
    # c=1 a=26
    bn.lid x0, 96(x2)
    bn.lid x6, 128(x2)
    bn.lid x7, 160(x2)
    bn.lid x8, 192(x2)
    bn.rshi w0, w1, w0 >> 208
    bn.rshi w1, w2, w1 >> 208
    bn.rshi w2, w3, w2 >> 208
    bn.and w2, w2, w4
    bn.sid x0, 128(x2)
    bn.sid x6, 160(x2)
    bn.sid x7, 192(x2)
    # c=0 a=16
    bn.lid x0, 32(x2)
    bn.lid x6, 64(x2)
    bn.lid x7, 96(x2)
    bn.rshi w0, w1, w0 >> 128
    bn.rshi w1, w2, w1 >> 128
    bn.rshi w2, w31, w2 >> 128
    bn.and w2, w2, w4
    bn.sid x0, 32(x2)
    bn.sid x6, 64(x2)
    bn.sid x7, 96(x2)
    li x31, 0x80000000
    csrrw x0, kmac_cfg, x31
    
ret