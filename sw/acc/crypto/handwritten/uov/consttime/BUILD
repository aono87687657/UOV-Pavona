# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@rules_python//python:defs.bzl", "py_test")

# Constant-time checks of signing (sign_ldirect) and streamed key generation (keygen_stream) with
# bn.gfmul (bngfaes, bngfonly): check_const_time.py with fine-grained DMEM tracking and only the secret
# marked secret. Signing marks csk and runs ov_<P>_skc_sign at message lengths 0, 32 and 33; only the
# retry when L is singular may be reported. Key generation runs INIT (sk_seed secret) and every window
# the host uses (O and pk_seed secret); nothing may be reported. A window takes up to about 25 minutes
# and 1 GB; all 66 tests take about 25 CPU hours.

filegroup(
    name = "ov-Ip-sign_ldirect_bngfaes_elf",
    srcs = ["//sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip-skc:ov-Ip-sign_ldirect_bngfaes"],
    output_group = "elf",
)

filegroup(
    name = "ov-Ip-keygen_stream_bngfaes_elf",
    srcs = ["//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Ip-pkc+skc:ov-Ip-keygen_stream_bngfaes"],
    output_group = "elf",
)

py_test(
    name = "ov-Ip-sign_ldirect_bngfaes_len0_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-sign_ldirect_bngfaes_elf)",
        "$(rootpath expected/ov-Ip-sign_ldirect_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:csk[:32]",
        "--subroutine",
        "ov_Ip_skc_sign",
        "--constants",
        "x2:stack_end",
        "x10:sig",
        "x11:csk",
        "x12:msg",
        "x13:0",
    ],
    data = [
        "expected/ov-Ip-sign_ldirect_bngfaes.txt",
        ":ov-Ip-sign_ldirect_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip-sign_ldirect_bngfaes_len32_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-sign_ldirect_bngfaes_elf)",
        "$(rootpath expected/ov-Ip-sign_ldirect_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:csk[:32]",
        "--subroutine",
        "ov_Ip_skc_sign",
        "--constants",
        "x2:stack_end",
        "x10:sig",
        "x11:csk",
        "x12:msg",
        "x13:32",
    ],
    data = [
        "expected/ov-Ip-sign_ldirect_bngfaes.txt",
        ":ov-Ip-sign_ldirect_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip-sign_ldirect_bngfaes_len33_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-sign_ldirect_bngfaes_elf)",
        "$(rootpath expected/ov-Ip-sign_ldirect_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:csk[:32]",
        "--subroutine",
        "ov_Ip_skc_sign",
        "--constants",
        "x2:stack_end",
        "x10:sig",
        "x11:csk",
        "x12:msg",
        "x13:33",
    ],
    data = [
        "expected/ov-Ip-sign_ldirect_bngfaes.txt",
        ":ov-Ip-sign_ldirect_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip-keygen_stream_bngfaes_init_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Ip-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:sk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:0",
    ],
    data = [
        "expected/ov-Ip-keygen_stream_bngfaes.txt",
        ":ov-Ip-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "moderate",
)

py_test(
    name = "ov-Ip-keygen_stream_bngfaes_win0_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Ip-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4224]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:0",
        "dmem:0x8:7",
    ],
    data = [
        "expected/ov-Ip-keygen_stream_bngfaes.txt",
        ":ov-Ip-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip-keygen_stream_bngfaes_win7_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Ip-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4224]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:7",
        "dmem:0x8:7",
    ],
    data = [
        "expected/ov-Ip-keygen_stream_bngfaes.txt",
        ":ov-Ip-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip-keygen_stream_bngfaes_win14_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Ip-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4224]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:14",
        "dmem:0x8:7",
    ],
    data = [
        "expected/ov-Ip-keygen_stream_bngfaes.txt",
        ":ov-Ip-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip-keygen_stream_bngfaes_win21_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Ip-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4224]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:21",
        "dmem:0x8:7",
    ],
    data = [
        "expected/ov-Ip-keygen_stream_bngfaes.txt",
        ":ov-Ip-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip-keygen_stream_bngfaes_win28_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Ip-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4224]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:28",
        "dmem:0x8:7",
    ],
    data = [
        "expected/ov-Ip-keygen_stream_bngfaes.txt",
        ":ov-Ip-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip-keygen_stream_bngfaes_win35_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Ip-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4224]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:35",
        "dmem:0x8:7",
    ],
    data = [
        "expected/ov-Ip-keygen_stream_bngfaes.txt",
        ":ov-Ip-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip-keygen_stream_bngfaes_win42_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Ip-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4224]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:42",
        "dmem:0x8:2",
    ],
    data = [
        "expected/ov-Ip-keygen_stream_bngfaes.txt",
        ":ov-Ip-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

filegroup(
    name = "ov-Ip-sign_ldirect_bngfonly_elf",
    srcs = ["//sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip-skc:ov-Ip-sign_ldirect_bngfonly"],
    output_group = "elf",
)

filegroup(
    name = "ov-Ip-keygen_stream_bngfonly_elf",
    srcs = ["//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Ip-pkc+skc:ov-Ip-keygen_stream_bngfonly"],
    output_group = "elf",
)

py_test(
    name = "ov-Ip-sign_ldirect_bngfonly_len0_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-sign_ldirect_bngfonly_elf)",
        "$(rootpath expected/ov-Ip-sign_ldirect_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:csk[:32]",
        "--subroutine",
        "ov_Ip_skc_sign",
        "--constants",
        "x2:stack_end",
        "x10:sig",
        "x11:csk",
        "x12:msg",
        "x13:0",
    ],
    data = [
        "expected/ov-Ip-sign_ldirect_bngfonly.txt",
        ":ov-Ip-sign_ldirect_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip-sign_ldirect_bngfonly_len32_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-sign_ldirect_bngfonly_elf)",
        "$(rootpath expected/ov-Ip-sign_ldirect_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:csk[:32]",
        "--subroutine",
        "ov_Ip_skc_sign",
        "--constants",
        "x2:stack_end",
        "x10:sig",
        "x11:csk",
        "x12:msg",
        "x13:32",
    ],
    data = [
        "expected/ov-Ip-sign_ldirect_bngfonly.txt",
        ":ov-Ip-sign_ldirect_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip-sign_ldirect_bngfonly_len33_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-sign_ldirect_bngfonly_elf)",
        "$(rootpath expected/ov-Ip-sign_ldirect_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:csk[:32]",
        "--subroutine",
        "ov_Ip_skc_sign",
        "--constants",
        "x2:stack_end",
        "x10:sig",
        "x11:csk",
        "x12:msg",
        "x13:33",
    ],
    data = [
        "expected/ov-Ip-sign_ldirect_bngfonly.txt",
        ":ov-Ip-sign_ldirect_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip-keygen_stream_bngfonly_init_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Ip-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:sk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:0",
    ],
    data = [
        "expected/ov-Ip-keygen_stream_bngfonly.txt",
        ":ov-Ip-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "moderate",
)

py_test(
    name = "ov-Ip-keygen_stream_bngfonly_win0_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Ip-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4224]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:0",
        "dmem:0x8:7",
    ],
    data = [
        "expected/ov-Ip-keygen_stream_bngfonly.txt",
        ":ov-Ip-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip-keygen_stream_bngfonly_win7_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Ip-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4224]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:7",
        "dmem:0x8:7",
    ],
    data = [
        "expected/ov-Ip-keygen_stream_bngfonly.txt",
        ":ov-Ip-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip-keygen_stream_bngfonly_win14_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Ip-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4224]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:14",
        "dmem:0x8:7",
    ],
    data = [
        "expected/ov-Ip-keygen_stream_bngfonly.txt",
        ":ov-Ip-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip-keygen_stream_bngfonly_win21_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Ip-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4224]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:21",
        "dmem:0x8:7",
    ],
    data = [
        "expected/ov-Ip-keygen_stream_bngfonly.txt",
        ":ov-Ip-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip-keygen_stream_bngfonly_win28_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Ip-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4224]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:28",
        "dmem:0x8:7",
    ],
    data = [
        "expected/ov-Ip-keygen_stream_bngfonly.txt",
        ":ov-Ip-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip-keygen_stream_bngfonly_win35_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Ip-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4224]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:35",
        "dmem:0x8:7",
    ],
    data = [
        "expected/ov-Ip-keygen_stream_bngfonly.txt",
        ":ov-Ip-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip-keygen_stream_bngfonly_win42_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Ip-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4224]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:42",
        "dmem:0x8:2",
    ],
    data = [
        "expected/ov-Ip-keygen_stream_bngfonly.txt",
        ":ov-Ip-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

filegroup(
    name = "ov-Is-sign_ldirect_bngfaes_elf",
    srcs = ["//sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Is-skc:ov-Is-sign_ldirect_bngfaes"],
    output_group = "elf",
)

filegroup(
    name = "ov-Is-keygen_stream_bngfaes_elf",
    srcs = ["//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Is-pkc+skc:ov-Is-keygen_stream_bngfaes"],
    output_group = "elf",
)

py_test(
    name = "ov-Is-sign_ldirect_bngfaes_len0_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Is-sign_ldirect_bngfaes_elf)",
        "$(rootpath expected/ov-Is-sign_ldirect_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:csk[:32]",
        "--subroutine",
        "ov_Is_skc_sign",
        "--constants",
        "x2:stack_end",
        "x10:sig",
        "x11:csk",
        "x12:msg",
        "x13:0",
    ],
    data = [
        "expected/ov-Is-sign_ldirect_bngfaes.txt",
        ":ov-Is-sign_ldirect_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Is-sign_ldirect_bngfaes_len32_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Is-sign_ldirect_bngfaes_elf)",
        "$(rootpath expected/ov-Is-sign_ldirect_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:csk[:32]",
        "--subroutine",
        "ov_Is_skc_sign",
        "--constants",
        "x2:stack_end",
        "x10:sig",
        "x11:csk",
        "x12:msg",
        "x13:32",
    ],
    data = [
        "expected/ov-Is-sign_ldirect_bngfaes.txt",
        ":ov-Is-sign_ldirect_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Is-sign_ldirect_bngfaes_len33_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Is-sign_ldirect_bngfaes_elf)",
        "$(rootpath expected/ov-Is-sign_ldirect_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:csk[:32]",
        "--subroutine",
        "ov_Is_skc_sign",
        "--constants",
        "x2:stack_end",
        "x10:sig",
        "x11:csk",
        "x12:msg",
        "x13:33",
    ],
    data = [
        "expected/ov-Is-sign_ldirect_bngfaes.txt",
        ":ov-Is-sign_ldirect_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Is-keygen_stream_bngfaes_init_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Is-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Is-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:sk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:0",
    ],
    data = [
        "expected/ov-Is-keygen_stream_bngfaes.txt",
        ":ov-Is-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "moderate",
)

py_test(
    name = "ov-Is-keygen_stream_bngfaes_win0_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Is-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Is-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_ctx[:3072]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:0",
        "dmem:0x8:12",
    ],
    data = [
        "expected/ov-Is-keygen_stream_bngfaes.txt",
        ":ov-Is-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Is-keygen_stream_bngfaes_win12_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Is-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Is-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_ctx[:3072]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:12",
        "dmem:0x8:12",
    ],
    data = [
        "expected/ov-Is-keygen_stream_bngfaes.txt",
        ":ov-Is-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Is-keygen_stream_bngfaes_win24_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Is-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Is-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_ctx[:3072]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:24",
        "dmem:0x8:12",
    ],
    data = [
        "expected/ov-Is-keygen_stream_bngfaes.txt",
        ":ov-Is-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Is-keygen_stream_bngfaes_win36_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Is-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Is-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_ctx[:3072]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:36",
        "dmem:0x8:12",
    ],
    data = [
        "expected/ov-Is-keygen_stream_bngfaes.txt",
        ":ov-Is-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Is-keygen_stream_bngfaes_win48_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Is-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Is-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_ctx[:3072]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:48",
        "dmem:0x8:12",
    ],
    data = [
        "expected/ov-Is-keygen_stream_bngfaes.txt",
        ":ov-Is-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Is-keygen_stream_bngfaes_win60_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Is-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Is-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_ctx[:3072]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:60",
        "dmem:0x8:4",
    ],
    data = [
        "expected/ov-Is-keygen_stream_bngfaes.txt",
        ":ov-Is-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

filegroup(
    name = "ov-Is-sign_ldirect_bngfonly_elf",
    srcs = ["//sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Is-skc:ov-Is-sign_ldirect_bngfonly"],
    output_group = "elf",
)

filegroup(
    name = "ov-Is-keygen_stream_bngfonly_elf",
    srcs = ["//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Is-pkc+skc:ov-Is-keygen_stream_bngfonly"],
    output_group = "elf",
)

py_test(
    name = "ov-Is-sign_ldirect_bngfonly_len0_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Is-sign_ldirect_bngfonly_elf)",
        "$(rootpath expected/ov-Is-sign_ldirect_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:csk[:32]",
        "--subroutine",
        "ov_Is_skc_sign",
        "--constants",
        "x2:stack_end",
        "x10:sig",
        "x11:csk",
        "x12:msg",
        "x13:0",
    ],
    data = [
        "expected/ov-Is-sign_ldirect_bngfonly.txt",
        ":ov-Is-sign_ldirect_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Is-sign_ldirect_bngfonly_len32_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Is-sign_ldirect_bngfonly_elf)",
        "$(rootpath expected/ov-Is-sign_ldirect_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:csk[:32]",
        "--subroutine",
        "ov_Is_skc_sign",
        "--constants",
        "x2:stack_end",
        "x10:sig",
        "x11:csk",
        "x12:msg",
        "x13:32",
    ],
    data = [
        "expected/ov-Is-sign_ldirect_bngfonly.txt",
        ":ov-Is-sign_ldirect_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Is-sign_ldirect_bngfonly_len33_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Is-sign_ldirect_bngfonly_elf)",
        "$(rootpath expected/ov-Is-sign_ldirect_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:csk[:32]",
        "--subroutine",
        "ov_Is_skc_sign",
        "--constants",
        "x2:stack_end",
        "x10:sig",
        "x11:csk",
        "x12:msg",
        "x13:33",
    ],
    data = [
        "expected/ov-Is-sign_ldirect_bngfonly.txt",
        ":ov-Is-sign_ldirect_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Is-keygen_stream_bngfonly_init_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Is-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Is-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:sk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:0",
    ],
    data = [
        "expected/ov-Is-keygen_stream_bngfonly.txt",
        ":ov-Is-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "moderate",
)

py_test(
    name = "ov-Is-keygen_stream_bngfonly_win0_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Is-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Is-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_ctx[:3072]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:0",
        "dmem:0x8:12",
    ],
    data = [
        "expected/ov-Is-keygen_stream_bngfonly.txt",
        ":ov-Is-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Is-keygen_stream_bngfonly_win12_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Is-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Is-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_ctx[:3072]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:12",
        "dmem:0x8:12",
    ],
    data = [
        "expected/ov-Is-keygen_stream_bngfonly.txt",
        ":ov-Is-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Is-keygen_stream_bngfonly_win24_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Is-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Is-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_ctx[:3072]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:24",
        "dmem:0x8:12",
    ],
    data = [
        "expected/ov-Is-keygen_stream_bngfonly.txt",
        ":ov-Is-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Is-keygen_stream_bngfonly_win36_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Is-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Is-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_ctx[:3072]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:36",
        "dmem:0x8:12",
    ],
    data = [
        "expected/ov-Is-keygen_stream_bngfonly.txt",
        ":ov-Is-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Is-keygen_stream_bngfonly_win48_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Is-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Is-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_ctx[:3072]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:48",
        "dmem:0x8:12",
    ],
    data = [
        "expected/ov-Is-keygen_stream_bngfonly.txt",
        ":ov-Is-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Is-keygen_stream_bngfonly_win60_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Is-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Is-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_ctx[:3072]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:60",
        "dmem:0x8:4",
    ],
    data = [
        "expected/ov-Is-keygen_stream_bngfonly.txt",
        ":ov-Is-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

filegroup(
    name = "ov-Ip3-sign_ldirect_bngfaes_elf",
    srcs = ["//sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip3-skc:ov-Ip3-sign_ldirect_bngfaes"],
    output_group = "elf",
)

filegroup(
    name = "ov-Ip3-keygen_stream_bngfaes_elf",
    srcs = ["//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Ip3-pkc+skc:ov-Ip3-keygen_stream_bngfaes"],
    output_group = "elf",
)

py_test(
    name = "ov-Ip3-sign_ldirect_bngfaes_len0_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-sign_ldirect_bngfaes_elf)",
        "$(rootpath expected/ov-Ip3-sign_ldirect_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:csk[:32]",
        "--subroutine",
        "ov_Ip3_skc_sign",
        "--constants",
        "x2:stack_end",
        "x10:sig",
        "x11:csk",
        "x12:msg",
        "x13:0",
    ],
    data = [
        "expected/ov-Ip3-sign_ldirect_bngfaes.txt",
        ":ov-Ip3-sign_ldirect_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip3-sign_ldirect_bngfaes_len32_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-sign_ldirect_bngfaes_elf)",
        "$(rootpath expected/ov-Ip3-sign_ldirect_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:csk[:32]",
        "--subroutine",
        "ov_Ip3_skc_sign",
        "--constants",
        "x2:stack_end",
        "x10:sig",
        "x11:csk",
        "x12:msg",
        "x13:32",
    ],
    data = [
        "expected/ov-Ip3-sign_ldirect_bngfaes.txt",
        ":ov-Ip3-sign_ldirect_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip3-sign_ldirect_bngfaes_len33_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-sign_ldirect_bngfaes_elf)",
        "$(rootpath expected/ov-Ip3-sign_ldirect_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:csk[:32]",
        "--subroutine",
        "ov_Ip3_skc_sign",
        "--constants",
        "x2:stack_end",
        "x10:sig",
        "x11:csk",
        "x12:msg",
        "x13:33",
    ],
    data = [
        "expected/ov-Ip3-sign_ldirect_bngfaes.txt",
        ":ov-Ip3-sign_ldirect_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip3-keygen_stream_bngfaes_init_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Ip3-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:sk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:0",
    ],
    data = [
        "expected/ov-Ip3-keygen_stream_bngfaes.txt",
        ":ov-Ip3-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "moderate",
)

py_test(
    name = "ov-Ip3-keygen_stream_bngfaes_win0_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Ip3-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4320]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:0",
        "dmem:0x8:6",
    ],
    data = [
        "expected/ov-Ip3-keygen_stream_bngfaes.txt",
        ":ov-Ip3-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip3-keygen_stream_bngfaes_win6_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Ip3-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4320]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:6",
        "dmem:0x8:6",
    ],
    data = [
        "expected/ov-Ip3-keygen_stream_bngfaes.txt",
        ":ov-Ip3-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip3-keygen_stream_bngfaes_win12_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Ip3-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4320]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:12",
        "dmem:0x8:6",
    ],
    data = [
        "expected/ov-Ip3-keygen_stream_bngfaes.txt",
        ":ov-Ip3-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip3-keygen_stream_bngfaes_win18_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Ip3-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4320]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:18",
        "dmem:0x8:6",
    ],
    data = [
        "expected/ov-Ip3-keygen_stream_bngfaes.txt",
        ":ov-Ip3-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip3-keygen_stream_bngfaes_win24_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Ip3-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4320]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:24",
        "dmem:0x8:6",
    ],
    data = [
        "expected/ov-Ip3-keygen_stream_bngfaes.txt",
        ":ov-Ip3-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip3-keygen_stream_bngfaes_win30_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Ip3-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4320]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:30",
        "dmem:0x8:6",
    ],
    data = [
        "expected/ov-Ip3-keygen_stream_bngfaes.txt",
        ":ov-Ip3-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip3-keygen_stream_bngfaes_win36_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Ip3-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4320]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:36",
        "dmem:0x8:6",
    ],
    data = [
        "expected/ov-Ip3-keygen_stream_bngfaes.txt",
        ":ov-Ip3-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip3-keygen_stream_bngfaes_win42_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-keygen_stream_bngfaes_elf)",
        "$(rootpath expected/ov-Ip3-keygen_stream_bngfaes.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4320]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:42",
        "dmem:0x8:3",
    ],
    data = [
        "expected/ov-Ip3-keygen_stream_bngfaes.txt",
        ":ov-Ip3-keygen_stream_bngfaes_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

filegroup(
    name = "ov-Ip3-sign_ldirect_bngfonly_elf",
    srcs = ["//sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip3-skc:ov-Ip3-sign_ldirect_bngfonly"],
    output_group = "elf",
)

filegroup(
    name = "ov-Ip3-keygen_stream_bngfonly_elf",
    srcs = ["//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Ip3-pkc+skc:ov-Ip3-keygen_stream_bngfonly"],
    output_group = "elf",
)

py_test(
    name = "ov-Ip3-sign_ldirect_bngfonly_len0_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-sign_ldirect_bngfonly_elf)",
        "$(rootpath expected/ov-Ip3-sign_ldirect_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:csk[:32]",
        "--subroutine",
        "ov_Ip3_skc_sign",
        "--constants",
        "x2:stack_end",
        "x10:sig",
        "x11:csk",
        "x12:msg",
        "x13:0",
    ],
    data = [
        "expected/ov-Ip3-sign_ldirect_bngfonly.txt",
        ":ov-Ip3-sign_ldirect_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip3-sign_ldirect_bngfonly_len32_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-sign_ldirect_bngfonly_elf)",
        "$(rootpath expected/ov-Ip3-sign_ldirect_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:csk[:32]",
        "--subroutine",
        "ov_Ip3_skc_sign",
        "--constants",
        "x2:stack_end",
        "x10:sig",
        "x11:csk",
        "x12:msg",
        "x13:32",
    ],
    data = [
        "expected/ov-Ip3-sign_ldirect_bngfonly.txt",
        ":ov-Ip3-sign_ldirect_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip3-sign_ldirect_bngfonly_len33_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-sign_ldirect_bngfonly_elf)",
        "$(rootpath expected/ov-Ip3-sign_ldirect_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:csk[:32]",
        "--subroutine",
        "ov_Ip3_skc_sign",
        "--constants",
        "x2:stack_end",
        "x10:sig",
        "x11:csk",
        "x12:msg",
        "x13:33",
    ],
    data = [
        "expected/ov-Ip3-sign_ldirect_bngfonly.txt",
        ":ov-Ip3-sign_ldirect_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip3-keygen_stream_bngfonly_init_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Ip3-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:sk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:0",
    ],
    data = [
        "expected/ov-Ip3-keygen_stream_bngfonly.txt",
        ":ov-Ip3-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "moderate",
)

py_test(
    name = "ov-Ip3-keygen_stream_bngfonly_win0_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Ip3-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4320]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:0",
        "dmem:0x8:6",
    ],
    data = [
        "expected/ov-Ip3-keygen_stream_bngfonly.txt",
        ":ov-Ip3-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip3-keygen_stream_bngfonly_win6_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Ip3-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4320]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:6",
        "dmem:0x8:6",
    ],
    data = [
        "expected/ov-Ip3-keygen_stream_bngfonly.txt",
        ":ov-Ip3-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip3-keygen_stream_bngfonly_win12_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Ip3-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4320]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:12",
        "dmem:0x8:6",
    ],
    data = [
        "expected/ov-Ip3-keygen_stream_bngfonly.txt",
        ":ov-Ip3-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip3-keygen_stream_bngfonly_win18_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Ip3-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4320]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:18",
        "dmem:0x8:6",
    ],
    data = [
        "expected/ov-Ip3-keygen_stream_bngfonly.txt",
        ":ov-Ip3-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip3-keygen_stream_bngfonly_win24_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Ip3-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4320]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:24",
        "dmem:0x8:6",
    ],
    data = [
        "expected/ov-Ip3-keygen_stream_bngfonly.txt",
        ":ov-Ip3-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip3-keygen_stream_bngfonly_win30_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Ip3-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4320]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:30",
        "dmem:0x8:6",
    ],
    data = [
        "expected/ov-Ip3-keygen_stream_bngfonly.txt",
        ":ov-Ip3-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip3-keygen_stream_bngfonly_win36_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Ip3-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4320]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:36",
        "dmem:0x8:6",
    ],
    data = [
        "expected/ov-Ip3-keygen_stream_bngfonly.txt",
        ":ov-Ip3-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)

py_test(
    name = "ov-Ip3-keygen_stream_bngfonly_win42_consttime",
    srcs = ["check_branches.py"],
    args = [
        "$(rootpath //hw/ip/acc/util:check_const_time)",
        "$(rootpath :ov-Ip3-keygen_stream_bngfonly_elf)",
        "$(rootpath expected/ov-Ip3-keygen_stream_bngfonly.txt)",
        "--track-dmem",
        "--secret",
        "dmem:o_aligned[:4320]",
        "dmem:pk_seed[:32]",
        "--subroutine",
        "main",
        "--constants",
        "dmem:0x0:1",
        "dmem:0x4:42",
        "dmem:0x8:3",
    ],
    data = [
        "expected/ov-Ip3-keygen_stream_bngfonly.txt",
        ":ov-Ip3-keygen_stream_bngfonly_elf",
        "//hw/ip/acc/util:check_const_time",
    ],
    main = "check_branches.py",
    timeout = "eternal",
)
