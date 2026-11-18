load(
    "//rules/pavona:defs.bzl",
    "fpga_params",
    "verilator_params",
)
load(":uov_test.bzl", "uov_test")

package(default_visibility = ["//visibility:public"])

# Chip-level UOV tests: Ibex drives ACC over TL-UL under Verilator (AccPQCEn=1).
# Naming: acc_uov_<op>_<family>_<param>_<tier>_test. Roles:
#   keygen_stream_*          the shipped streamed keygen; bngfaes is the deployed
#                            backend, other tiers select GF/AES independently
#   verify_stream_*          tuned streamed verify; bngfaes deployed
#   verify_stream_uniform_*     ablation rig: uniform geometry, only the backend swaps,
#                            so tier ratios isolate the instructions
#   sign_*                   one kernel family; bngfaes deployed, others ablation
# Conventions: copts belong on uov_test (pavona_test + METER_ID from the name),
# never on verilator_params; every single-subject target keeps exactly one
# acc_binary dep so a dropped copt is a link error rather than a silent
# wrong-subject pass.

uov_test(
    name = "acc_uov_verify_stream_uniform_ip_bngfaes_test",
    srcs = [
        "verify_ip_test.c",
        "verify_ip_testvec.h",
    ],
    copts = [
        "-DVERIFY_ARM=ov_Ip_verify_stream_uniform_bngfaes",
        '-DVERIFY_LABEL="Ip stream_uniform bngfaes"',
    ],
    exec_env = {
        "//hw/top_egret:sim_verilator": None,
    },
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/verify_stream_uniform/ov-Ip-pkc:ov_Ip_verify_stream_uniform_bngfaes",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

uov_test(
    name = "acc_uov_verify_stream_ip_bngfaes_test",
    srcs = [
        "verify_ip_test.c",
        "verify_ip_testvec.h",
    ],
    copts = [
        "-DVERIFY_ARM=ov_Ip_verify_stream_bngfaes",
        '-DVERIFY_LABEL="Ip streamed bngfaes (deployed)"',
    ],
    exec_env = {
        "//hw/top_egret:fpga_cw340_test_rom": None,
        "//hw/top_egret:sim_verilator": None,
    },
    fpga = fpga_params(
        timeout = "moderate",
        tags = ["manual"],
    ),
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/ov-Ip-pkc:ov_Ip_verify_stream_bngfaes",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

uov_test(
    name = "acc_uov_keygen_stream_ip_bngfaes_test",
    srcs = [
        "keygen_stream_ip_test.c",
        "keygen_stream_ip_bngfaes_testvec.h",
    ],
    exec_env = {
        "//hw/top_egret:fpga_cw340_test_rom": None,
        "//hw/top_egret:sim_verilator": None,
    },
    fpga = fpga_params(
        timeout = "moderate",
        tags = ["manual"],
    ),
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Ip-pkc+skc:ov_Ip_keygen_stream_bngfaes",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

uov_test(
    name = "acc_uov_keygen_stream_is_bngfaes_test",
    srcs = [
        "keygen_stream_is_test.c",
        "keygen_stream_is_bngfaes_testvec.h",
    ],
    exec_env = {
        "//hw/top_egret:fpga_cw340_test_rom": None,
        "//hw/top_egret:sim_verilator": None,
    },
    fpga = fpga_params(
        timeout = "moderate",
        tags = ["manual"],
    ),
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Is-pkc+skc:ov_Is_keygen_stream_bngfaes",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

uov_test(
    name = "acc_uov_verify_stream_is_bngfaes_test",
    srcs = [
        "verify_is_test.c",
        "verify_stream_is_testvec.h",
    ],
    copts = [
        "-DVERIFY_ARM=ov_Is_verify_stream_bngfaes",
        '-DVERIFY_LABEL="Is streamed bngfaes (deployed)"',
    ],
    exec_env = {
        "//hw/top_egret:fpga_cw340_test_rom": None,
        "//hw/top_egret:sim_verilator": None,
    },
    fpga = fpga_params(
        timeout = "moderate",
        tags = ["manual"],
    ),
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/ov-Is-pkc:ov_Is_verify_stream_bngfaes",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

uov_test(
    name = "acc_uov_keygen_stream_ip_bngfonly_test",
    srcs = [
        "keygen_stream_ip_test.c",
        "keygen_stream_ip_bngfonly_testvec.h",
    ],
    copts = [
        "-DKEYGEN_APP=ov_Ip_keygen_stream_bngfonly",
        '-DKEYGEN_TIER="Ip bngfonly"',
        "-DKEYGEN_TESTVEC=sw/device/tests/acc_uov/keygen_stream_ip_bngfonly_testvec.h",
    ],
    exec_env = {
        "//hw/top_egret:sim_verilator": None,
    },
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Ip-pkc+skc:ov_Ip_keygen_stream_bngfonly",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

uov_test(
    name = "acc_uov_keygen_stream_ip_sw_test",
    srcs = [
        "keygen_stream_ip_test.c",
        "keygen_stream_ip_sw_testvec.h",
    ],
    copts = [
        "-DKEYGEN_APP=ov_Ip_keygen_stream_sw",
        '-DKEYGEN_TIER="Ip sw"',
        "-DKEYGEN_TESTVEC=sw/device/tests/acc_uov/keygen_stream_ip_sw_testvec.h",
    ],
    exec_env = {
        "//hw/top_egret:sim_verilator": None,
    },
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Ip-pkc+skc:ov_Ip_keygen_stream_sw",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

uov_test(
    name = "acc_uov_keygen_stream_is_bngfonly_test",
    srcs = [
        "keygen_stream_is_test.c",
        "keygen_stream_is_bngfonly_testvec.h",
    ],
    copts = [
        "-DKEYGEN_APP=ov_Is_keygen_stream_bngfonly",
        '-DKEYGEN_TIER="Is bngfonly"',
        "-DKEYGEN_TESTVEC=sw/device/tests/acc_uov/keygen_stream_is_bngfonly_testvec.h",
    ],
    exec_env = {
        "//hw/top_egret:sim_verilator": None,
    },
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Is-pkc+skc:ov_Is_keygen_stream_bngfonly",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

uov_test(
    name = "acc_uov_keygen_stream_is_sw_test",
    srcs = [
        "keygen_stream_is_test.c",
        "keygen_stream_is_sw_testvec.h",
    ],
    copts = [
        "-DKEYGEN_APP=ov_Is_keygen_stream_sw",
        '-DKEYGEN_TIER="Is sw"',
        "-DKEYGEN_TESTVEC=sw/device/tests/acc_uov/keygen_stream_is_sw_testvec.h",
    ],
    exec_env = {
        "//hw/top_egret:sim_verilator": None,
    },
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream/ov-Is-pkc+skc:ov_Is_keygen_stream_sw",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

uov_test(
    name = "acc_uov_verify_stream_uniform_ip_bngfonly_test",
    srcs = [
        "verify_ip_test.c",
        "verify_ip_testvec.h",
    ],
    copts = [
        "-DVERIFY_ARM=ov_Ip_verify_stream_uniform_bngfonly",
        '-DVERIFY_LABEL="Ip stream_uniform bngfonly"',
    ],
    exec_env = {
        "//hw/top_egret:sim_verilator": None,
    },
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/verify_stream_uniform/ov-Ip-pkc:ov_Ip_verify_stream_uniform_bngfonly",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

uov_test(
    name = "acc_uov_verify_stream_uniform_ip_sw_test",
    srcs = [
        "verify_ip_test.c",
        "verify_ip_testvec.h",
    ],
    copts = [
        "-DVERIFY_ARM=ov_Ip_verify_stream_uniform_sw",
        '-DVERIFY_LABEL="Ip stream_uniform sw"',
    ],
    exec_env = {
        "//hw/top_egret:sim_verilator": None,
    },
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/verify_stream_uniform/ov-Ip-pkc:ov_Ip_verify_stream_uniform_sw",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

uov_test(
    name = "acc_uov_verify_stream_uniform_is_bngfaes_test",
    srcs = [
        "verify_is_test.c",
        "verify_stream_uniform_is_testvec.h",
    ],
    copts = [
        "-DVERIFY_ARM=ov_Is_verify_stream_uniform_bngfaes",
        "-DVERIFY_TESTVEC=sw/device/tests/acc_uov/verify_stream_uniform_is_testvec.h",
        '-DVERIFY_LABEL="Is stream_uniform bngfaes"',
    ],
    exec_env = {
        "//hw/top_egret:sim_verilator": None,
    },
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/verify_stream_uniform/ov-Is-pkc:ov_Is_verify_stream_uniform_bngfaes",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

uov_test(
    name = "acc_uov_verify_stream_uniform_is_bngfonly_test",
    srcs = [
        "verify_is_test.c",
        "verify_stream_uniform_is_testvec.h",
    ],
    copts = [
        "-DVERIFY_ARM=ov_Is_verify_stream_uniform_bngfonly",
        "-DVERIFY_TESTVEC=sw/device/tests/acc_uov/verify_stream_uniform_is_testvec.h",
        '-DVERIFY_LABEL="Is stream_uniform bngfonly"',
    ],
    exec_env = {
        "//hw/top_egret:sim_verilator": None,
    },
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/verify_stream_uniform/ov-Is-pkc:ov_Is_verify_stream_uniform_bngfonly",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

uov_test(
    name = "acc_uov_verify_stream_uniform_is_sw_test",
    srcs = [
        "verify_is_test.c",
        "verify_stream_uniform_is_testvec.h",
    ],
    copts = [
        "-DVERIFY_ARM=ov_Is_verify_stream_uniform_sw",
        "-DVERIFY_TESTVEC=sw/device/tests/acc_uov/verify_stream_uniform_is_testvec.h",
        '-DVERIFY_LABEL="Is stream_uniform sw"',
    ],
    exec_env = {
        "//hw/top_egret:sim_verilator": None,
    },
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/verify_stream_uniform/ov-Is-pkc:ov_Is_verify_stream_uniform_sw",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

uov_test(
    name = "acc_uov_sign_ip_bngfaes_test",
    srcs = [
        "sign_test.c",
        "sign_ip_testvec.h",
    ],
    exec_env = {
        "//hw/top_egret:fpga_cw340_test_rom": None,
        "//hw/top_egret:sim_verilator": None,
    },
    fpga = fpga_params(
        timeout = "moderate",
        tags = ["manual"],
    ),
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/sign_rtl/ov-Ip-skc:ov_Ip_sign_rtl_bngfaes_0",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

uov_test(
    name = "acc_uov_sign_ip_bngfonly_test",
    srcs = [
        "sign_test.c",
        "sign_ip_testvec.h",
    ],
    copts = [
        "-DSIGN_APP=ov_Ip_sign_rtl_bngfonly_0",
        '-DSIGN_TIER="Ip bngfonly"',
        "-DSIGN_TESTVEC=sw/device/tests/acc_uov/sign_ip_testvec.h",
    ],
    exec_env = {
        "//hw/top_egret:sim_verilator": None,
    },
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/sign_rtl/ov-Ip-skc:ov_Ip_sign_rtl_bngfonly_0",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

uov_test(
    name = "acc_uov_sign_ip_sw_test",
    srcs = [
        "sign_test.c",
        "sign_ip_testvec.h",
    ],
    copts = [
        "-DSIGN_APP=ov_Ip_sign_rtl_sw_0",
        '-DSIGN_TIER="Ip sw"',
        "-DSIGN_TESTVEC=sw/device/tests/acc_uov/sign_ip_testvec.h",
    ],
    exec_env = {
        "//hw/top_egret:sim_verilator": None,
    },
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/sign_rtl/ov-Ip-skc:ov_Ip_sign_rtl_sw_0",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

uov_test(
    name = "acc_uov_sign_is_bngfaes_test",
    srcs = [
        "sign_test.c",
        "sign_is_testvec.h",
    ],
    copts = [
        "-DSIGN_APP=ov_Is_sign_rtl_bngfaes_0",
        '-DSIGN_TIER="Is bngfaes"',
        "-DSIGN_TESTVEC=sw/device/tests/acc_uov/sign_is_testvec.h",
    ],
    exec_env = {
        "//hw/top_egret:fpga_cw340_test_rom": None,
        "//hw/top_egret:sim_verilator": None,
    },
    fpga = fpga_params(
        timeout = "moderate",
        tags = ["manual"],
    ),
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/sign_rtl/ov-Is-skc:ov_Is_sign_rtl_bngfaes_0",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

uov_test(
    name = "acc_uov_sign_is_bngfonly_test",
    srcs = [
        "sign_test.c",
        "sign_is_testvec.h",
    ],
    copts = [
        "-DSIGN_APP=ov_Is_sign_rtl_bngfonly_0",
        '-DSIGN_TIER="Is bngfonly"',
        "-DSIGN_TESTVEC=sw/device/tests/acc_uov/sign_is_testvec.h",
    ],
    exec_env = {
        "//hw/top_egret:sim_verilator": None,
    },
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/sign_rtl/ov-Is-skc:ov_Is_sign_rtl_bngfonly_0",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

uov_test(
    name = "acc_uov_sign_is_sw_test",
    srcs = [
        "sign_test.c",
        "sign_is_testvec.h",
    ],
    copts = [
        "-DSIGN_APP=ov_Is_sign_rtl_sw_0",
        '-DSIGN_TIER="Is sw"',
        "-DSIGN_TESTVEC=sw/device/tests/acc_uov/sign_is_testvec.h",
    ],
    exec_env = {
        "//hw/top_egret:sim_verilator": None,
    },
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/sign_rtl/ov-Is-skc:ov_Is_sign_rtl_sw_0",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

# ── keygen stream_uniform: the ablation rig on chip ──────────────────────────
# Same outer kernel across arms, only the backend swaps, so these tier ratios
# isolate the instructions. The rig runs at the sw arm's geometry (Ip WJ=5,
# Is WJ=10) and keeps the stream host contract, so it reuses the sw testvec
# headers verbatim — the expected key is tier-invariant and the window
# geometry already matches.
uov_test(
    name = "acc_uov_keygen_stream_uniform_ip_bngfaes_test",
    srcs = [
        "keygen_stream_ip_test.c",
        "keygen_stream_ip_sw_testvec.h",
    ],
    copts = [
        "-DKEYGEN_APP=ov_Ip_keygen_stream_uniform_bngfaes",
        '-DKEYGEN_TIER="Ip stream_uniform bngfaes"',
        "-DKEYGEN_TESTVEC=sw/device/tests/acc_uov/keygen_stream_ip_sw_testvec.h",
    ],
    exec_env = {
        "//hw/top_egret:sim_verilator": None,
    },
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream_uniform/ov-Ip-pkc+skc:ov_Ip_keygen_stream_uniform_bngfaes",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)
uov_test(
    name = "acc_uov_keygen_stream_uniform_ip_bngfonly_test",
    srcs = [
        "keygen_stream_ip_test.c",
        "keygen_stream_ip_sw_testvec.h",
    ],
    copts = [
        "-DKEYGEN_APP=ov_Ip_keygen_stream_uniform_bngfonly",
        '-DKEYGEN_TIER="Ip stream_uniform bngfonly"',
        "-DKEYGEN_TESTVEC=sw/device/tests/acc_uov/keygen_stream_ip_sw_testvec.h",
    ],
    exec_env = {
        "//hw/top_egret:sim_verilator": None,
    },
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream_uniform/ov-Ip-pkc+skc:ov_Ip_keygen_stream_uniform_bngfonly",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)
uov_test(
    name = "acc_uov_keygen_stream_uniform_ip_sw_test",
    srcs = [
        "keygen_stream_ip_test.c",
        "keygen_stream_ip_sw_testvec.h",
    ],
    copts = [
        "-DKEYGEN_APP=ov_Ip_keygen_stream_uniform_sw",
        '-DKEYGEN_TIER="Ip stream_uniform sw"',
        "-DKEYGEN_TESTVEC=sw/device/tests/acc_uov/keygen_stream_ip_sw_testvec.h",
    ],
    exec_env = {
        "//hw/top_egret:sim_verilator": None,
    },
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream_uniform/ov-Ip-pkc+skc:ov_Ip_keygen_stream_uniform_sw",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)
uov_test(
    name = "acc_uov_keygen_stream_uniform_is_bngfaes_test",
    srcs = [
        "keygen_stream_is_test.c",
        "keygen_stream_is_sw_testvec.h",
    ],
    copts = [
        "-DKEYGEN_APP=ov_Is_keygen_stream_uniform_bngfaes",
        '-DKEYGEN_TIER="Is stream_uniform bngfaes"',
        "-DKEYGEN_TESTVEC=sw/device/tests/acc_uov/keygen_stream_is_sw_testvec.h",
    ],
    exec_env = {
        "//hw/top_egret:sim_verilator": None,
    },
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream_uniform/ov-Is-pkc+skc:ov_Is_keygen_stream_uniform_bngfaes",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)
uov_test(
    name = "acc_uov_keygen_stream_uniform_is_bngfonly_test",
    srcs = [
        "keygen_stream_is_test.c",
        "keygen_stream_is_sw_testvec.h",
    ],
    copts = [
        "-DKEYGEN_APP=ov_Is_keygen_stream_uniform_bngfonly",
        '-DKEYGEN_TIER="Is stream_uniform bngfonly"',
        "-DKEYGEN_TESTVEC=sw/device/tests/acc_uov/keygen_stream_is_sw_testvec.h",
    ],
    exec_env = {
        "//hw/top_egret:sim_verilator": None,
    },
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream_uniform/ov-Is-pkc+skc:ov_Is_keygen_stream_uniform_bngfonly",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)
uov_test(
    name = "acc_uov_keygen_stream_uniform_is_sw_test",
    srcs = [
        "keygen_stream_is_test.c",
        "keygen_stream_is_sw_testvec.h",
    ],
    copts = [
        "-DKEYGEN_APP=ov_Is_keygen_stream_uniform_sw",
        '-DKEYGEN_TIER="Is stream_uniform sw"',
        "-DKEYGEN_TESTVEC=sw/device/tests/acc_uov/keygen_stream_is_sw_testvec.h",
    ],
    exec_env = {
        "//hw/top_egret:sim_verilator": None,
    },
    verilator = verilator_params(
        timeout = "eternal",
        tags = ["manual"],
    ),
    deps = [
        "//hw/top/dt",
        "//sw/acc/crypto/handwritten/uov/dmem32k/keygen_stream_uniform/ov-Is-pkc+skc:ov_Is_keygen_stream_uniform_sw",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/dif:acc",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:acc_testutils",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

# ---- Round-3 Ip3 cells: four tiers (bnaesonly = hardware AES, software GF) ----
# Same drivers as the R2 cells; the generated headers carry the R3 geometry and
# host map. Uniform-rig arms reuse the streamed headers (same host contract).
_IP3 = "//sw/acc/crypto/handwritten/uov/dmem32k/"

_CHIP_DEPS = [
    "//hw/top/dt",
    "//sw/device/lib/base:memory",
    "//sw/device/lib/dif:acc",
    "//sw/device/lib/runtime:ibex",
    "//sw/device/lib/runtime:log",
    "//sw/device/lib/testing:acc_testutils",
    "//sw/device/lib/testing:entropy_testutils",
    "//sw/device/lib/testing/test_framework:ottf_main",
]

_IP3_TIERS = ["bngfaes", "bngfonly", "bnaesonly", "sw"]

# tier -> tuned acc_binary suffix; hw-GF arms fold WJ=6 windows, software-GF
# arms WJ=5, and the header names the geometry, not the tier.
_IP3_TUNED = {
    "bngfaes": ("_bngfaes", "wj6"),
    "bngfonly": ("_bngfonly", "wj6"),
    "bnaesonly": ("_bnaesonly", "wj5"),
    "sw": ("_sw", "wj5"),
}

[
    uov_test(
        name = "acc_uov_keygen_stream_ip3_{}_test".format(tier),
        srcs = [
            "keygen_stream_ip_test.c",
            "keygen_stream_ip3_{}_testvec.h".format(geo),
        ],
        copts = [
            "-DKEYGEN_APP=ov_Ip3_keygen_stream" + app,
            '-DKEYGEN_TIER="Ip3 {}"'.format(tier),
            "-DKEYGEN_TESTVEC=sw/device/tests/acc_uov/keygen_stream_ip3_{}_testvec.h".format(geo),
        ],
        exec_env = {"//hw/top_egret:sim_verilator": None},
        verilator = verilator_params(
            timeout = "eternal",
            tags = ["manual"],
        ),
        deps = _CHIP_DEPS + [_IP3 + "keygen_stream/ov-Ip3-pkc+skc:ov_Ip3_keygen_stream" + app],
    )
    for tier, (app, geo) in _IP3_TUNED.items()
]

# The uniform keygen rig runs every arm at WJ=5.
[
    uov_test(
        name = "acc_uov_keygen_stream_uniform_ip3_{}_test".format(tier),
        srcs = [
            "keygen_stream_ip_test.c",
            "keygen_stream_ip3_wj5_testvec.h",
        ],
        copts = [
            "-DKEYGEN_APP=ov_Ip3_keygen_stream_uniform_" + tier,
            '-DKEYGEN_TIER="Ip3 stream_uniform {}"'.format(tier),
            "-DKEYGEN_TESTVEC=sw/device/tests/acc_uov/keygen_stream_ip3_wj5_testvec.h",
        ],
        exec_env = {"//hw/top_egret:sim_verilator": None},
        verilator = verilator_params(
            timeout = "eternal",
            tags = ["manual"],
        ),
        deps = _CHIP_DEPS + [_IP3 + "keygen_stream_uniform/ov-Ip3-pkc+skc:ov_Ip3_keygen_stream_uniform_" + tier],
    )
    for tier in _IP3_TIERS
]

[
    uov_test(
        name = "acc_uov_verify_stream_ip3_{}_test".format(tier),
        srcs = [
            "verify_ip_test.c",
            "verify_ip3_testvec.h",
        ],
        copts = [
            "-DVERIFY_ARM=ov_Ip3_verify_stream" + app,
            '-DVERIFY_LABEL="Ip3 streamed {}"'.format(tier),
            "-DVERIFY_TESTVEC=sw/device/tests/acc_uov/verify_ip3_testvec.h",
        ],
        exec_env = {"//hw/top_egret:sim_verilator": None},
        verilator = verilator_params(
            timeout = "eternal",
            tags = ["manual"],
        ),
        deps = _CHIP_DEPS + [_IP3 + "verify_stream/ov-Ip3-pkc:ov_Ip3_verify_stream" + app],
    )
    for tier, (app, _) in _IP3_TUNED.items()
]

[
    uov_test(
        name = "acc_uov_verify_stream_uniform_ip3_{}_test".format(tier),
        srcs = [
            "verify_ip_test.c",
            "verify_ip3_testvec.h",
        ],
        copts = [
            "-DVERIFY_ARM=ov_Ip3_verify_stream_uniform_" + tier,
            '-DVERIFY_LABEL="Ip3 stream_uniform {}"'.format(tier),
            "-DVERIFY_TESTVEC=sw/device/tests/acc_uov/verify_ip3_testvec.h",
        ],
        exec_env = {"//hw/top_egret:sim_verilator": None},
        verilator = verilator_params(
            timeout = "eternal",
            tags = ["manual"],
        ),
        deps = _CHIP_DEPS + [_IP3 + "verify_stream_uniform/ov-Ip3-pkc:ov_Ip3_verify_stream_uniform_" + tier],
    )
    for tier in _IP3_TIERS
]

[
    uov_test(
        name = "acc_uov_sign_ip3_{}_test".format(tier),
        srcs = [
            "sign_test.c",
            "sign_ip3_testvec.h",
        ],
        copts = [
            "-DSIGN_APP=ov_Ip3_sign_rtl_{}_0".format(tier),
            '-DSIGN_TIER="Ip3 {}"'.format(tier),
            "-DSIGN_TESTVEC=sw/device/tests/acc_uov/sign_ip3_testvec.h",
        ],
        exec_env = {"//hw/top_egret:sim_verilator": None},
        verilator = verilator_params(
            timeout = "eternal",
            tags = ["manual"],
        ),
        deps = _CHIP_DEPS + [_IP3 + "sign_rtl/ov-Ip3-skc:ov_Ip3_sign_rtl_{}_0".format(tier)],
    )
    for tier in _IP3_TIERS
]

# Round-2 hardware AES with the software-GF geometry.
[
    uov_test(
        name = "acc_uov_keygen_{}_{}_bnaesonly_test".format(family, param.lower()),
        srcs = [
            "keygen_stream_{}_test.c".format(param.lower()),
            "keygen_stream_{}_sw_testvec.h".format(param.lower()),
        ],
        copts = [
            "-DKEYGEN_APP=" + app,
            '-DKEYGEN_TIER="{} {} bnaesonly"'.format(param, family),
            "-DKEYGEN_TESTVEC=sw/device/tests/acc_uov/keygen_stream_{}_sw_testvec.h".format(param.lower()),
        ],
        exec_env = {"//hw/top_egret:sim_verilator": None},
        verilator = verilator_params(timeout = "eternal", tags = ["manual"]),
        deps = _CHIP_DEPS[:1] + [
            "//sw/acc/crypto/handwritten/uov/dmem32k/keygen_{}/ov-{}-pkc+skc:".format(family, param) + app,
        ] + _CHIP_DEPS[1:],
    )
    for param, family, app in [
        ("Ip", "stream", "ov_Ip_keygen_stream_bnaesonly"),
        ("Is", "stream", "ov_Is_keygen_stream_bnaesonly"),
        ("Ip", "stream_uniform", "ov_Ip_keygen_stream_uniform_bnaesonly"),
        ("Is", "stream_uniform", "ov_Is_keygen_stream_uniform_bnaesonly"),
    ]
]

[
    uov_test(
        name = "acc_uov_verify_{}_{}_bnaesonly_test".format(family, param.lower()),
        srcs = ["verify_{}_test.c".format(param.lower()), header],
        copts = [
            "-DVERIFY_ARM=" + app,
            '-DVERIFY_LABEL="{} {} bnaesonly"'.format(param, family),
            "-DVERIFY_TESTVEC=sw/device/tests/acc_uov/" + header,
        ],
        exec_env = {"//hw/top_egret:sim_verilator": None},
        verilator = verilator_params(timeout = "eternal", tags = ["manual"]),
        deps = _CHIP_DEPS[:1] + [
            "//sw/acc/crypto/handwritten/uov/dmem32k/verify_{}/ov-{}-pkc:".format(family, param) + app,
        ] + _CHIP_DEPS[1:],
    )
    for param, family, app, header in [
        ("Ip", "stream", "ov_Ip_verify_stream_bnaesonly", "verify_ip_testvec.h"),
        ("Is", "stream", "ov_Is_verify_stream_bnaesonly", "verify_stream_is_sw_testvec.h"),
        ("Ip", "stream_uniform", "ov_Ip_verify_stream_uniform_bnaesonly", "verify_ip_testvec.h"),
        ("Is", "stream_uniform", "ov_Is_verify_stream_uniform_bnaesonly", "verify_stream_uniform_is_testvec.h"),
    ]
]

# Round-2 tuned verify on the tiers that had chip cells only through the uniform rig.
# Ip keeps its fixed 13/31 window split on every tier; Is switches header with the
# window geometry (gfhw arms vs the software-GF arm).
[
    uov_test(
        name = "acc_uov_verify_stream_{}_{}_test".format(param.lower(), tier),
        srcs = ["verify_{}_test.c".format(param.lower()), header],
        copts = [
            "-DVERIFY_ARM=ov_{}_verify_stream_{}".format(param, tier),
            '-DVERIFY_LABEL="{} streamed {}"'.format(param, tier),
            "-DVERIFY_TESTVEC=sw/device/tests/acc_uov/" + header,
        ],
        exec_env = {"//hw/top_egret:sim_verilator": None},
        verilator = verilator_params(timeout = "eternal", tags = ["manual"]),
        deps = _CHIP_DEPS[:1] + [
            "//sw/acc/crypto/handwritten/uov/dmem32k/verify_stream/ov-{}-pkc:ov_{}_verify_stream_{}".format(param, param, tier),
        ] + _CHIP_DEPS[1:],
    )
    for param, tier, header in [
        ("Ip", "bngfonly", "verify_ip_testvec.h"),
        ("Ip", "sw", "verify_ip_testvec.h"),
        ("Is", "bngfonly", "verify_stream_is_testvec.h"),
        ("Is", "sw", "verify_stream_is_sw_testvec.h"),
    ]
]

[
    uov_test(
        name = "acc_uov_sign_{}_bnaesonly_test".format(param.lower()),
        srcs = ["sign_test.c", "sign_{}_testvec.h".format(param.lower())],
        copts = [
            "-DSIGN_APP=ov_{}_sign_rtl_bnaesonly_0".format(param),
            '-DSIGN_TIER="{} bnaesonly"'.format(param),
            "-DSIGN_TESTVEC=sw/device/tests/acc_uov/sign_{}_testvec.h".format(param.lower()),
        ],
        exec_env = {"//hw/top_egret:sim_verilator": None},
        verilator = verilator_params(timeout = "eternal", tags = ["manual"]),
        deps = _CHIP_DEPS[:1] + [
            "//sw/acc/crypto/handwritten/uov/dmem32k/sign_rtl/ov-{}-skc:ov_{}_sign_rtl_bnaesonly_0".format(param, param),
        ] + _CHIP_DEPS[2:],
    )
    for param in ["Ip", "Is"]
]

# One-shot keygen at the 128 KiB profile: `_sp` (single pass) and `_min` (smallest
# footprint) on every tier; one EXECUTE per key, cpk + csk read back, meters v2 lines.
[
    uov_test(
        name = "acc_uov_keygen_{}_{}_{}_test".format(family, param.lower(), tier),
        srcs = [
            "keygen_oneshot_test.c",
            "keygen_oneshot_{}_testvec.h".format(param.lower()),
            "keygen_oneshot_geom_{}.h".format(app),
        ],
        copts = [
            "-DKEYGEN_APP=" + app,
            '-DKEYGEN_TIER="{} {} {}"'.format(param, family, tier),
            '-DMETER_ID="op=keygen param={} family={} tier={}"'.format(param.lower(), family, tier),
            "-DKEYGEN_TESTVEC=sw/device/tests/acc_uov/keygen_oneshot_{}_testvec.h".format(param.lower()),
            "-DKEYGEN_GEOM=sw/device/tests/acc_uov/keygen_oneshot_geom_{}.h".format(app),
            # software-GF cells take hours per keygen: the accepting run only
            "-DONESHOT_LEGS={}".format(1 if tier in ("bnaesonly", "sw") else 3),
        ],
        exec_env = {"//hw/top_egret:sim_verilator": None},
        verilator = verilator_params(timeout = "eternal", tags = ["manual"]),
        deps = _CHIP_DEPS[:1] + [
            "//sw/acc/crypto/handwritten/uov/dmem_large/keygen_{}/ov-{}-pkc+skc:".format(family, param) + app,
        ] + _CHIP_DEPS[1:],
    )
    for param, family, tier, app in [
        (p, f, t, "ov_{}_keygen_{}_{}".format(p, f, t))
        for f in ("sp", "min")
        for p in ("Ip", "Ip3", "Is")
        for t in ("bngfaes", "bngfonly", "bnaesonly", "sw")
    ]
]

# One-shot verify at the 128 KiB profile (Ip3, Ip, Is; every tier): whole cpk resident, one EXECUTE per
# verification; accept (key transferred) -> reject -> accept (key resident) metered. Each parameter set has its
# own vector header (keys, check plan), each ELF its own geometry header.
[
    uov_test(
        name = "acc_uov_verify_full_{}_{}_test".format(param.lower(), tier),
        srcs = [
            "verify_oneshot_test.c",
            "verify_oneshot_{}_testvec.h".format(param.lower()),
            "verify_oneshot_geom_{}.h".format(app),
        ],
        copts = [
            "-DVERIFY_APP=" + app,
            "-DVERIFY_TESTVEC=sw/device/tests/acc_uov/verify_oneshot_{}_testvec.h".format(param.lower()),
            "-DVERIFY_GEOM=sw/device/tests/acc_uov/verify_oneshot_geom_{}.h".format(app),
        ],
        exec_env = {"//hw/top_egret:sim_verilator": None},
        verilator = verilator_params(timeout = "eternal", tags = ["manual"]),
        deps = _CHIP_DEPS[:1] + [
            "//sw/acc/crypto/handwritten/uov/dmem_large/verify_full/ov-{}-pkc:".format(param) + app,
        ] + _CHIP_DEPS[1:],
    )
    for param, tier, app in [
        (p, t, "ov_{}_verify_full_{}".format(p, t))
        for p in ("Ip3", "Ip", "Is")
        for t in ("bngfaes", "bngfonly", "bnaesonly", "sw")
    ]
]
