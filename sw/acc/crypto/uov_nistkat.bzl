# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

"""UOV KAT drivers on the NIST KAT counts 0..11 (handwritten/test_data/testvectors-<P>-pkc-skc.nistkat).

One test per kernel, tier, parameter set and count. The 128 and 512 KiB kernels run only at their DMEM
profile (tools/uov.py profile), so they are manual and run through uov_nistkat_dmem128 and
uov_nistkat_dmem512; uov_nistkat_dmem32 holds the 32 KiB tests.
"""

load("@ot_python_deps//:requirements.bzl", "requirement")
load("@rules_python//python:defs.bzl", "py_test")

_TIERS = ["bngfaes", "bngfonly", "bnaesonly", "sw"]

# (op, kernel, DMEM KiB, tiers): every kernel of the paper's cycle tables
_KERNELS = [
    ("keygen", "stream", 32, _TIERS),
    ("keygen", "stream_uniform", 32, _TIERS),
    ("sign", "ldirect", 32, _TIERS),
    ("verify", "stream", 32, _TIERS),
    ("verify", "stream_uniform", 32, _TIERS),
    ("keygen", "min", 128, _TIERS),
    ("keygen", "sp", 128, _TIERS),
    ("verify", "full", 128, _TIERS),
    ("keygen", "full", 512, ["bngfaes"]),
    ("sign", "sprec", 512, ["bngfaes"]),
]

_SETS = ["Ip", "Ip3", "Is"]
_COUNTS = 12

def _elf(op, k, kib, t, p):
    dmem = "dmem32k" if kib == 32 else "dmem_large"
    sub = {"keygen": "pkc+skc", "sign": "skc", "verify": "pkc"}[op]
    testvec = "testvec_" if op == "sign" else ""
    return "//sw/acc/crypto/handwritten/uov/{}/{}_{}/ov-{}-{}:ov-{}-{}_{}_{}{}".format(
        dmem,
        op,
        k,
        p,
        sub,
        p,
        op,
        k,
        testvec,
        t,
    )

def _driver(op, k, t, p):
    """The driver, its own arguments, and the option that names the vector file."""
    tier = [] if (op, p) == ("sign", "Ip3") else ["--tier", t]
    if op == "keygen" and k.startswith("stream"):
        return "handwritten/uov/dmem32k/keygen_stream/tests/test_stream_keygen.py", [], "--vectors"
    if op == "keygen":
        return "handwritten/own_utils/run_test.py", ["keygen"] + tier, "--test-data-file"
    if op == "sign":
        precompute = ["--precompute"] if k == "sprec" else []
        return "handwritten/own_utils/run_test.py", ["sign"] + tier + precompute, "--test-data-file"
    if k.startswith("stream"):
        return "handwritten/uov/dmem32k/verify_stream/tests/measure_cycles.py", [], "--vectors"

    # The Ip3 one-shot verify takes its second key from another file; the .nistkat keys are the test's own.
    second = ["--vectors2", "$(rootpath handwritten/test_data/testvectors-Ip3-pkc-skc)"] if p == "Ip3" else []
    return "handwritten/uov/dmem_large/verify_full/tests/test_full_verify.py", tier + second, "--vectors"

def uov_nistkat_tests(name):
    """The tests <name>_<op>_<kernel>_<tier>_<set>_<count> and the suites <name>_dmem<KiB>.

    The streamed verify kernels also get <name>_verify_<kernel>_<tier>_<set>_reject: mutations of count 0 must reject.

    Args:
      name: the prefix of every target.
    """
    suites = {32: [], 128: [], 512: []}
    for op, k, kib, tiers in _KERNELS:
        manual = [] if kib == 32 else ["manual"]
        for t in tiers:
            for p in _SETS:
                test = "{}_{}_{}_{}_{}".format(name, op, k, t, p)
                vectors = "handwritten/test_data/testvectors-{}-pkc-skc.nistkat".format(p)
                main, args, flag = _driver(op, k, t, p)
                native.filegroup(
                    name = test + "_elf",
                    srcs = [_elf(op, k, kib, t, p)],
                    output_group = "elf",
                    tags = manual,
                )
                runs = [(str(c), [], c) for c in range(_COUNTS)]
                if op == "verify" and k.startswith("stream"):
                    runs.append(("reject", ["--reject"], 0))
                for suffix, extra, c in runs:
                    py_test(
                        name = "{}_{}".format(test, suffix),
                        timeout = "eternal",
                        srcs = [main],
                        args = args + extra + [
                            "--param",
                            p,
                            "--elf",
                            "$(rootpath :{}_elf)".format(test),
                            "--cases",
                            str(c),
                            flag,
                            "$(rootpath {})".format(vectors),
                        ],
                        data = native.glob(["handwritten/**/*.py"]) + [
                            ":{}_elf".format(test),
                            vectors,
                            "handwritten/test_data/testvectors-Ip3-pkc-skc",
                            "//hw/ip/acc/util:acc_objdump",
                            "@llvm_toolchain_llvm//:bin/llvm-objdump",
                        ],
                        env = {"RV32_TOOL_OBJDUMP": "$(rootpath @llvm_toolchain_llvm//:bin/llvm-objdump)"},
                        main = main,
                        tags = manual,
                        deps = [
                            "//hw/ip/acc/dv/accsim/sim:load_elf",
                            "//hw/ip/acc/dv/accsim/sim:standalonesim",
                            "//hw/ip/acc/dv/accsim/sim:stats",
                            "//hw/ip/acc/util/shared:elf",
                            "//hw/ip/acc/util/shared:mem_layout",
                            requirement("galois"),
                            requirement("numpy"),
                            requirement("pycryptodome"),
                        ],
                    )
                    suites[kib].append(":{}_{}".format(test, suffix))
    for kib, tests in suites.items():
        native.test_suite(
            name = "{}_dmem{}".format(name, kib),
            tags = [] if kib == 32 else ["manual"],
            tests = tests,
        )
