#!/usr/bin/env python3

import subprocess
import re
import sys
import shutil
from collections import deque
import csv
import json
import argparse
from tabulate import tabulate

OUTDIR_GENUS = "reports/ASIC-Genus"
OUTDIR_VIVADO = "reports/FPGA-Vivado"

def extract_util_fpga(filepath):
    """Extract utilization information from FPGA utilization reports.
    """
    util_data = {
        "Slice LUTs": None,
        "DSPs": None,
        "CARRY4": None,
        "Slice Registers": None,
        "Block RAM Tile": None,
        "Fmax": None,
    }

    try:
        with open(filepath + "/utilization.txt", "r") as f:
            for line in f:
                for key in util_data.keys():
                    if f"| {key}" in line:
                        util_data[key] = float(line.split("|")[2].strip())
    except FileNotFoundError:
        pass

    try:
        with open(filepath + "/summary.txt", "r") as f:
            for line in f:
                for key in util_data.keys():
                    # Extract values for specific components
                    if key in line:
                        util_data[key] = float(line.split(" ")[1].strip())
    except FileNotFoundError:
        pass

    return util_data


def extract_delay_fpga(filepath):
    """Extract path delay information from FPGA timing reports.
    """
    delay_data = None

    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                line = re.sub(r'\s+', ' ', line)

                if "Requirement:" in line:
                    delay_data = float(line.split(" ")[1].strip()[:-3])
    except FileNotFoundError:
        pass

    return delay_data


def extract_genus(filepath):
    """Extract area and Fmax from Genus' ASIC reports.
    """
    util_data = {
        "Cell Area": None,
        "Net Area": None,
        "Total Area": None,
        "Fmax": None
    }

    try:
        with open(filepath + "/summary.txt", "r") as f:
            for line in f:
                for key in util_data.keys():
                    if key in line:
                        util_data[key] = float(line.split(" ")[1].strip())
    except FileNotFoundError:
        pass

    try:
        with open(filepath + "/area.rpt", "r") as f:
            for line in f:
                match = re.match(
                    r'^\s*\S+\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)',
                    line
                )
                if match:
                    util_data["Cell Area"] = float(match.group(2))
                    util_data["Net Area"] = float(match.group(3))
                    util_data["Total Area"] = float(match.group(4))
    except FileNotFoundError:
        pass

    return util_data


def extract_all(top, flag_group, tools):
    """Extract synthesis numbers for ASIC/FPGA reports.
    """
    if flag_group is not None:
        flag_group = "_" + flag_group
    else:
        flag_group = ""
    outdir = top + flag_group
    data = [outdir.replace("_", "\\_")]

    for tool in tools:
        if tool == 'vivado':
            result = extract_util_fpga(f"{OUTDIR_VIVADO}/{outdir}")
            data += list(result.values())
        elif tool == 'genus':
            result = extract_genus(f"{OUTDIR_GENUS}/{outdir}")
            data += list(result.values())

    return data


def report(data, tools):
    """Put collected data to a table in LaTex.
    """
    headers = ["topmodule"]
    floatfmt= [""]

    if 'vivado' in tools:
        headers += ["LUT", "DSP", "CARRY4", "FF", "BRAM", "Fmax"]
        floatfmt += ["g", "g", "g", "g", "g", "g"]
    if 'genus' in tools:
        headers += ["cellAreaGenus", "netAreaGenus", "totalAreaGenus", "FmaxGenus"]
        floatfmt += [".3f", "g"]

    latex_table = tabulate(
        data,
        headers,
        tablefmt="latex_raw",
        floatfmt=floatfmt,
        missingval="{---}"
    )

    print(latex_table)

    # Write results to a CSV file
    writer = csv.writer(sys.stdout)
    writer.writerows([headers] + data)


def report_latex_tables(flags, flags_aes):
    """Print the two paper tables from previously generated Vivado/Genus reports."""
    labels = {
        None: "Baseline",
        "mul": "GF fixed",
        "mul_reg": "GF config.",
        "aes": "AES",
        "mul+aes": "GF fixed + AES",
        "mul_reg+aes": "GF config. + AES",
    }

    # Build the same module/flag combinations as --mul, --aes, --mac and --acc.
    modules_mul = [
        ("gfmacc", "mul", ["gfmacc_bignum"]),
        ("gfmacc", "mul_reg", ["gfmacc_bignum", "mod_reg_poly"]),
    ]
    modules_aes = [("acc_aes_bignum", None, ["aes_bignum"])]
    modules_mac = [("acc_mac_bignum", flag_group, flag) for flag_group, flag in flags]
    modules_acc = [("acc_core", flag_group, flag) for flag_group, flag in flags + flags_aes]

    # Apply --pqc to the integrated variants, as in main().
    def with_pqc(modules):
        return [
            (top_module, "pqc+" + flag_group if flag_group else "pqc",
             flag + ["pqc"] if flag else ["pqc"])
            for top_module, flag_group, flag in modules
        ]

    modules_mac_pqc = with_pqc(modules_mac)
    modules_acc_pqc = with_pqc(modules_acc)
    modules = (modules_mul + modules_aes + modules_mac + modules_mac_pqc
               + modules_acc + modules_acc_pqc)

    # Resolve report paths exactly as in the existing synthesis loop.
    results = {}
    for top_module, flag_group, flag in modules:
        suffix = "_" + flag_group if flag_group is not None else ""
        vivado_dir = f"{OUTDIR_VIVADO}/{top_module}{suffix}"
        genus_dir = f"{OUTDIR_GENUS}/{top_module}{suffix}"
        results[(top_module, flag_group)] = (
            extract_util_fpga(vivado_dir), extract_genus(genus_dir)
        )

    def print_row(label, top_module, flag_group):
        fpga, asic = results[(top_module, flag_group)]
        lut = fpga["Slice LUTs"]
        dsp = fpga["DSPs"]
        carry4 = fpga["CARRY4"]
        ff = fpga["Slice Registers"]
        fpga_fmax = fpga["Fmax"]
        cell = asic["Cell Area"]
        net = asic["Net Area"]
        asic_fmax = asic["Fmax"]

        def integer(value, pos=2):
            return f"{'--':<{pos}}" if value is None else f"{value:>{pos},.0f}"

        def frequency(value, pos=2):
            return f"{'--':<{pos}}" if value is None else f"{value:>{pos}.0f}"

        def area(value, pos=4):
            return f"{'--':<{pos}}" if value is None else f"{value / 1000:>{pos},.1f}"

        print(f"    {label:<17} & {integer(lut,6)} & {integer(dsp,2)} & "
              f"{integer(carry4, 3)} & {integer(ff,3)} & {frequency(fpga_fmax,3)} & "
              f"{area(cell,5)} & {area(net,4)} & {frequency(asic_fmax,4)} \\\\")

    def print_group(title, group):
        print(r"    \multicolumn{9}{@{}c@{}}{\textit{" + title + r":}} \\[2pt]")
        for top_module, flag_group, flag in group:
            if top_module == "acc_aes_bignum":
                label = "AES"
            elif flag_group == "pqc":
                label = labels[None]
            elif flag_group is not None and flag_group.startswith("pqc+"):
                label = labels[flag_group[4:]]
            else:
                label = labels[flag_group]
            print_row(label, top_module, flag_group)

    print(r"""
  \begin{tabularx}{\linewidth}{@{}Xrrrrrrrr@{}}
    \toprule
    & \multicolumn{5}{c}{FPGA}
    & \multicolumn{3}{c}{ASIC} \\
    \cmidrule(lr){2-6}\cmidrule(l){7-9}
    Configuration & LUT & DSP & CY4 & FF & $f_{\max}$
                  & Cell & Net & $f_{\max}$ \\
    \midrule""")
    print_group("Standalone functional units", modules_mul + modules_aes)
    print(r"    \midrule")
    print_group("MAC without existing PQC extensions", modules_mac)
    print(r"    \midrule")
    print_group("MAC with existing PQC extensions", modules_mac_pqc)
    print(r"""    \bottomrule
  \end{tabularx}
""")

    print(r"""
  \begin{tabularx}{\linewidth}{@{}Xrrrrrrrr@{}}
    \toprule
    & \multicolumn{5}{c}{FPGA}
    & \multicolumn{3}{c}{ASIC} \\
    \cmidrule(lr){2-6}\cmidrule(l){7-9}
    Configuration & LUT & DSP & CY4 & FF & $f_{\max}$
                  & Cell & Net & $f_{\max}$ \\
    \midrule""")
    print_group("Without existing PQC extensions", modules_acc)
    print(r"    \midrule")
    print_group("With existing PQC extensions", modules_acc_pqc)
    print(r"""    \bottomrule
  \end{tabularx}
""")

def run_synthesis(top, tool, outdir, flags=None):
    """Run FPGA/ASIC synthesis with given tool and top module.
    """
    fusesoc_flags = ""
    if flags is not None:
        fusesoc_flags = '--flag ' + ' --flag '.join(flags)

    print(flags, 0 if not flags or 'pqc' not in flags else 1)

    cmd_synth = (
        f"fusesoc --cores-root . run --flag=fileset_top --target=sta {fusesoc_flags} --no-export "
        f"--tool={tool} --setup --mapping=lowrisc:prim_generic:all:0.1 lowrisc:ip:acc:0.1 && "
        f"mkdir -p {outdir} && cd build/lowrisc_ip_acc_0.1/sta-{tool} && "
    )
    cmd_timing = (
        f"fusesoc --cores-root . run --flag=fileset_top --target=sta {fusesoc_flags} --no-export "
        f"--tool={tool} --setup --mapping=lowrisc:prim_generic:all:0.1 lowrisc:ip:acc:0.1 && "
        f"cd build/lowrisc_ip_acc_0.1/sta-{tool} && "
    )
    if tool == 'vivado':
        cmd_synth += (
            f"vivado -mode batch -source vivado_synth.tcl -notrace -tclargs --top_module {top} "
            f"--outdir ../../../{outdir}"
        )
        cmd_timing += (
            f"vivado -mode batch -source vivado_timing.tcl -notrace -tclargs --top_module {top} "
            "--start_freq {freq} "
            f"--outdir ../../../{outdir}"
        )
    elif tool == 'genus':
        cmd_synth += (
            "source /path/to/genus.cshrc && "
            f"setenv TOP_MODULE {top} && setenv START_F 400 && setenv OUTDIR ../../../{outdir} && "
            f"setenv PQC_MODE {0 if not flags or 'pqc' not in flags else 1} &&"
            "genus -files genus_synth.tcl -log synth.log"
        )

        cmd_timing += (
            "tcsh -c 'source /path/to/genus.cshrc; "
            f"setenv TOP_MODULE {top}; "
            f"setenv OUTDIR ../../../{outdir}; "
            "setenv START_F {freq}; "
            "genus -files genus_timing.tcl -log synth.log'"
        )
    else:
        print(f"ERROR: Unsupported tool {tool}")
        return 1

    print(f"Command: {cmd_synth}")

    subprocess.run(
      cmd_synth,
      shell=True,
      check=True,
      executable='csh' if tool == 'genus' else 'sh'
    )

    print("done")

    start_f = 80

    slow_f = None
    fast_f = None
  
    best_f = None
    max_freq = None
  
    mid_f = float(start_f)
  
    # temp_file existed in Tcl but is unused in the shown code.
    # temp_file = "/tmp/timing.rpt"

    scale_factor = 1000.0
  
    if scale_factor == 1000.0:
        unit = "ns"
    else:
        unit = "ps"
  
    print()

    print("start loop")

    # Binary search for max frequency
    while True:
        mid_f = round(mid_f)
  
        if (mid_f == slow_f) or (mid_f == fast_f):
            break
  
        print(f"Slow frequency: {slow_f} MHz (period: {scale_factor/slow_f if slow_f else '--'} {unit})")
        print(f"Fast frequency: {fast_f} MHz (period: {scale_factor/fast_f if fast_f else '--'} {unit})")
        print(f"Testing clock period: {mid_f} MHz (Frequency: {scale_factor/mid_f} {unit})")
        print()
  
        print(cmd_timing.format(freq=mid_f))

        subprocess.run(
          cmd_timing.format(freq=mid_f),
          shell=True,
          check=True,
          executable='csh' if tool == 'genus' else 'sh'
        )

        print(f"{outdir}/child_result.json")
  
        with open(f"{outdir}/child_result.json", 'r') as file:
          data = json.load(file)
  
        print(data)

        slack = data["slack"]
  
        print()
        print(f"Slack: {slack} {unit}")
        print()
  
        if slack >= 0:
            if not best_f or (mid_f > best_f):
                best_f = mid_f
                max_freq = best_f
            slow_f = mid_f
        else:
            fast_f = mid_f

        print(f"New best frequency: {best_f} MHz (period: {scale_factor/best_f if best_f else '--'} {unit})")
        print(f"New slow frequency: {slow_f} MHz (period: {scale_factor/slow_f if slow_f else '--'} {unit})")
        print(f"New fast frequency: {fast_f} MHz (period: {scale_factor/fast_f if fast_f else '--'} {unit})")
        print(f"\n\n{'*' * shutil.get_terminal_size().columns}\n\n")
  
        # Update mid_f:
        if fast_f == None:
            mid_f = 2.0 * mid_f
        elif slow_f == None:
            mid_f = mid_f / 2.0
        else:
            mid_f = scale_factor / (((scale_factor / slow_f) + (scale_factor / fast_f)) / 2.0)
  
        if mid_f < 1.0:
            raise SystemExit(1)

        if fast_f and slow_f:
          if float(fast_f - slow_f) / fast_f < 0.025:
            print(f"Difference between high and low smaller than 2.5%. Exit search.")
            break

    best_period = scale_factor / max_freq
  
    print("\n\n================================================")
    print(f"Maximum Achievable Frequency: {max_freq} MHz")
    print(f"Clock Period: {best_period} {unit}")
    print("================================================\n\n")

    subprocess.run(
      cmd_timing.format(freq=max_freq),
      shell=True,
      check=True,
      executable='csh' if tool == 'genus' else 'sh'
    )

def main():
    parser = argparse.ArgumentParser(
        description="Python script for running FPGA and ASIC synthesis"
    )
    parser.add_argument(
        "--run_synthesis",
        action="store_true",
        default=False,
        help="Run synthesis. (default: False)"
    )
    parser.add_argument(
        "--tool",
        choices=['Vivado', 'Genus', 'all'],
        default='Vivado',
        help="Output results or run synthesis for specified tool. (default: Vivado)"
    )
    parser.add_argument(
        "--aes",
        action="store_true",
        default=False,
        help="Output synthesis results for AES. (default: False)"
    )
    parser.add_argument(
        "--mul",
        action="store_true",
        default=False,
        help="Output synthesis results for all multipliers. (default: False)"
    )
    parser.add_argument(
        "--acc",
        action="store_true",
        default=False,
        help="Output synthesis results for the 'acc' module. (default: False)"
    )
    parser.add_argument(
        "--mac",
        action="store_true",
        default=False,
        help="Output synthesis results for all OTBN's submodules. (default: False)"
    )
    parser.add_argument(
        "--pqc",
        action="store_true",
        default=False,
        help="Enable PQC in ACC. (default: False)"
    )
    parser.add_argument(
        "--flags",
        type=str,
        default=None,
        help="Comma-separated list of flags for module variants."
    )
    parser.add_argument(
        "--top_module",
        type=str,
        default=None,
        help="Top-level hardware module to be synthesized."
    )
    parser.add_argument(
        "--latex-tables",
        action="store_true",
        help="Print both paper-ready tabularx tables from existing reports."
    )

    args = parser.parse_args()

    if not args.latex_tables and not args.top_module and not args.aes and not args.mul and not args.acc \
        and not args.mac:
        print(
            "ERROR: Please give one of the arugments: --top_module, --aes, --mul, --acc, "
            ", --mac"
        )
        return 1

    if args.flags and (args.aes or args.mul or args.acc or args.mac):
        print("ERROR: --flag is only used with --top_module.")
        return 1

    if not args.latex_tables:
        print(f"run_synthesis: {args.run_synthesis}")
        print(f"top_module: {args.top_module}")

    FLAGS = [
        (None, None),
        ("mul", ["gfmacc_bignum"]),
        ("mul_reg", ["gfmacc_bignum", "mod_reg_poly"]),
    ]

    FLAGS_AES = [
        ("aes", ["aes_bignum"]),
        ("mul+aes", ["gfmacc_bignum", "aes_bignum"]),
        ("mul_reg+aes", ["gfmacc_bignum", "mod_reg_poly", "aes_bignum"]),
    ]

    if args.latex_tables:
        report_latex_tables(FLAGS, FLAGS_AES)
        return 0

    if args.top_module:
        modules = [(args.top_module, None, None)]
    if args.flags:
        flags = args.flags.split(",")
        modules = [(args.top_module, "_".join(flags), flags)]

    if args.mul:
        modules = [
            ("gfmacc", "mul", ["gfmacc_bignum"]),
            ("gfmacc", "mul_reg", ["gfmacc_bignum", "mod_reg_poly"]),
        ]
    elif args.aes:
        modules = [
            ("acc_aes_bignum", None, ["aes_bignum"]),
        ]
    elif args.acc:
        modules = [("acc_core", flag_group, flag) for flag_group, flag in FLAGS + FLAGS_AES]
    elif args.mac:
        modules = [("acc_mac_bignum", flag_group, flag) for flag_group, flag in FLAGS]

    if args.tool == 'all':
        tools = ['vivado', 'genus']
    else:
        tools = [args.tool.lower()]

    if args.pqc:
        modules = [
            (top_module, "pqc+" + flag_group if flag_group else "pqc", flag + ["pqc"] if flag else ["pqc"])
            for top_module, flag_group, flag in modules
        ]

    if args.run_synthesis:
        for top_module, flag_group, flag in modules:
            flag_group = '_' + flag_group if flag_group is not None else ''
            for tool in tools:
                if tool == 'genus':
                    outdir = f"{OUTDIR_GENUS}/{top_module}{flag_group}"
                else:
                    outdir = f"{OUTDIR_VIVADO}/{top_module}{flag_group}"
                # Run synthesis
                run_synthesis(top_module, tool, outdir, flag)

    data = [
        extract_all(top_module, flag_group, tools) for top_module, flag_group, flag in modules
    ]

    report(data, tools)
    return 0


if __name__ == "__main__":
    sys.exit(main())
