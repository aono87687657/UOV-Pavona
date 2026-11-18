#!/usr/bin/env python3

"""
Common ACC Simulation Utilities

This module provides the main high-level function for ACC simulation workflow.
Low-level operations are called directly to avoid unnecessary indirection.

KEY FUNCTION:
    run_acc_test() - Complete test lifecycle in one call

USAGE EXAMPLE:
    from acc_sim_utils import run_acc_test, setup_default_keys

    def inject_my_data(sim):
        # Your injection logic
        pass

    success, dmem_bytes, sim = run_acc_test(
        elf_path="test.elf",
        data_injection_func=inject_my_data
    )
"""

import argparse
import os
import sys
from typing import Callable, List, Optional, Tuple, TextIO


def get_err_names(err: int) -> List[str]:
    """Return human-readable names for all set bits in an ERR_BITS value."""
    try:
        from hw.ip.acc.dv.accsim.sim.constants import ErrBits
        return [bit.name for bit in ErrBits
                if bit.name != 'MASK' and (err & bit.value) != 0]
    except ImportError:
        return [f'0x{err:x}']


def setup_default_keys(sim, key0: Optional[int] = None, key1: Optional[int] = None) -> None:
    """
    Set up sideload keys for the simulator with sensible defaults.

    This is a thin wrapper that provides default keys matching standalone.py.
    Kept because it encapsulates the default key pattern used across all tests.

    Args:
        sim: Simulator instance
        key0: First key (default: deadbeef pattern)
        key1: Second key (default: baadf00d pattern)
    """
    if key0 is None:
        key0 = int("deadbeef" * 12, 16)
    if key1 is None:
        key1 = int("baadf00d" * 12, 16)

    sim.state.wsrs.set_sideload_keys(key0, key1)
    sim.state.ext_regs.commit()


def run_acc_test(
    elf_path: str,
    data_injection_func: Callable[[object], None] = None,
    verbose: bool = False,
    dump_regs_file: Optional[TextIO] = None,
    dump_stats_file: Optional[TextIO] = None,
    dump_dmem_file: Optional[object] = None,
    key0: Optional[int] = None,
    key1: Optional[int] = None,
    pqc: bool = True,
    dmem_words: Optional[dict] = None,
) -> Tuple[bool, bytes, object]:
    """
    Run a complete ACC test with standardized workflow.

    This is the MAIN function - it orchestrates the entire test lifecycle.
    All other operations are called directly to avoid unnecessary wrapper layers.

    Workflow:
    1. Create simulator
    2. Load ELF file
    3. Inject test data (via dmem_words dict and/or callback)
    4. Set up keys and commit
    5. Start simulation
    6. Run simulation
    7. Validate PC
    8. Dump outputs
    9. Return results

    Args:
        elf_path: Path to ELF file to execute
        data_injection_func: (Legacy) Function that takes (sim) and injects test data.
            Prefer dmem_words for simple DMEM injection.
        verbose: Whether to print verbose execution output
        dump_regs_file: Optional file handle to dump register contents
        dump_stats_file: Optional file handle to write statistics
        dump_dmem_file: Optional file handle (binary mode) to write DMEM
        key0: Optional custom key0 (default: deadbeef pattern)
        key1: Optional custom key1 (default: baadf00d pattern)
        pqc: Enable PQC extension instructions (default: True, since most
             OV/GF tests require bn.mulv, bn.gfmul, etc.)
        dmem_words: Dict mapping DMEM word addresses to 32-bit values.
            Injected before data_injection_func (if both provided).

    Returns:
        Tuple of (success, dmem_bytes, sim)
        - success: True if test passed (PC and ERR_BITS valid), False otherwise
        - dmem_bytes: DMEM contents after execution
        - sim: Simulator instance (for post-run analysis)

    Example:
        from dmem_utils import bytes_to_dmem_words

        words = {}
        words.update(bytes_to_dmem_words(pk_seed, 0x20))
        words.update(bytes_to_dmem_words(vinegar, 0x40))

        success, dmem, sim = run_acc_test("test.elf", dmem_words=words)
    """
    # Import modules directly (no wrapper needed)
    try:
        from hw.ip.acc.dv.accsim.sim.standalonesim import StandaloneSim
        from hw.ip.acc.dv.accsim.sim.load_elf import load_elf
    except ImportError as e:
        print(f"Error importing ACC modules: {e}", file=sys.stderr)
        print("Make sure OPENTITAN_ROOT is in sys.path", file=sys.stderr)
        return (False, b'', None)

    # Create simulator (direct call - no wrapper)
    sim = StandaloneSim(pqc=pqc)

    # Load ELF file (direct call - no wrapper)
    try:
        exp_end_addr = load_elf(sim, elf_path)
    except Exception as e:
        print(f"Error loading ELF '{elf_path}': {e}", file=sys.stderr)
        return (False, b'', sim)

    # Inject DMEM words (direct dict injection)
    if dmem_words:
        try:
            from dmem_utils import inject_words_to_dmem
            inject_words_to_dmem(sim, dmem_words)
        except Exception as e:
            print(f"Error injecting DMEM words: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            return (False, b'', sim)

    # Inject custom test data (legacy callback)
    if data_injection_func is not None:
        try:
            data_injection_func(sim)
        except Exception as e:
            print(f"Error injecting test data: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            return (False, b'', sim)

    # Set up keys (use our helper for default keys)
    setup_default_keys(sim, key0, key1)

    # Start simulation (direct call - no wrapper)
    collect_stats = dump_stats_file is not None
    sim.start(collect_stats=collect_stats)

    # Run simulation (direct call - no wrapper)
    try:
        sim.run(verbose=verbose, dump_file=dump_regs_file)
    except Exception as e:
        print(f"Error running simulation: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return (False, b'', sim)

    # Validate PC against expected end address
    if exp_end_addr is not None:
        if sim.state.pc != exp_end_addr:
            print(f'Run stopped at PC {sim.state.pc:#x}, '
                  f'but _expected_end_addr was {exp_end_addr:#x}.',
                  file=sys.stderr)
            return (False, b'', sim)

    # Check ERR_BITS
    err_bits = sim.state.ext_regs.read('ERR_BITS', False)
    if err_bits != 0:
        err_names = ', '.join(get_err_names(err_bits))
        print(f'ACC error(s): {err_names} (ERR_BITS={err_bits:#x})', file=sys.stderr)
        return (False, b'', sim)

    # Dump DMEM (matches standalone.py format)
    try:
        dmem_bytes = sim.dump_data(include_validity=False)
        if dump_dmem_file is not None:
            dump_dmem_file.write(b"dmem:\n")
            dump_dmem_file.write(dmem_bytes.hex().encode('ascii'))
    except Exception as e:
        print(f"Error dumping DMEM: {e}", file=sys.stderr)
        return (False, b'', sim)

    # Handle statistics (only if stats were collected and file provided)
    if collect_stats and sim.stats is not None and dump_stats_file is not None:
        try:     # requested evidence that cannot be written fails the run
            from hw.ip.acc.dv.accsim.sim.stats import ExecutionStatAnalyzer
            dump_stats_file.write(ExecutionStatAnalyzer(sim.stats, elf_path).dump())
        except Exception as e:
            print(f"Error writing statistics: {e}", file=sys.stderr)
            return (False, dmem_bytes, sim)

    # Success! PC validated, no exceptions
    return (True, dmem_bytes, sim)


def run_acc_test_iteration(
    iteration_func: Callable[[], bool],
    iteration_num: int
) -> bool:
    """
    Run a single ACC test iteration with standardized header/footer.

    Lightweight wrapper that adds iteration numbering and status reporting.
    The actual test logic is fully customizable via iteration_func callback.

    Args:
        iteration_func: Callable that performs the test and returns bool (pass/fail)
        iteration_num: Iteration number (for reporting, 0-indexed)

    Returns:
        True if test passed, False if failed

    Example:
        def my_test():
            matrix = generate_random_matrix()
            vector = generate_random_vector()
            success, dmem = run_acc_test(elf, lambda sim: inject(sim, matrix, vector))
            expected = compute_expected(matrix, vector)
            actual = extract_result(dmem)
            return expected == actual

        success = run_acc_test_iteration(my_test, iteration_num=0)
    """
    print(f"\n========== TEST ITERATION {iteration_num + 1} ==========")

    try:
        success = iteration_func()
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"Test result: {status}")
        return success
    except Exception as e:
        print(f"✗ Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return False


# Utility functions for test organization (these add value)

def print_test_header(title: str, width: int = 60) -> None:
    """Print a formatted test header to console."""
    print(f"\n{'='*width}")
    print(title)
    print(f"{'='*width}")


def create_test_output_dir(base_name: str) -> str:
    """
    Create a timestamped output directory.

    Args:
        base_name: Base name for the directory

    Returns:
        Path to created directory

    Example:
        output_dir = create_test_output_dir("gf16_test")
        # Returns: "gf16_test_20251025_143022"
    """
    import os
    import datetime

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"{base_name}_{timestamp}"

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    return output_dir


###############################################################################
# Shared parser-argument helpers
###############################################################################

def add_dump_args(parser) -> None:
    """Add --dump-regs and --dump-stats arguments to parser.

    Args:
        parser: argparse.ArgumentParser instance to extend.
    """
    import argparse as _argparse
    parser.add_argument(
        '--dump-regs', metavar='FILE', type=_argparse.FileType('w'),
        help='After execution, write register values to this file',
    )
    parser.add_argument(
        '--dump-stats', metavar='FILE', type=_argparse.FileType('w'),
        help='After execution, write execution statistics to this file',
    )


TIERS = ('bngfaes', 'bngfonly', 'bnaesonly', 'sw')


def elf_tier(syms) -> str:
    """The tier an ACC ELF was built for, from the symbols its backends link in: bngfonly
    carries rcon (software AES key schedule), sw the AES128_TABLE, bnaesonly an aes128hw_*
    leaf, bngfaes none of them."""
    if 'rcon' in syms:
        return 'bngfonly'
    if 'AES128_TABLE' in syms:
        return 'sw'
    return 'bnaesonly' if any(k.startswith('aes128hw_') for k in syms) else 'bngfaes'


def parse_cases(spec: str) -> list:
    """'0', '0,11' or '0-11' -> the case indices in the order given; refuses an empty list,
    a negative index, a descending range and a case listed twice."""
    out = []
    for tok in spec.split(','):
        lo, sep, hi = tok.strip().partition('-')
        if not lo.isdigit() or (sep and not hi.isdigit()):
            raise argparse.ArgumentTypeError(f'bad case list {spec!r}: use 0, 0,11 or 0-11')
        a, b = int(lo), int(hi) if sep else int(lo)
        if b < a:
            raise argparse.ArgumentTypeError(f'descending range {tok.strip()!r} in {spec!r}')
        out += range(a, b + 1)
    if len(set(out)) != len(out):
        raise argparse.ArgumentTypeError(f'a case is listed twice in {spec!r}')
    return out


def add_kat_driver_args(parser, cases='0', tier=True, poison=True,
                        stats='print the ACC instructions and cycles of every run',
                        dump_stats='write the ISS statistics of every run to FILE, one labelled record per run') -> None:
    """The options every KAT proof driver takes: the ELF, the cases, the expected tier, poisoning
    and statistics. Drivers without a tier check or poisoning leave those out; drivers add their
    own options next to these."""
    parser.add_argument('--elf', required=True, help='the built app the ISS runs')
    parser.add_argument('--cases', type=parse_cases, default=parse_cases(cases), metavar='LIST',
                        help=f'KAT cases: 0, 0,11 or 0-11 (default {cases})')
    if tier:
        parser.add_argument('--tier', choices=TIERS,
                            help="fail unless the ELF's symbol fingerprint is this tier")
    if poison:
        parser.add_argument('--poison', action='store_true',
                            help='fill the working buffers with 0xA5 before the first run, so stale data cannot pass')
    parser.add_argument('--stats', action='store_true', help=stats)
    parser.add_argument('--dump-stats', metavar='FILE', help=dump_stats)


def require_dmem_profile(total_bytes: int):
    """Exit unless the tree's DMEM profile (acc.hjson) gives total_bytes of DMEM; the ISS is
    never resized behind the profile's back. Returns the layout."""
    from shared.mem_layout import get_memory_layout
    layout = get_memory_layout()
    if layout.dmem_size_bytes != total_bytes:
        kib = total_bytes // 1024
        sys.exit(f'this kernel runs on the {kib} KiB DMEM profile, the tree has {layout.dmem_size_bytes} B: '
                 f'python3 tools/uov.py profile --profile {kib}')
    return layout


###############################################################################
# Common CLI Arguments
###############################################################################

def create_common_argparser(
    description: str,
    default_elf: str = None,
    default_iterations: int = 10,
) -> argparse.ArgumentParser:
    """
    Create a standard argparser with common test flags.

    Standard flags:
        --elf           Path to ELF file (relative from repo root)
        --output-dir    Output directory (auto-generated if not specified)
        --iterations    Number of test iterations
        --seed          Random seed for reproducibility
        --verbose       Enable verbose output

    Args:
        description: Test script description
        default_elf: Default ELF path (required if None)
        default_iterations: Default iteration count

    Returns:
        Configured ArgumentParser (call parser.parse_args())
    """
    parser = argparse.ArgumentParser(description=description)
    if default_elf:
        parser.add_argument(
            '--elf', type=str, default=default_elf,
            help=f'Path to ELF file (default: {default_elf})')
    else:
        parser.add_argument(
            '--elf', type=str, required=True,
            help='Path to ELF file')
    parser.add_argument(
        '--output-dir', type=str, default=None,
        help='Output directory (auto-generated if not specified)')
    parser.add_argument(
        '--iterations', '-n', type=int, default=default_iterations,
        help=f'Number of test iterations (default: {default_iterations})')
    parser.add_argument(
        '--seed', type=int, default=None,
        help='Random seed for reproducibility')
    parser.add_argument(
        '--verbose', '-v', action='store_true',
        help='Enable verbose output')
    return parser


###############################################################################
# Unified Output Helpers
###############################################################################

def print_test_summary(passed: int, total: int, test_name: str = "") -> None:
    """Print standardized test summary."""
    failed = total - passed
    label = f" - {test_name}" if test_name else ""
    print(f"\n{'='*60}")
    print(f"TEST SUMMARY{label}")
    print(f"{'='*60}")
    print(f"  Total:  {total}")
    print(f"  Passed: {passed}")
    print(f"  Failed: {failed}")
    if failed == 0:
        print("\nALL TESTS PASSED")
    else:
        print("\nSOME TESTS FAILED")


###############################################################################
# Test Suite Runner
###############################################################################

def run_test_suite(
    test_name: str,
    test_func,
    elf_path: str,
    iterations: int = 10,
    output_dir: str = None,
    seed: int = None,
) -> int:
    """
    Run a complete test suite with standard iteration loop and summary.

    Handles: ELF validation, output directory creation, random seeding,
    per-iteration dump files, iteration headers, and final summary.

    Args:
        test_name: Human-readable test name
        test_func: Callable(iteration_num, regs_file, stats_file) -> bool
        elf_path: Path to ELF file
        iterations: Number of test iterations
        output_dir: Output directory (auto-created if None)
        seed: Random seed (None for non-deterministic)

    Returns:
        Exit code: 0 if all passed, 1 otherwise
    """
    import random

    print_test_header(f"{test_name} Test")

    # Validate ELF
    if not os.path.exists(elf_path):
        print(f"Error: ELF file not found: {elf_path}")
        return 1

    # Random seed
    if seed is not None:
        random.seed(seed)
        print(f"Using random seed: {seed}")

    # Output directory
    if output_dir is None:
        output_dir = create_test_output_dir(
            test_name.lower().replace(' ', '_').replace('-', '_')
        )
    elif not os.path.exists(output_dir):
        os.makedirs(output_dir)
    print(f"Output directory: {output_dir}")
    print(f"ELF: {elf_path}")
    print(f"Iterations: {iterations}")
    if iterations < 1:
        raise ValueError(f"iterations must be positive, got {iterations}")

    # Run iterations
    passed = 0
    for i in range(iterations):
        print(f"\n{'='*60}")
        print(f"Test Iteration {i + 1}/{iterations}")
        print(f"{'='*60}")

        regs_path = os.path.join(output_dir, f"registers_{i}.txt")
        stats_path = os.path.join(output_dir, f"statistics_{i}.txt")

        with open(regs_path, 'w') as regs_f, \
             open(stats_path, 'w') as stats_f:
            try:
                if test_func(i, regs_f, stats_f):
                    passed += 1
            except Exception as e:
                print(f"Test iteration {i+1} failed with exception: {e}")
                import traceback
                traceback.print_exc()

    print_test_summary(passed, iterations, test_name)
    return 0 if passed == iterations else 1


###############################################################################
# Register Access Helpers
###############################################################################

def read_wdr_register(sim, reg_index: int) -> int:
    """
    Read a WDR (Wide Data Register) from the simulator state.

    Args:
        sim: Simulator instance
        reg_index: WDR register index (0-31)

    Returns:
        256-bit integer value of the register

    Example:
        w24_value = read_wdr_register(sim, 24)
        if w24_value == 0:
            print("W24 is all zeros")
        elif w24_value == (1 << 256) - 1:
            print("W24 is all ones")
    """
    return sim.state.wdrs.get_reg(reg_index).read_unsigned()

def read_gpr_register(sim, reg_index: int) -> int:
    """
    Read a GPR (General Purpose Register) from the simulator state.

    Args:
        sim: Simulator instance
        reg_index: GPR register index (0-31)

    Returns:
        32-bit unsigned integer value of the register

    Example:
        x8_value = read_gpr_register(sim, 8)
        print(f"Counter (x8) = {x8_value}")
    """
    return sim.state.gprs.get_reg(reg_index).read_unsigned()
