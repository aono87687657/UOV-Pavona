#!/usr/bin/env python3

import re
import subprocess
import os

###############################################################################
# Configurable file names and Bazel target
###############################################################################
# Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Files in your GF256 directory with absolute paths
EXPECTED_OUTPUT_FILE = os.path.join(SCRIPT_DIR, "expected_output.txt")
GF256_EXTMUL_TEST_S   = os.path.join(SCRIPT_DIR, "../gf256_extmul_test.s")
GF256_EXTMUL_TEST_EXP = os.path.join(SCRIPT_DIR, "../gf256_extmul_test.exp")

# Use absolute path to bazelisk.sh
REPO_TOP = os.path.normpath(os.path.join(SCRIPT_DIR, "../../../../../../"))
BAZEL_CMD = [
    os.path.join(REPO_TOP, "bazelisk.sh"),
    "test",
    "//sw/acc/crypto/handwritten/gf256:gf256_extmul_test"
]

###############################################################################
# 1) Read (b, w0) pairs from expected_output.txt
###############################################################################
def read_pairs_from_expected(file_path):
    """
    Expects lines in expected_output.txt like:
        b = 0x00
        w0 = 0x000000000000...
        b = 0x01
        w0 = 0x9abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345678
        ...
    Returns a list of tuples [(b_hex, w0_hex), ...].
    """
    pairs = []
    with open(file_path, "r") as f:
        b_val = None
        w0_val = None
        for line in f:
            line = line.strip()
            if line.startswith("b ="):
                # e.g. line: "b = 0x00" or "b = 0xFF"
                b_val = line.split('=')[1].strip()  # "0x00"
            elif line.startswith("w0 ="):
                # e.g. line: "w0 = 0x85449add..."
                w0_val = line.split('=')[1].strip()
                # Once we have both, store and reset
                if b_val is not None and w0_val is not None:
                    pairs.append((b_val, w0_val))
                    b_val, w0_val = None, None

    return pairs

###############################################################################
# 2) Update gf256_extmul_test.s to set `val_b` with the new `b`
###############################################################################
def update_b_in_extmul_test_s(file_path, new_b_hex):
    """
    Your gf256_extmul_test.s has a val_b section like:
      val_b:
          .word 0x0157,0,0,0,0,0,0,0
    We'll replace that first word with your new `b`.
    
    Convert the hex value to proper format for the .word directive.
    """
    # Convert "0xFF" -> "0xFF" but ensure proper formatting
    b_stripped = new_b_hex.replace("0x", "").upper()
    
    # For GF256, b should be a single byte (0x00 to 0xFF)
    # Pad to at least 1-4 hex digits for proper .word directive
    if len(b_stripped) <= 2:  # Single byte
        new_word_line = f".word 0x{b_stripped},0,0,0,0,0,0,0"
    elif len(b_stripped) <= 8:  # Up to 32-bit value
        new_word_line = f".word 0x{b_stripped},0,0,0,0,0,0,0"
    else:
        # For larger values, use only the lower 32 bits
        new_word_line = f".word 0x{b_stripped[-8:]},0,0,0,0,0,0,0"

    with open(file_path, "r") as f:
        lines = f.readlines()

    new_lines = []
    in_val_b_block = False
    for line in lines:
        if "val_b:" in line:
            # Next line that contains .word is the one we update
            in_val_b_block = True
            new_lines.append(line)
            continue

        if in_val_b_block and ".word" in line:
            # Replace the .word line with new value
            indent = len(line) - len(line.lstrip())  # Preserve indentation
            new_lines.append(" " * indent + new_word_line + "\n")
            in_val_b_block = False
            continue

        new_lines.append(line)

    with open(file_path, "w") as f:
        f.writelines(new_lines)

###############################################################################
# 3) Update gf256_extmul_test.exp with the new `w0`
###############################################################################
def update_w0_in_exp(file_path, new_w0_hex):
    """
    Update the expected output file with the new w0 value.
    The exp file should contain a line like:
      w0 = 0x85449addbb7aa4e3...
    We'll replace that with w0 = {new_w0_hex}.
    """
    pattern_w0 = re.compile(r"(w0\s*=\s*0x[0-9A-Fa-f]+)")
    replacement = f"w0 = {new_w0_hex}"

    with open(file_path, "r") as f:
        contents = f.read()

    new_contents = pattern_w0.sub(replacement, contents)

    with open(file_path, "w") as f:
        f.write(new_contents)

###############################################################################
# 4) Run the Bazel test
###############################################################################
def run_bazel_test():
    """Run the Bazel test and return the result."""
    print(f"  Running: {' '.join(BAZEL_CMD)}")
    result = subprocess.run(BAZEL_CMD, capture_output=True, text=True)
    return result

###############################################################################
# 5) Backup and restore functions
###############################################################################
def backup_files():
    """Create backup copies of the test files."""
    import shutil
    try:
        shutil.copy(GF256_EXTMUL_TEST_S, GF256_EXTMUL_TEST_S + ".backup")
        shutil.copy(GF256_EXTMUL_TEST_EXP, GF256_EXTMUL_TEST_EXP + ".backup")
        print("Created backup files")
    except Exception as e:
        print(f"Warning: Could not create backups: {e}")

def restore_files():
    """Restore files from backup."""
    import shutil
    try:
        shutil.copy(GF256_EXTMUL_TEST_S + ".backup", GF256_EXTMUL_TEST_S)
        shutil.copy(GF256_EXTMUL_TEST_EXP + ".backup", GF256_EXTMUL_TEST_EXP)
        print("Restored files from backup")
    except Exception as e:
        print(f"Warning: Could not restore from backups: {e}")

###############################################################################
# main
###############################################################################
def main():
    print("=== GF256 Extended Multiplication Test Runner ===")
    
    # Create backup of original files
    backup_files()
    
    try:
        # Read all (b, w0) pairs from the expected_output.txt
        pairs = read_pairs_from_expected(EXPECTED_OUTPUT_FILE)
        print(f"Found {len(pairs)} test cases in {EXPECTED_OUTPUT_FILE}")
        
        if not pairs:
            print("No test cases found! Check the format of expected_output.txt")
            return
        
        passed_tests = 0
        failed_tests = 0
        
        for i, (b_val, w0_val) in enumerate(pairs, start=1):
            print(f"\n=== Test Case {i}/{len(pairs)} ===")
            print(f"  Input b = {b_val}")
            print(f"  Expected w0 = {w0_val[:32]}..." if len(w0_val) > 32 else f"  Expected w0 = {w0_val}")
            
            try:
                # 1) Update gf256_extmul_test.s with the new b value
                print("  Updating test file with new b value...")
                update_b_in_extmul_test_s(GF256_EXTMUL_TEST_S, b_val)
                
                # 2) Update gf256_extmul_test.exp with the new expected w0
                print("  Updating expected output file...")
                update_w0_in_exp(GF256_EXTMUL_TEST_EXP, w0_val)
                
                # 3) Run Bazel test
                print("  Running Bazel test...")
                result = run_bazel_test()
                
                # 4) Check results
                if result.returncode == 0:
                    print("  ✅ PASS")
                    passed_tests += 1
                else:
                    print("  ❌ FAIL")
                    failed_tests += 1
                    print(f"  Return code: {result.returncode}")
                    
                    if result.stdout:
                        print("  STDOUT:")
                        print("    " + "\n    ".join(result.stdout.strip().split('\n')))
                    if result.stderr:
                        print("  STDERR:")
                        print("    " + "\n    ".join(result.stderr.strip().split('\n')))
                        
            except Exception as e:
                print(f"  ❌ ERROR: {e}")
                failed_tests += 1
            
            # Optional: pause between tests for debugging
            # input("Press Enter to continue to next test...")
        
        # Final summary
        print(f"\n=== Test Summary ===")
        print(f"Total tests: {len(pairs)}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success rate: {passed_tests/len(pairs)*100:.1f}%")
        
        # Print some statistics
        print(f"\n=== Statistics ===")
        print(f"GF256 field size: 2^8 = 256 elements")
        print(f"Test coverage: {len(pairs)}/256 = {len(pairs)/256*100:.1f}% of field")
        
        if len(pairs) == 256:
            print("✅ Complete field coverage!")
        elif len(pairs) >= 128:
            print("✅ Good field coverage")
        else:
            print("⚠️  Partial field coverage")
        
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Restore original files
        restore_files()

if __name__ == "__main__":
    main()
