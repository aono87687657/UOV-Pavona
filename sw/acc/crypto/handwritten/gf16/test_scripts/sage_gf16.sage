#!/usr/bin/env sage

import sys
import json
import os
import argparse

def load_test_data(json_file):
    """Load test data from a JSON file."""
    with open(json_file, 'r') as f:
        return json.load(f)

def setup_gf16():
    """Set up GF(16) field in SageMath."""
    # Create polynomial ring over GF(2)
    R.<x> = PolynomialRing(GF(2))
    
    # Create GF(16) as GF(2)[x]/(x^4 + x + 1)
    modulus = x^4 + x + 1
    F16 = GF(16, name='a', modulus=modulus)
    
    return F16

def convert_to_sage_matrix(raw_matrix, F16):
    """Convert raw matrix to SageMath matrix over GF(16)."""
    # Extract dimensions
    cols = len(raw_matrix)
    rows = len(raw_matrix[0]) if cols > 0 else 0
    
    # Initialize matrix with zeros
    M = matrix(F16, rows, cols)
    
    # Fill in values
    for c in range(cols):
        for r in range(rows):
            if c < len(raw_matrix) and r < len(raw_matrix[c]):
                # Convert integer to field element using from_integer
                M[r, c] = F16.from_integer(raw_matrix[c][r])
    
    return M

def convert_to_sage_vector(raw_vector, F16):
    """Convert raw vector to SageMath vector over GF(16)."""
    return vector(F16, [F16.from_integer(x) for x in raw_vector])

def calculate_matvec(M, v):
    """Calculate matrix-vector product in GF(16)."""
    if M.ncols() != len(v):
        raise ValueError(f"Matrix columns ({M.ncols()}) must match vector length ({len(v)})")
        
    return M * v

def convert_from_sage_vector(sage_vector):
    """Convert SageMath vector to list of integers."""
    return [int(x._integer_representation()) for x in sage_vector]

def verify_test_data(json_file):
    """Verify GF16 matrix-vector multiplication using SageMath."""
    # Load test data
    data = load_test_data(json_file)
    matrix_A = data['matrix_A']
    vector_B = data['vector_B']
    expected_result = data['expected_result']
    actual_result = data['actual_result']
    
    # Setup GF(16)
    F16 = setup_gf16()
    
    # Convert data to SageMath types
    sage_matrix = convert_to_sage_matrix(matrix_A, F16)
    sage_vector = convert_to_sage_vector(vector_B, F16)
    
    # Calculate matrix-vector product using SageMath
    sage_result = calculate_matvec(sage_matrix, sage_vector)
    
    # Convert result back to integers
    sage_result_ints = convert_from_sage_vector(sage_result)
    
    # Compare with expected result
    matches_expected = (sage_result_ints == expected_result)
    matches_actual = (sage_result_ints == actual_result)
    
    # Prepare results
    results = {
        'file_name': os.path.basename(json_file),
        'matrix_dims': f"{sage_matrix.nrows()} × {sage_matrix.ncols()}",
        'vector_length': len(sage_vector),
        'sage_result': sage_result_ints,
        'expected_result': expected_result,
        'actual_result': actual_result,
        'matches_expected': matches_expected,
        'matches_actual': matches_actual
    }
    
    return results

def print_verification_results(results):
    """Print verification results in a readable format."""
    print(f"\n=== Verification Results for {results['file_name']} ===")
    print(f"Matrix dimensions: {results['matrix_dims']}")
    print(f"Vector length: {results['vector_length']}")
    
    print("\nSageMath calculation matches expected result: ", end="")
    if results['matches_expected']:
        print("✓ YES")
    else:
        print("✗ NO")
        
    print("SageMath calculation matches actual python implementation result: ", end="")
    if results['matches_actual']:
        print("✓ YES")
    else:
        print("✗ NO")
    
    if not results['matches_expected'] or not results['matches_actual']:
        print("\nDifferences found:")
        
        if not results['matches_expected']:
            print("  SageMath vs Expected:")
            show_differences(results['sage_result'], results['expected_result'])
            
        if not results['matches_actual']:
            print("  SageMath vs Actual python implementation:")
            show_differences(results['sage_result'], results['actual_result'])

def show_differences(list1, list2, max_diffs=10):
    """Show differences between two lists."""
    count = 0
    for i, (a, b) in enumerate(zip(list1, list2)):
        if a != b:
            print(f"    Index {i}: {a} vs {b}")
            count += 1
            if count >= max_diffs:
                print(f"    ... and more differences (showing first {max_diffs} only)")
                break

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Verify GF16 matrix-vector multiplication using SageMath')
    parser.add_argument('json_file', nargs='?', help='Path to JSON test data file')
    parser.add_argument('--dir', help='Directory containing JSON test data files')
    parser.add_argument('--all', action='store_true', help='Process all JSON files in the directory')
    args = parser.parse_args()
    
    # Check arguments
    if args.all and args.dir:
        # Process all JSON files in directory
        if not os.path.isdir(args.dir):
            print(f"Error: Directory '{args.dir}' not found", file=sys.stderr)
            return 1
            
        json_files = [os.path.join(args.dir, f) for f in os.listdir(args.dir) 
                     if f.endswith('.json') and f.startswith('test_data_')]
        
        if not json_files:
            print(f"No JSON test data files found in '{args.dir}'", file=sys.stderr)
            return 1
            
        print(f"Found {len(json_files)} JSON test data files to verify")
        
        # Process each file
        summary = {'total': 0, 'match_expected': 0, 'match_actual': 0}
        for json_file in sorted(json_files):
            results = verify_test_data(json_file)
            print_verification_results(results)
            
            summary['total'] += 1
            if results['matches_expected']:
                summary['match_expected'] += 1
            if results['matches_actual']:
                summary['match_actual'] += 1
        
        # Print summary
        print("\n=== Overall Verification Summary ===")
        print(f"Total test files: {summary['total']}")
        print(f"Files matching expected results: {summary['match_expected']}/{summary['total']}")
        print(f"Files matching actual python implementation results: {summary['match_actual']}/{summary['total']}")
        
    elif args.json_file:
        # Process single file
        if not os.path.isfile(args.json_file):
            print(f"Error: File '{args.json_file}' not found", file=sys.stderr)
            return 1
            
        results = verify_test_data(args.json_file)
        print_verification_results(results)
        
        # Return success if matches both expected and actual
        return 0 if results['matches_expected'] and results['matches_actual'] else 1
    else:
        parser.print_help()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())