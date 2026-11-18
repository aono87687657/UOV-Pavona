#!/usr/bin/env python3
"""Run one own_utils ISS test for one parameter set: run_test.py TEST --param P [the test's own options].

keygen and sign are the KAT drivers the collector runs (tools/gather_kat_stats.py); the others are the leaf
tests of the sign kernels. `run_test.py TEST --param P --help` lists a test's options.

  python3 sw/acc/crypto/handwritten/own_utils/run_test.py sign --param Ip --tier bngfaes \\
    --test-data-file sw/acc/crypto/handwritten/test_data/testvectors-Ip-pkc-skc --case-start 0 --iterations 1
"""
import argparse
import importlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.abspath(os.path.join(HERE, *['..'] * 5)), HERE]   # the repo root and own_utils

from ov_params import OV_IP, OV_IP3, OV_IS

PARAMS = {'Ip': OV_IP, 'Is': OV_IS, 'Ip3': OV_IP3}
# test -> (module, main, the parameter sets it has, extra arguments of the main per parameter set)
TESTS = {
    'keygen':       ('ov_keygen_test_utils', 'keygen_main', ('Ip', 'Is', 'Ip3'), {}),
    'sign':         ('ov_sign_test_utils', 'sign_main', ('Ip', 'Is', 'Ip3'), {}),
    'expandsk':     ('ov_expandsk_test_utils', 'expandsk_main', ('Ip', 'Is'), {}),
    'hash':         ('ov_hash_test_utils', 'run_hash_test_main', ('Ip', 'Is'),
                     {'Ip': ('KMAC SHAKE256 (Ip)',), 'Is': ('KMAC SHAKE256 (Is)',)}),
    'ge':           ('ov_ge_test_utils', 'ge_main', ('Ip', 'Is'), {}),
    'backsub':      ('ov_ge_test_utils', 'backsub_main', ('Ip', 'Is'), {}),
    'transpose':    ('ov_transpose_test_utils', 'transpose_main', ('Ip', 'Is'), {}),
    'matvec_small': ('ov_matvec_test_utils', 'small_matvec_main', ('Ip', 'Is'), {}),
    'matvec_large': ('ov_matvec_test_utils', 'large_matvec_main', ('Ip', 'Is'), {'Ip': (2816, 68), 'Is': (2048, 96)}),
    'trimat_eval':  ('ov_trimat_eval_test_utils', 'trimat_eval_main', ('Ip', 'Is'), {}),
    'p1p1to':       ('ov_p1_test_utils', 'p1p1to_main', ('Ip', 'Is'), {}),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
                                 add_help=False, allow_abbrev=False)
    ap.add_argument('test', nargs='?', choices=sorted(TESTS))
    ap.add_argument('--param', choices=sorted(PARAMS))
    a, rest = ap.parse_known_args()
    if a.test is None or a.param is None:
        ap.print_help()
        print('\ntests and their parameter sets:')
        for t, (_, _, params, _) in TESTS.items():
            print(f'  {t:13s} {", ".join(params)}')
        return 0 if {'-h', '--help'} & set(rest) else 2
    module, function, params, extra = TESTS[a.test]
    if a.param not in params:
        ap.error(f'{a.test} has no {a.param} test (it has {", ".join(params)})')
    sys.argv = [f'{os.path.basename(__file__)} {a.test} --param {a.param}', *rest]   # the test's own parser
    return getattr(importlib.import_module(module), function)(PARAMS[a.param], *extra.get(a.param, ()))


if __name__ == '__main__':
    sys.exit(main())
