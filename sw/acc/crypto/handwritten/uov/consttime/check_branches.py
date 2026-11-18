#!/usr/bin/env python3
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
'''Run check_const_time.py and compare the reported branches with a list.

The expected file lists the PCs of the branches the checker may report (one
PC per line, comments after #). The test fails if the checker reports a branch
that is not listed, or no longer reports one that is.

usage: check_branches.py CHECKER ELF EXPECTED [checker args...]
'''

import re
import subprocess
import sys


def main() -> int:
    checker, elf, expected = sys.argv[1:4]
    r = subprocess.run([checker, elf] + sys.argv[4:], capture_output=True,
                       text=True)
    out = r.stdout + r.stderr
    if r.returncode not in (0, 1) or (r.returncode == 1 and
                                      'may influence control flow' not in out):
        print(out)
        print('check_const_time.py failed')
        return 1
    found = {int(pc, 16) for line in out.splitlines() if '(via' in line
             for pc in re.findall(r'PC (0x[0-9a-f]+)', line)}
    listed = set()
    with open(expected) as f:
        for line in f:
            line = line.split('#')[0].strip()
            if line:
                listed.add(int(line.split()[0], 16))
    new = sorted(found - listed)
    gone = sorted(listed - found)
    for pc in new:
        print('reported but not listed: {:#06x}'.format(pc))
    for pc in gone:
        print('listed but not reported: {:#06x}'.format(pc))
    if new or gone:
        print(out)
        return 1
    print('{} reported branches, all listed'.format(len(found)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
