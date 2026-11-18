"""stream_uniform_gates.sh on a temporary tree with stand-ins for the build, the decoder, objdump and check_loop:
a file that cannot be read completely stops the run, and the gates read what was read once."""
import os
import shutil
import subprocess
import tempfile
import unittest

GATES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'stream_uniform_gates.sh')
PKG = 'bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k/verify_stream_uniform/ov-Ip-pkc'
ARMS = ('bngfaes', 'bngfonly', 'bnaesonly', 'sw')
LW, JAL = '       0:\t00002203\tlw             x4, 0(x0)\n', '       4:\t249000ef\tjal            x1, .+2632\n'
GF, AES, MULV = ('       8:\t6033642b\tbn.gfmul.8.acc w8, w6, w3 \n', '       c:\tc1e0aef7\tbn.aes128.kf   w29, w30, 1\n',
                 '      10:\t4309694b\tbn.mulv.l.16h.lo w18, w18, sw1.0 \n')
TEXT = 'section .text.start: SHT_PROGBITS, flags 0x6, address 0x0, 8 bytes, align 4\n'
OUTER = TEXT + 'start:\n' + LW + JAL + 'section .data: SHT_PROGBITS, flags 0x3, address 0x0, 4 bytes, align 32\n       0:\t01000000\n'
BACKEND = {'bngfaes': GF + AES, 'bngfonly': GF, 'bnaesonly': AES + MULV, 'sw': MULV}
SYMS = ''.join(f'{i * 4:08x} g       .data\t00000000 {name}\n' for i, name in enumerate(
    'ctrl initdone acc oil target sig seed msgwin winend backend_verify_p1p2 backend_verify_p3_rows'.split()))
RELOC = 'RELOCATION RECORDS FOR [.text.start]:\nOFFSET   TYPE              VALUE\n00000004 R_RISCV_JAL       backend_verify_p1p2\n'
RODATA = 'section .rodata: SHT_PROGBITS, flags 0x2, address 0x0, 4 bytes, align 4\n       0:\t00000000\n'
# a tool of the script's own steps that fails on its Nth call in a run (N and "silent" or "after-output" in the file
# fail-<tool> beside bin/): it exits 1 without output, or after the real tool's complete output
TOOLS = ('awk', 'sort', 'wc', 'sha256sum')
TOOL_STUB = '''#!/usr/bin/env bash
here=$(dirname "$0")/..; tool=$(basename "$0")
n=$(( $(cat "$here/calls-$tool" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$here/calls-$tool"
on=; how=; [ -r "$here/fail-$tool" ] && read -r on how < "$here/fail-$tool"
if [ "$n" = "$on" ]; then [ "$how" = silent ] && { cat > /dev/null; exit 1; }; "/usr/bin/$tool" "$@"; exit 1; fi
exec "/usr/bin/$tool" "$@"
'''
# each stand-in prints the text prepared beside the file, then exits with the status in <text file>.rc if there is one
TOOL = '''import os, sys
text = sys.argv[-1] + {'--elf': '.dis', '-r': '.reloc', '-t': '.syms'}[sys.argv[1]]
sys.stdout.write(open(text).read())
if os.path.exists(text + '.rc'):
    sys.exit(f'stand-in: {os.path.basename(text)} failed after its output')
'''


class Gates(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = self.tmp.name
        for rel, text in {'bazelisk.sh': '#!/bin/sh\nexit 0\n', 'tools/acc_disasm.py': TOOL,
                          'hw/ip/acc/util/acc_objdump.py': TOOL, 'hw/ip/acc/util/check_loop.py': ''}.items():
            self.write(rel, text)
        os.chmod(os.path.join(self.repo, 'bazelisk.sh'), 0o755)
        for tool in TOOLS:
            self.write('bin/' + tool, TOOL_STUB)
            os.chmod(os.path.join(self.repo, 'bin', tool), 0o755)
        shutil.copy(GATES, os.path.join(self.repo, 'tools'))
        for arm in ARMS:
            self.write(self.obj(arm), '')
            self.write(self.obj(arm) + '.dis', OUTER)
            self.write(self.obj(arm) + '.reloc', RELOC)
            self.write(self.elf(arm), '')
            self.write(self.elf(arm) + '.dis', TEXT + LW + JAL + BACKEND[arm])
            self.write(self.elf(arm) + '.syms', SYMS)

    def obj(self, arm):
        return f'{PKG}/ov-Ip-verify_stream_uniform_{arm}.o'

    def elf(self, arm):
        return f'{PKG}/ov-Ip-verify_stream_uniform_{arm}.elf'

    def write(self, rel, text):
        path = os.path.join(self.repo, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as fh:
            fh.write(text)

    def gates(self):
        for tool in TOOLS:
            self.write('calls-' + tool, '0')
        r = subprocess.run(['bash', os.path.join(self.repo, 'tools/stream_uniform_gates.sh'), 'verify', 'Ip'], text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                           env=dict(os.environ, PATH=os.path.join(self.repo, 'bin') + os.pathsep + os.environ['PATH']))
        return r.returncode, r.stdout

    def test_a_consistent_family_passes(self):
        rc, out = self.gates()
        self.assertEqual(rc, 0, out)
        self.assertIn('ALL GATES PASS (verify)', out)
        self.assertIn('PASS bngfaes (4 ELF + 2 outer instructions)', out)
        self.assertNotIn('FAIL', out)

    def test_a_read_that_fails_after_its_output_stops_the_run(self):
        # every tool printed its complete, valid text and then exited nonzero: the text must not be used
        for text in (self.elf('bngfonly') + '.dis', self.obj('sw') + '.dis', self.obj('bngfaes') + '.reloc',
                     self.elf('bnaesonly') + '.syms'):
            with self.subTest(os.path.basename(text)):
                self.write(text + '.rc', '')
                rc, out = self.gates()
                self.assertEqual(rc, 1)
                self.assertIn(f'stand-in: {os.path.basename(text)} failed after its output', out)
                self.assertIn('GATES FAILED (verify): not every arm could be read', out)
                self.assertNotIn('gate 1', out)
                self.assertNotIn('ALL GATES PASS', out)
                os.remove(os.path.join(self.repo, text + '.rc'))
        self.assertEqual(self.gates()[0], 0)

    def test_outer_objects_must_have_the_same_sections_and_bytes(self):
        for what, text in {'a word': OUTER.replace('249000ef', '249000ee'), 'a data byte': OUTER.replace('01000000', '02000000'),
                           'an address': OUTER.replace('       4:\t249', '       8:\t249'),
                           'the alignment': OUTER.replace('align 32', 'align 4'),
                           'a section name': OUTER.replace('.text.start', '.text')}.items():
            with self.subTest(what):
                self.write(self.obj('bnaesonly') + '.dis', text)
                rc, out = self.gates()
                self.assertEqual(rc, 1)
                self.assertIn('FAIL text+data (2 hashes from 4 of 4 arms)', out)
        self.write(self.obj('bnaesonly') + '.dis', OUTER.replace('\nstart:\n', '\nbegin:\n'))    # a symbol name is not a byte
        self.assertEqual(self.gates()[0], 0)

    def test_an_arm_whose_hash_fails_does_not_drop_out_of_the_comparison(self):
        # the calls are bytes then relocations per arm: 3 = bngfonly's bytes, 6 = bnaesonly's relocations
        for call, how, want in ((3, 'silent', "FAIL bngfonly: the outer's sections could not be hashed"),
                                (3, 'after-output', 'FAIL text+data (1 hashes from 3 of 4 arms)'),
                                (6, 'silent', 'FAIL relocations (1 hashes from 3 of 4 arms)'),
                                (6, 'after-output', "FAIL bnaesonly: the outer's relocations could not be hashed")):
            with self.subTest(call=call, how=how):
                self.write('fail-sha256sum', f'{call} {how}\n')
                rc, out = self.gates()
                self.assertEqual(rc, 1)
                self.assertIn(want, out)
                self.assertNotIn('ALL GATES PASS', out)
        os.remove(os.path.join(self.repo, 'fail-sha256sum'))
        self.assertEqual(self.gates()[0], 0)

    def test_no_failing_step_of_the_script_can_end_in_a_pass(self):
        # every call of awk, sort, wc and sha256sum in a good run, failing alone: without output, and after its full output
        self.assertEqual(self.gates()[0], 0)
        calls = {}
        for tool in TOOLS:
            with open(os.path.join(self.repo, 'calls-' + tool)) as fh:
                calls[tool] = int(fh.read())
        self.assertGreaterEqual(min(calls.values()), 2, calls)
        for tool in TOOLS:
            for call in range(1, calls[tool] + 1):
                for how in ('silent', 'after-output'):
                    with self.subTest(tool=tool, call=call, how=how):
                        self.write('fail-' + tool, f'{call} {how}\n')
                        rc, out = self.gates()
                        self.assertNotEqual(rc, 0, out)
                        self.assertNotIn('ALL GATES PASS', out)
            os.remove(os.path.join(self.repo, 'fail-' + tool))
        self.assertEqual(self.gates()[0], 0)

    def test_outer_objects_must_have_the_same_relocations_in_the_same_sections(self):
        for what, text in {'the target': RELOC.replace('backend_verify_p1p2', 'backend_verify_p3_rows'),
                           'an offset': RELOC.replace('00000004 R_', '00000000 R_')}.items():
            with self.subTest(what):
                self.write(self.obj('bngfonly') + '.reloc', text)
                rc, out = self.gates()
                self.assertEqual(rc, 1)
                self.assertIn('FAIL relocations (2 hashes from 4 of 4 arms)', out)
        self.write(self.obj('bngfonly') + '.reloc', RELOC)
        # relocations of every loaded section count, here a .rodata with the same bytes in every arm
        more = 'RELOCATION RECORDS FOR [.rodata]:\nOFFSET   TYPE              VALUE\n00000000 R_RISCV_32        table_a\n'
        for arm in ARMS:
            self.write(self.obj(arm) + '.dis', OUTER + RODATA)
            self.write(self.obj(arm) + '.reloc', RELOC + more)
        self.assertEqual(self.gates()[0], 0)
        self.write(self.obj('sw') + '.reloc', RELOC + more.replace('table_a', 'table_b'))
        rc, out = self.gates()
        self.assertEqual((rc, 'FAIL relocations (2 hashes from 4 of 4 arms)' in out), (1, True))
        # the same rows in the same order, but under the other section's line, are another table
        self.write(self.obj('sw') + '.reloc', (RELOC + more).replace('[.text.start]', '[.x]').replace('[.rodata]', '[.text.start]').replace('[.x]', '[.rodata]'))
        rc, out = self.gates()
        self.assertEqual((rc, 'FAIL relocations (2 hashes from 4 of 4 arms)' in out), (1, True))
        # those of a section that is not loaded do not
        self.write(self.obj('sw') + '.reloc', RELOC + more + more.replace('.rodata', '.debug_info').replace('table_a', 'elsewhere'))
        self.assertEqual(self.gates()[0], 0)

    def test_a_relocation_table_without_a_row_cannot_pass(self):
        # in every arm alike: only the section line, rows only under a section that is not loaded, nothing at all
        head = 'RELOCATION RECORDS FOR [.text.start]:\nOFFSET   TYPE              VALUE\n'
        for what, text in {'the section line alone': head, 'rows of another section': RELOC.replace('[.text.start]', '[.text]'),
                           'nothing': 'no relocations\n'}.items():
            with self.subTest(what):
                for arm in ARMS:
                    self.write(self.obj(arm) + '.reloc', text)
                rc, out = self.gates()
                self.assertEqual(rc, 1)
                self.assertIn('FAIL sw: no relocation row for a loaded section', out)

    def test_symbol_gates_read_the_listed_table(self):
        self.write(self.elf('sw') + '.syms', SYMS.replace('00000004 g       .data\t00000000 initdone', '00000104 g       .data\t00000000 initdone'))
        rc, out = self.gates()
        self.assertEqual((rc, 'FAIL addresses differ' in out), (1, True))
        self.write(self.elf('sw') + '.syms', SYMS + '00000080 g       .text\t00000000 backend_verify_p1p2\n')
        rc, out = self.gates()
        self.assertEqual((rc, 'FAIL sw backend_verify_p1p2 = 2 providers' in out), (1, True))

    def test_the_opcode_policy_counts_mnemonics_of_the_decoded_text(self):
        self.write(self.elf('bngfaes') + '.dis', TEXT + LW + JAL + GF)                               # no AES in the AES arm
        # the name in a symbol, in data or after the mnemonic is not an instruction
        self.write(self.elf('sw') + '.dis', TEXT + 'bn.gfmul.helper:\n' + LW + JAL.replace('.+2632', 'bn.gfmul') + MULV
                   + 'section .data: 16 bytes\n       0:\tbn.gfmul\n')
        rc, out = self.gates()
        self.assertEqual(rc, 1)
        self.assertIn('FAIL bngfaes ELF gfmul=1 aes=0 mulv=0', out)
        self.assertIn('PASS sw ELF gfmul=0 aes=0 mulv=1', out)
        self.write(self.elf('bngfaes') + '.dis', TEXT + LW + JAL + BACKEND['bngfaes'])               # the valid ELF again
        self.assertEqual(self.gates()[0], 0)
        for arm in ARMS:
            self.write(self.obj(arm) + '.dis', OUTER + GF)                                         # a backend opcode in the outer
        rc, out = self.gates()
        self.assertEqual(rc, 1)
        self.assertIn('FAIL outer(sw) gfmul=1 aes=0 mulv=0', out)
        self.assertEqual(out.count('   FAIL '), 4, out)                                             # the four outers, nothing else
        self.assertNotIn('ALL GATES PASS', out)

    def test_a_missing_arm_or_a_failed_build_cannot_pass(self):
        os.remove(os.path.join(self.repo, self.obj('sw')))
        rc, out = self.gates()
        self.assertEqual(rc, 1)
        self.assertIn('family needs all 4 arms (found 3)', out)
        self.assertNotIn('ALL GATES PASS', out)
        self.write(self.obj('sw'), '')                                                             # all four arms again
        self.assertEqual(self.gates()[0], 0)
        self.write('bazelisk.sh', '#!/bin/sh\nexit 1\n')
        rc, out = self.gates()
        self.assertEqual((rc, 'BUILD FAIL' in out), (1, True))
        self.assertNotIn('gate 0', out)                                                            # no gate starts after a failed build


if __name__ == '__main__':
    unittest.main()
