"""acc_disasm on small ELF files written here: every word of an executable section goes through the instruction
database, a word it does not know fails the run, other loaded sections are shown as bytes, and a file outside the
supported shape is refused. The expected instructions are written out, not computed."""
import contextlib
import io
import os
import struct
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # tools/
import acc_disasm
from shared.mem_layout import get_memory_layout

PROGBITS, NOTE, NOBITS, ALLOC, WRITE, EXEC, COMPRESSED = 1, 7, 8, 2, 1, 4, 0x800
REL, EXE, DYN, UNDEF, ABS = 1, 2, 3, 0, 0xfff1
# words of real kernels; 4309694b sits in the opcode space RV32 gives to fnmsub
LW, JAL, LOOPI, CSRRW, GFMUL, AES, MULV = 0x00002203, 0x249000ef, 0x038012fb, 0x7d101073, 0x6033642b, 0xc1e0aef7, 0x4309694b
CODE = ALLOC | EXEC


def words(*w):
    return struct.pack(f'<{len(w)}I', *w)


def elf(sections, symbols=(), etype=REL, load=(), e='<', machine=243, cut=0):
    """ELF32 bytes. sections: (name, type, flags, address, bytes or a size); symbols: (name, section number, value).
    The sections' bytes end the file, in order. load: (section number, physical address[, n]) per PT_LOAD segment,
    which maps that section's bytes and the n bytes after them. cut drops bytes from the end of the file."""
    strtab = b'\0' + b''.join(n.encode() + b'\0' for n, _, _ in symbols)
    symtab = bytes(16) + b''.join(struct.pack(e + 'IIIBBH', strtab.index(n.encode() + b'\0'), value, 0, 0x10, 0, shndx)
                                  for n, shndx, value in symbols)
    shstr = b'\0' + b''.join(n.encode() + b'\0' for n in [s[0] for s in sections] + ['.symtab', '.strtab', '.shstrtab'])
    table = [s + (0, 0) for s in sections] + [('.symtab', 2, 0, 0, symtab, len(sections) + 2, 16),
                                              ('.strtab', 3, 0, 0, strtab, 0, 0), ('.shstrtab', 3, 0, 0, shstr, 0, 0)]
    offset, body = [0] * len(table), b''
    start = 52 + 32 * len(load) + 40 * (len(table) + 1)
    for i in list(range(len(sections), len(table))) + list(range(len(sections))):
        offset[i] = start + len(body)
        body += b'' if isinstance(table[i][4], int) else table[i][4]
    heads = bytes(40) + b''.join(
        struct.pack(e + '10I', shstr.index(name.encode() + b'\0'), typ, flags, addr, offset[i],
                    payload if isinstance(payload, int) else len(payload), link, 0, 4, entsize)
        for i, (name, typ, flags, addr, payload, link, entsize) in enumerate(table))
    phdr = b''
    for n, paddr, *more in load:
        size = len(sections[n - 1][4]) + (more[0] if more else 0)
        phdr += struct.pack(e + '8I', 1, offset[n - 1], sections[n - 1][3], paddr, size, size, 5, 4)
    header = b'\x7fELF' + bytes([1, 1 if e == '<' else 2, 1]) + bytes(9) + struct.pack(
        e + 'HHIIIIIHHHHHH', etype, machine, 1, 0, 52 if load else 0, 52 + len(phdr), 0, 52, 32 if load else 0,
        len(load), 40, len(table) + 1, len(table))
    data = header + phdr + heads + body
    return data[:len(data) - cut]


def elf64(code):
    """A well-formed 64-bit object with one executable section."""
    shstr = b'\0.text\0.shstrtab\0'
    heads = bytes(64) + struct.pack('<IIQQQQIIQQ', 1, PROGBITS, CODE, 0, 64 + 3 * 64, len(code), 0, 0, 4, 0) \
        + struct.pack('<IIQQQQIIQQ', 7, 3, 0, 0, 64 + 3 * 64 + len(code), len(shstr), 0, 0, 1, 0)
    header = b'\x7fELF\x02\x01\x01' + bytes(9) + struct.pack('<HHIQQQIHHHHHH', REL, 243, 1, 0, 0, 64, 0, 64, 0, 0, 64, 3, 2)
    return header + heads + code + shstr


class Disassemble(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.insns = acc_disasm.load_insns_yaml()
        cls.imem = get_memory_layout().imem_address

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def file(self, data, name='x.elf'):
        path = os.path.join(self.tmp.name, name)
        with open(path, 'wb') as fh:
            fh.write(data)
        return path

    def run_main(self, path):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = acc_disasm.main(['--elf', path])
        return rc, out.getvalue(), err.getvalue()

    @staticmethod
    def shown(lines):
        """(address, word, text with single spaces) of the instruction lines"""
        rows = [line.split('\t') for line in lines if line.count('\t') == 2]
        return [(int(pc.strip(' :'), 16), word, ' '.join(text.split())) for pc, word, text in rows]

    def test_words_render_through_the_database_at_their_addresses(self):
        path = self.file(elf([('.text', PROGBITS, CODE, 0x30, words(LW, JAL, LOOPI, CSRRW, GFMUL, AES, MULV))]))
        lines, n, unknown = acc_disasm.disassemble(path, self.insns)
        self.assertEqual((n, unknown), (7, 0))
        self.assertEqual(lines[0], 'section .text: SHT_PROGBITS, flags 0x6, address 0x30, 28 bytes, align 4')
        self.assertEqual(self.shown(lines), [
            (0x30, '00002203', 'lw x4, 0(x0)'), (0x34, '249000ef', 'jal x1, .+2632'), (0x38, '038012fb', 'loopi 5, 57'),
            (0x3c, '7d101073', 'csrrw x0, mod1, x0'), (0x40, '6033642b', 'bn.gfmul.8.acc w8, w6, w3'),
            (0x44, 'c1e0aef7', 'bn.aes128.kf w29, w30, 1'), (0x48, '4309694b', 'bn.mulv.l.16h.lo w18, w18, sw1.0')])
        self.assertEqual(self.run_main(path)[::2], (0, ''))

    def test_a_word_without_a_decoding_is_shown_counted_and_fails_the_run(self):
        path = self.file(elf([('.text', PROGBITS, CODE, 0, words(LW, 0, GFMUL, 0xffffffff))]))
        lines, n, unknown = acc_disasm.disassemble(path, self.insns)
        self.assertEqual((n, unknown), (4, 2))
        self.assertEqual([t for _, _, t in self.shown(lines)], ['lw x4, 0(x0)', '0x0', 'bn.gfmul.8.acc w8, w6, w3', '0xffffffff'])
        rc, out, err = self.run_main(path)
        self.assertEqual(rc, 1)
        self.assertIn('2 of 4 words have no decoding', err)
        self.assertIn('bn.gfmul.8.acc', out)                              # what decodes is still printed

    def test_only_executable_sections_are_decoded(self):
        path = self.file(elf([('.text', PROGBITS, CODE, 0, words(LW)),
                              ('.data', PROGBITS, ALLOC | WRITE, 0x100, words(GFMUL) * 5),
                              ('.odd', PROGBITS, ALLOC, 0x180, b'\x01\x02\x03\x04\x05'),
                              ('.bss', NOBITS, ALLOC | WRITE, 0x200, 64),
                              ('.comment', PROGBITS, 0, 0, words(AES))]))
        lines, n, unknown = acc_disasm.disassemble(path, self.insns)
        self.assertEqual((n, unknown), (1, 0))
        self.assertEqual(lines, ['section .text: SHT_PROGBITS, flags 0x6, address 0x0, 4 bytes, align 4', lines[1],
                                 'section .data: SHT_PROGBITS, flags 0x3, address 0x100, 20 bytes, align 4',
                                 '     100:\t' + '2b643360' * 4, '     110:\t2b643360',
                                 'section .odd: SHT_PROGBITS, flags 0x2, address 0x180, 5 bytes, align 4', '     180:\t0102030405',
                                 'section .bss: SHT_NOBITS, flags 0x3, address 0x200, 64 bytes, align 4'])
        self.assertNotIn('bn.', '\n'.join(lines))

    def test_every_executable_section_of_an_object_is_shown_with_its_own_symbols(self):
        path = self.file(elf([('.text', PROGBITS, CODE, 0, words(LW, JAL)),
                              ('.text.start', PROGBITS, CODE, 0, words(LOOPI)),
                              ('.data', PROGBITS, ALLOC | WRITE, 0, words(1))],
                             [('main', 1, 0), ('again', 1, 4), ('a_first', 1, 4), ('start', 2, 0), ('ctrl', 3, 0),
                              ('elsewhere', UNDEF, 0), ('fixed', ABS, 4)]), 'x.o')
        lines, n, unknown = acc_disasm.disassemble(path, self.insns)
        self.assertEqual((n, unknown), (3, 0))
        keep = [line.split(':')[0] if line.startswith('section') else line.split('\t')[1] if '\t' in line else line for line in lines]
        self.assertEqual(keep, ['section .text', 'main:', '00002203', 'a_first:', 'again:', '249000ef',
                                'section .text.start', 'start:', '038012fb', 'section .data', '01000000'])
        self.assertEqual([pc for pc, _, _ in self.shown(lines)], [0, 4, 0])

    def test_a_linked_file_must_show_exactly_what_the_loader_takes(self):
        text, more = ('.text', PROGBITS, CODE, 0, words(LW, JAL)), ('.more', PROGBITS, 0, 0, words(GFMUL))
        second, empty, i = ('.text2', PROGBITS, CODE, 8, words(LOOPI)), ('.text0', PROGBITS, CODE, 0x100, b''), self.imem
        accepted = {'one section': (elf([text, more], etype=EXE, load=[(1, i)]), ['lw x4, 0(x0)', 'jal x1, .+2632']),
                    'two sections one after the other, and an empty one':
                        (elf([empty, text, second], etype=EXE, load=[(2, i), (3, i + 8)]), ['lw x4, 0(x0)', 'jal x1, .+2632', 'loopi 5, 57']),
                    'the same two listed in the other order':
                        (elf([second, text], etype=EXE, load=[(1, i + 8), (2, i)]), ['loopi 5, 57', 'lw x4, 0(x0)', 'jal x1, .+2632'])}
        for what, (data, want) in accepted.items():
            with self.subTest(what):
                lines, n, unknown = acc_disasm.disassemble(self.file(data), self.insns)
                self.assertEqual(([t for _, _, t in self.shown(lines)], n, unknown), (want, len(want), 0))
        late = ('.text', PROGBITS, CODE, 8, words(LW, JAL))
        refused = {'a segment longer than the sections': elf([text, more], etype=EXE, load=[(1, i, 4)]),
                   'code that does not start at 0': elf([late], etype=EXE, load=[(1, i + 8)]),
                   'an address that is not the load offset': elf([late], etype=EXE, load=[(1, i)]),
                   # the bytes load one after the other, as the sections' bytes follow each other; only the address differs
                   'a gap in the addresses': elf([text, ('.text2', PROGBITS, CODE, 12, words(LOOPI))], etype=EXE, load=[(1, i), (2, i + 8)]),
                   'sections that overlap': elf([text, ('.text2', PROGBITS, CODE, 4, words(LOOPI))], etype=EXE, load=[(1, i), (2, i + 8)]),
                   'a section that is not loaded': elf([text, second], etype=EXE, load=[(1, i)]),
                   'nothing loaded': elf([text], etype=EXE)}
        for what, data in refused.items():
            with self.subTest(what):
                rc, _, err = self.run_main(self.file(data))
                self.assertEqual(rc, 1)
                self.assertIn('not the loaded instruction memory', err)

    def test_what_cannot_be_read_exits_1_with_the_reason(self):
        text = ('.text', PROGBITS, CODE, 0, words(LW, JAL))
        cases = {'no data-only file': ('no instructions', elf([('.data', PROGBITS, ALLOC | WRITE, 0, words(LW))])),
                 'no empty code': ('no instructions', elf([('.text', PROGBITS, CODE, 0, b'')])),
                 'half a word': ('not whole words', elf([('.text', PROGBITS, CODE, 0, words(LW) + b'\x13\x00')])),
                 'a file cut by one word': ('holds 4 of its 8 bytes', elf([text], cut=4)),
                 'a linked file cut by one word': ('holds 4 of its 8 bytes', elf([text], etype=EXE, load=[(1, self.imem)], cut=4)),
                 'code without contents': ('is not handled', elf([('.text', NOBITS, CODE, 0, 8)])),
                 'compressed code': ('is not handled', elf([('.text', PROGBITS, CODE | COMPRESSED, 0,
                                                             struct.pack('<III', 1, 8, 4) + zlib.compress(words(LW, JAL)))])),
                 'a loaded section of another type': ('is not handled', elf([text, ('.note', NOTE, ALLOC, 0, words(1))])),
                 'a loaded section with a space in its name': ("section name '.rodata extra' is not handled",
                                                               elf([text, ('.rodata extra', PROGBITS, ALLOC, 0, words(1))])),
                 'a loaded section with a bracket in its name': ("section name '.ro]data' is not handled",
                                                                 elf([text, ('.ro]data', PROGBITS, ALLOC, 0, words(1))])),
                 'big-endian': ('not a 32-bit little-endian RISC-V', elf([text], e='>')),
                 'another machine': ('not a 32-bit little-endian RISC-V', elf([text], machine=62)),
                 'a shared object': ('not a 32-bit little-endian RISC-V', elf([text], etype=DYN)),
                 '64-bit class': ('not a 32-bit little-endian RISC-V', elf64(words(LW, JAL))),
                 'not an ELF': ('Magic number', b'not an ELF file')}
        for what, (reason, data) in cases.items():
            with self.subTest(what):
                rc, out, err = self.run_main(self.file(data))
                self.assertEqual(rc, 1)
                self.assertIn(reason, err)
                self.assertTrue(err.startswith('acc_disasm: '))
        rc, out, err = self.run_main(os.path.join(self.tmp.name, 'missing.elf'))
        self.assertEqual((rc, out), (1, ''))
        self.assertIn('missing.elf', err)


if __name__ == '__main__':
    unittest.main()
