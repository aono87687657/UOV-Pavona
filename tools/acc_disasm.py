#!/usr/bin/env python3
"""Disassemble an ACC object or ELF with the instruction database.

  python3 tools/acc_disasm.py --elf FILE

Every 32-bit word of the executable sections goes through acc_objdump.py's decoder, with the names of the symbols
defined in that section; the other loaded sections follow as hex, each section under a line with its type, flags,
address, size and alignment. The words are read from the file, so the result does not depend on how the installed
objdump prints a word it does not know (`.word`, `.insn`, a float mnemonic). In an object the operands are the
stored ones, before relocation. For a linked ELF the executable sections must be exactly the instruction memory
that the ACC loader takes from the file.
Exit status 1: a word without a decoding (printed as `0x...`), no instruction at all, or a file this cannot read
(not a 32-bit little-endian RISC-V object or executable, a section cut short, of a type or with a name not handled)."""
import argparse
import os
import re
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(REPO, d) for d in ('hw/ip/acc/util', 'util')]
from acc_objdump import transform_disasm_line
from elftools.common.exceptions import ELFError
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile
from shared.elf import read_elf
from shared.insn_yaml import load_insns_yaml


def disassemble(path, insns_file):
    """(lines, instruction words, words without a decoding) for the loaded sections of the file at path"""
    lines, words, unknown, code = [], 0, 0, []
    with open(path, 'rb') as fh:
        elf = ELFFile(fh)
        if (elf.elfclass, elf.little_endian, elf['e_machine']) != (32, True, 'EM_RISCV') \
                or elf['e_type'] not in ('ET_REL', 'ET_EXEC'):
            raise ValueError('not a 32-bit little-endian RISC-V object or executable')
        symtab = elf.get_section_by_name('.symtab')
        for index, sec in enumerate(elf.iter_sections()):
            flags, kind, addr, size = sec['sh_flags'], sec['sh_type'], sec['sh_addr'], sec['sh_size']
            if not flags & SH_FLAGS.SHF_ALLOC:
                continue
            if not re.fullmatch(r'[A-Za-z0-9_.$-]+', sec.name):         # the lines below are split on spaces and ':'
                raise ValueError(f'section name {sec.name!r} is not handled')
            lines.append(f'section {sec.name}: {kind}, flags {flags:#x}, address {addr:#x}, {size} bytes, '
                         f'align {sec["sh_addralign"]}')
            executable = flags & SH_FLAGS.SHF_EXECINSTR
            if kind == 'SHT_NOBITS' and not executable:
                continue                                                # no contents in the file
            if kind != 'SHT_PROGBITS' or flags & SH_FLAGS.SHF_COMPRESSED:
                raise ValueError(f'section {sec.name}: {kind} with flags {flags:#x} is not handled')
            data = sec.data()
            if len(data) != size:
                raise ValueError(f'section {sec.name}: the file holds {len(data)} of its {size} bytes')
            if not executable:
                lines += [f'{addr + i:8x}:\t{data[i:i + 16].hex()}' for i in range(0, size, 16)]
                continue
            if size % 4:
                raise ValueError(f'section {sec.name} is {size} bytes, not whole words')
            code.append((addr, data))
            labels = {}
            for sym in symtab.iter_symbols() if symtab else ():
                if sym['st_shndx'] == index and sym.name:
                    labels.setdefault(sym['st_value'], []).append(sym.name)
            for i, (word,) in enumerate(struct.iter_unpack('<I', data)):
                pc = addr + 4 * i
                lines += [f'{name}:' for name in sorted(labels.get(pc, ()))]
                raw = f'{pc:8x}:\t{word:08x}\t0x{word:x}'               # the line form acc_objdump.py decodes
                line = transform_disasm_line(raw, insns_file)
                words += 1
                unknown += line == raw
                lines.append(line)
        linked = elf['e_type'] == 'ET_EXEC'
    if linked:                              # the sections, by address from 0 without a gap, are what the loader takes
        code = sorted(c for c in code if c[1])
        starts = [sum(len(d) for _, d in code[:i]) for i in range(len(code))]
        if [a for a, _ in code] != starts or b''.join(d for _, d in code) != read_elf(path)[0]:
            raise ValueError('the executable sections are not the loaded instruction memory')
    return lines, words, unknown


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--elf', required=True, metavar='FILE', help='an ACC object (.o) or linked ELF')
    path = parser.parse_args(argv).elf
    try:
        lines, words, unknown = disassemble(path, load_insns_yaml())
    except (OSError, ELFError, ValueError, RuntimeError) as e:
        print(f'acc_disasm: {path}: {e}', file=sys.stderr)
        return 1
    print('\n'.join(lines))
    if unknown or not words:
        print(f'acc_disasm: {path}: ' + (f'{unknown} of {words} words have no decoding' if words else 'no instructions'),
              file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
