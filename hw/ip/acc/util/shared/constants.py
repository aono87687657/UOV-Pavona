#!/usr/bin/env python3
# Copyright lowRISC contributors (OpenTitan project).
# Copyright zeroRISC Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

from copy import deepcopy
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .insn_yaml import Insn
from .operand import RegOperandType


def get_op_val_str(insn: Insn, op_vals: Dict[str, int], opname: str) -> str:
    '''Get the value of the given (register) operand as a string.'''
    op = insn.name_to_operand[opname]
    assert isinstance(op.op_type, RegOperandType)
    return op.op_type.op_val_to_str(op_vals[opname], None)


def _sra(a: int, b: int) -> int:
    a = a - (1 << 32) if a >> 31 else a
    return a >> (b & 31)


# Further RV32 ALU instructions whose result is tracked when the inputs are.
_IMM_OPS = {
    'andi': lambda a, b: a & b,
    'ori': lambda a, b: a | b,
    'xori': lambda a, b: a ^ b,
    'srai': _sra,
}
_REG_OPS = {
    'and': lambda a, b: a & b,
    'or': lambda a, b: a | b,
    'xor': lambda a, b: a ^ b,
    'sll': lambda a, b: a << (b & 31),
    'srl': lambda a, b: a >> (b & 31),
    'sra': _sra,
}


def dmem_word_name(addr: int) -> str:
    '''Name of the constant for the DMEM word at addr.

    Matches the name of the DMEM information-flow node for the word, so the
    sources of a loaded value name the constant it came from.
    '''
    return f'dmem:{addr:#06x}-{addr + 4:#06x}'


def parse_dmem_range(name: str) -> Optional[Tuple[int, int]]:
    '''Returns (start, end) for a DMEM node name, None for other names.'''
    m = re.fullmatch(r'dmem:(0x[0-9a-f]+)-(0x[0-9a-f]+)', name)
    if m is None:
        return None
    return int(m.group(1), 16), int(m.group(2), 16)


def dmem_word_names(start: int, end: int) -> List[str]:
    '''Names of the DMEM word constants overlapping [start, end).'''
    return [dmem_word_name(a) for a in range(start & ~3, end, 4)]


class ConstantContext:
    '''Represents known-constant GPRs and DMEM words.

    This datatype is used to track and evaluate GPR pointers for indirect
    references. With fine-grained DMEM tracking, words stored with a known
    value at a known address are tracked too (named by dmem_word_name), so
    values spilled to the stack stay known.
    '''

    def __init__(self, values: Dict[str, int]):
        # The x0 register needs to always be 0
        assert values.get('x0', None) == 0
        self.values = values.copy()

    @staticmethod
    def empty() -> 'ConstantContext':
        '''Represents a context with no known constants.'''
        return ConstantContext({'x0': 0})

    def set(self, gpr: str, value: int) -> None:
        '''Set the value of a GPR in the context.'''
        if gpr == 'x0':
            # Ignore writes to x0; it's read-only.
            return
        self.values[gpr] = value

    def get(self, gpr: str) -> Optional[int]:
        '''Get the value of a GPR in the context.'''
        return self.values.get(gpr, None)

    def __contains__(self, gpr: str) -> bool:
        return gpr in self.values

    def __deepcopy__(self, memo: Optional[Dict[int,
                                               Any]]) -> 'ConstantContext':
        return ConstantContext(deepcopy(self.values, memo))

    def includes(self, other: 'ConstantContext') -> bool:
        '''Returns true iff other is a restriction of self.'''
        for k, v in other.values.items():
            if self.get(k) != v:
                return False
        return True

    def intersect(self, other: 'ConstantContext') -> 'ConstantContext':
        '''Returns a new context with only values on which self/other agree.

        Does not modify self or other.
        '''
        out = {}
        for k, v in self.values.items():
            if other.get(k) == v:
                out[k] = v
        return ConstantContext(out)

    def removemany(self, to_remove: Iterable[str]) -> None:
        '''Remove the given registers from the constant context.

        Useful for cases when, for example, the given registers have been
        overwritten. Does nothing for registers that are not known constants,
        or for the special register x0.
        '''
        for reg in to_remove:
            if reg == 'x0':
                continue
            if reg == 'dmem':
                # Coarse DMEM node: any word may have changed.
                for k in [k for k in self.values if k.startswith('dmem:')]:
                    del self.values[k]
                continue
            rng = parse_dmem_range(reg)
            if rng is not None:
                for k in [k for k in self.values if k.startswith('dmem:')]:
                    start, end = parse_dmem_range(k)  # type: ignore
                    if start < rng[1] and rng[0] < end:
                        del self.values[k]
                continue
            self.values.pop(reg, None)

    def update_insn(self, insn: Insn, op_vals: Dict[str, int],
                    track_dmem: bool = False) -> None:
        '''Updates to new known constant values GPRs after the instruction.

        Currently, this procedure supports only a limited set of instructions.
        Since constant values only need to be known in order to decode indirect
        references to WDRs and loop counts, this set is chosen based on
        operations likely to happen to those registers: `addi`, `lui`, and
        bignum instructions containing `_inc` op_vals.
        '''
        new_values = {}
        if insn.mnemonic == 'addi':
            grs1_name = get_op_val_str(insn, op_vals, 'grs1')
            if grs1_name in self.values:
                grd_name = get_op_val_str(insn, op_vals, 'grd')
                # Operand is a constant; add/update grd
                new_values[grd_name] = (self.values[grs1_name] +
                                        op_vals['imm']) % (1 << 32)
        elif insn.mnemonic == 'slli':
            grs1_name = get_op_val_str(insn, op_vals, 'grs1')
            if grs1_name in self.values:
                grd_name = get_op_val_str(insn, op_vals, 'grd')
                # Operand is a constant; add/update grd
                new_values[grd_name] = (
                    self.values[grs1_name] << op_vals['shamt']) % (1 << 32)
        elif insn.mnemonic == 'srli':
            grs1_name = get_op_val_str(insn, op_vals, 'grs1')
            if grs1_name in self.values:
                grd_name = get_op_val_str(insn, op_vals, 'grd')
                # Operand is a constant; add/update grd
                new_values[
                    grd_name] = self.values[grs1_name] >> op_vals['shamt']
        elif insn.mnemonic == 'add':
            grs1_name = get_op_val_str(insn, op_vals, 'grs1')
            grs2_name = get_op_val_str(insn, op_vals, 'grs2')
            if grs1_name in self.values and grs2_name in self.values:
                grd_name = get_op_val_str(insn, op_vals, 'grd')
                # Operand is a constant; add/update grd
                new_values[grd_name] = (self.values[grs1_name] +
                                        self.values[grs2_name]) % (1 << 32)
        elif insn.mnemonic == 'sub':
            grs1_name = get_op_val_str(insn, op_vals, 'grs1')
            grs2_name = get_op_val_str(insn, op_vals, 'grs2')
            if grs1_name in self.values and grs2_name in self.values:
                grd_name = get_op_val_str(insn, op_vals, 'grd')
                # Operand is a constant; add/update grd
                new_values[grd_name] = (self.values[grs1_name] -
                                        self.values[grs2_name]) % (1 << 32)
        elif track_dmem and (insn.mnemonic in _IMM_OPS or
                             insn.mnemonic in _REG_OPS):
            grs1_name = get_op_val_str(insn, op_vals, 'grs1')
            if insn.mnemonic in _IMM_OPS:
                fn = _IMM_OPS[insn.mnemonic]
                key = 'imm' if 'imm' in op_vals else 'shamt'
                b = op_vals[key] % (1 << 32)
                known = grs1_name in self.values
            else:
                fn = _REG_OPS[insn.mnemonic]
                grs2_name = get_op_val_str(insn, op_vals, 'grs2')
                b = self.values.get(grs2_name, 0)
                known = grs1_name in self.values and grs2_name in self.values
            if known:
                grd_name = get_op_val_str(insn, op_vals, 'grd')
                new_values[grd_name] = fn(self.values[grs1_name], b) % (1 << 32)
        elif insn.mnemonic == 'lui':
            grd_name = get_op_val_str(insn, op_vals, 'grd')
            new_values[grd_name] = op_vals['imm'] << 12
        elif insn.mnemonic in ['bn.lid', 'bn.sid', 'bn.movr'] or (
                track_dmem and insn.mnemonic in ['bn.ld', 'bn.sd']):
            # If the instruction has any op_vals ending in _inc,
            # assume we're incrementing the corresponding register
            for op in insn.operands:
                if op.name.endswith('_inc') and op_vals[op.name] != 0:
                    # If reg to be incremented is a constant, increment it
                    inc_op = op.name[:-(len('_inc'))]
                    inc_name = get_op_val_str(insn, op_vals, inc_op)
                    inc_amount = 1
                    if insn.mnemonic in ['bn.lid', 'bn.sid'] and op.name == 'grs1_inc':
                        inc_amount = 32
                    if insn.mnemonic in ['bn.ld', 'bn.sd']:
                        inc_amount = 32
                    if inc_name in self.values:
                        new_values[inc_name] = (self.values[inc_name] +
                                                inc_amount) % (1 << 32)

        elif track_dmem and insn.mnemonic in ['lw', 'sw']:
            base = get_op_val_str(insn, op_vals, 'grs1')
            if base in self.values:
                addr = (self.values[base] + op_vals['offset']) % (1 << 32)
                word = dmem_word_name(addr)
                if insn.mnemonic == 'lw':
                    if word in self.values:
                        grd = get_op_val_str(insn, op_vals, 'grd')
                        new_values[grd] = self.values[word]
                else:
                    src = get_op_val_str(insn, op_vals, 'grs2')
                    if src in self.values:
                        new_values[word] = self.values[src]

        # If the instruction's information-flow graph indicates that we updated
        # any constant register other than the ones handled above, the value of
        # that register can no longer be determined; remove it from the
        # constants dictionary. With DMEM tracking, the sinks name the exact
        # words written; a store to an unknown address drops every word.
        iflow = None
        if track_dmem:
            try:
                iflow = insn.iflow.evaluate(op_vals, self.values, False)
            except (RuntimeError, ValueError):
                iflow = None
        if iflow is None:
            iflow = insn.iflow.evaluate(op_vals, self.values, True)
        self.removemany([n.name for n in iflow.all_sinks()])

        self.values.update(new_values)


def is_gpr_name(name: str):
    return name in [f'x{i}' for i in range(32)]


def parse_required_constants(constants: List[str],
                             dmem_symbols: Dict[str, int]) -> Dict[str, int]:
    '''Parses required initial constants.

    Constants are expected to be provided in the form <reg>:<value>, e.g.
    x5:0xfffffff or x22:0. The value can be expressed in decimal or integer
    form. Only GPRs are accepted as required constants (not wide registers or
    special registers). With fine-grained DMEM tracking, a 32-bit DMEM word
    can be given as dmem:<address or label>:<value>, e.g. dmem:0x8:7.
    '''
    GPR_MAX = (1 << 32) - 1

    out = {}
    for token in constants:
        if token.startswith('dmem:'):
            fields = token.split(':')
            if len(fields) != 3:
                raise ValueError(
                    f'Could not parse required constant {token}. Please '
                    'provide DMEM constants as dmem:<address or label>:<value>.')
            addr = dmem_symbols[fields[1]] if fields[1] in dmem_symbols \
                else int(fields[1], 0)
            if addr % 4:
                raise ValueError(f'DMEM constant {token} is not word-aligned.')
            out[dmem_word_name(addr)] = int(fields[2], 0) & GPR_MAX
            continue
        reg_and_value = token.split(':')
        if len(reg_and_value) != 2:
            raise ValueError(
                f'Could not parse required constant {token}. Please provide '
                'required constants in the form <reg>:<value>, e.g. x5:3.')
        reg, value = reg_and_value
        if not is_gpr_name(reg):
            raise ValueError(
                f'Cannot parse required constant {token}: {reg} is not a '
                'valid GPR name.')
        try:
            if value in dmem_symbols:
                value = dmem_symbols[value]
            else:
                value = int(value, 0)
        except ValueError:
            raise ValueError(
                f'Cannot parse required constant {token}: {value} is not a '
                'recognized numeric value or DMEM label.')
        if value < 0 or value > GPR_MAX:
            raise ValueError(
                f'Cannot parse required constant {token}: {value} is out of '
                'range [0, GPR_MAX].')
        out[reg] = value

    return out
