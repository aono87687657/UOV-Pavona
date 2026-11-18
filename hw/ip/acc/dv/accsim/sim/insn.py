# Copyright lowRISC contributors (OpenTitan project).
# Copyright zeroRISC Inc.
# Modified by Authors of "Towards ML-KEM & ML-DSA on OpenTitan" (https://eprint.iacr.org/2024/1192).
# Copyright "Towards ML-KEM & ML-DSA on OpenTitan" Authors.
# Modified by Ruben Niederhagen and Hoang Nguyen Hien Pham - authors of
# "Improving ML-KEM & ML-DSA on OpenTitan - Efficient Multiplication Vector Instructions for OTBN"
# (https://eprint.iacr.org/2025/2028).
# Copyright Ruben Niederhagen and Hoang Nguyen Hien Pham.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0


from typing import Dict, Iterator, Optional
import sys

from .constants import ErrBits
from .flags import FlagReg
from .isa import (ACCInsn, RV32RegReg, RV32RegImm,
                  RV32ImmShift, insn_for_mnemonic, logical_byte_shift,
                  bit_shift,
                  extract_quarter_word, extract_sub_word)
from .state import ACCState

DEBUG_MEM = False
DEBUG_BRANCH = False
DEBUG_ARITH = False
DEBUG_KMAC = False
DEBUG_FLOW = False

STACK_BENCH = False
STACK_SIZE = 20000


def eprint(text: str) -> None:
    print(text, file=sys.stderr)


def cmod(n: int, q: int) -> int:
    t = n % q
    # if t > floor(q / 2):
    #     t -= q
    return t


def cmod_single_addv(n: int, q: int) -> int:
    if n >= q:
        return n - q
    else:
        return n


def cmod_single_subv(n: int, q: int) -> int:
    if n < 0:
        return n + q
    else:
        return n


class ADD(RV32RegReg):
    insn = insn_for_mnemonic('add', 3)

    def execute(self, state: ACCState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = state.gprs.get_reg(self.grs2).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = (val1 + val2) & ((1 << 32) - 1)
        if DEBUG_ARITH or (STACK_BENCH and self.grd == 2):
            eprint(f"add {val1} + {val2} = {result}")

        if STACK_BENCH and self.grd == 2:
            with open("/home/dev/src/stack_bench.txt", "r") as f:
                try:
                    prev_min = int(f.readline(), 10)
                except ValueError:
                    prev_min = 0
            print(f"result: {result} ")
            print(f"prev_min: {prev_min} ")
            print(f"STACK_SIZE - result: {STACK_SIZE - result}")
            if (STACK_SIZE - result) > prev_min:
                with open("/home/dev/src/stack_bench.txt", "w") as f:
                    f.write(str(STACK_SIZE - result))

        state.gprs.get_reg(self.grd).write_unsigned(result)


class ADDI(RV32RegImm):
    insn = insn_for_mnemonic('addi', 3)

    def execute(self, state: ACCState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = (val1 + self.imm) & ((1 << 32) - 1)
        if DEBUG_ARITH or (STACK_BENCH and self.grd == 2):
            eprint(f"addi {val1} + {self.imm} = {result}")

        if STACK_BENCH and self.grd == 2 and self.imm != 0:
            with open("/home/dev/src/stack_bench.txt", "r") as f:
                try:
                    prev_min = int(f.readline(), 10)
                except ValueError:
                    prev_min = 0
            print(f"result: {result} ")
            print(f"prev_min: {prev_min} ")
            print(f"STACK_SIZE - result: {STACK_SIZE - result}")
            if (STACK_SIZE - result) > prev_min:
                with open("/home/dev/src/stack_bench.txt", "w") as f:
                    f.write(str(STACK_SIZE - result))

        state.gprs.get_reg(self.grd).write_unsigned(result)


class LUI(ACCInsn):
    insn = insn_for_mnemonic('lui', 2)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grd = op_vals['grd']
        self.imm = op_vals['imm']

    def execute(self, state: ACCState) -> None:
        state.gprs.get_reg(self.grd).write_unsigned(self.imm << 12)


class SUB(RV32RegReg):
    insn = insn_for_mnemonic('sub', 3)

    def execute(self, state: ACCState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = state.gprs.get_reg(self.grs2).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = (val1 - val2) & ((1 << 32) - 1)
        if DEBUG_ARITH:
            eprint(f"sub {val1} - {val2} = {result}")
        state.gprs.get_reg(self.grd).write_unsigned(result)


class SLL(RV32RegReg):
    insn = insn_for_mnemonic('sll', 3)

    def execute(self, state: ACCState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = state.gprs.get_reg(self.grs2).read_unsigned() & 0x1f
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = (val1 << val2) & ((1 << 32) - 1)
        if DEBUG_ARITH:
            eprint(f"sll {hex(val1)} << {(val2)} = {hex(result)}")
        state.gprs.get_reg(self.grd).write_unsigned(result)


class SLLI(RV32ImmShift):
    insn = insn_for_mnemonic('slli', 3)

    def execute(self, state: ACCState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return
        result = (val1 << self.shamt) & ((1 << 32) - 1)
        if DEBUG_ARITH:
            eprint(f"slli {hex(val1)} << {self.shamt} = {hex(result)}")
        state.gprs.get_reg(self.grd).write_unsigned(result)


class SRL(RV32RegReg):
    insn = insn_for_mnemonic('srl', 3)

    def execute(self, state: ACCState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = state.gprs.get_reg(self.grs2).read_unsigned() & 0x1f
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = val1 >> val2
        if DEBUG_ARITH:
            eprint(f"srl {hex(val1)} >> {(val2)} = {hex((result) & ((1 << 32) - 1))}")
        state.gprs.get_reg(self.grd).write_unsigned(result)


class SRLI(RV32ImmShift):
    insn = insn_for_mnemonic('srli', 3)

    def execute(self, state: ACCState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return
        result = val1 >> self.shamt
        if DEBUG_ARITH:
            eprint(f"srli {hex(val1)} >> {self.shamt} = {hex(result)}")
        state.gprs.get_reg(self.grd).write_unsigned(result)


class SRA(RV32RegReg):
    insn = insn_for_mnemonic('sra', 3)

    def execute(self, state: ACCState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_signed()
        val2 = state.gprs.get_reg(self.grs2).read_unsigned() & 0x1f
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = val1 >> val2
        if DEBUG_ARITH:
            eprint(f"sra {hex(val1)} >> {val2} = {hex(result)}")
        state.gprs.get_reg(self.grd).write_signed(result)


class SRAI(RV32ImmShift):
    insn = insn_for_mnemonic('srai', 3)

    def execute(self, state: ACCState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_signed()
        val2 = self.shamt
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = val1 >> val2
        state.gprs.get_reg(self.grd).write_signed(result)


class AND(RV32RegReg):
    insn = insn_for_mnemonic('and', 3)

    def execute(self, state: ACCState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = state.gprs.get_reg(self.grs2).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = val1 & val2
        if DEBUG_ARITH:
            eprint(f"and {hex(val1)} & {hex(val2)} = {hex(val1 & val2)}")
        state.gprs.get_reg(self.grd).write_unsigned(result)


class ANDI(RV32RegImm):
    insn = insn_for_mnemonic('andi', 3)

    def execute(self, state: ACCState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = self.to_2s_complement(self.imm)
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return
        if DEBUG_ARITH:
            eprint(f"andi {hex(val1)} & {hex(val2)} = {hex(val1 & val2)}")
        result = val1 & val2
        state.gprs.get_reg(self.grd).write_unsigned(result)


class OR(RV32RegReg):
    insn = insn_for_mnemonic('or', 3)

    def execute(self, state: ACCState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = state.gprs.get_reg(self.grs2).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return
        if DEBUG_ARITH:
            eprint(f"or {hex(val1)} | {hex(val2)} = {hex(val1 | val2)}")
        result = val1 | val2
        state.gprs.get_reg(self.grd).write_unsigned(result)


class ORI(RV32RegImm):
    insn = insn_for_mnemonic('ori', 3)

    def execute(self, state: ACCState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = self.to_2s_complement(self.imm)
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = val1 | val2
        state.gprs.get_reg(self.grd).write_unsigned(result)


class XOR(RV32RegReg):
    insn = insn_for_mnemonic('xor', 3)

    def execute(self, state: ACCState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = state.gprs.get_reg(self.grs2).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = val1 ^ val2
        state.gprs.get_reg(self.grd).write_unsigned(result)


class XORI(RV32RegImm):
    insn = insn_for_mnemonic('xori', 3)

    def execute(self, state: ACCState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = self.to_2s_complement(self.imm)
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = val1 ^ val2
        state.gprs.get_reg(self.grd).write_unsigned(result)


class LW(ACCInsn):
    insn = insn_for_mnemonic('lw', 3)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grd = op_vals['grd']
        self.offset = op_vals['offset']
        self.grs1 = op_vals['grs1']

    def execute(self, state: ACCState) -> Optional[Iterator[None]]:
        # LW executes over two cycles. On the first cycle, we read the base
        # address, compute the load address and check it for correctness, then
        # perform the load itself, returning the result.
        #
        # On the second cycle, we write the result to the destination register.

        base = state.gprs.get_reg(self.grs1).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return None

        addr = (base + self.offset) & ((1 << 32) - 1)

        if not state.dmem.is_valid_32b_addr(addr):
            if DEBUG_MEM:
                print(f"lw {base} {self.offset}: failed", file=sys.stderr)
            state.stop_at_end_of_cycle(ErrBits.BAD_DATA_ADDR)
            return None

        result = state.dmem.load_u32(addr)

        # Stall for a single cycle for memory to respond
        yield None

        if DEBUG_MEM:
            print(f"lw {base} {self.offset}", file=sys.stderr)

        if result is None:
            state.stop_at_end_of_cycle(ErrBits.DMEM_INTG_VIOLATION)
            return None

        if DEBUG_MEM:
            print(f"\t{format(result, '08x')}", file=sys.stderr)

        state.gprs.get_reg(self.grd).write_unsigned(result)
        return None


class SW(ACCInsn):
    insn = insn_for_mnemonic('sw', 3)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grs2 = op_vals['grs2']
        self.offset = op_vals['offset']
        self.grs1 = op_vals['grs1']

    def execute(self, state: ACCState) -> None:
        base = state.gprs.get_reg(self.grs1).read_unsigned()
        addr = (base + self.offset) & ((1 << 32) - 1)
        value = state.gprs.get_reg(self.grs2).read_unsigned()
        if DEBUG_MEM:
            print(f"sw {base} {self.offset}: {format(value, '08x')}", file=sys.stderr)
        bad_grs1 = state.gprs.call_stack_err and (self.grs1 == 1)

        saw_err = False

        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            saw_err = True

        if not state.dmem.is_valid_32b_addr(addr) and not bad_grs1:
            state.stop_at_end_of_cycle(ErrBits.BAD_DATA_ADDR)
            saw_err = True

        if saw_err:
            return

        state.dmem.store_u32(addr, value)


class BEQ(ACCInsn):
    insn = insn_for_mnemonic('beq', 3)
    affects_control = True
    has_fetch_stall = True

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grs1 = op_vals['grs1']
        self.grs2 = op_vals['grs2']
        self.offset = op_vals['offset']

    def execute(self, state: ACCState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = state.gprs.get_reg(self.grs2).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return
        if DEBUG_BRANCH:
            eprint(f"Branch: {val1} ?== {val2} to {self.offset}")
        tgt_pc = self.offset & ((1 << 32) - 1)
        if val1 == val2:
            if DEBUG_BRANCH:
                eprint("taken")
            if not state.is_pc_valid(tgt_pc):
                state.stop_at_end_of_cycle(ErrBits.BAD_INSN_ADDR)
            else:
                state.set_next_pc(tgt_pc)
        else:
            if DEBUG_BRANCH:
                eprint("not taken")


class BNE(ACCInsn):
    insn = insn_for_mnemonic('bne', 3)
    affects_control = True
    has_fetch_stall = True

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grs1 = op_vals['grs1']
        self.grs2 = op_vals['grs2']
        self.offset = op_vals['offset']

    def execute(self, state: ACCState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = state.gprs.get_reg(self.grs2).read_unsigned()

        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return
        if DEBUG_BRANCH:
            eprint(f"Branch: {val1} ?!= {val2} to {self.offset}")
        tgt_pc = self.offset & ((1 << 32) - 1)
        if val1 != val2:
            if DEBUG_BRANCH:
                eprint("taken")
            if not state.is_pc_valid(tgt_pc):
                state.stop_at_end_of_cycle(ErrBits.BAD_INSN_ADDR)
            else:
                state.set_next_pc(tgt_pc)
        else:
            if DEBUG_BRANCH:
                eprint("not taken")


class JAL(ACCInsn):
    insn = insn_for_mnemonic('jal', 2)
    affects_control = True
    has_fetch_stall = True

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grd = op_vals['grd']
        self.offset = op_vals['offset']

    def execute(self, state: ACCState) -> None:
        mask32 = ((1 << 32) - 1)
        link_pc = (state.pc + 4) & mask32
        state.gprs.get_reg(self.grd).write_unsigned(link_pc)
        if DEBUG_FLOW:
            eprint(f"jal {self.offset}")
        next_pc = self.offset & mask32
        if not state.is_pc_valid(next_pc):
            state.stop_at_end_of_cycle(ErrBits.BAD_INSN_ADDR)
        else:
            state.set_next_pc(next_pc)


class JALR(ACCInsn):
    insn = insn_for_mnemonic('jalr', 3)
    affects_control = True
    has_fetch_stall = True

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grd = op_vals['grd']
        self.grs1 = op_vals['grs1']
        self.offset = op_vals['offset']

    def execute(self, state: ACCState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        mask32 = ((1 << 32) - 1)
        link_pc = (state.pc + 4) & mask32

        state.gprs.get_reg(self.grd).write_unsigned(link_pc)

        next_pc = (val1 + self.offset) & mask32
        if not state.is_pc_valid(next_pc):
            state.stop_at_end_of_cycle(ErrBits.BAD_INSN_ADDR)
        else:
            state.set_next_pc(next_pc)


class CSRRS(ACCInsn):
    insn = insn_for_mnemonic('csrrs', 3)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grd = op_vals['grd']
        self.csr = op_vals['csr']
        self.grs1 = op_vals['grs1']

    def execute(self, state: ACCState) -> Optional[Iterator[None]]:
        if not state.csrs.check_idx(self.csr):
            # Invalid CSR index. Stop with an illegal instruction error.
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)
            return None

        bits_to_set = state.gprs.get_reg(self.grs1).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return None

        if self.csr == 0xfc0:
            # A read from RND. If a RND value is not available, request_value()
            # initiates or continues an EDN request and returns False. If a RND
            # value is available, it returns True.
            while not state.wsrs.RND.request_value():
                # There's a pending EDN request. Stall for a cycle.
                yield None

        # At this point, the CSR is ready. Read, update and write back to grs1.
        old_val = state.read_csr(self.csr)
        new_val = old_val | bits_to_set
        state.gprs.get_reg(self.grd).write_unsigned(old_val)
        if self.grs1 != 0:
            state.write_csr(self.csr, new_val)

        return None


class CSRRW(ACCInsn):
    insn = insn_for_mnemonic('csrrw', 3)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grd = op_vals['grd']
        self.csr = op_vals['csr']
        self.grs1 = op_vals['grs1']

    def execute(self, state: ACCState) -> Optional[Iterator[None]]:
        # eprint("csrrw")
        if not state.csrs.check_idx(self.csr):
            # Invalid CSR index. Stop with an illegal instruction error.
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)
            return None

        new_val = state.gprs.get_reg(self.grs1).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return None

        if self.csr == 0xfc0 and self.grd != 0:
            # A read from RND. If a RND value is not available, request_value()
            # initiates or continues an EDN request and returns False. If a RND
            # value is available, it returns True.
            while not state.wsrs.RND.request_value():
                # There's a pending EDN request. Stall for a cycle.
                yield None

        if self.csr == 0x7f3:
            # A write to KMAC_PW might stall, if there is a pending write
            # to the AppIntf FIFO inside ACC Bignum ALU
            if DEBUG_KMAC:
                eprint("\tBNWSRW FOR KMAC PARTIAL WRITE REGISTER")
            while (
                state.wsrs.KMAC_MSG0.pending_write_pw() or
                state.wsrs.KMAC_MSG1.pending_write_pw()
            ):
                if DEBUG_KMAC:
                    eprint("\tBNWSRW to KMAC_PW stall")

                # The following conditions cause a deadlock in execution
                if (
                    state.wsrs.KMAC_MSG1._pending_write_to_app_intf and
                    not state.kmac.app_intf_fifo1_ready() and
                    state.kmac.app_intf_fifo0_ready() and
                    state.kmac._masked_mode
                ):
                    state.stop_at_end_of_cycle(ErrBits.KMAC_FATAL_ERROR)

                if (
                    state.wsrs.KMAC_MSG0._pending_write_to_app_intf and
                    not state.kmac.app_intf_fifo0_ready() and
                    state.kmac.app_intf_fifo1_ready() and
                    state.kmac._masked_mode
                ):
                    state.stop_at_end_of_cycle(ErrBits.KMAC_FATAL_ERROR)

                yield None

        # At this point, the CSR is either ready or unneeded. Read it if
        # necessary and write to grd, then overwrite with new_val.

        if self.grd != 0:
            old_val = state.read_csr(self.csr)
            state.gprs.get_reg(self.grd).write_unsigned(old_val)

        state.write_csr(self.csr, new_val)
        return None


class ECALL(ACCInsn):
    insn = insn_for_mnemonic('ecall', 0)

    def execute(self, state: ACCState) -> None:
        # Set INTR_STATE.done and STATUS, reflecting the fact we've stopped.
        state.stop_at_end_of_cycle(err_bits=0)


class LOOP(ACCInsn):
    insn = insn_for_mnemonic('loop', 2)
    affects_control = True

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grs = op_vals['grs']
        self.bodysize = op_vals['bodysize']

    def execute(self, state: ACCState) -> None:
        num_iters = state.gprs.get_reg(self.grs).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        if num_iters == 0:
            state.stop_at_end_of_cycle(ErrBits.LOOP)
        else:
            state.loop_start(num_iters, self.bodysize)


class LOOPI(ACCInsn):
    insn = insn_for_mnemonic('loopi', 2)
    affects_control = True

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.iterations = op_vals['iterations']
        self.bodysize = op_vals['bodysize']

    def execute(self, state: ACCState) -> None:
        if DEBUG_FLOW:
            eprint("LOOPI")
        if self.iterations == 0:
            state.stop_at_end_of_cycle(ErrBits.LOOP)
        else:
            state.loop_start(self.iterations, self.bodysize)


class BNADD(ACCInsn):
    insn = insn_for_mnemonic('bn.add', 6)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.shift_type = op_vals['shift_type']
        self.shift_bytes = op_vals['shift_bits'] // 8
        self.flag_group = op_vals['flag_group']

    def execute(self, state: ACCState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        b_shifted = logical_byte_shift(b, self.shift_type, self.shift_bytes)

        full_result = a + b_shifted
        mask256 = (1 << 256) - 1
        masked_result = full_result & mask256
        carry_flag = bool((full_result >> 256) & 1)
        flags = FlagReg.mlz_for_result(carry_flag, masked_result)

        if DEBUG_ARITH:
            eprint(f"bn.add 0x{format(a, '064x')} + 0x{format(b, '064x')} = "
                   f"{format(a+b, '064x')} = {format(masked_result, '064x')}")

        state.wdrs.get_reg(self.wrd).write_unsigned(masked_result)
        state.set_flags(self.flag_group, flags)


class BNADDC(ACCInsn):
    insn = insn_for_mnemonic('bn.addc', 6)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.shift_type = op_vals['shift_type']
        self.shift_bytes = op_vals['shift_bits'] // 8
        self.flag_group = op_vals['flag_group']

    def execute(self, state: ACCState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        b_shifted = logical_byte_shift(b, self.shift_type, self.shift_bytes)

        carry = int(state.csrs.flags[self.flag_group].C)
        full_result = a + b_shifted + carry
        mask256 = (1 << 256) - 1
        masked_result = full_result & mask256
        carry_flag = bool((full_result >> 256) & 1)
        flags = FlagReg.mlz_for_result(carry_flag, masked_result)

        state.wdrs.get_reg(self.wrd).write_unsigned(masked_result)
        state.set_flags(self.flag_group, flags)


class BNADDI(ACCInsn):
    insn = insn_for_mnemonic('bn.addi', 4)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs = op_vals['wrs']
        self.imm = op_vals['imm']
        self.flag_group = op_vals['flag_group']

    def execute(self, state: ACCState) -> None:
        a = state.wdrs.get_reg(self.wrs).read_unsigned()
        b = self.imm

        full_result = a + b
        mask256 = (1 << 256) - 1
        masked_result = full_result & mask256
        if DEBUG_ARITH:
            eprint(f"bn.addi {format(a, '064x')} + {b} = {format(a+b, '064x')} = "
                   f"{format(masked_result, '064x')}")
        carry_flag = bool((full_result >> 256) & 1)
        flags = FlagReg.mlz_for_result(carry_flag, masked_result)

        state.wdrs.get_reg(self.wrd).write_unsigned(masked_result)
        state.set_flags(self.flag_group, flags)


class BNADDM(ACCInsn):
    insn = insn_for_mnemonic('bn.addm', 3)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']

    def execute(self, state: ACCState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        mod_val = state.wsrs.MOD.read_unsigned()

        result = a + b

        if result >= mod_val:
            result -= mod_val

        result = result & ((1 << 256) - 1)

        if DEBUG_ARITH:
            eprint(f"bn.addm 0x{format(a, '064x')} + 0x{format(b, '064x')} = "
                   f"{format(a+b, '064x')} = {format(result, '064x')}")
            if result >= mod_val:
                eprint("incomplete reduction")

        state.wdrs.get_reg(self.wrd).write_unsigned(result)


class BNADDV(ACCInsn):
    insn = insn_for_mnemonic('bn.addv', 4)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.type = op_vals['type']

    def execute(self, state: ACCState) -> None:
        if not state.EN_PQC:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)

        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        mod_val = state.wsrs.MOD.read_unsigned()
        red = True if self.type > 1 else False
        size = 32 if (self.type % 2 == 0) else 16
        mod_val = extract_sub_word(mod_val, size, 0)
        result = 0

        for i in range(256 // size - 1, -1, -1):
            ai = extract_sub_word(a, size, i)
            bi = extract_sub_word(b, size, i)
            resulti = ai + bi
            if red:
                resulti = cmod_single_addv(resulti, mod_val)
            if DEBUG_ARITH:
                eprint(f"addvm {ai:#x} + {bi:#x} = {ai + bi:#x} = {resulti:#x}")
            result <<= size
            result |= (resulti & ((1 << size) - 1))

        result = result & ((1 << 256) - 1)
        state.wdrs.get_reg(self.wrd).write_unsigned(result)


class BNMULV(ACCInsn):
    insn = insn_for_mnemonic('bn.mulv', 4)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.type = op_vals['type']

    def execute(self, state: ACCState) -> None:
        if not state.EN_PQC:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)

        wrs1 = state.wdrs.get_reg(self.wrs1).read_unsigned()
        wrs2 = state.wdrs.get_reg(self.wrs2).read_unsigned()

        # Extract fields in the encoding:
        #    data_type:    0 = .16H, 1 = .8S
        #    sel:       0 = .even, 1 = .odd
        #    acc_mode:  0 = disabled, 1 = .acc, 2 = .acc.z
        #    exec_mode: 0 = standard, 1 = .lo, 2 = .hi
        data_type = self.type & 0b01
        sel = (self.type & 0b10) >> 1
        acc_mode = (self.type & 0b1100) >> 2
        exec_mode = (self.type & 0b110000) >> 4

        if data_type:
            size = 32
        else:
            size = 16
        num_lanes = 256 // size

        wrs1_v = [extract_sub_word(wrs1, size, i) for i in range(num_lanes)]
        wrs2_v = [extract_sub_word(wrs2, size, i) for i in range(num_lanes)]
        wrd_v = wrs1_v.copy()

        if (data_type == 0) and (exec_mode != 0):
            lane_indices = range(num_lanes)
        else:
            if sel:
                lane_indices = range(1, num_lanes, 2)
            else:
                lane_indices = range(0, num_lanes, 2)

        acc_en = (acc_mode == 1) or (acc_mode == 2)
        accl = state.wsrs.ACC.read_unsigned()
        acch = state.wsrs.ACCH.read_unsigned()
        if acc_mode == 2:
            accl = 0
            acch = 0

        accl_v = [extract_sub_word(accl, 2 * size, i) for i in range(num_lanes // 2)]
        acch_v = [extract_sub_word(acch, 2 * size, i) for i in range(num_lanes // 2)]
        acc_v = accl_v + acch_v

        dmask = (1 << 2 * size) - 1
        mask = (1 << size) - 1

        if DEBUG_ARITH:
            eprint("BNMULV")
            eprint(f"lane_mode | exec_mode | acc_mode | sel | data_type = \
                   0 | {exec_mode} | {acc_mode} | {sel} | {data_type}")
            eprint(f"acc_v = {[hex(acci) for acci in acc_v]}")
            eprint(f'lane_indices = {lane_indices}')
            eprint(f"acc_en = {acc_en}")

        for i in lane_indices:
            prodi = wrs1_v[i] * wrs2_v[i]

            if DEBUG_ARITH:
                eprint(f'i = {i}')
                eprint(f"ai * bi = {hex(wrs1_v[i])} * {hex(wrs2_v[i])} = {hex(prodi)}")
                eprint(f"acci = {hex(acc_v[i])}")

            if acc_en:
                prodi += acc_v[i]
                acc_v[i] = prodi
                if DEBUG_ARITH:
                    eprint(f"acc_mode: prodi = acci = {hex(prodi)}")

            if exec_mode == 0:
                lo = prodi & mask
                hi = (prodi >> size) & mask
                wrd_v[i - 1 if sel else i] = lo
                wrd_v[i if sel else i + 1] = hi
            elif exec_mode == 1:
                wrd_v[i] = prodi & mask
            elif exec_mode == 2:
                wrd_v[i] = (prodi >> size) & mask

            if DEBUG_ARITH:
                eprint(f"wrd_v[{i}] = {hex(wrd_v[i])}")

        result = sum((wrd_v[i] & mask) << (i * size) for i in range(num_lanes))
        state.wdrs.get_reg(self.wrd).write_unsigned(result)

        if acc_en:
            acc_o = sum((acc_v[i] & dmask) << (i * 2 * size) for i in range(num_lanes))
            accl = acc_o & ((1 << 256) - 1)
            acch = (acc_o >> 256) & ((1 << 256) - 1)
            state.wsrs.ACC.write_unsigned(accl)
            state.wsrs.ACCH.write_unsigned(acch)

        if DEBUG_ARITH:
            eprint(f"result at the end = {hex(result)}")
            eprint(f"accl at the end = {hex(accl)}")
            eprint(f"acch at the end = {hex(acch)}")


class BNMULVL(ACCInsn):
    insn = insn_for_mnemonic('bn.mulv.l', 5)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.type = op_vals['type']
        self.lane_reg = op_vals['lane_reg']
        self.lane_index = op_vals['lane_index']

    def execute(self, state: ACCState) -> None:
        if not state.EN_PQC:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)

        # Extract fields in the encoding:
        #    data_type:    0 = .16H, 1 = .8S
        #    sel:       0 = .even, 1 = .odd
        #    acc_mode:  0 = disabled, 1 = .acc, 2 = .acc.z
        #    exec_mode: 0 = standard, 1 = .lo, 2 = .hi
        data_type = self.type & 0b01
        sel = (self.type & 0b10) >> 1
        acc_mode = (self.type & 0b1100) >> 2
        exec_mode = (self.type & 0b110000) >> 4

        wrs1 = state.wdrs.get_reg(self.wrs1).read_unsigned()
        if self.lane_reg:
            wrs2 = state.wdrs.get_reg(17).read_unsigned()
        else:
            wrs2 = state.wdrs.get_reg(16).read_unsigned()

        if data_type:
            size = 32
        else:
            size = 16
        num_lanes = 256 // size

        wrs1_v = [extract_sub_word(wrs1, size, i) for i in range(num_lanes)]
        wrs2_v = [extract_sub_word(wrs2, size, self.lane_index) for i in range(num_lanes)]
        wrd_v = wrs1_v.copy()

        if (data_type == 0) and (exec_mode != 0):
            lane_indices = range(num_lanes)
        else:
            if sel:
                lane_indices = range(1, num_lanes, 2)
            else:
                lane_indices = range(0, num_lanes, 2)

        acc_en = (acc_mode == 1) or (acc_mode == 2)
        accl = state.wsrs.ACC.read_unsigned()
        acch = state.wsrs.ACCH.read_unsigned()
        if acc_mode == 2:
            accl = 0
            acch = 0

        accl_v = [extract_sub_word(accl, 2 * size, i) for i in range(num_lanes // 2)]
        acch_v = [extract_sub_word(acch, 2 * size, i) for i in range(num_lanes // 2)]
        acc_v = accl_v + acch_v

        dmask = (1 << 2 * size) - 1
        mask = (1 << size) - 1

        if DEBUG_ARITH:
            eprint("BNMULV.L")
            eprint(f"lane_mode | exec_mode | acc_mode | sel | data_type = \
                   1 | {exec_mode} | {acc_mode} | {sel} | {data_type}")
            eprint(f"acc_v = {[hex(acci) for acci in acc_v]}")
            eprint(f'lane_indices = {lane_indices}')
            eprint(f"acc_en = {acc_en}")

        for i in lane_indices:
            prodi = wrs1_v[i] * wrs2_v[i]

            if DEBUG_ARITH:
                eprint(f'i = {i}')
                eprint(f"ai * bi = {hex(wrs1_v[i])} * {hex(wrs2_v[i])} = {hex(prodi)}")
                eprint(f"acci = {hex(acc_v[i])}")

            if acc_en:
                prodi += acc_v[i]
                acc_v[i] = prodi
                if DEBUG_ARITH:
                    eprint(f"acc_mode: prodi = acci = {hex(prodi)}")

            if exec_mode == 0:
                lo = prodi & mask
                hi = (prodi >> size) & mask
                wrd_v[i - 1 if sel else i] = lo
                wrd_v[i if sel else i + 1] = hi
            elif exec_mode == 1:
                wrd_v[i] = prodi & mask
            elif exec_mode == 2:
                wrd_v[i] = (prodi >> size) & mask

            if DEBUG_ARITH:
                eprint(f"wrd_v[{i}] = {hex(wrd_v[i])}")

        result = sum((wrd_v[i] & mask) << (i * size) for i in range(num_lanes))
        state.wdrs.get_reg(self.wrd).write_unsigned(result)

        if acc_en:
            acc_o = sum((acc_v[i] & dmask) << (i * 2 * size) for i in range(num_lanes))
            accl = acc_o & ((1 << 256) - 1)
            acch = (acc_o >> 256) & ((1 << 256) - 1)
            state.wsrs.ACC.write_unsigned(accl)
            state.wsrs.ACCH.write_unsigned(acch)

        if DEBUG_ARITH:
            eprint(f"result at the end = {hex(result)}")
            eprint(f"accl at the end = {hex(accl)}")
            eprint(f"acch at the end = {hex(acch)}")


class BNMULQACC(ACCInsn):
    insn = insn_for_mnemonic('bn.mulqacc', 6)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.zero_acc = op_vals['zero_acc']
        self.wrs1 = op_vals['wrs1']
        self.wrs1_qwsel = op_vals['wrs1_qwsel']
        self.wrs2 = op_vals['wrs2']
        self.wrs2_qwsel = op_vals['wrs2_qwsel']
        self.acc_shift_imm = op_vals['acc_shift_imm']

    def execute(self, state: ACCState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()

        a_qw = extract_quarter_word(a, self.wrs1_qwsel)
        b_qw = extract_quarter_word(b, self.wrs2_qwsel)

        mul_res = a_qw * b_qw

        acc = state.wsrs.ACC.read_unsigned()
        if self.zero_acc:
            acc = 0

        acc += (mul_res << self.acc_shift_imm)

        truncated = acc & ((1 << 256) - 1)

        if DEBUG_ARITH:
            eprint(f"mulqacc {a_qw} * {b_qw} = {truncated}")

        state.wsrs.ACC.write_unsigned(truncated)


class BNMULQACCWO(ACCInsn):
    insn = insn_for_mnemonic('bn.mulqacc.wo', 8)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.zero_acc = op_vals['zero_acc']
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs1_qwsel = op_vals['wrs1_qwsel']
        self.wrs2 = op_vals['wrs2']
        self.wrs2_qwsel = op_vals['wrs2_qwsel']
        self.acc_shift_imm = op_vals['acc_shift_imm']
        self.flag_group = op_vals['flag_group']

    def execute(self, state: ACCState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()

        a_qw = extract_quarter_word(a, self.wrs1_qwsel)
        b_qw = extract_quarter_word(b, self.wrs2_qwsel)

        mul_res = a_qw * b_qw

        acc = state.wsrs.ACC.read_unsigned()
        if self.zero_acc:
            acc = 0

        acc += (mul_res << self.acc_shift_imm)

        truncated = acc & ((1 << 256) - 1)
        state.wdrs.get_reg(self.wrd).write_unsigned(truncated)
        state.wsrs.ACC.write_unsigned(truncated)
        if DEBUG_ARITH:
            eprint(f"mulqacc.wo {a_qw} * {b_qw} = {truncated}")
        state.set_mlz_flags(self.flag_group, truncated)


class BNMULQACCSO(ACCInsn):
    insn = insn_for_mnemonic('bn.mulqacc.so', 9)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.zero_acc = op_vals['zero_acc']
        self.wrd = op_vals['wrd']
        self.wrd_hwsel = op_vals['wrd_hwsel']
        self.wrs1 = op_vals['wrs1']
        self.wrs1_qwsel = op_vals['wrs1_qwsel']
        self.wrs2 = op_vals['wrs2']
        self.wrs2_qwsel = op_vals['wrs2_qwsel']
        self.acc_shift_imm = op_vals['acc_shift_imm']
        self.flag_group = op_vals['flag_group']

    def execute(self, state: ACCState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()

        a_qw = extract_quarter_word(a, self.wrs1_qwsel)
        b_qw = extract_quarter_word(b, self.wrs2_qwsel)

        mul_res = a_qw * b_qw

        acc = state.wsrs.ACC.read_unsigned()
        if self.zero_acc:
            acc = 0

        acc += (mul_res << self.acc_shift_imm)
        truncated = acc & ((1 << 256) - 1)

        if DEBUG_ARITH:
            eprint(f"mulqacc.so {a_qw} * {b_qw} = {truncated}")

        # Split the result into low and high parts
        lo_part = truncated & ((1 << 128) - 1)
        hi_part = truncated >> 128

        # Shift out the low part of the result
        hw_shift = 128 * self.wrd_hwsel
        hw_mask = ((1 << 128) - 1) << hw_shift
        old_wrd = state.wdrs.get_reg(self.wrd).read_unsigned()
        new_wrd = (old_wrd & ~hw_mask) | (lo_part << hw_shift)
        state.wdrs.get_reg(self.wrd).write_unsigned(new_wrd)

        # Write back the high part of the result
        state.wsrs.ACC.write_unsigned(hi_part)

        old_flags = state.csrs.flags[self.flag_group]
        if self.wrd_hwsel:
            new_flags = FlagReg(C=old_flags.C,
                                M=bool((lo_part >> 127) & 1),
                                L=old_flags.L,
                                Z=old_flags.Z and lo_part == 0)
        else:
            new_flags = FlagReg(C=old_flags.C,
                                M=old_flags.M,
                                L=bool(lo_part & 1),
                                Z=lo_part == 0)
        state.set_flags(self.flag_group, new_flags)


class BNSUB(ACCInsn):
    insn = insn_for_mnemonic('bn.sub', 6)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.shift_type = op_vals['shift_type']
        self.shift_bytes = op_vals['shift_bits'] // 8
        self.flag_group = op_vals['flag_group']

    def execute(self, state: ACCState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        b_shifted = logical_byte_shift(b, self.shift_type, self.shift_bytes)

        full_result = a - b_shifted
        mask256 = (1 << 256) - 1
        masked_result = full_result & mask256
        carry_flag = bool((full_result >> 256) & 1)
        flags = FlagReg.mlz_for_result(carry_flag, masked_result)

        if DEBUG_ARITH:
            eprint(f"bn.sub 0x{format(a, '064x')} - 0x{format(b, '064x')} = "
                   f"{format(a-b, '064x')} = {format(masked_result, '064x')}")

        state.wdrs.get_reg(self.wrd).write_unsigned(masked_result)
        state.set_flags(self.flag_group, flags)


class BNSUBB(ACCInsn):
    insn = insn_for_mnemonic('bn.subb', 6)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.shift_type = op_vals['shift_type']
        self.shift_bytes = op_vals['shift_bits'] // 8
        self.flag_group = op_vals['flag_group']

    def execute(self, state: ACCState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        b_shifted = logical_byte_shift(b, self.shift_type, self.shift_bytes)
        borrow = int(state.csrs.flags[self.flag_group].C)

        full_result = a - b_shifted - borrow
        mask256 = (1 << 256) - 1
        masked_result = full_result & mask256
        carry_flag = bool((full_result >> 256) & 1)
        flags = FlagReg.mlz_for_result(carry_flag, masked_result)

        state.wdrs.get_reg(self.wrd).write_unsigned(masked_result)
        state.set_flags(self.flag_group, flags)


class BNSUBI(ACCInsn):
    insn = insn_for_mnemonic('bn.subi', 4)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs = op_vals['wrs']
        self.imm = op_vals['imm']
        self.flag_group = op_vals['flag_group']

    def execute(self, state: ACCState) -> None:
        a = state.wdrs.get_reg(self.wrs).read_unsigned()
        b = self.imm

        full_result = a - b
        mask256 = (1 << 256) - 1
        masked_result = full_result & mask256
        carry_flag = bool((full_result >> 256) & 1)
        flags = FlagReg.mlz_for_result(carry_flag, masked_result)

        state.wdrs.get_reg(self.wrd).write_unsigned(masked_result)
        state.set_flags(self.flag_group, flags)


class BNSUBM(ACCInsn):
    insn = insn_for_mnemonic('bn.subm', 3)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']

    def execute(self, state: ACCState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        mod_val = state.wsrs.MOD.read_unsigned()

        result = a - b
        if result < 0:
            result += mod_val

        result = result & ((1 << 256) - 1)

        if DEBUG_ARITH:
            eprint(f"bn.subm 0x{format(a, '064x')} - 0x{format(b, '064x')} = "
                   f"{format(a-b, '064x')} = {format(result, '064x')}")

        state.wdrs.get_reg(self.wrd).write_unsigned(result)


class BNSUBV(ACCInsn):
    insn = insn_for_mnemonic('bn.subv', 4)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.type = op_vals['type']

    def execute(self, state: ACCState) -> None:
        if not state.EN_PQC:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)

        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        mod_val = state.wsrs.MOD.read_unsigned()
        red = True if self.type > 1 else False
        size = 32 if (self.type % 2 == 0) else 16
        mod_val = extract_sub_word(mod_val, size, 0)
        result = 0

        for i in range(256 // size - 1, -1, -1):
            ai = extract_sub_word(a, size, i)
            bi = extract_sub_word(b, size, i)
            resulti = ai - bi
            if red:
                resulti = cmod_single_subv(resulti, mod_val)
            if DEBUG_ARITH:
                eprint(f"subvm {ai:#x} - {bi:#x} = {ai - bi:#x} = {resulti:#x} | MOD: {mod_val:#x}")
            result <<= size
            result |= (resulti & ((1 << size) - 1))

        result &= ((1 << 256) - 1)
        state.wdrs.get_reg(self.wrd).write_unsigned(result)


class BNAND(ACCInsn):
    insn = insn_for_mnemonic('bn.and', 6)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.shift_type = op_vals['shift_type']
        self.shift_bytes = op_vals['shift_bits'] // 8
        self.flag_group = op_vals['flag_group']

    def execute(self, state: ACCState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        b_shifted = logical_byte_shift(b, self.shift_type, self.shift_bytes)

        result = a & b_shifted

        if DEBUG_ARITH:
            eprint(f"bn.and {format(a,'064x')} & {format(b_shifted, '064x')} = "
                   f"{format(result, '064x')}")

        state.wdrs.get_reg(self.wrd).write_unsigned(result)
        state.set_mlz_flags(self.flag_group, result)


class BNOR(ACCInsn):
    insn = insn_for_mnemonic('bn.or', 6)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.shift_type = op_vals['shift_type']
        self.shift_bytes = op_vals['shift_bits'] // 8
        self.flag_group = op_vals['flag_group']

    def execute(self, state: ACCState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        b_shifted = logical_byte_shift(b, self.shift_type, self.shift_bytes)

        result = a | b_shifted

        if DEBUG_ARITH:
            eprint(f"bn.or {format(a,'064x')} & {format(b_shifted, '064x')} = "
                   f"{format(result, '064x')}")

        state.wdrs.get_reg(self.wrd).write_unsigned(result)
        state.set_mlz_flags(self.flag_group, result)


class BNNOT(ACCInsn):
    insn = insn_for_mnemonic('bn.not', 5)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs = op_vals['wrs']
        self.shift_type = op_vals['shift_type']
        self.shift_bytes = op_vals['shift_bits'] // 8
        self.flag_group = op_vals['flag_group']

    def execute(self, state: ACCState) -> None:
        a = state.wdrs.get_reg(self.wrs).read_unsigned()
        a_shifted = logical_byte_shift(a, self.shift_type, self.shift_bytes)

        result = a_shifted ^ ((1 << 256) - 1)
        state.wdrs.get_reg(self.wrd).write_unsigned(result)
        state.set_mlz_flags(self.flag_group, result)


class BNXOR(ACCInsn):
    insn = insn_for_mnemonic('bn.xor', 6)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.shift_type = op_vals['shift_type']
        self.shift_bytes = op_vals['shift_bits'] // 8
        self.flag_group = op_vals['flag_group']

    def execute(self, state: ACCState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        b_shifted = logical_byte_shift(b, self.shift_type, self.shift_bytes)

        result = a ^ b_shifted
        if DEBUG_ARITH:
            eprint(f"bn.xor 0x{format(a, '064x')} ^ 0x{format(b_shifted, '064x')} = "
                   f"{format(a^b, '064x')} = {format(result, '064x')}")
        state.wdrs.get_reg(self.wrd).write_unsigned(result)
        state.set_mlz_flags(self.flag_group, result)


class BNRSHI(ACCInsn):
    insn = insn_for_mnemonic('bn.rshi', 4)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.imm = op_vals['imm']

    def execute(self, state: ACCState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()

        result = (((a << 256) | b) >> self.imm) & ((1 << 256) - 1)
        if DEBUG_ARITH:
            eprint(f"bn.rshi {format(a, '064x')}, {format(b, '064x')} = {format(result, '064x')}")
        state.wdrs.get_reg(self.wrd).write_unsigned(result)


class BNSHV(ACCInsn):
    insn = insn_for_mnemonic('bn.shv', 6)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.type = op_vals['type']
        self.shift_type = op_vals['shift_type']
        self.shift_bits = op_vals['shift_bits']
        self.shift_arith = op_vals['shift_arith']

    def execute(self, state: ACCState) -> None:
        if not state.EN_PQC:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)

        a = state.wdrs.get_reg(self.wrs1).read_unsigned()

        size = 32 if self.type == 0 else 16

        result = 0

        for i in range((256 - size) // size, -1, -1):
            ai = extract_sub_word(a, size, i)
            ai_shifted = bit_shift(ai, self.shift_type, self.shift_bits, size)

            resulti = ai_shifted
            result = (result << size) | (resulti & ((1 << size) - 1))

        state.wdrs.get_reg(self.wrd).write_unsigned(result)


class BNSEL(ACCInsn):
    insn = insn_for_mnemonic('bn.sel', 5)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.flag_group = op_vals['flag_group']
        self.flag = op_vals['flag']

    def execute(self, state: ACCState) -> None:
        flag_is_set = state.csrs.flags[self.flag_group].get_by_idx(self.flag)
        wrs = self.wrs1 if flag_is_set else self.wrs2
        value = state.wdrs.get_reg(wrs).read_unsigned()
        if DEBUG_ARITH:
            eprint(f"bn.sel {flag_is_set} -> {format(value, '064x')}")
        state.wdrs.get_reg(self.wrd).write_unsigned(value)


class BNCMP(ACCInsn):
    insn = insn_for_mnemonic('bn.cmp', 5)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.shift_type = op_vals['shift_type']
        self.shift_bytes = op_vals['shift_bits'] // 8
        self.flag_group = op_vals['flag_group']

    def execute(self, state: ACCState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        b_shifted = logical_byte_shift(b, self.shift_type, self.shift_bytes)

        full_result = a - b_shifted
        mask256 = (1 << 256) - 1
        masked_result = full_result & mask256
        carry_flag = bool((full_result >> 256) & 1)
        flags = FlagReg.mlz_for_result(carry_flag, masked_result)

        if DEBUG_ARITH:
            eprint(f"bn.cmp {format(a, '064x')}, {format(b_shifted, '064x')} = "
                   f"{format(full_result, '064x')}")
            eprint(f"\tCarry: {carry_flag}")

        state.set_flags(self.flag_group, flags)


class BNCMPB(ACCInsn):
    insn = insn_for_mnemonic('bn.cmpb', 5)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.shift_type = op_vals['shift_type']
        self.shift_bytes = op_vals['shift_bits'] // 8
        self.flag_group = op_vals['flag_group']

    def execute(self, state: ACCState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        b_shifted = logical_byte_shift(b, self.shift_type, self.shift_bytes)
        borrow = int(state.csrs.flags[self.flag_group].C)

        full_result = a - b_shifted - borrow
        mask256 = (1 << 256) - 1
        masked_result = full_result & mask256
        carry_flag = bool((full_result >> 256) & 1)
        flags = FlagReg.mlz_for_result(carry_flag, masked_result)

        state.set_flags(self.flag_group, flags)


class BNLID(ACCInsn):
    insn = insn_for_mnemonic('bn.lid', 5)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grd = op_vals['grd']
        self.grd_inc = op_vals['grd_inc']
        self.offset = op_vals['offset']
        self.grs1 = op_vals['grs1']
        self.grs1_inc = op_vals['grs1_inc']

    def execute(self, state: ACCState) -> Optional[Iterator[None]]:
        # BN.LID executes over two cycles. On the first cycle, we read the base
        # address, compute the load address and check it for correctness,
        # increment any GPRs, then perform the load itself. On the second
        # cycle, update the WDR with the result.

        if self.grs1_inc and self.grd_inc:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)
            return None

        grs1_val = state.gprs.get_reg(self.grs1).read_unsigned()
        addr = (grs1_val + self.offset) & ((1 << 32) - 1)
        grd_val = state.gprs.get_reg(self.grd).read_unsigned()
        if DEBUG_MEM:
            print(f"bn.lid {grs1_val} {self.offset}", file=sys.stderr)
        bad_grs1 = state.gprs.call_stack_err and (self.grs1 == 1)
        bad_grd = state.gprs.call_stack_err and (self.grd == 1)

        saw_err = False

        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            saw_err = True

        if grd_val > 31 and not bad_grd:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)
            saw_err = True

        if not state.dmem.is_valid_256b_addr(addr) and not bad_grs1:
            state.stop_at_end_of_cycle(ErrBits.BAD_DATA_ADDR)
            saw_err = True

        if saw_err:
            return None

        wrd = grd_val & 0x1f
        value = state.dmem.load_u256(addr)

        if self.grd_inc:
            new_grd_val = grd_val + 1
            state.gprs.get_reg(self.grd).write_unsigned(new_grd_val)

        if self.grs1_inc:
            new_grs1_val = (grs1_val + 32) & ((1 << 32) - 1)
            state.gprs.get_reg(self.grs1).write_unsigned(new_grs1_val)

        # Stall for a single cycle for memory to respond
        yield None

        if value is None:
            state.stop_at_end_of_cycle(ErrBits.DMEM_INTG_VIOLATION)
            return None

        if DEBUG_MEM:
            print(f"\t {format(value, '064x')}", file=sys.stderr)

        state.wdrs.get_reg(wrd).write_unsigned(value)
        return None


class BNSID(ACCInsn):
    insn = insn_for_mnemonic('bn.sid', 5)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grs2 = op_vals['grs2']
        self.grs2_inc = op_vals['grs2_inc']
        self.offset = op_vals['offset']
        self.grs1 = op_vals['grs1']
        self.grs1_inc = op_vals['grs1_inc']

    def execute(self, state: ACCState) -> Optional[Iterator[None]]:
        if self.grs1_inc and self.grs2_inc:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)
            return None

        grs1_val = state.gprs.get_reg(self.grs1).read_unsigned()
        addr = (grs1_val + self.offset) & ((1 << 32) - 1)
        grs2_val = state.gprs.get_reg(self.grs2).read_unsigned()

        bad_grs1 = state.gprs.call_stack_err and (self.grs1 == 1)
        bad_grs2 = state.gprs.call_stack_err and (self.grs2 == 1)
        if DEBUG_MEM:
            print(f"bn.sid {grs1_val} {self.offset} <- {grs2_val}", file=sys.stderr)
        saw_err = False

        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            saw_err = True

        if grs2_val > 31 and not bad_grs2:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)
            saw_err = True

        if not state.dmem.is_valid_256b_addr(addr) and not bad_grs1:
            state.stop_at_end_of_cycle(ErrBits.BAD_DATA_ADDR)
            saw_err = True

        if saw_err:
            return None

        if self.grs1_inc:
            new_grs1_val = (grs1_val + 32) & ((1 << 32) - 1)
            state.gprs.get_reg(self.grs1).write_unsigned(new_grs1_val)

        if self.grs2_inc:
            new_grs2_val = grs2_val + 1
            state.gprs.get_reg(self.grs2).write_unsigned(new_grs2_val)

        yield None

        wrs = grs2_val & 0x1f
        wrs_val = state.wdrs.get_reg(wrs).read_unsigned()
        if DEBUG_MEM:
            print(f"\t {format(wrs_val, '064x')}", file=sys.stderr)
        state.dmem.store_u256(addr, wrs_val)
        return None


class BNLD(ACCInsn):
    insn = insn_for_mnemonic('bn.ld', 4)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.offset = op_vals['offset']
        self.grs = op_vals['grs']
        self.grs_inc = op_vals['grs_inc']

    def execute(self, state: ACCState) -> Optional[Iterator[None]]:
        # BN.LD executes over two cycles. On the first cycle, we read the base
        # address, compute the load address and check it for correctness,
        # increment any GPRs, then perform the load itself. On the second
        # cycle, update the WDR with the result.

        grs_val = state.gprs.get_reg(self.grs).read_unsigned()
        addr = (grs_val + self.offset) & ((1 << 32) - 1)
        if DEBUG_MEM:
            print(f"bn.ld {grs_val} {self.offset}", file=sys.stderr)
        bad_grs = state.gprs.call_stack_err and (self.grs == 1)

        saw_err = False

        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            saw_err = True

        if not state.dmem.is_valid_256b_addr(addr) and not bad_grs:
            state.stop_at_end_of_cycle(ErrBits.BAD_DATA_ADDR)
            saw_err = True

        if saw_err:
            return None

        wrd = self.wrd
        value = state.dmem.load_u256(addr)

        if self.grs_inc:
            new_grs_val = (grs_val + 32) & ((1 << 32) - 1)
            state.gprs.get_reg(self.grs).write_unsigned(new_grs_val)

        # Stall for a single cycle for memory to respond
        yield None

        if value is None:
            state.stop_at_end_of_cycle(ErrBits.DMEM_INTG_VIOLATION)
            return None

        if DEBUG_MEM:
            print(f"\t {format(value, '064x')}", file=sys.stderr)

        state.wdrs.get_reg(wrd).write_unsigned(value)
        return None


class BNSD(ACCInsn):
    insn = insn_for_mnemonic('bn.sd', 4)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrs = op_vals['wrs']
        self.offset = op_vals['offset']
        self.grs = op_vals['grs']
        self.grs_inc = op_vals['grs_inc']

    def execute(self, state: ACCState) -> Optional[Iterator[None]]:
        grs_val = state.gprs.get_reg(self.grs).read_unsigned()
        addr = (grs_val + self.offset) & ((1 << 32) - 1)
        wrs_val = state.wdrs.get_reg(self.wrs).read_unsigned()

        bad_grs = state.gprs.call_stack_err and (self.grs == 1)
        if DEBUG_MEM:
            print(f"bn.sd {grs_val} {self.offset} <- {self.wrs}", file=sys.stderr)

        saw_err = False

        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            saw_err = True

        if not state.dmem.is_valid_256b_addr(addr) and not bad_grs:
            state.stop_at_end_of_cycle(ErrBits.BAD_DATA_ADDR)
            saw_err = True

        if saw_err:
            return None

        if self.grs_inc:
            new_grs_val = (grs_val + 32) & ((1 << 32) - 1)
            state.gprs.get_reg(self.grs).write_unsigned(new_grs_val)

        if DEBUG_MEM:
            print(f"\t {format(wrs_val, '064x')}", file=sys.stderr)

        state.dmem.store_u256(addr, wrs_val)
        return None


class BNMOV(ACCInsn):
    insn = insn_for_mnemonic('bn.mov', 2)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs = op_vals['wrs']

    def execute(self, state: ACCState) -> None:
        value = state.wdrs.get_reg(self.wrs).read_unsigned()
        state.wdrs.get_reg(self.wrd).write_unsigned(value)


class BNMOVR(ACCInsn):
    insn = insn_for_mnemonic('bn.movr', 4)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grd = op_vals['grd']
        self.grd_inc = op_vals['grd_inc']
        self.grs = op_vals['grs']
        self.grs_inc = op_vals['grs_inc']

    def execute(self, state: ACCState) -> Optional[Iterator[None]]:
        if DEBUG_ARITH:
            eprint("MOVR")
        if self.grs_inc and self.grd_inc:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)
            return None

        grd_val = state.gprs.get_reg(self.grd).read_unsigned()
        grs_val = state.gprs.get_reg(self.grs).read_unsigned()

        bad_grs = state.gprs.call_stack_err and (self.grs == 1)
        bad_grd = state.gprs.call_stack_err and (self.grd == 1)

        saw_err = False

        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            saw_err = True

        if grd_val > 31 and not bad_grd:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)
            saw_err = True

        if grs_val > 31 and not bad_grs:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)
            saw_err = True

        if saw_err:
            return None

        wrd = grd_val & 0x1f
        wrs = grs_val & 0x1f

        if self.grd_inc:
            new_grd_val = grd_val + 1
            state.gprs.get_reg(self.grd).write_unsigned(new_grd_val)

        if self.grs_inc:
            new_grs_val = grs_val + 1
            state.gprs.get_reg(self.grs).write_unsigned(new_grs_val)

        yield None

        value = state.wdrs.get_reg(wrs).read_unsigned()
        state.wdrs.get_reg(wrd).write_unsigned(value)
        return None


class BNWSRR(ACCInsn):
    insn = insn_for_mnemonic('bn.wsrr', 2)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wsr = op_vals['wsr']

    def execute(self, state: ACCState) -> Optional[Iterator[None]]:
        # The first, and possibly only, cycle of execution.
        if not state.wsrs.check_idx(self.wsr):
            # Invalid WSR index. Stop with an illegal instruction error.
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)
            return None

        if self.wsr == 0x1:
            # A read from RND. If a RND value is not available, request_value()
            # initiates or continues an EDN request and returns False. If a RND
            # value is available, it returns True.
            while not state.wsrs.RND.request_value():
                # There's a pending EDN request. Stall for a cycle.
                yield None

        if self.wsr == 0xA:
            # A read from KMAC_DIGEST0. If a digest value is not available, request_value()
            # initiates or continues the request for the next digest word from KMAC and
            # returns false. If a digest value is available, it returns True.
            while not state.wsrs.KMAC_DIGEST0.request_value_share0():
                # There's a pending KMAC request. Stall for a cycle.
                yield None

        if self.wsr == 0xD:
            # A read from KMAC_DIGEST1. If a digest value is not available, request_value()
            # initiates or continues the request for the next digest word from KMAC and
            # returns false. If a digest value is available, it returns True.
            if not state.kmac._masked_mode:
                state.stop_at_end_of_cycle(ErrBits.KMAC_RECOV_ERROR)
                return

            while not state.wsrs.KMAC_DIGEST1.request_value_share1():
                # There's a pending KMAC request. Stall for a cycle.
                yield None

        # At this point, the WSR is ready. Does it have a valid value? (It
        # might not if this is a sideload key register and keymgr hasn't
        # provided us with a value). If not, fail with a KEY_INVALID error.
        if not state.wsrs.has_value_at_idx(self.wsr):
            state.stop_at_end_of_cycle(ErrBits.KEY_INVALID)
            return None

        # The WSR is ready and has a value. Read it.
        val = state.wsrs.read_at_idx(self.wsr)
        if DEBUG_KMAC:
            eprint(f"read WSR: {format(val, '064x')}")
        state.wdrs.get_reg(self.wrd).write_unsigned(val)
        return None


class BNWSRW(ACCInsn):
    insn = insn_for_mnemonic('bn.wsrw', 2)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wsr = op_vals['wsr']
        self.wrs = op_vals['wrs']

    def execute(self, state: ACCState) -> Optional[Iterator[None]]:
        if DEBUG_KMAC:
            eprint(f"\tRun BNWSRW Address {self.wsr}")
        if not state.wsrs.check_idx(self.wsr):
            # Invalid WSR index. Stop with an illegal instruction error.
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)
            return None

        if self.wsr == 0x9:
            # A write to KMAC_MSG0 might stall, if the register has not yet pushed
            # all its contents to the FIFO connected to the KMAC app interface.
            while not state.wsrs.KMAC_MSG0.request_write():
                if DEBUG_KMAC:
                    eprint("\tBNWSRW to KMAC_MSG0 stall")
                # The following write will cause a deadlock by a full fifo
                if (
                    not state.wsrs.KMAC_MSG1._pending_write_to_app_intf and
                    state.kmac.app_intf_fifo1_ready() and
                    state.kmac._masked_mode
                ):
                    state.stop_at_end_of_cycle(ErrBits.KMAC_FATAL_ERROR)
                    return None
                yield None

        if self.wsr == 0xC:
            # A write to KMAC_MSG1 might stall, if the register has not yet pushed
            # all its contents to the FIFO connected to the KMAC app interface.
            if not state.kmac._masked_mode:
                state.stop_at_end_of_cycle(ErrBits.KMAC_RECOV_ERROR)
                return None
            while not state.wsrs.KMAC_MSG1.request_write():
                if DEBUG_KMAC:
                    eprint("\tBNWSRW to KMAC_MSG1 stall")
                # The following write will cause a deadlock by a full fifo
                if (
                    not state.wsrs.KMAC_MSG0._pending_write_to_app_intf and
                    state.kmac.app_intf_fifo0_ready()
                ):
                    state.stop_at_end_of_cycle(ErrBits.KMAC_FATAL_ERROR)
                    return None
                yield None

        val = state.wdrs.get_reg(self.wrs).read_unsigned()
        if DEBUG_KMAC or DEBUG_ARITH:
            eprint(f"write WSR: {format(val, '064x')}")
        state.wsrs.write_at_idx(self.wsr, val)


class BNTRN(ACCInsn):
    insn = insn_for_mnemonic('bn.trn', 4)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.type = op_vals['type']

    def execute(self, state: ACCState) -> None:
        if not state.EN_PQC:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)

        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()

        # see instruction scheme for details
        mode_2 = True if self.type in [4, 5, 6, 7] else False
        size = None
        if (self.type % 4) == 0:
            size = 16
        elif (self.type % 4) == 1:
            size = 32
        elif (self.type % 4) == 2:
            size = 64
        else:
            size = 128
        result = 0

        if mode_2:
            a >>= size
            b >>= size

        for i in range(256 // size - 2, -1, -2):
            ai = extract_sub_word(a, size, i)
            bi = extract_sub_word(b, size, i)
            result = (result << size) | bi
            result = (result << size) | ai

        result = result & ((1 << 256) - 1)
        if (DEBUG_ARITH):
            eprint(f"trn: {format(a,'064x')}, {format(b,'064x')}, {format(result, '064x')}")
        state.wdrs.get_reg(self.wrd).write_unsigned(result)

class BNGFMUL(ACCInsn):
    '''Vectorized GF(2^4)/GF(2^8) multiply-accumulate (ACC or ACCH accumulator).'''
    insn = insn_for_mnemonic('bn.gfmul', 4)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.type = op_vals['type']

        # type[0] selects the accumulator WSR (0 = ACC, 1 = ACCH); the
        # remaining bits keep the pre-acc_sel layout, shifted up by one.
        self.acc_sel    = (self.type & 0b0000001) >> 0
        t = self.type >> 1
        self.inc        = (t & 0b000001) >> 0
        self.vxv        = (t & 0b000010) >> 1
        self.zero_acc   = (t & 0b000100) >> 2
        self.acc        = (t & 0b001000) >> 3
        self.field_size = (t & 0b110000) >> 4

        if self.field_size == 0:
           self.field_size = 4
        elif self.field_size == 1:
           self.field_size = 8
 
    def execute(self, state: ACCState) -> None:
        if self.acc_sel and not state.EN_PQC:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)

        # acc_sel without .acc lands in an unallocated ("") encoding slot
        if self.acc_sel and not self.acc:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)

        # Get values from source registers
        a_data = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b_data = state.wdrs.get_reg(self.wrs2).read_unsigned()

        # Determine scalar element (for non-vxv modes)
        if not self.vxv:
            # Always read scalar index from mod1
            idx = state.read_csr(0x7d1)
            if self.field_size == 4:
                b_elem = (b_data >> (idx * 4)) & 0xF
            elif self.field_size == 8:
                b_elem = (b_data >> (idx * 8)) & 0xFF
            # Auto-increment mod1 only when .inc is set
            if self.inc:
                if (idx == 63 and self.field_size == 4) or (idx == 31 and self.field_size == 8):
                    # wrap around at respecive index range
                    state.write_csr(0x7d1, 0)
                else:
                    state.write_csr(0x7d1, idx + 1)
        
        
        # Get GF(2^4) reduction polynomial from mod0 CSR (bits [3:0])
        mod0_value = state.read_csr(0x7d0)  # Read mod0 CSR
        gf16_poly = mod0_value & 0xF  # Extract bits [3:0] for GF(2^4)
        gf256_poly = mod0_value & 0xFF  # Extract bits [7:0] for GF(2^8)
        
        # Get the selected accumulator (ACC, or ACCH for .acch forms)
        acc_wsr = state.wsrs.ACCH if self.acc_sel else state.wsrs.ACC
        acc = acc_wsr.read_unsigned()
        if self.zero_acc or not self.acc:
            acc = 0
        
        if self.field_size == 4:
          for i in range(64):  # 64 elements of 4 bits each
              a_elem = (a_data >> (i * 4)) & 0xF

              if self.vxv:
                b_elem = (b_data >> (i * 4)) & 0xF
              
              if a_elem == 0:
                  continue
              
              product = self._gf16_mul(a_elem, b_elem, gf16_poly)
              acc ^= (product << (i * 4))

        if self.field_size == 8:
          for i in range(32):  # 32 elements of 8 bits each
              a_elem = (a_data >> (i * 8)) & 0xFF

              if self.vxv:
                b_elem = (b_data >> (i * 8)) & 0xFF
               
              if a_elem == 0:
                  continue
              
              product = self._gf256_mul(a_elem, b_elem, gf256_poly)
              acc ^= (product << (i * 8))

        
        # Write back to the selected accumulator
        if self.acc:
          acc = acc & ((1 << 256) - 1)
          acc_wsr.write_unsigned(acc)

        state.wdrs.get_reg(self.wrd).write_unsigned(acc)
    
    def _gf16_mul(self, a: int, b: int, poly: int) -> int:
        """
        Perform GF(2^4) multiplication of two elements.
        
        Args:
            a: Element from GF(2^4) (4 bits)
            b: Element from GF(2^4) (4 bits)
            poly: Reduction polynomial (4 bits)
            
        Returns:
            Result in GF(2^4) (4 bits)
        """
        # Both inputs must be 4-bit values
        a &= 0xF
        b &= 0xF
        poly &= 0xF
        
        result = 0
        
        # Process the 4 bits of b
        for i in range(4):
            # If the i-th bit of b is set, XOR a into result
            if (b >> i) & 1:
                result ^= a
                
            # Check if MSB is set
            if a & 0x8:
                # Clear MSB
                a ^= 0x8
                # Shift left by 1
                a <<= 1
                # If the MSB was set, XOR with the reduction polynomial
                a ^= poly
            else:
                # Just shift left
                a <<= 1
                
            # Keep within 4 bits
            a &= 0xF
        
        return result & 0xF

    def _gf256_mul(self, a: int, b: int, poly: int) -> int:
        """
        Perform GF(2^8) multiplication of two elements.
        
        Args:
            a: Element from GF(2^8) (8 bits)
            b: Element from GF(2^8) (8 bits)
            poly: Reduction polynomial (8 bits)
            
        Returns:
            Result in GF(2^8) (8 bits)
        """
        # Both inputs must be 8-bit values
        a &= 0xFF
        b &= 0xFF
        poly &= 0xFF
        
        result = 0
        
        # Process the 8 bits of b
        for i in range(8):
            # If the i-th bit of b is set, XOR a into result
            if (b >> i) & 1:
                result ^= a
                
            # Check if MSB is set before shifting
            if a & 0x80:
                # Clear MSB, shift left by 1, and apply reduction polynomial
                a = ((a << 1) & 0xFF) ^ poly
            else:
                # Just shift left by 1
                a = (a << 1) & 0xFF
        
        return result & 0xFF


# AES S-box and helper functions
AES_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
)

# AES round constants
# Index 0 is not used, Rcon[1] = 0x01, Rcon[2] = 0x02, etc.
AES_RCON = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a
)

def aes_rot_word(word):
    """Rotate a 4-byte word circulant right by one byte."""
    return ((word & 0xFF) << 24 | (word & 0xFFFFFF00) >> 8 )

def aes_sub_word(word):
    """Apply S-box substitution to each byte of a 4-byte word."""
    return (AES_SBOX[(word >> 24) & 0xFF] << 24) | \
           (AES_SBOX[(word >> 16) & 0xFF] << 16) | \
           (AES_SBOX[(word >> 8) & 0xFF] << 8) | \
           AES_SBOX[word & 0xFF]


def aes_sub_bytes(state):
    """Apply S-box substitution to each byte of a 128-bit state."""
    result = 0
    for i in range(16):  # 16 bytes in 128-bit state
        byte_val = (state >> (i * 8)) & 0xFF
        sub_byte = AES_SBOX[byte_val]
        result |= (sub_byte << (i * 8))
    return result


def aes_shift_rows(state):
    """Apply AES ShiftRows transformation to a 128-bit state."""
    # Convert 128-bit state to 4x4 byte matrix
    # In AES, the state is organized as:
    # [ s0  s4  s8  s12 ]
    # [ s1  s5  s9  s13 ]
    # [ s2  s6  s10 s14 ]
    # [ s3  s7  s11 s15 ]
    # where s0 is the least significant byte
    matrix = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(16):
        # Byte i goes to row (i % 4), column (i // 4)
        row = i % 4
        col = i // 4
        matrix[row][col] = (state >> (i * 8)) & 0xFF
    
    # Apply ShiftRows transformation
    # Row 0: no shift
    # Row 1: shift left by 1
    # Row 2: shift left by 2
    # Row 3: shift left by 3
    shifted = [[0 for _ in range(4)] for _ in range(4)]
    for row in range(4):
        for col in range(4):
            shifted[row][col] = matrix[row][(col + row) % 4]
    
    # Convert back to 128-bit state
    result = 0
    for i in range(16):
        row = i % 4
        col = i // 4
        result |= (shifted[row][col] << (i * 8))
    
    return result


def aes_gf_mult(a, b):
    """Multiply two bytes in GF(2^8) using AES irreducible polynomial."""
    result = 0
    for i in range(8):
        if b & 1:
            result ^= a
        high_bit = a & 0x80
        a <<= 1
        if high_bit:
            a ^= 0x1b  # AES irreducible polynomial
        b >>= 1
    return result & 0xFF


def aes_mix_columns(state):
    """Apply AES MixColumns transformation to a 128-bit state."""
    # Convert 128-bit state to 4x4 byte matrix
    # In AES, the state is organized as:
    # [ s0  s4  s8  s12 ]
    # [ s1  s5  s9  s13 ]
    # [ s2  s6  s10 s14 ]
    # [ s3  s7  s11 s15 ]
    # where s0 is the least significant byte
    matrix = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(16):
        # Byte i goes to row (i % 4), column (i // 4)
        row = i % 4
        col = i // 4
        matrix[row][col] = (state >> (i * 8)) & 0xFF
    
    # Apply MixColumns transformation
    mixed = [[0 for _ in range(4)] for _ in range(4)]
    for col in range(4):
        # MixColumns matrix multiplication
        mixed[0][col] = (aes_gf_mult(0x02, matrix[0][col]) ^ 
                        aes_gf_mult(0x03, matrix[1][col]) ^ 
                        matrix[2][col] ^ 
                        matrix[3][col])
        
        mixed[1][col] = (matrix[0][col] ^ 
                        aes_gf_mult(0x02, matrix[1][col]) ^ 
                        aes_gf_mult(0x03, matrix[2][col]) ^ 
                        matrix[3][col])
        
        mixed[2][col] = (matrix[0][col] ^ 
                        matrix[1][col] ^ 
                        aes_gf_mult(0x02, matrix[2][col]) ^ 
                        aes_gf_mult(0x03, matrix[3][col]))
        
        mixed[3][col] = (aes_gf_mult(0x03, matrix[0][col]) ^ 
                        matrix[1][col] ^ 
                        matrix[2][col] ^ 
                        aes_gf_mult(0x02, matrix[3][col]))
    
    # Convert back to 128-bit state
    result = 0
    for i in range(16):
        row = i % 4
        col = i // 4
        result |= (mixed[row][col] << (i * 8))
    
    return result


def aes_swap_counter_endian(value: int) -> int:
    """Byte-swap the upper 32 bits (counter field, bytes 12-15) of a 128-bit value.

    Converts between ACC little-endian WDR layout and the big-endian counter
    field used in AES-CTR mode. The lower 96 bits (nonce/prefix) are unchanged.
    """
    lower96 = value & ((1 << 96) - 1)
    upper32 = (value >> 96) & 0xFFFFFFFF
    b0 = (upper32 >> 0) & 0xFF
    b1 = (upper32 >> 8) & 0xFF
    b2 = (upper32 >> 16) & 0xFF
    b3 = (upper32 >> 24) & 0xFF
    swapped = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    return lower96 | (swapped << 96)


class BNAES128ENCZ(ACCInsn):
    '''AES-128 Zero Round Encryption with Optional CTR Counter-Field Endian Swap.'''
    insn = insn_for_mnemonic('bn.aes128.encz', 4)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.swap_endian = op_vals['swap_endian']
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']

    def execute(self, state: ACCState) -> None:
        plaintext_raw = state.wdrs.get_reg(self.wrs1).read_unsigned()
        plaintext_block1 = plaintext_raw & ((1 << 128) - 1)
        plaintext_block2 = (plaintext_raw >> 128) & ((1 << 128) - 1)

        if self.swap_endian:
            plaintext_block1 = aes_swap_counter_endian(plaintext_block1)
            plaintext_block2 = aes_swap_counter_endian(plaintext_block2)

        key_raw = state.wdrs.get_reg(self.wrs2).read_unsigned()
        key = key_raw & ((1 << 128) - 1)

        result_block1 = plaintext_block1 ^ key
        result_block2 = plaintext_block2 ^ key
        result = result_block1 | (result_block2 << 128)
        state.wdrs.get_reg(self.wrd).write_unsigned(result)


class BNAES128ENCM(ACCInsn):
    '''AES-128 Middle Round Encryption.'''
    insn = insn_for_mnemonic('bn.aes128.encm', 3)
    
    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
    
    def execute(self, state: ACCState) -> None:
        # Read 256-bit data from wrs1 (two 128-bit state blocks)
        state_raw = state.wdrs.get_reg(self.wrs1).read_unsigned()
        state_block1 = (state_raw & ((1 << 128) - 1))
        state_block2 = ((state_raw >> 128) & ((1 << 128) - 1))
        
        # Read 256-bit data from wrs2 (128-bit round key in lower 128 bits)
        key_raw = state.wdrs.get_reg(self.wrs2).read_unsigned()
        round_key = (key_raw & ((1 << 128) - 1))
        
        # Perform AES middle round on first 128-bit state
        # Step 1: SubBytes
        after_sub1 = aes_sub_bytes(state_block1)
        
        # Step 2: ShiftRows
        after_shift1 = aes_shift_rows(after_sub1)
        
        # Step 3: MixColumns
        after_mix1 = aes_mix_columns(after_shift1)
        
        # Step 4: AddRoundKey (XOR with the 128-bit key)
        result_state1 = after_mix1 ^ round_key
        
        # Perform AES middle round on second 128-bit state
        # Step 1: SubBytes
        after_sub2 = aes_sub_bytes(state_block2)
        
        # Step 2: ShiftRows
        after_shift2 = aes_shift_rows(after_sub2)
        
        # Step 3: MixColumns
        after_mix2 = aes_mix_columns(after_shift2)
        
        # Step 4: AddRoundKey (XOR with the same 128-bit key)
        result_state2 = after_mix2 ^ round_key
        
        # Combine both states back into 256-bit result
        result = result_state1 | (result_state2 << 128)
        
        # Write combined result to destination register
        state.wdrs.get_reg(self.wrd).write_unsigned(result)


class BNAES128ENCF(ACCInsn):
    '''AES-128 Final Round Encryption.'''
    insn = insn_for_mnemonic('bn.aes128.encf', 3)
    
    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
    
    def execute(self, state: ACCState) -> None:
        # Read 256-bit data from wrs1 (two 128-bit AES states)
        state_raw = state.wdrs.get_reg(self.wrs1).read_unsigned()
        state_val1 = (state_raw & ((1 << 128) - 1))
        state_val2 = ((state_raw >> 128) & ((1 << 128) - 1))
        
        # Read 128-bit key from wrs2 (only low 128 bits contain the key)
        key_raw = state.wdrs.get_reg(self.wrs2).read_unsigned()
        key = (key_raw & ((1 << 128) - 1))
        
        # Perform AES final round on first 128-bit state
        # Step 1: SubBytes
        after_sub1 = aes_sub_bytes(state_val1)
        
        # Step 2: ShiftRows
        after_shift1 = aes_shift_rows(after_sub1)
        
        # Step 3: AddRoundKey (XOR with the 128-bit key) - NO MixColumns in final round
        result_state1 = after_shift1 ^ key
        
        # Perform AES final round on second 128-bit state
        # Step 1: SubBytes
        after_sub2 = aes_sub_bytes(state_val2)
        
        # Step 2: ShiftRows
        after_shift2 = aes_shift_rows(after_sub2)
        
        # Step 3: AddRoundKey (XOR with the same 128-bit key) - NO MixColumns in final round
        result_state2 = after_shift2 ^ key
        
        # Combine both states back into 256-bit result
        result = result_state1 | (result_state2 << 128)
        
        # Write combined result to destination register
        state.wdrs.get_reg(self.wrd).write_unsigned(result)


class BNAES128KF(ACCInsn):
    '''AES-128 Key Schedule Forward.'''
    insn = insn_for_mnemonic('bn.aes128.kf', 3)
    
    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs = op_vals['wrs']
        self.imm = op_vals['imm']
    
    def execute(self, state: ACCState) -> None:
        # Read current round key from wrs (128-bit key)
        current_key_raw = state.wdrs.get_reg(self.wrs).read_unsigned()
        current_key = (current_key_raw & ((1 << 128) - 1))
        
        # Get round number from immediate
        round_num = self.imm
        
        # Extract key as 4 32-bit words
        w0 = (current_key >> 0) & 0xFFFFFFFF
        w1 = (current_key >> 32) & 0xFFFFFFFF
        w2 = (current_key >> 64) & 0xFFFFFFFF
        w3 = (current_key >> 96) & 0xFFFFFFFF
        
        # AES key schedule forward: generate next 4 words
        # The immediate represents the round number (1-10 for AES-128)
        # We generate the next round key using Rcon[round_num]
        # w4 = w0 ^ SubWord(RotWord(w3)) ^ Rcon[round_num]
        # w5 = w1 ^ w4
        # w6 = w2 ^ w5
        # w7 = w3 ^ w6
        
        if 1 <= round_num <= 10:  # AES-128 has 10 rounds (1-10)
            temp = aes_rot_word(w3)
            temp = aes_sub_word(temp)
            # Use Rcon[round_num] for the specified round
            w4 = w0 ^ temp ^ (AES_RCON[round_num])
            w5 = w1 ^ w4
            w6 = w2 ^ w5
            w7 = w3 ^ w6
            
            # Combine new key words back into 128-bit result
            next_key = (w7 << 96) | (w6 << 64) | (w5 << 32) | w4
        else:
            # Invalid round number, return original key
            next_key = current_key
        
        # Write next round key to destination register
        state.wdrs.get_reg(self.wrd).write_unsigned(next_key)




INSN_CLASSES = [
    ADD, ADDI, LUI, SUB, SLL, SLLI, SRL, SRLI, SRA, SRAI,
    AND, ANDI, OR, ORI, XOR, XORI,
    LW, SW,
    BEQ, BNE, JAL, JALR,
    CSRRS, CSRRW,
    ECALL,
    LOOP, LOOPI,

    BNADD, BNADDC, BNADDI, BNADDM, BNADDV,
    BNMULV, BNMULVL,
    BNMULQACC, BNMULQACCWO, BNMULQACCSO,
    BNSUB, BNSUBB, BNSUBI, BNSUBM, BNSUBV,
    BNAND, BNOR, BNNOT, BNXOR,
    BNSHV,
    BNRSHI,
    BNSEL,
    BNCMP, BNCMPB,
    BNLID, BNSID,
    BNLD, BNSD,
    BNMOV, BNMOVR, BNTRN,
    BNWSRR, BNWSRW, BNGFMUL,
    BNAES128ENCZ, BNAES128ENCM, BNAES128ENCF, BNAES128KF
]
