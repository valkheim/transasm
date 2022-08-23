import ctypes
import random
from typing import Optional

import capstone

from transasm import types
from transasm.config import config


def get_x86_64_instruction(code: bytes) -> capstone.CsInsn:
    return next(config.md.disasm(code, 0))


def get_x86_instruction(code: bytes) -> capstone.CsInsn:
    return next(config.md_x86.disasm(code, 0))


def get_instruction(code: bytes) -> capstone.CsInsn:
    if config.md_mode == capstone.CS_MODE_64:
        return get_x86_64_instruction(code)
    else:
        return get_x86_instruction(code)


def yield_x86_64_instructions(code: bytes):
    for i in config.md.disasm(code, 0):
        yield i


def yield_x86_instructions(code: bytes):
    for i in config.md_x86.disasm(code, 0):
        yield i


def yield_instructions(code: bytes):
    if config.md_mode == capstone.CS_MODE_64:
        yield from yield_x86_64_instructions(code)
    else:
        yield from yield_x86_instructions(code)


def has_register_operands(insn: capstone.CsInsn) -> bool:
    try:
        return all(
            [
                len(insn.operands) == 2,
                insn.operands[0].type == capstone.x86.X86_OP_REG,
                insn.operands[1].type == capstone.x86.X86_OP_REG,
            ]
        )
    except BaseException:
        return False


def swap_reg_rm_in_modrm(modrm: types.ModRM) -> types.ModRM:
    swapped = modrm
    swapped.s.r_x, swapped.s.r_m = swapped.s.r_m, swapped.s.r_x
    return swapped


def swap_base_index_in_sib(sib: types.SIB) -> types.SIB:
    swapped = sib
    swapped.s.base, swapped.s.index = swapped.s.index, swapped.s.base
    return swapped


def get_ev_gv_equivalent_opcode_for_reg_ops(
    opcode: ctypes.c_uint8,
) -> Optional[ctypes.c_uint8]:
    return {
        # add
        0x01: 0x03,
        0x03: 0x01,
        # adc
        0x11: 0x13,
        0x13: 0x11,
        # and
        0x21: 0x23,
        0x23: 0x21,
        # xor
        0x31: 0x33,
        0x33: 0x31,
        # or
        0x09: 0x0B,
        0x0B: 0x09,
        # sbb
        0x19: 0x1B,
        0x1B: 0x19,
        # sub
        0x29: 0x2B,
        0x2B: 0x29,
        # cmp
        0x39: 0x3B,
        0x3B: 0x39,
        # mov
        0x89: 0x8B,
        0x8B: 0x89,
    }.get(opcode)


def has_ev_gv_equivalent_opcode_for_reg_ops(opcode: ctypes.c_uint8) -> bool:
    return get_ev_gv_equivalent_opcode_for_reg_ops(opcode) is not None


def has_ev_gv_opcode(opcode: ctypes.c_uint8) -> bool:
    return opcode in (
        0x01,  # add
        0x11,  # adc
        0x21,  # and
        0x31,  # xor
        0x85,  # test
        0x87,  # xchg
        0x09,  # or
        0x19,  # sbb
        0x29,  # sub
        0x39,  # cmp
        0x89,  # mov
    )


def get_acc_equivalent_opcode_for_imm_op_for_mod_reg_reg(
    opcode: ctypes.c_uint8, modrm
) -> Optional[ctypes.c_uint8]:
    if modrm.s.r_x == 0b000:  # add
        return {
            # add al
            0x80: 0x04,
            # add eax/rax
            0x81: random.choice([0x05, 0x83]),
            0x83: random.choice([0x05, 0x81]),
        }.get(opcode)
    elif modrm.s.r_x == 0b001:  # or
        return {
            0x80: 0x0C,
            0x81: random.choice([0x0D, 0x83]),
            0x83: random.choice([0x0D, 0x81]),
        }.get(opcode)
    elif modrm.s.r_x == 0b010:  # adc
        return {
            0x80: 0x14,
            0x81: random.choice([0x15, 0x83]),
            0x83: random.choice([0x15, 0x81]),
        }.get(opcode)
    elif modrm.s.r_x == 0b011:  # sbb
        return {
            0x80: 0x1C,
            0x81: random.choice([0x1D, 0x83]),
            0x83: random.choice([0x1D, 0x81]),
        }.get(opcode)
    elif modrm.s.r_x == 0b100:  # and
        return {
            0x80: 0x24,
            0x81: random.choice([0x25, 0x83]),
            0x83: random.choice([0x25, 0x81]),
        }.get(opcode)
    elif modrm.s.r_x == 0b101:  # sub
        return {
            0x80: 0x2C,
            0x81: random.choice([0x2D, 0x83]),
            0x83: random.choice([0x2D, 0x81]),
        }.get(opcode)
    elif modrm.s.r_x == 0b110:  # xor
        return {
            0x80: 0x34,
            0x81: random.choice([0x35, 0x83]),
            0x83: random.choice([0x35, 0x81]),
        }.get(opcode)
    elif modrm.s.r_x == 0b111:  # cmp
        return {
            0x80: 0x3C,
            0x81: random.choice([0x3D, 0x83]),
            0x83: random.choice([0x3D, 0x81]),
        }.get(opcode)

    return None


def get_acc_equivalent_opcode_for_imm_op_for_mod_reg_imm(
    opcode: ctypes.c_uint8, modrm
) -> Optional[ctypes.c_uint8]:
    return {
        0x04: 0x80,  # add al
        0x05: random.choice([0x81, 0x83]),  # add eax/rax
        0x0C: 0x80,  # or al
        0x0D: random.choice([0x81, 0x83]),  # or eax/rax
        0x14: 0x80,  # adc al
        0x15: random.choice([0x81, 0x83]),  # adc eax/rax
        0x1C: 0x80,  # sbb al
        0x1D: random.choice([0x81, 0x83]),  # sbb eax/rax
        0x24: 0x80,  # and al
        0x25: random.choice([0x81, 0x83]),  # and eax/rax
        0x2C: 0x80,  # sub al
        0x2D: random.choice([0x81, 0x83]),  # sub eax/rax
        0x34: 0x80,  # xor al
        0x35: random.choice([0x81, 0x83]),  # xor eax/rax
        0x3C: 0x80,  # cmp al
        0x3D: random.choice([0x81, 0x83]),  # cmp eax/rax
    }.get(opcode)


def get_acc_equivalent_opcode_for_imm_op(
    opcode: ctypes.c_uint8, modrm
) -> Optional[ctypes.c_uint8]:
    # non deterministic as some opcodes can translate to more than a single equivalent opcode
    if modrm.s.mod == 0b11:
        return get_acc_equivalent_opcode_for_imm_op_for_mod_reg_reg(
            opcode, modrm
        )

    elif modrm.s.mod == 0b00:
        return get_acc_equivalent_opcode_for_imm_op_for_mod_reg_imm(
            opcode, modrm
        )


def get_modrm_r_x_for_imm_op(opcode):
    return {
        # add
        0x04: 0b000,
        0x05: 0b000,
        # or
        0x0C: 0b001,
        0x0D: 0b001,
        # adc
        0x14: 0b010,
        0x15: 0b010,
        # sbb
        0x1C: 0b011,
        0x1D: 0b011,
        # and
        0x24: 0b100,
        0x25: 0b100,
        # sub
        0x2C: 0b101,
        0x2D: 0b101,
        # xor
        0x34: 0b110,
        0x35: 0b110,
        # cmp
        0x3C: 0b111,
        0x3D: 0b111,
    }.get(opcode)


def set_bit(value: int, bit: int) -> int:
    return value | (1 << bit)


def clear_bit(value: int, bit: int) -> int:
    return value & ~(1 << bit)


def is_bit_set(value: int, bit: int) -> bool:
    return value & (1 << bit) != 0


def has_rex_prefix(insn: capstone.CsInsn) -> bool:
    return 0x40 <= insn.rex <= 0x4F
