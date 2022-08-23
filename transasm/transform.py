import random
from typing import Optional

import capstone

from transasm import types, utils
from transasm.config import config


def try_transform_gv_ev_instruction_for_reg_ops(
    code: bytes,
) -> Optional[bytes]:
    insn = utils.get_x86_64_instruction(code)
    if not utils.has_register_operands(insn):
        return None

    if not utils.has_ev_gv_equivalent_opcode_for_reg_ops(insn.opcode[0]):
        return None

    transform = insn.bytes
    # Update opcode byte (before modrm)
    transform[
        insn.modrm_offset - 1
    ] = utils.get_ev_gv_equivalent_opcode_for_reg_ops(insn.opcode[0])
    # Update modrm byte
    transform[insn.modrm_offset] = utils.swap_reg_rm_in_modrm(
        types.ModRM(insn.modrm)
    ).v
    return bytes(transform)


def try_transform_zero_scale_sib(code: bytes) -> Optional[bytes]:
    insn = utils.get_x86_64_instruction(code)
    sib = types.SIB(insn.sib)
    if sib.v == 0:
        return None

    if sib.s.scale != 0:  # Factor 1
        return None

    transform = insn.bytes
    # Update sib byte
    transform[insn.modrm_offset + 1] = utils.swap_base_index_in_sib(sib).v
    return bytes(transform)


def try_transform_duplicate_opcode_extensions(code: bytes) -> Optional[bytes]:
    insn = utils.get_x86_64_instruction(code)
    transform = None
    if (
        insn.opcode[0] == 0xF6 or insn.opcode[0] == 0xF7  # group 3 Eb
    ):  # group 3 Ev
        transform = insn.bytes
        modrm = types.ModRM(insn.modrm)
        if all(
            [
                not utils.is_bit_set(modrm.s.r_x, 0),
                not utils.is_bit_set(modrm.s.r_x, 1),
                not utils.is_bit_set(modrm.s.r_x, 2),
            ]
        ):  # ModR/M: xx000xxx
            modrm.s.r_x = utils.set_bit(modrm.s.r_x, 0)
            transform[insn.modrm_offset] = modrm.v
        elif all(
            [
                utils.is_bit_set(modrm.s.r_x, 0),
                not utils.is_bit_set(modrm.s.r_x, 1),
                not utils.is_bit_set(modrm.s.r_x, 2),
            ]
        ):  # ModR/M: xx001xxx
            modrm.s.r_x = utils.clear_bit(modrm.s.r_x, 0)
            transform[insn.modrm_offset] = modrm.v

    return transform


def try_transform_duplicate_x86_opcodes(code: bytes) -> Optional[bytes]:
    insn = utils.get_x86_instruction(code)
    transform = insn.bytes
    if insn.opcode[0] == 0x80:
        transform[insn.modrm_offset - 1] = 0x82
    elif insn.opcode[0] == 0x82:
        transform[insn.modrm_offset - 1] = 0x80

    return transform


def try_transform_imm_operand_size(code: bytes) -> Optional[bytes]:
    insn = utils.get_instruction(code)
    if len(insn.operands) != 2:
        return None

    if insn.operands[1].type != capstone.x86.X86_OP_IMM:
        return None

    # capstone gives the same operands[1].size for 83C001 and 81C001000000 :(
    transform = insn.bytes
    if (
        insn.opcode[0] == 0x81
        and insn.imm_size == 4
        and insn.operands[1].value.imm <= 0xFF
    ):  # 81C001000000 ; add eax, 1
        transform[insn.modrm_offset - 1] = 0x83
        transform = transform[:-3]

    elif insn.opcode[0] == 0x83 and insn.operands[1].value.imm <= 0xFF:
        transform[insn.modrm_offset - 1] = 0x81
        transform += b"\x00" * 3

    return transform


def try_transform_acc_with_imm8_on_16_bit_mode(
    insn, opcode, opcode_alt, has_rax
) -> bytes:
    if opcode_alt in (
        0x80,
        0x83,
    ):
        opsize = 1
    else:
        opsize = 4

    transform = bytes()
    if has_rax:
        transform += insn.rex.to_bytes(1, byteorder="little")

    transform += opcode_alt.to_bytes(1, byteorder="little")
    # Craft ModRM/reg part, see 1-byte opcode and opcode groups tables
    if opcode in (
        0x04,
        0x05,
        0x0C,
        0x0D,
        0x14,
        0x15,
        0x1C,
        0x1D,
        0x24,
        0x25,
        0x2C,
        0x2D,
        0x34,
        0x35,
        0x3C,
        0x3D,
    ):
        modrm = types.ModRM(0b11000000)  # mod = reg
        modrm.s.r_x = utils.get_modrm_r_x_for_imm_op(opcode)
        transform += int(modrm.v).to_bytes(1, byteorder="little")

    transform += int(insn.operands[1].value.imm).to_bytes(
        opsize, byteorder="little"
    )
    return transform


def try_transform_acc_with_imm8_on_32_64_bit_mode(
    insn, opcode_alt, modrm, has_rax
) -> bytes:
    if opcode_alt in (
        0x04,
        0x0C,
        0x14,
        0x1C,
        0x24,
        0x2C,
        0x34,
        0x3C,
        0x83,
    ):
        opsize = 1
    else:
        opsize = 4

    transform = bytes()
    if has_rax:
        transform += insn.rex.to_bytes(1, byteorder="little")

    transform += opcode_alt.to_bytes(1, byteorder="little")
    # Copy ModR/M if required
    if opcode_alt not in (
        0x04,
        0x05,
        0x0C,
        0x0D,
        0x14,
        0x15,
        0x1C,
        0x1D,
        0x24,
        0x25,
        0x2C,
        0x2D,
        0x34,
        0x35,
        0x3C,
        0x3D,
    ):
        transform += int(modrm.v).to_bytes(1, byteorder="little")

    transform += int(insn.operands[1].value.imm).to_bytes(
        opsize, byteorder="little"
    )
    return transform


def try_transform_acc_with_imm8(code: bytes) -> Optional[bytes]:
    insn = utils.get_instruction(code)
    if not len(insn.operands) == 2:
        return None

    if not all(
        [
            insn.operands[0].type == capstone.x86.X86_OP_REG,
            insn.operands[0].reg
            in (
                capstone.x86.X86_REG_AL,
                capstone.x86.X86_REG_EAX,
                capstone.x86.X86_REG_RAX,
            ),
            insn.operands[1].type == capstone.x86.X86_OP_IMM,
            insn.operands[1].value.imm <= 0xFF,  # this range can be enlarged
        ]
    ):
        return None

    opcode = insn.opcode[0]
    modrm = types.ModRM(insn.modrm)
    has_rax = insn.rex != 0
    opcode_alt = utils.get_acc_equivalent_opcode_for_imm_op(opcode, modrm)
    if opcode_alt is None:
        return None

    # Handle 16-bit mode
    if opcode & 0xF in (0x4, 0x5, 0xC, 0xD):
        return try_transform_acc_with_imm8_on_16_bit_mode(
            insn, opcode, opcode_alt, has_rax
        )

    # Handle 32/64-bit mode
    elif opcode & 0xF0 == 0x80:
        return try_transform_acc_with_imm8_on_32_64_bit_mode(
            insn, opcode_alt, modrm, has_rax
        )

    return None


def get_random_disp_size(insn) -> int:
    modrm = types.ModRM(insn.modrm)
    if modrm.s.mod == 0b11:
        return None
    elif modrm.s.mod == 0b00:  # 0-byte disp
        disp_choices = [1, 4]
    elif modrm.s.mod == 0b01:  # 1-byte disp
        disp_choices = [4]
        if 0x00 == insn.disp:
            disp_choices += [0]
    elif modrm.s.mod == 0b10:  # 4-bytes disp
        disp_choices = []
        if 0x00 == insn.disp:
            disp_choices += [0]
        if 0x00 <= insn.disp <= 0xFF:
            disp_choices += [1]

    return random.choice(disp_choices)


def try_transform_gv_ev_instruction_using_displ(
    code: bytes,
) -> Optional[bytes]:
    insn = utils.get_instruction(code)
    opcode = insn.opcode[0]
    if not utils.has_ev_gv_opcode(opcode):
        return None

    modrm = types.ModRM(insn.modrm)
    disp_size = get_random_disp_size(insn)
    transform = insn.bytes
    transform = transform[: insn.modrm_offset]
    # Add ModR/M
    new_modrm = modrm
    if disp_size == 0:
        new_modrm.s.mod = 0b00
    elif disp_size == 1:
        new_modrm.s.mod = 0b01
    elif disp_size == 4:
        new_modrm.s.mod = 0b10

    transform += modrm.v.to_bytes(1, byteorder="little")
    transform += insn.disp.to_bytes(disp_size, byteorder="little")
    return bytes(transform)


def try_transform_using_sib(code: bytes, insn) -> Optional[bytes]:
    # TODO: support adding SIB byte (with ModR/M update)
    if insn.sib == 0x00:
        return None

    sib = types.SIB(insn.sib)
    if sib.s.scale == 0b00:
        sib.s.scale = random.choice([0b01, 0b10, 0b11])
    elif sib.s.scale == 0b01:
        sib.s.scale = random.choice([0b00, 0b10, 0b11])
    elif sib.s.scale == 0b10:
        sib.s.scale = random.choice([0b00, 0b01, 0b11])

    transform = insn.bytes
    transform[insn.modrm_offset + 1] = sib.v
    return bytes(transform)


def try_transform_x86_using_sib(code: bytes) -> Optional[bytes]:
    insn = utils.get_x86_instruction(code)
    return try_transform_using_sib(code, insn)


def try_transform_x86_64_using_sib(code: bytes) -> Optional[bytes]:
    insn = utils.get_x86_64_instruction(code)
    return try_transform_using_sib(code, insn)


def try_transform_zeroing(code: bytes) -> Optional[bytes]:
    insn = utils.get_instruction(code)
    modrm = types.ModRM(insn.modrm)
    opcode = insn.opcode[0]
    transform = insn.bytes
    if all(
        [modrm.s.mod == 0b11, modrm.s.r_x == modrm.s.r_m]
    ):  # <mnem> reg, reg
        if opcode == 0x31:  # xor reg, reg
            transform[insn.modrm_offset - 1] = 0x29
        elif opcode == 0x29:  # sub reg, reg
            transform[insn.modrm_offset - 1] = 0x31

        return bytes(transform)

    return None


def transform(code: bytes) -> Optional[bytes]:
    if config.md_mode == capstone.CS_MODE_64:
        transformers = [
            try_transform_gv_ev_instruction_for_reg_ops,
            try_transform_zero_scale_sib,
            try_transform_duplicate_opcode_extensions,
            try_transform_imm_operand_size,
            try_transform_acc_with_imm8,
            try_transform_gv_ev_instruction_using_displ,
            try_transform_x86_64_using_sib,
        ]
    else:
        transformers = [
            try_transform_gv_ev_instruction_for_reg_ops,
            try_transform_zero_scale_sib,
            try_transform_duplicate_opcode_extensions,
            try_transform_duplicate_x86_opcodes,
            try_transform_imm_operand_size,
            try_transform_acc_with_imm8,
            try_transform_gv_ev_instruction_using_displ,
            try_transform_x86_using_sib,
        ]

    transformed_bytes = b""
    for insn in utils.yield_instructions(code):
        transformed = insn.bytes
        for transformer in transformers:
            new_data = transformer(transformed)
            if new_data is not None:
                transformed = new_data

        if insn.bytes != transformed:
            new_insn = utils.get_instruction(transformed)
            print(
                "<<",
                " ".join([f"{byte:02x}" for byte in insn.bytes]),
                "->",
                insn.mnemonic,
                insn.op_str,
            )
            print(
                ">>",
                " ".join([f"{byte:02x}" for byte in new_insn.bytes]),
                "->",
                new_insn.mnemonic,
                new_insn.op_str,
            )

        transformed_bytes += transformed

    return transformed_bytes
