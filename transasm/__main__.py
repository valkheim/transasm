#       888                                                                  888
#       888                                                                  888
#       888                                                                  888
#   .d88888  .d88b.  88888b.d88b.   .d88b.       88888b.d88b.   .d88b.   .d88888  .d88b.
#  d88" 888 d8P  Y8b 888 "888 "88b d88""88b      888 "888 "88b d88""88b d88" 888 d8P  Y8b
#  888  888 88888888 888  888  888 888  888      888  888  888 888  888 888  888 88888888
#  Y88b 888 Y8b.     888  888  888 Y88..88P      888  888  888 Y88..88P Y88b 888 Y8b.
#   "Y88888  "Y8888  888  888  888  "Y88P"       888  888  888  "Y88P"   "Y88888  "Y8888

import os

import capstone
import keystone

from transasm import transform, utils


def assemble(ks, asm_string):
    code = bytearray()
    try:
        encoding, _ = ks.asm(asm_string)
        code += bytearray(encoding)

    except keystone.keystone.KsError:
        print(f"Cannot assemble {asm_string}")
        return None

    return bytes(code)


def as_hex(xs) -> str:
    return " ".join([f"{x:#04x}" for x in xs])


def show_insn(insn):
    line = [f"mnemonic:     {insn.mnemonic} {insn.op_str}"]
    code = " ".join([f"{b:#04x}" for b in insn.bytes])
    line += [f"bytes:        {code}"]
    line += [f"prefix:       {as_hex(insn.prefix)}"]
    line += [f"opcode:       {as_hex(insn.opcode)}"]
    line += [f"rex:          {insn.rex:#04x}"]
    modrm = bin(insn.modrm)[2:].zfill(8)
    modrm_line = f"modrm:        {insn.modrm:#04x} "
    modrm_line += f"(mod: 0b{modrm[0:2]}) "
    modrm_line += f"(reg: 0b{modrm[2:5]}) "
    modrm_line += f"(rm: 0b{modrm[5:8]})"
    line += [modrm_line]
    line += [f"modrm offset: {insn.modrm_offset:#04x}"]
    line += [f"disp:         {insn.disp:#04x}"]
    sib = bin(insn.sib)[2:].zfill(8)
    sib_line = f"sib:          {insn.sib:#04x} "
    sib_line += f"(scale: 0b{sib[0:2]}) "
    sib_line += f"(index: 0b{sib[2:5]}) "
    sib_line += f"(base: 0b{sib[5:8]}) "
    line += [sib_line]
    print(os.linesep.join(line))


def find_alt(code):
    transformers = [
        transform.try_transform_gv_ev_instruction_for_reg_ops,
        transform.try_transform_zero_scale_sib,
        transform.try_transform_duplicate_opcode_extensions,
        transform.try_transform_imm_operand_size,
        transform.try_transform_acc_with_imm8,
        transform.try_transform_gv_ev_instruction_using_displ,
        transform.try_transform_x86_64_using_sib,
    ]
    insn = next(utils.yield_instructions(code))
    transformed = insn.bytes
    for transformer in transformers:
        new_data = transformer(transformed)
        if new_data is not None:
            transformed = new_data

    if insn.bytes == transformed:
        print("no alt found")
        return

    new_insn = utils.get_instruction(transformed)
    print("== input:")
    show_insn(insn)
    print()
    print("== alternative:")
    show_insn(new_insn)
    print()


def main() -> None:
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    ks.syntax = keystone.KS_OPT_SYNTAX_INTEL
    while "I'm reading user input":
        try:
            code = assemble(ks, input("> "))
            find_alt(code)
        except (EOFError, SystemExit):  # Ctrl+D
            break
        except KeyboardInterrupt:  # Ctrl+C
            print()
        except:
            continue
