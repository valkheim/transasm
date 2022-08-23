import unittest

import capstone

from transasm import types, utils


class TestUtils(unittest.TestCase):
    def test_get_x86_64_instruction(self) -> None:
        self.assertEqual(
            utils.get_x86_64_instruction(b"\x48\x01\xd8").bytes,
            b"\x48\x01\xd8",
        )  # add rax, rbx
        self.assertEqual(
            utils.get_x86_64_instruction(b"\x01\xd8").bytes, b"\x01\xd8"
        )  # add eax, ebx

    def test_get_x86_instruction(self) -> None:
        self.assertEqual(
            utils.get_x86_instruction(b"\x01\xd8").bytes, b"\x01\xd8"
        )  # add eax, ebx

    def test_yield_x86_64_instructions(self) -> None:
        instructions = list(
            utils.yield_x86_64_instructions(
                b"\x48\xff\xc0" b"\x48\xff\xc3"  # inc rax  # inc rbx
            )
        )
        self.assertEqual(len(instructions), 2)
        self.assertEqual(type(instructions[0]), capstone.CsInsn)
        self.assertEqual(instructions[0].bytes, b"\x48\xff\xc0")
        self.assertEqual(instructions[1].bytes, b"\x48\xff\xc3")

    def test_has_register_operands(self) -> None:
        self.assertTrue(
            utils.has_register_operands(
                utils.get_x86_64_instruction(b"\x01\xd8")
            )
        )  # add eax, ebx

        self.assertFalse(
            utils.has_register_operands(
                utils.get_x86_64_instruction(b"\x48\xff\xc0")
            )
        )  # inc rax
        self.assertFalse(
            utils.has_register_operands(
                utils.get_x86_64_instruction(b"\x48\x83\xc0\x10")
            )
        )  # add rax, 0x10

    def test_swap_reg_rm_in_modrm(self) -> None:
        self.assertEqual(
            utils.swap_reg_rm_in_modrm(types.ModRM(0xC3)), types.ModRM(0xD8)
        )
        self.assertEqual(
            utils.swap_reg_rm_in_modrm(types.ModRM(0xD8)), types.ModRM(0xC3)
        )

    def test_swap_base_index_in_sib(self) -> None:
        self.assertEqual(
            utils.swap_base_index_in_sib(types.SIB(0x0B)), types.SIB(0x19)
        )
        self.assertEqual(
            utils.swap_base_index_in_sib(types.SIB(0x19)), types.SIB(0x0B)
        )

    def test_get_ev_gv_equivalent_opcode_for_reg_ops(self) -> None:
        self.assertEqual(
            utils.get_ev_gv_equivalent_opcode_for_reg_ops(0x01), 0x03
        )
        self.assertEqual(
            utils.get_ev_gv_equivalent_opcode_for_reg_ops(0x03), 0x01
        )
        self.assertEqual(
            utils.get_ev_gv_equivalent_opcode_for_reg_ops(0xFF), None
        )

    def test_has_ev_gv_equivalent_opcode_for_reg_ops(self) -> None:
        test_data = [
            ("add dword ptr [eax], eax", b"\x67\x01\x00"),
            ("adc dword ptr [eax], eax", b"\x67\x11\x00"),
            ("adc eax, ebx", b"\x11\xd8"),
            ("and dword ptr [eax], eax", b"\x67\x21\x00"),
            ("xor dword ptr [eax], eax", b"\x67\x31\x00"),
            ("test dword ptr [eax], eax", b"\x67\x85\x00"),
            ("xchg dword ptr [eax], eax", b"\x67\x87\x00"),
            ("or dword ptr [eax], eax", b"\x67\x09\x00"),
            ("sbb dword ptr [eax], eax", b"\x67\x19\x00"),
            ("sub dword ptr [eax], eax", b"\x67\x29\x00"),
            ("cmp dword ptr [eax], eax", b"\x67\x39\x00"),
            ("mov dword ptr [eax], eax", b"\x67\x89\x00"),
        ]
        for literal, code in test_data:
            insn = utils.get_x86_64_instruction(code)
            self.assertEqual(f"{insn.mnemonic} {insn.op_str}", literal)
            opcode = insn.opcode[0]
            self.assertTrue(utils.has_ev_gv_opcode(opcode))

    def test_set_bit(self) -> None:
        self.assertEqual(utils.set_bit(0b00, 0), 0b01)
        self.assertEqual(utils.set_bit(0b00, 1), 0b10)

    def test_clear_bit(self) -> None:
        self.assertEqual(utils.clear_bit(0b11, 0), 0b10)
        self.assertEqual(utils.clear_bit(0b11, 1), 0b01)

    def test_is_bit_set(self) -> None:
        self.assertEqual(utils.is_bit_set(0b00, 0), False)
        self.assertEqual(utils.is_bit_set(0b01, 0), True)
        self.assertEqual(utils.is_bit_set(0b00, 1), False)
        self.assertEqual(utils.is_bit_set(0b10, 1), True)

    def test_has_rex_prefix(self) -> None:
        self.assertFalse(
            utils.has_rex_prefix(utils.get_x86_64_instruction(b"\xff\xc0"))
        )  # inc eax
        self.assertTrue(
            utils.has_rex_prefix(utils.get_x86_64_instruction(b"\x48\xff\xc0"))
        )  # inc rax
