import unittest

from transasm import transform, utils


class TestUtils(unittest.TestCase):
    def test_try_transform_gv_ev_instruction(self) -> None:
        test_data = [
            ("add eax, ebx", b"\x01\xd8", b"\x03\xc3"),
            ("adc eax, ebx", b"\x11\xd8", b"\x13\xc3"),
            ("and eax, ebx", b"\x21\xd8", b"\x23\xc3"),
            ("xor eax, ebx", b"\x31\xd8", b"\x33\xc3"),
            ("or eax, ebx", b"\x09\xd8", b"\x0b\xc3"),
            ("sbb eax, ebx", b"\x19\xd8", b"\x1b\xc3"),
            ("sub eax, ebx", b"\x29\xd8", b"\x2b\xc3"),
            ("cmp eax, ebx", b"\x39\xd8", b"\x3b\xc3"),
            ("mov eax, ebx", b"\x89\xd8", b"\x8b\xc3"),
            ("mov rax, rbx", b"\x48\x89\xd8", b"\x48\x8b\xc3"),
            # non regression
            ("mov rsi, rdx", b"\x48\x89\xd6", b"\x48\x8b\xf2"),
        ]
        for literal, left, right in test_data:
            with self.subTest(f"Test {literal}"):
                insn = utils.get_x86_64_instruction(left)
                self.assertEqual(f"{insn.mnemonic} {insn.op_str}", literal)
                self.assertEqual(
                    transform.try_transform_gv_ev_instruction_for_reg_ops(
                        left
                    ),
                    right,
                )
                self.assertEqual(
                    transform.try_transform_gv_ev_instruction_for_reg_ops(
                        right
                    ),
                    left,
                )

    def test_try_transform_zero_scale_sib(self) -> None:
        test_data = [
            (
                "mov rax, qword ptr [rbx + rcx]",
                b"\x48\x8b\x04\x0b",
                b"\x48\x8b\x04\x19",
            ),
            (
                "mov byte ptr [eax + ebx], 5",
                b"\x67\xc6\x04\x18\x05",
                b"\x67\xc6\x04\x03\x05",
            ),
        ]
        for literal, left, right in test_data:
            with self.subTest(f"Test {literal}"):
                insn = utils.get_x86_64_instruction(left)
                self.assertEqual(f"{insn.mnemonic} {insn.op_str}", literal)
                self.assertEqual(
                    transform.try_transform_zero_scale_sib(left), right
                )
                self.assertEqual(
                    transform.try_transform_zero_scale_sib(right), left
                )

    def test_try_transform_duplicate_opcode_extensions(self) -> None:
        test_data = [
            ("test bl, 0x10", b"\xf6\xc3\x10", b"\xf6\xcb\x10"),
            (
                "test ebx, 0xaabbccdd",
                b"\xf7\xc3\xdd\xcc\xbb\xaa",
                b"\xf7\xcb\xdd\xcc\xbb\xaa",
            ),
        ]
        for literal, left, right in test_data:
            with self.subTest(f"Test {literal}"):
                insn = utils.get_x86_64_instruction(left)
                self.assertEqual(f"{insn.mnemonic} {insn.op_str}", literal)
                self.assertEqual(
                    transform.try_transform_duplicate_opcode_extensions(left),
                    right,
                )
                self.assertEqual(
                    transform.try_transform_duplicate_opcode_extensions(right),
                    left,
                )

    def test_try_transform_duplicate_x86_opcodes(self) -> None:
        test_data = [
            ("add byte ptr [eax], 0x10", b"\x80\x00\x10", b"\x82\x00\x10"),
            ("or byte ptr [eax], 0x10", b"\x80\x08\x10", b"\x82\x08\x10"),
            ("adc byte ptr [eax], 0x10", b"\x80\x10\x10", b"\x82\x10\x10"),
            ("sbb byte ptr [eax], 0x10", b"\x80\x18\x10", b"\x82\x18\x10"),
            ("and byte ptr [eax], 0x10", b"\x80\x20\x10", b"\x82\x20\x10"),
            ("sub byte ptr [eax], 0x10", b"\x80\x28\x10", b"\x82\x28\x10"),
            ("xor byte ptr [eax], 0x10", b"\x80\x30\x10", b"\x82\x30\x10"),
            ("cmp byte ptr [eax], 0x10", b"\x80\x38\x10", b"\x82\x38\x10"),
        ]
        for literal, left, right in test_data:
            with self.subTest(f"Test {literal}"):
                insn = utils.get_x86_instruction(left)
                self.assertEqual(f"{insn.mnemonic} {insn.op_str}", literal)
                self.assertEqual(
                    transform.try_transform_duplicate_x86_opcodes(left), right
                )
                self.assertEqual(
                    transform.try_transform_duplicate_x86_opcodes(right), left
                )

    def test_try_transform_imm_operand_size(self) -> None:
        test_data = [
            ("add eax, 0x10", b"\x81\xc0\x10\x00\x00\x00", b"\x83\xc0\x10"),
            ("or eax, 0x10", b"\x81\xc8\x10\x00\x00\x00", b"\x83\xc8\x10"),
            ("adc eax, 0x10", b"\x81\xd0\x10\x00\x00\x00", b"\x83\xd0\x10"),
            ("sbb eax, 0x10", b"\x81\xd8\x10\x00\x00\x00", b"\x83\xd8\x10"),
            ("and eax, 0x10", b"\x81\xe0\x10\x00\x00\x00", b"\x83\xe0\x10"),
            ("sub eax, 0x10", b"\x81\xe8\x10\x00\x00\x00", b"\x83\xe8\x10"),
            ("xor eax, 0x10", b"\x81\xf0\x10\x00\x00\x00", b"\x83\xf0\x10"),
            (
                "add rax, 0x10",
                b"\x48\x81\xc0\x10\x00\x00\x00",
                b"\x48\x83\xc0\x10",
            ),
            (
                "or rax, 0x10",
                b"\x48\x81\xc8\x10\x00\x00\x00",
                b"\x48\x83\xc8\x10",
            ),
            (
                "adc rax, 0x10",
                b"\x48\x81\xd0\x10\x00\x00\x00",
                b"\x48\x83\xd0\x10",
            ),
            (
                "sbb rax, 0x10",
                b"\x48\x81\xd8\x10\x00\x00\x00",
                b"\x48\x83\xd8\x10",
            ),
            (
                "and rax, 0x10",
                b"\x48\x81\xe0\x10\x00\x00\x00",
                b"\x48\x83\xe0\x10",
            ),
            (
                "sub rax, 0x10",
                b"\x48\x81\xe8\x10\x00\x00\x00",
                b"\x48\x83\xe8\x10",
            ),
            (
                "xor rax, 0x10",
                b"\x48\x81\xf0\x10\x00\x00\x00",
                b"\x48\x83\xf0\x10",
            ),
        ]
        for literal, left, right in test_data:
            with self.subTest(f"Test {literal}"):
                insn = utils.get_x86_64_instruction(left)
                self.assertEqual(f"{insn.mnemonic} {insn.op_str}", literal)
                self.assertEqual(
                    transform.try_transform_imm_operand_size(left), right
                )
                self.assertEqual(
                    transform.try_transform_imm_operand_size(right), left
                )

    def test_try_transform_acc_with_imm(self) -> None:
        test_data = [
            ("add al, 0x10", b"\x04\x10", [b"\x80\xc0\x10"]),
            ("add al, 0x10", b"\x80\xc0\x10", [b"\x04\x10"]),
            (
                "add eax, 0x10",
                b"\x05\x10\x00\x00\x00",
                [b"\x81\xc0\x10\x00\x00\x00", b"\x83\xc0\x10"],
            ),
            (
                "add eax, 0x10",
                b"\x81\xc0\x10\x00\x00\x00",
                [b"\x05\x10\x00\x00\x00", b"\x83\xc0\x10"],
            ),
            (
                "add eax, 0x10",
                b"\x83\xc0\x10",
                [b"\x05\x10\x00\x00\x00", b"\x81\xc0\x10\x00\x00\x00"],
            ),
            (
                "add rax, 0x10",
                b"\x48\x05\x10\x00\x00\x00",
                [b"\x48\x81\xc0\x10\x00\x00\x00", b"\x48\x83\xc0\x10"],
            ),
            (
                "add rax, 0x10",
                b"\x48\x81\xc0\x10\x00\x00\x00",
                [b"\x48\x05\x10\x00\x00\x00", b"\x48\x83\xc0\x10"],
            ),
            (
                "add rax, 0x10",
                b"\x48\x83\xc0\x10",
                [b"\x48\x05\x10\x00\x00\x00", b"\x48\x81\xc0\x10\x00\x00\x00"],
            ),
            ("or al, 0x10", b"\x0c\x10", [b"\x80\xc8\x10"]),
            ("or al, 0x10", b"\x80\xc8\x10", [b"\x0c\x10"]),
            (
                "or eax, 0x10",
                b"\x0d\x10\x00\x00\x00",
                [b"\x81\xc8\x10\x00\x00\x00", b"\x83\xc8\x10"],
            ),
            (
                "or rax, 0x10",
                b"\x48\x0d\x10\x00\x00\x00",
                [b"\x48\x81\xc8\x10\x00\x00\x00", b"\x48\x83\xc8\x10"],
            ),
            ("adc al, 0x10", b"\x14\x10", [b"\x80\xd0\x10"]),
            ("adc al, 0x10", b"\x80\xd0\x10", [b"\x14\x10"]),
            (
                "adc eax, 0x10",
                b"\x15\x10\x00\x00\x00",
                [b"\x81\xd0\x10\x00\x00\x00", b"\x83\xd0\x10"],
            ),
            (
                "adc eax, 0x10",
                b"\x81\xd0\x10\x00\x00\x00",
                [b"\x15\x10\x00\x00\x00", b"\x83\xd0\x10"],
            ),
            (
                "adc eax, 0x10",
                b"\x83\xd0\x10",
                [b"\x15\x10\x00\x00\x00", b"\x81\xd0\x10\x00\x00\x00"],
            ),
            (
                "adc rax, 0x10",
                b"\x48\x15\x10\x00\x00\x00",
                [b"\x48\x81\xd0\x10\x00\x00\x00", b"\x48\x83\xd0\x10"],
            ),
            (
                "adc rax, 0x10",
                b"\x48\x81\xd0\x10\x00\x00\x00",
                [b"\x48\x15\x10\x00\x00\x00", b"\x48\x83\xd0\x10"],
            ),
            (
                "adc rax, 0x10",
                b"\x48\x83\xd0\x10",
                [b"\x48\x15\x10\x00\x00\x00", b"\x48\x81\xd0\x10\x00\x00\x00"],
            ),
            ("sbb al, 0x10", b"\x1c\x10", [b"\x80\xd8\x10"]),
            ("sbb al, 0x10", b"\x80\xd8\x10", [b"\x1c\x10"]),
            (
                "sbb eax, 0x10",
                b"\x1d\x10\x00\x00\x00",
                [b"\x81\xd8\x10\x00\x00\x00", b"\x83\xd8\x10"],
            ),
            (
                "sbb rax, 0x10",
                b"\x48\x1d\x10\x00\x00\x00",
                [b"\x48\x81\xd8\x10\x00\x00\x00", b"\x48\x83\xd8\x10"],
            ),
            ("and al, 0x10", b"\x24\x10", [b"\x80\xe0\x10"]),
            ("and al, 0x10", b"\x80\xe0\x10", [b"\x24\x10"]),
            (
                "and eax, 0x10",
                b"\x25\x10\x00\x00\x00",
                [b"\x81\xe0\x10\x00\x00\x00", b"\x83\xe0\x10"],
            ),
            (
                "and eax, 0x10",
                b"\x81\xe0\x10\x00\x00\x00",
                [b"\x25\x10\x00\x00\x00", b"\x83\xe0\x10"],
            ),
            (
                "and eax, 0x10",
                b"\x83\xe0\x10",
                [b"\x25\x10\x00\x00\x00", b"\x81\xe0\x10\x00\x00\x00"],
            ),
            (
                "and rax, 0x10",
                b"\x48\x25\x10\x00\x00\x00",
                [b"\x48\x81\xe0\x10\x00\x00\x00", b"\x48\x83\xe0\x10"],
            ),
            (
                "and rax, 0x10",
                b"\x48\x81\xe0\x10\x00\x00\x00",
                [b"\x48\x25\x10\x00\x00\x00", b"\x48\x83\xe0\x10"],
            ),
            (
                "and rax, 0x10",
                b"\x48\x83\xe0\x10",
                [b"\x48\x25\x10\x00\x00\x00", b"\x48\x81\xe0\x10\x00\x00\x00"],
            ),
            ("sub al, 0x10", b"\x2c\x10", [b"\x80\xe8\x10"]),
            ("sub al, 0x10", b"\x80\xe8\x10", [b"\x2c\x10"]),
            (
                "sub eax, 0x10",
                b"\x2d\x10\x00\x00\x00",
                [b"\x81\xe8\x10\x00\x00\x00", b"\x83\xe8\x10"],
            ),
            (
                "sub rax, 0x10",
                b"\x48\x2d\x10\x00\x00\x00",
                [b"\x48\x81\xe8\x10\x00\x00\x00", b"\x48\x83\xe8\x10"],
            ),
            ("xor al, 0x10", b"\x34\x10", [b"\x80\xf0\x10"]),
            ("xor al, 0x10", b"\x80\xf0\x10", [b"\x34\x10"]),
            (
                "xor eax, 0x10",
                b"\x35\x10\x00\x00\x00",
                [b"\x81\xf0\x10\x00\x00\x00", b"\x83\xf0\x10"],
            ),
            (
                "xor rax, 0x10",
                b"\x48\x35\x10\x00\x00\x00",
                [b"\x48\x81\xf0\x10\x00\x00\x00", b"\x48\x83\xf0\x10"],
            ),
            ("cmp al, 0x10", b"\x3c\x10", [b"\x80\xf8\x10"]),
            ("cmp al, 0x10", b"\x80\xf8\x10", [b"\x3c\x10"]),
            (
                "cmp eax, 0x10",
                b"\x3d\x10\x00\x00\x00",
                [b"\x81\xf8\x10\x00\x00\x00", b"\x83\xf8\x10"],
            ),
            (
                "cmp rax, 0x10",
                b"\x48\x3d\x10\x00\x00\x00",
                [b"\x48\x81\xf8\x10\x00\x00\x00", b"\x48\x83\xf8\x10"],
            ),
        ]
        for literal, left, right in test_data:
            with self.subTest(f"Test {literal}"):
                insn = utils.get_x86_64_instruction(left)
                self.assertEqual(f"{insn.mnemonic} {insn.op_str}", literal)
                found_transformations = set()
                while len(found_transformations) != len(right):
                    found_transformation = (
                        transform.try_transform_acc_with_imm8(left)
                    )
                    found_transformations.add(found_transformation)
                    self.assertTrue(found_transformation in right)
                    insn = utils.get_x86_64_instruction(found_transformation)
                    self.assertEqual(f"{insn.mnemonic} {insn.op_str}", literal)

    def test_try_transform_gv_ev_instruction_using_displ(self) -> None:
        test_data = [
            (
                "add dword ptr [eax], eax",
                b"\x67\x01\x00",
                [b"\x67\x01\x40\x00", b"\x67\x01\x80\x00\x00\x00\x00"],
            ),
            (
                "add dword ptr [eax], eax",
                b"\x67\x01\x40\x00",
                [b"\x67\x01\x00", b"\x67\x01\x80\x00\x00\x00\x00"],
            ),
            (
                "add dword ptr [eax], eax",
                b"\x67\x01\x80\x00\x00\x00\x00",
                [b"\x67\x01\x00", b"\x67\x01\x40\x00"],
            ),
            (
                "add dword ptr [eax + 1], eax",
                b"\x67\x01\x40\x01",
                [b"\x67\x01\x80\x01\x00\x00\x00"],
            ),
            (
                "add dword ptr [eax + 1], eax",
                b"\x67\x01\x80\x01\x00\x00\x00",
                [b"\x67\x01\x40\x01"],
            ),
            (
                "add qword ptr [rax], rax",
                b"\x48\x01\x00",
                [b"\x48\x01\x40\x00", b"\x48\x01\x80\x00\x00\x00\x00"],
            ),
            (
                "add dword ptr [ebx], ebx",
                b"\x67\x01\x1b",
                [b"\x67\x01\x5b\x00", b"\x67\x01\x9b\x00\x00\x00\x00"],
            ),
        ]
        for literal, left, right in test_data:
            with self.subTest(f"Test {literal}"):
                insn = utils.get_x86_64_instruction(left)
                self.assertEqual(f"{insn.mnemonic} {insn.op_str}", literal)
                found_transformations = set()
                while len(found_transformations) != len(right):
                    found_transformation = (
                        transform.try_transform_gv_ev_instruction_using_displ(
                            left
                        )
                    )
                    found_transformations.add(found_transformation)
                    self.assertTrue(found_transformation in right)
                    insn = utils.get_x86_64_instruction(found_transformation)
                    self.assertEqual(f"{insn.mnemonic} {insn.op_str}", literal)

    def test_try_transform_x86_using_sib(self) -> None:
        test_data = [
            (
                "mov byte ptr [0xaabbccdd], 0xff",
                b"\xc6\x04\x25\xdd\xcc\xbb\xaa\xff",
                [
                    b"\xc6\x04\x65\xdd\xcc\xbb\xaa\xff",
                    b"\xc6\x04\xa5\xdd\xcc\xbb\xaa\xff",
                    b"\xc6\x04\xe5\xdd\xcc\xbb\xaa\xff",
                ],
            ),
            (
                "mov byte ptr [esp - 0x56], 0xff",
                b"\xc6\x44\x64\xaa\xff",
                [
                    b"\xc6\x44\x24\xaa\xff",
                    b"\xc6\x44\xa4\xaa\xff",
                    b"\xc6\x44\xe4\xaa\xff",
                ],
            ),
            (
                "mov byte ptr [ebp + 0x56], 0xff",
                b"\xc6\x44\xa5\x56\xff",
                [
                    b"\xc6\x44\x25\x56\xff",
                    b"\xc6\x44\x65\x56\xff",
                    b"\xc6\x44\xe5\x56\xff",
                ],
            ),
        ]
        for literal, left, right in test_data:
            with self.subTest(f"Test {literal}"):
                insn = utils.get_x86_instruction(left)
                self.assertEqual(f"{insn.mnemonic} {insn.op_str}", literal)
                found_transformations = set()
                while len(found_transformations) != len(right):
                    found_transformation = (
                        transform.try_transform_x86_using_sib(left)
                    )
                    found_transformations.add(found_transformation)
                    self.assertTrue(found_transformation in right)
                    insn = utils.get_x86_instruction(found_transformation)
                    self.assertEqual(f"{insn.mnemonic} {insn.op_str}", literal)

    def test_try_transform_x86_64_using_sib(self) -> None:
        test_data = [
            (
                "mov byte ptr [rsp - 0x56], 0xff",
                b"\xc6\x44\x24\xaa\xff",
                [
                    b"\xc6\x44\x64\xaa\xff",
                    b"\xc6\x44\xa4\xaa\xff",
                    b"\xc6\x44\xe4\xaa\xff",
                ],
            ),
        ]
        for literal, left, right in test_data:
            with self.subTest(f"Test {literal}"):
                insn = utils.get_x86_64_instruction(left)
                self.assertEqual(f"{insn.mnemonic} {insn.op_str}", literal)
                found_transformations = set()
                while len(found_transformations) != len(right):
                    found_transformation = (
                        transform.try_transform_x86_64_using_sib(left)
                    )
                    found_transformations.add(found_transformation)
                    self.assertTrue(found_transformation in right)

    def test_try_transform_zeroing(self) -> None:
        test_data = [
            ("xor ax, ax", b"\x66\x31\xc0", b"\x66\x29\xc0"),
            ("xor eax, eax", b"\x31\xc0", b"\x29\xc0"),
            ("xor rax, rax", b"\x48\x31\xc0", b"\x48\x29\xc0"),
            ("xor r8, r8", b"\x4d\x31\xc0", b"\x4d\x29\xc0"),
            ("sub ax, ax", b"\x66\x29\xc0", b"\x66\x31\xc0"),
            ("sub eax, eax", b"\x29\xc0", b"\x31\xc0"),
            ("sub rax, rax", b"\x48\x29\xc0", b"\x48\x31\xc0"),
            ("sub r8, r8", b"\x4d\x29\xc0", b"\x4d\x31\xc0"),
        ]
        for literal, left, right in test_data:
            with self.subTest(f"Test {literal}"):
                insn = utils.get_x86_64_instruction(left)
                self.assertEqual(f"{insn.mnemonic} {insn.op_str}", literal)
                self.assertEqual(transform.try_transform_zeroing(left), right)
