import unittest

from transasm import types


class TestTypes(unittest.TestCase):
    def test_modrm_type(self) -> None:
        modrm = types.ModRM(0xD8)
        self.assertEqual(modrm.v, 0xD8)
        self.assertEqual(modrm.v, 0b11011000)
        self.assertEqual(modrm.s.mod, 0b11)
        self.assertEqual(modrm.s.r_x, 0b011)
        self.assertEqual(modrm.s.r_m, 0b000)

    def test_sib_type(self) -> None:
        sib = types.SIB(0x18)
        self.assertEqual(sib.v, 0x18)
        self.assertEqual(sib.v, 0b00011000)
        self.assertEqual(sib.s.scale, 0b00)
        self.assertEqual(sib.s.index, 0b011)
        self.assertEqual(sib.s.scale, 0b000)
