import ctypes


class ModRM_bits(ctypes.LittleEndianStructure):
    _fields_ = [
        ("r_m", ctypes.c_uint8, 3),
        ("r_x", ctypes.c_uint8, 3),
        ("mod", ctypes.c_uint8, 2),
    ]


class ModRM(ctypes.Union):
    _fields_ = [("s", ModRM_bits), ("v", ctypes.c_uint8)]

    def __init__(self, v: ctypes.c_uint8):
        self.v = v

    def __eq__(self, other):
        return isinstance(other, ModRM) and self.v == other.v


class SIB_bits(ctypes.LittleEndianStructure):
    _fields_ = [
        ("base", ctypes.c_uint8, 3),
        ("index", ctypes.c_uint8, 3),
        ("scale", ctypes.c_uint8, 2),
    ]


class SIB(ctypes.Union):
    _fields_ = [("s", SIB_bits), ("v", ctypes.c_uint8)]

    def __init__(self, v: ctypes.c_uint8):
        self.v = v

    def __eq__(self, other):
        return isinstance(other, SIB) and self.v == other.v
