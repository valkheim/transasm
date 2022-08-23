import dataclasses

import capstone


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)

        return cls._instances[cls]


@dataclasses.dataclass()
class Config(metaclass=Singleton):
    md: object = dataclasses.field(init=False)
    md_x86: object = dataclasses.field(init=False)

    md_mode: int = dataclasses.field(default=capstone.CS_MODE_64)

    def init_capstone(self):
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True
        self.md_x86 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.md_x86.detail = True

    def __post_init__(self):
        self.init_capstone()


config = Config()
