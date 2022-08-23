# Transasm

Exploiting x86 redundancy machine code to create polymorphic shellcodes

# Example with register operands and the ModR/M byte

Some x86 instructions have two opcodes so we can write the following two forms:

| instructions               | bytes   | opcode reference | opcode table | ModR/M                                       |
|----------------------------|---------|------------------|--------------|----------------------------------------------|
| `add dword ptr [rcx], eax` | `01 01` | `reg/mem32, reg` | `Ev, Gv`     | 0x01 (mod: 0b00) (reg: 0b000) (rm: 0b001)    |
| `add eax, dword ptr [rcx]` | `03 01` | `reg, reg/mem32` | `Gv, Ev`     | 0x01 (mod: 0b00) (reg: 0b000) (rm: 0b001)    |

When both operands are registers, the opcode  is redundant.
To obtain the same instruction with a different opcode, we need to rewrite the ModR/M part and especially, invert the reg and the rm parts.

| instructions   | bytes   | opcode reference | opcode table | ModR/M                                       |
|----------------|---------|------------------|--------------|----------------------------------------------|
| `add eax, ebx` | `01 d8` | `reg/mem32, reg` | `Ev, Gv`     | 0xd8 (mod: 0b11) (reg: 0b011) (rm: 0b000)    |
| `add eax, ebx` | `03 c3` | `reg, reg/mem32` | `Gv, Ev`     | 0xc3 (mod: 0b11) (reg: 0b000) (rm: 0b011)    |

# Example with register operands and the SIB byte

If the scale factor is 1 (sib.scale == 0b00), then it is possible to swap the base and the index register:

| instructions                      | bytes             | SIB                                                       |
|-----------------------------------|-------------------|-----------------------------------------------------------|
| `mov rax, qword ptr [rbx + rcx]`  | `48 8b 04 0b`     | 0x0b (scale: 0b00) (index: 0b001, rcx) (base: 0b011, rbx) |
| `mov rax, qword ptr [rcx + rbx]`  | `49 8b 04 19`     | 0x19 (scale: 0b00) (index: 0b011, rbx) (base: 0b001, rcx) |
| `mov byte ptr [eax + ebx], 5`     | `67 c6 04 18 05`  | 0x18 (scale: 0b00) (index: 0b011, ebx) (base: 0b000, eax) |
| `mov byte ptr [ebx + eax], 5`     | `67 c6 04 03 05`  | 0x03 (scale: 0b00) (index: 0b000, eax) (base: 0b011, ebx) |

Note that this manipulation alters the literal representation of the assembly.

# Example with duplicate opcode extensions

Some instructions have two opcode extensions like the TEST extension when used with a immediate operand:

With Group 3 Eb (`0xf6`):

| instructions      | bytes         | ModR/M reg    |
|-------------------|---------------|---------------|
| `test bl, 0x10`   | `f6 c3 10`    | `000`         |
| `test bl, 0x10`   | `f6 cb 10`    | `001`         |

With Group 3 Ev (`0xf7`):

| instructions              | bytes                 | ModR/M reg    |
|---------------------------|-----------------------|---------------|
| `test ebx, 0xaabbccdd`    | `f7 c3 dd cc bb aa`   | `000`         |
| `test ebx, 0xaabbccdd`    | `f7 cb dd cc bb aa`   | `001`         |

# Example with duplicate opcode on x86

Group 1 have have duplicated opcodes for `0x80` and `0x82` on x86:

| instructions                  | bytes         |
|-------------------------------|---------------|
| `add byte ptr [eax], 0x10`    | `80 00 10`    |
| `add byte ptr [eax], 0x10`    | `82 00 10`    |

| ModR/M reg    | Instruction   |
|---------------|---------------|
| `000`         | ADD           |
| `001`         | OR            |
| `010`         | ADC           |
| `011`         | SBB           |
| `100`         | AND           |
| `101`         | SUB           |
| `110`         | XOR           |
| `111`         | CMP           |

# Example with variable immediate operand sizes

| instructions      | bytes                     |
|-------------------|---------------------------|
| `add eax, 0x10`   | `83 c0 10`                |
| `add eax, 0x10`   | `81 c0 10 00 00 00`       |
| `add rax, 0x10`   | `48 83 c0 10`             |
| `add rax, 0x10`   | `48 81 c0 10 00 00 00`    |

Under some constraints, we can also use the `Eb, Ib` versions with opcodes `80` and `82`.

# Example with opcodes targeting the accumulator register

There is also a special case with the accumulator register where we can use the `x4` and `x5` opcodes:

| instructions      | bytes                     | ModR/M reg    |
|-------------------|---------------------------|---------------|
| `add al, 0x10`    | `04 10`                   | `000`         |
| `add al, 0x10`    | `80 c0 10`                | `000`         |
| `add eax, 0x10`   | `05 10 00 00 00`          | `000`         |
| `add eax, 0x10`   | `81 c0 10 00 00 00`       | `000`         |
| `add eax, 0x10`   | `83 c0 10`                | `000`         |
| `add rax, 0x10`   | `48 05 10 00 00 00`       | `000`         |
| `add rax, 0x10`   | `48 81 c0 10 00 00 00`    | `000`         |
| `add rax, 0x10`   | `48 83 c0 10`             | `000`         |

This works with the following common instructions: `and`, `or`, `adc`, `sbb`, `sub`, `xor`, `cmp`. See the `adc` equivalences below:

| instructions      | bytes                     | ModR/M reg    |
|-------------------|---------------------------|---------------|
| `adc al, 0x10`    | `14 10`                   | `000`         |
| `adc al, 0x10`    | `80 d0 10`                | `010`         |
| `adc eax, 0x10`   | `15 10 00 00 00`          | `000`         |
| `adc eax, 0x10`   | `81 d0 10 00 00 00`       | `010`         |
| `adc eax, 0x10`   | `83 d0 10`                | `010`         |
| `adc rax, 0x10`   | `48 15 10 00 00 00`       | `000`         |
| `adc rax, 0x10`   | `48 81 d0 10 00 00 00`    | `010`         |
| `adc rax, 0x10`   | `48 83 d0 10`             | `010`         |

TODO: capstone fails at disassembling group 82?!

# Example with zero displacement

When used with reg/reg operands, displacement size depends on the ModR/M mod part:

| instructions                          | bytes                     | ModR/M                                    |
|---------------------------------------|---------------------------|-------------------------------------------|
| `add dword ptr [eax], eax`            | `67 01 00`                | 0x00 (mod: 0b00) (reg: 0b000) (rm: 0b000) |
| `add dword ptr [eax + 00], eax`       | `67 01 40 00`             | 0x40 (mod: 0b01) (reg: 0b000) (rm: 0b000) |
| `add dword ptr [eax + 00000000], eax` | `67 01 80 00 00 00 00`    | 0x40 (mod: 0b10) (reg: 0b000) (rm: 0b000) |
| `add qword ptr [rax], rax`            | `48 01 00`                | 0x00 (mod: 0b00) (reg: 0b000) (rm: 0b000) |
| `add qword ptr [rax + 00], rax`       | `48 01 40 00`             | 0x00 (mod: 0b01) (reg: 0b000) (rm: 0b000) |
| `add qword ptr [rax + 00000000], rax` | `48 01 80 00 00 00 00`    | 0x40 (mod: 0b10) (reg: 0b000) (rm: 0b000) |

# Example with the SIB byte

The SIB byte has a corner case when it comes to the index and base parts. Index and base registers may be not encoded (e.g. direct addressing encoding). Depending on the SIB presence and the SIB.scale, we can craft 5 different but equivalent encodings for a single instruction:

In 32-bit mode:

| instructions                      | bytes                     | SIB                                               |
|-----------------------------------|---------------------------|---------------------------------------------------|
| `mov byte ptr [0xaabbccdd], 0xff` | `c6 05    dd cc bb aa ff` |                                                   |
| `mov byte ptr [0xaabbccdd], 0xff` | `c6 04 25 dd cc bb aa ff` | 0x25 (scale: 0b00) (index: 0b100) (base: 0b101)   |
| `mov byte ptr [0xaabbccdd], 0xff` | `c6 04 65 dd cc bb aa ff` | 0x65 (scale: 0b01) (index: 0b100) (base: 0b101)   |
| `mov byte ptr [0xaabbccdd], 0xff` | `c6 04 a5 dd cc bb aa ff` | 0xa5 (scale: 0b10) (index: 0b100) (base: 0b101)   |
| `mov byte ptr [0xaabbccdd], 0xff` | `c6 04 e5 dd cc bb aa ff` | 0xe5 (scale: 0b11) (index: 0b100) (base: 0b101)   |
|-----------------------------------|---------------------------|---------------------------------------------------|
| `mov byte ptr [esp - 0x56], 0xff` | `c6 45    aa ff`          |                                                   |
| `mov byte ptr [esp - 0x56], 0xff` | `c6 44 24 aa ff`          | 0x24 (scale: 0b00) (index: 0b100) (base: 0b100)   |
| `mov byte ptr [esp - 0x56], 0xff` | `c6 44 64 aa ff`          | 0x64 (scale: 0b01) (index: 0b100) (base: 0b100)   |
| `mov byte ptr [esp - 0x56], 0xff` | `c6 44 a4 aa ff`          | 0xa4 (scale: 0b10) (index: 0b100) (base: 0b100)   |
| `mov byte ptr [esp - 0x56], 0xff` | `c6 44 e4 aa ff`          | 0xe4 (scale: 0b11) (index: 0b100) (base: 0b100)   |
|-----------------------------------|---------------------------|---------------------------------------------------|
| `mov byte ptr [ebp + 0x56], 0xff` | `c6 45    56 ff`          |                                                   |
| `mov byte ptr [ebp + 0x56], 0xff` | `c6 44 25 56 ff`          | 0x25 (scale: 0b00) (index: 0b100) (base: 0b101)   |
| `mov byte ptr [ebp + 0x56], 0xff` | `c6 44 65 56 ff`          | 0x65 (scale: 0b01) (index: 0b100) (base: 0b101)   |
| `mov byte ptr [ebp + 0x56], 0xff` | `c6 44 a5 56 ff`          | 0xa5 (scale: 0b10) (index: 0b100) (base: 0b101)   |
| `mov byte ptr [ebp + 0x56], 0xff` | `c6 44 e5 56 ff`          | 0xe5 (scale: 0b11) (index: 0b100) (base: 0b101)   |


In 64-bit mode:

| instructions                      | bytes                     | SIB                                               |
|-----------------------------------|---------------------------|---------------------------------------------------|
| `mov byte ptr [rsp - 0x56], 0xff` | `c6 45    aa ff`          |                                                   |
| `mov byte ptr [rsp - 0x56], 0xff` | `c6 44 24 aa ff`          | 0x24 (scale: 0b00) (index: 0b100) (base: 0b100)   |
| ...                               | ...                       | ...                                               |
|-----------------------------------|---------------------------|---------------------------------------------------|
| `mov byte ptr [esp - 0x56], 0xff` | `67 c6 45    aa ff`       |                                                   |
| `mov byte ptr [esp - 0x56], 0xff` | `67 c6 44 24 aa ff`       | 0x24 (scale: 0b00) (index: 0b100) (base: 0b100)   |
| ...                               | ...                       | ...                                               |

# Example with legacy prefixes

In 32-bit mode, we can omit some legacy prefixes:

| instructions                  | bytes         |
|-------------------------------|---------------|
| `add qword ptr [eax], eax`    | `01 00`       |
| `add qword ptr [eax], eax`    | `67 01 00`    |

Some instructions might accept one or more prefixes:

| instructions  | bytes         |
|---------------|---------------|
| `nop`         | `90`          |
| `nop`         | `66 90`       |
| `nop`         | `66 67 90`    |
| `nop`         | `66 66 67 90` |

# Logic transformation

Zeroing registers:

| instructions      |
|-------------------|
| `mov eax, 0x0`    |
| `xor eax, eax`    |
| `sub eax, eax`    |

| instructions      | code                      | ModR/M                                    |
|-------------------|---------------------------|-------------------------------------------|
| `xor bx, bx`      | `66 31 db`                | 0xdb (mod: 0b11) (reg: 0b011) (rm: 0b011) |
| `xor ebx, ebx`    | `31 db`                   | 0xdb (mod: 0b11) (reg: 0b011) (rm: 0b011) |
| `xor rbx, rbx`    | `48 31 db`                | 0xdb (mod: 0b11) (reg: 0b011) (rm: 0b011) |
| `sub bx, bx`      | `66 29 db`                | 0xdb (mod: 0b11) (reg: 0b011) (rm: 0b011) |
| `sub ebx, ebx`    | `29 db`                   | 0xdb (mod: 0b11) (reg: 0b011) (rm: 0b011) |
| `sub rbx, rbx`    | `48 29 db`                | 0xdb (mod: 0b11) (reg: 0b011) (rm: 0b011) |
| `mov bx, 0`       | `66 bb 00 00`             | 0x00 (mod: 0b00) (reg: 0b000) (rm: 0b000) |
| `mov eax, 0`      | `b8 00 00 00 00`          | 0x00 (mod: 0b00) (reg: 0b000) (rm: 0b000) |
| `mov ebx, 0`      | `bb 00 00 00 00`          | 0x00 (mod: 0b00) (reg: 0b000) (rm: 0b000) |
| `mov rax, 0`      | `48 c7 c0 00 00 00 00`    | 0xc0 (mod: 0b11) (reg: 0b000) (rm: 0b000) |
| `mov rbx, 0`      | `48 c7 c3 00 00 00 00`    | 0xc3 (mod: 0b11) (reg: 0b000) (rm: 0b011) |

To switch between the `xor` and the `sub`, we have to switch opcodes.
The switch between the `xor` and the `mov` is not supported yet.


# Going further

* LIEF frontend
* cmake module
* <insert your favourite c2 framework> module
* llvm pass
* steganography

# Research

https://www.sandpile.org/x86/opc_grp.htm
duplicates TEST (*)
duplicates with (* i64)

# References

* 1 byte opcodes: https://www.sandpile.org/x86/opc_1.htm
* https://events.static.linuxfound.org/sites/events/files/slides/bpetkov-x86-hacks.pdf
* https://www.strchr.com/machine_code_redundancy
* http://ref.x86asm.net/
* http://www.c-jump.com/CIS77/CPU/x86/lecture.html (25.)
* Hydan program
* irasm program https://github.com/XlogicX/irasm
