primes_x86 = [
#00000000 <_start>:
    0x31, 0xd2,                     # xor    edx,edx
    0x31, 0xc9,                     # xor    ecx,ecx
    0xb9, 0x64, 0x00, 0x00, 0x00,   # mov    ecx,0x64
    0xba, 0x02, 0x00, 0x00, 0x00,   # mov    edx,0x2
#0000000e <primus>:
    0x83, 0xf9, 0x02,               # cmp    ecx,0x2
    0x74, 0x2b,                     # je     3e <exit>
    0x89, 0xc8,                     # mov    eax,ecx
    0x31, 0xdb,                     # xor    ebx,ebx
    0xb3, 0x01,                     # mov    bl,0x1
    0x51,                           # push   ecx
    0x83, 0xe9, 0x01,               # sub    ecx,0x1
#0000001d <looop>:
    0x83, 0xf9, 0x01,               # cmp    ecx,0x1
    0x74, 0x0b,                     # je     2d <cont>
    0x50,                           # push   eax
    0xf6, 0xf1,                     # div    cl
    0x80, 0xfc, 0x00,               # cmp    ah,0x0
    0x74, 0x0b,                     # je     35 <flag_down>
    0x58,                           # pop    eax
    0xe2, 0xf0,                     # loop   1d <looop>
#0000002d <cont>:
    0x80, 0xfb, 0x01,               # cmp    bl,0x1
    0x74, 0x07,                     # je     39 <sum>
    0x59,                           # pop    ecx
    0xe2, 0xd9,                     # loop   e <primus>
#00000035 <flag_down>:
    0xb3, 0x00,                     # mov    bl,0x0
    0xeb, 0xf4,                     # jmp    2d <cont>
#00000039 <sum>:
    0x59,                           # pop    ecx
    0x01, 0xca,                     # add    edx,ecx
    0xe2, 0xd0,                     # loop   e <primus>
#0000003e <exit>:
    0x52,                           # push   edx
    0x68, 0x00, 0x00, 0x00, 0x00,   # push   0x0
    0xe8, 0xfc, 0xff, 0xff, 0xff,   # call   45 <printf>
    0x66, 0x83, 0xc4, 0x08,         # add    sp,0x8
    0xb8, 0x01, 0x00, 0x00, 0x00,   # mov    eax,0x1
    0xbb, 0x00, 0x00, 0x00, 0x00,   # mov    ebx,0x0
    0xcd, 0x80,                     # int    0x80
#.data:
#    0x25, 0x78, 0x0a, 0x00
]

# relative jmps are corrupted here because of instructions size updating transformations
primes_x86_transformed = [
    0x33, 0xd2,                                 # xor  edx,edx
    0x33, 0xc9,                                 # xor  ecx,ecx
    0xb9, 0x64, 0x00, 0x00, 0x00,               # mov  ecx,0x64
    0xba, 0x02, 0x00, 0x00, 0x00,               # mov  edx,0x2

    0x81, 0xf9, 0x02, 0x00, 0x00, 0x00,         # cmp  ecx,0x2
    0x74, 0x2b,                                 # je   0x41
    0x8b, 0xc1,                                 # mov  eax,ecx
    0x33, 0xdb,                                 # xor  ebx,ebx
    0xb3, 0x01,                                 # mov  bl,0x1
    0x51,                                       # push ecx
    0x81, 0xe9, 0x01, 0x00, 0x00, 0x00,         # sub  ecx,0x1

    0x81, 0xf9, 0x01, 0x00, 0x00, 0x00,         # cmp  ecx,0x1
    0x74, 0x0b,                                 # je   0x36
    0x50,                                       # push eax
    0xf6, 0xf1,                                 # div  cl
    0x80, 0xfc, 0x00,                           # cmp  ah,0x0
    0x74, 0x0b,                                 # je   0x3e
    0x58,                                       # pop  eax
    0xe2, 0xf0,                                 # loop 0x26

    0x80, 0xfb, 0x01,                           # cmp  bl,0x1
    0x74, 0x07,                                 # je   0x42
    0x59,                                       # pop  ecx
    0xe2, 0xd9,                                 # loop 0x17

    0xb3, 0x00,                                 # mov  bl,0x0
    0xeb, 0xf4,                                 # jmp  0x36

    0x59,                                       # pop  ecx
    0x03, 0xd1,                                 # add  edx,ecx
    0xe2, 0xd0,                                 # loop 0x17

    0x52,                                       # push edx
    0x68, 0x00, 0x00, 0x00, 0x00,               # push 0x0
    0xe8, 0xfc, 0xff, 0xff, 0xff,               # call 0x4e
    0x66, 0x81, 0xc4, 0x08, 0x00,               # add  sp,0x8
    0x00, 0x00,                                 # add  BYTE PTR [eax],al
    0xb8, 0x01, 0x00, 0x00, 0x00,               # mov  eax,0x1
    0xbb, 0x00, 0x00, 0x00, 0x00,               # mov  ebx,0x0
    0xcd, 0x80,                                 # int  0x80
]

primes_x86_64 = [
#0000000000000000 <_start>:
    0x31, 0xd2,                                                 # xor    edx,edx
    0x31, 0xc9,                                                 # xor    ecx,ecx
    0xb9, 0x64, 0x00, 0x00, 0x00,                               # mov    ecx,0x64
    0xba, 0x02, 0x00, 0x00, 0x00,                               # mov    edx,0x2
#000000000000000e <primus>:
    0x83, 0xf9, 0x02,                                           # cmp    ecx,0x2
    0x74, 0x2b,                                                 # je     3e <exit>
    0x89, 0xc8,                                                 # mov    eax,ecx
    0x31, 0xdb,                                                 # xor    ebx,ebx
    0xb3, 0x01,                                                 # mov    bl,0x1
    0x51,                                                       # push   rcx
    0x83, 0xe9, 0x01,                                           # sub    ecx,0x1
#000000000000001d <looop>:
    0x83, 0xf9, 0x01,                                           # cmp    ecx,0x1
    0x74, 0x0b,                                                 # je     2d <cont>
    0x50,                                                       # push   rax
    0xf6, 0xf1,                                                 # div    cl
    0x80, 0xfc, 0x00,                                           # cmp    ah,0x0
    0x74, 0x0b,                                                 # je     35 <flag_down>
    0x58,                                                       # pop    rax
    0xe2, 0xf0,                                                 # loop   1d <looop>
#000000000000002d <cont>:
    0x80, 0xfb, 0x01,                                           # cmp    bl,0x1
    0x74, 0x07,                                                 # je     39 <sum>
    0x59,                                                       # pop    rcx
    0xe2, 0xd9,                                                 # loop   e <primus>
#0000000000000035 <flag_down>:
    0xb3, 0x00,                                                 # mov    bl,0x0
    0xeb, 0xf4,                                                 # jmp    2d <cont>
#0000000000000039 <sum>:
    0x59,                                                       # pop    rcx
    0x01, 0xca,                                                 # add    edx,ecx
    0xe2, 0xd0,                                                 # loop   e <primus>
#000000000000003e <exit>:
    0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # movabs rdi,0x0
    0x48, 0x89, 0xd6,                                           # mov    rsi,rdx
    0xe8, 0x00, 0x00, 0x00, 0x00,                               # call   50 <exit+0x12>
    0x48, 0x31, 0xff,                                           # xor    rdi,rdi
    0xb8, 0x3c, 0x00, 0x00, 0x00,                               # mov    eax,0x3c
    0x0f, 0x05                                                  # syscall
]
