# From https://github.com/armut/x86-Linux-Assembly-Examples/tree/master/prime_numbers

all: x86 x84

x86:
	nasm -f elf32 prime_x86.s
	ld -m elf_i386 -dynamic-linker /lib/ld-linux.so.2 -lc prime_x86.o -o prime_x86

x64:
	nasm -f elf64 prime_x86_64.s
	ld -dynamic-linker /lib64/ld-linux-x86-64.so.2 -lc prime_x86_64.o -o prime_x86_64

clean:
	rm -f prime_x86 prime_x86.o
	rm -f prime_x86_64 prime_x86_64.o
