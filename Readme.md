# Motorola 68000 Disassembler

> Disassemble into what `as` can assemble back

This project aims to be a disassembler that is capable to produce assembly code
that GNU AS will translate into the same original machine code. It's only use
case for now is Sega Mega Drive / Genesis ROM hacking. I failed to find any way
to disassemble SMD ROMs in such a way that it would be possible to assemble it
back with GNU AS. All disassemblers I tried produce either syntactically
incompatible asembly listing, or it is not the same as original binary after
translation into machine code. So I decided to build my own disassembler, that
will do exactly what I need with full control over the process and maybe more.

Goals of this Motorola 68000 disassembler project in this particular repo:
- Support all Motorola 68000 ISA instructions.
- Flawless compatibility with GNU AS syntax. It should always emit the code on
  which GNU AS produces absolutely identical binary (with or without linkage)
  without errors or warnings, unless some peculiar flags has been specified.
- Support PC trace tables. With trace tables it will disassemble traced PC
  locations only, without attempt to disassemble everything, because not
  everything is instruction, some code is just data.
- Mark jump locations and bind jumps and calls to them. Mark obvious ROM read
  accessed locations and bind the instructions to the marked locations. To make
  it possible to split and reorganize the binary.

What could become a goal (possible features):
- Other Motorola 680x0 instruction sets support, including ColdFire.
- Functions and function boundaries detection.
- Static analysis of call graph of branches and subroutine calls.
- PC trace aided static analysis of dynamic branches and subroutine calls.
- Base address other than `0x00000000`. It is only zero for now because it is
  sufficient for Sega Mega Drive / Genesis ROM images.
- Support for more than 4MiB of code size.
- Sparse address space support (instead of single continuous 4MiB block that
  starts at `0x00000000` offset).
- Other assembler syntaxes (e.g. ASM68K.EXE).
- Expose a library API.

What is **not** the goal (at least not in this repo):
- Decompilation into some high level language like C or C++.
- Other instruction set architectures support like MIPS, x86, amd64, ARM,
  PowerPC and so on.

## Build

```
cmake -B cmake-build -S .
cmake --build cmake-build
```

## Usage example

```
./cmake-build/m68k-disasm -t pc-trace.txt -o disasm.S original.bin
```

To get detailed help you can run:

```
./cmake-build/m68k-disasm -h`
```

## Meta

Authors:
- Vladimir Novikov – oxore@protonmail.com

This is free and unencumbered software released into the public domain. See
``UNLICENSE`` for more information.

Resources used to implement the disassember (this set is more than sufficient to
support all of M68000 instructions):
- [The 68000's Instruction Set](http://wpage.unina.it/rcanonic/didattica/ce1/docs/68000.pdf) - Appendix of an unrecognized book. Basically the same information also could be found in [gh:prb28/m68k-instructions-documentation](https://github.com/prb28/m68k-instructions-documentation).
- [Motorola 68000 CPU Opcodes](http://goldencrystal.free.fr/M68kOpcodes-v2.3.pdf).
- GNU assembler (GNU Binutils) 2.40 (`m68k-none-elf-as`).
- GNU objdump (GNU Binutils) 2.40 (`m68k-none-elf-objdump`).

## Contributing

Coming soon.

<!-- Markdown link & img dfn's -->
[readme-template]: https://github.com/dbader/readme-template
