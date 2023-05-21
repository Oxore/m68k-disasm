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

## Current state

### Features

- All M68000 instructions supported
- It generates GNU AS compatible listing, that may be translated back to machine
  code using `m68k-none-elf-as` in the way that it matches original binary file,
  no matter what.
- It generates labels (marks) for all jump instructions (JSR, JMP, BRA, Bcc and
  DBcc) if jump location is inside the code being disassembled. This feature can
  be enabled with `-fmarks`, `-frel-marks` and `-fabs-marks` options, all at
  once. It also generates marks for some data accessing instructions (namely:
  NBCD, PEA, LEA, CMP, SUB, ADD, MOVEM and MOVE) and this behavior enabled with
  the same options as per jump instructions. It is possible to implement this
  for all of the rest instructions, but it just has to be done if someone needs
  it.

### Limitations

- Motorola 68000 only supported. That means no 68010 support or any 680x0,
  except 68000. No ColdFire support.
- Code must be aligned to 2 bytes boundary. All PC trace values have to be
  dividable by 2 without remaining. That limitation has been put into design
  from the beginning, because 68000 cannot perform unaligned `word` and `long`
  memory access, including instruction fetch. This is not true for some of 680x0
  variations.
- Base address is always assumed to be `0x00000000`.
- Maximum binary size is 4MiB.
- Labels/marks for locations outside of the code being disassembled are not
  generated, they remain as raw address arguments and/or PC-relative offset
  arguments.

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

This repository includes source code of other projects:
- Optparse ([gh:skeeto/optparse](https://github.com/skeeto/optparse)) - Unlicense

Resources used to implement the disassember (this set is more than sufficient to
support all of M68000 instructions):
- [The 68000's Instruction Set](http://wpage.unina.it/rcanonic/didattica/ce1/docs/68000.pdf) - Appendix of an unrecognized book. Basically the same information also could be found in [gh:prb28/m68k-instructions-documentation](https://github.com/prb28/m68k-instructions-documentation).
- [Motorola 68000 CPU Opcodes](http://goldencrystal.free.fr/M68kOpcodes-v2.3.pdf).
- GNU assembler (GNU Binutils) 2.40 (`m68k-none-elf-as`).
- GNU objdump (GNU Binutils) 2.40 (`m68k-none-elf-objdump`).

## Contributing

I will eventually put this repo on GitHub, I guess. You can create issues and
pull requests there. You can [email me](mailto:oxore@protonmail.com) directly to
ask a question, send a patch or discuss problems if you prefer this over GitHub.

I decided to go without code formatting standard for now. Just be nice to not
mix up spaces with tabs (use spaces everywhere) if you are sending patch or
pull request and that's it.

C++ STL is not welcomed here. Almost every STL header (besides C standard
library wrappers like `cstring` or `cstdio`) increases compilation times
significantly. This disassembler is used to be developed on Celeron N4000
machine with eMMC memory instead of SSD and it is very sensitive to STL bullshit
increasing compile times. Please, make sure you don't use any compile time heavy
headers. If you really need something like hashmap or RB-tree, then bring some
tiny MIT/BSD/Unlicense library from somewhere or write it yourself.

Run tests when the work is done to make sure you didn't break anything.

<!-- Markdown link & img dfn's -->
[readme-template]: https://github.com/dbader/readme-template
