# TODO

Some thoughts about features that may be useful, but are either too complex to
be implemented right off the bat, or of a doubtful necessity.

- Fix immediate arguments to match the operand type. E.g.:

	andiw #0xffffc000,%d0 | 0240 c000 @0002e1dc

should be

	andiw #0xc000,%d0 | 0240 c000 @0002e1dc

- Add support for `DWARF` formats to split an `ELF` file into multiple
  original assembly files. These files may not be assembly files originally, but
  they will become after decompilation.
- Implement RAM symbol mapping from raw addresses found in the instructions like
  LEA, MOVE and address arithmetic instructions. Basically any direct RAM
  address accessed directly may be mapped as symbol. A hashmap is most likely
  necessary for this.
- Implement CLI option that can be used to specify regions of RAM and IO
  registers. Custom ROM location and size is still not the case, only 4MiB at
  the base `0x00000000` is supported and it remains.
