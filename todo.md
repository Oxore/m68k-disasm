# TODO

- Add tests for relocations with all supported addressing modes.
- Implement CLI option that can be used to specify regions of RAM and IO
  registers. Custom ROM location and size is still not the case, only 4MiB at
  the base `0x00000000` is supported and it remains.
- Implement address substitution with some symbol instead of raw offset on all
  instructions, that support `Word`, `Long`, `(d16,PC)` or relative displacement
  addressing modes. Also substitute `immediate` values if they are look like an
  address in the RAM, or other predefined location, but not ROM. Assume 24 bit
  address space.
