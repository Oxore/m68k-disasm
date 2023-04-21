#pragma once

#include "data_buffer.h"

#include <cstddef>
#include <cstdint>

size_t m68k_disasm(
        char *out,
        size_t out_sz,
        size_t *instr_sz,
        uint16_t instr,
        uint32_t offset,
        const DataBuffer &code);

size_t m68k_render_raw_data_comment(
        char *out,
        size_t out_sz,
        uint32_t offset,
        size_t instr_sz,
        const DataBuffer &code);
