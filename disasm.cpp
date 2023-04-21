#include "disasm.h"
#include "data_buffer.h"
#include "common.h"

#include <cstdio>

static size_t disasm_verbatim(
        char *out, size_t out_sz, size_t *instr_sz, uint16_t instr, uint32_t, const DataBuffer &)
{
    if (instr_sz) {
        *instr_sz = kInstructionSizeStepBytes;
    }
    return Min(out_sz, snprintf(out, out_sz, "  .short 0x%04x", instr));
}

static size_t disasm_mfff0_v4e70(
        char *out, size_t out_sz, size_t *instr_sz, uint16_t instr, uint32_t offset, const DataBuffer &code)
{
    if (instr_sz) {
        *instr_sz = kInstructionSizeStepBytes;
    }
    if (instr == 0x4e70) {
        return Min(out_sz, snprintf(out, out_sz, "  reset"));
    } else if (instr == 0x4e71) {
        return Min(out_sz, snprintf(out, out_sz, "  nop"));
    } else if (instr == 0x4e73) {
        return Min(out_sz, snprintf(out, out_sz, "  rte"));
    } else if (instr == 0x4e75) {
        return Min(out_sz, snprintf(out, out_sz, "  rts"));
    } else if (instr == 0x4e76) {
        return Min(out_sz, snprintf(out, out_sz, "  trapv"));
    } else if (instr == 0x4e77) {
        return Min(out_sz, snprintf(out, out_sz, "  rtr"));
    }
    return disasm_verbatim(out, out_sz, instr_sz, instr, offset, code);
}

enum class JsrJmp {
    kJsr,
    kJmp,
};

static size_t disasm_jsr_jmp(
        char *out, size_t out_sz, size_t *instr_sz, uint16_t instr, uint32_t offset, const DataBuffer & code, JsrJmp jsrjmp)
{
    const char *instr_repr = (jsrjmp == JsrJmp::kJsr) ? "jsr" : "jmp";
    const int addrmode = instr & 0x3f;
    const int m = (addrmode >> 3) & 0x7;
    const int xn = addrmode & 0x7;
    switch (m) {
    case 0: // 4e80 .. 4e87
    case 1: // 4e88 .. 4e8f
        break;
    case 2: // 4e90 .. 4e97
        if (instr_sz) {
            *instr_sz = kInstructionSizeStepBytes;
        }
        return Min(out_sz, snprintf(out, out_sz, "  %s %%a%d@", instr_repr, xn));
    case 3: // 4e98 .. 4e9f
    case 4: // 4ea0 .. 4ea7
        break;
    case 5: // 4ea8 .. 4eaf, Displacement
        {
            if (instr_sz) {
                *instr_sz = kInstructionSizeStepBytes * 2;
            }
            const int16_t dispmt = GetI16BE(code.buffer + offset + kInstructionSizeStepBytes);
            return Min(out_sz, snprintf(out, out_sz, "  %s %%a%d@(%d:w)", instr_repr, xn, dispmt));
        }
    case 6: // 4eb0 .. 4eb7, Brief Extension Word
        {
            if (instr_sz) {
                *instr_sz = kInstructionSizeStepBytes * 2;
            }
            const uint16_t briefext = GetU16BE(code.buffer + offset + kInstructionSizeStepBytes);
            const char reg = ((briefext >> 15) & 1) ? 'a' : 'd';
            const int xn2 = (briefext >> 12) & 7;
            const char size_spec = ((briefext >> 11) & 1) ? 'l' : 'w';
            const int8_t dispmt = briefext & 0xff;
            return Min(out_sz, snprintf(
                        out, out_sz, "  %s %%a%d@(%d,%%%c%d:%c)",
                        instr_repr, xn, dispmt, reg, xn2, size_spec));
        }
    case 7: // 4eb8 .. 4ebf, some are with Brief Extension Word
        switch (xn) {
        case 0: // 4eb8 (xxx).W
            {
                if (instr_sz) {
                    *instr_sz = kInstructionSizeStepBytes * 2;
                }
                const int32_t dispmt = GetI16BE(code.buffer + offset + kInstructionSizeStepBytes);
                return Min(out_sz, snprintf(out, out_sz, "  %s 0x%x:w", instr_repr, dispmt));
            }
        case 1: // 4eb9 (xxx).L
            {
                if (instr_sz) {
                    *instr_sz = kInstructionSizeStepBytes * 3;
                }
                const int32_t dispmt = GetI32BE(code.buffer + offset + kInstructionSizeStepBytes);
                return Min(out_sz, snprintf(out, out_sz, "  %s 0x%x:l", instr_repr, dispmt));
            }
        case 2: // 4eba, Displacement
            {
                if (instr_sz) {
                    *instr_sz = kInstructionSizeStepBytes * 2;
                }
                const int16_t dispmt = GetI16BE(code.buffer + offset + kInstructionSizeStepBytes);
                return Min(out_sz, snprintf(out, out_sz, "  %s %%pc@(%d:w)", instr_repr, dispmt));
            }
        case 3: // 4ebb
            {
                if (instr_sz) {
                    *instr_sz = kInstructionSizeStepBytes * 2;
                }
                const uint16_t briefext = GetU16BE(
                        code.buffer + offset + kInstructionSizeStepBytes);
                const char reg = ((briefext >> 15) & 1) ? 'a' : 'd';
                const int xn2 = (briefext >> 12) & 7;
                const char size_spec = ((briefext >> 11) & 1) ? 'l' : 'w';
                const int8_t dispmt = briefext & 0xff;
                return Min(out_sz, snprintf(
                            out, out_sz, "  %s %%pc@(%d,%%%c%d:%c)", instr_repr, dispmt, reg, xn2, size_spec));
            }
        case 4: // 4ebc
        case 5: // 4ebd
        case 6: // 4ebe
            break;
        }
        break;
    }
    return disasm_verbatim(out, out_sz, instr_sz, instr, offset, code);
}

size_t m68k_disasm(
        char *out, size_t out_sz, size_t *instr_sz, uint16_t instr, uint32_t offset, const DataBuffer &code)
{
    if ((instr & 0xfff0) == 0x4e70) {
        return disasm_mfff0_v4e70(out, out_sz, instr_sz, instr, offset, code);
    } else if ((instr & 0xffc0) == 0x4e80) {
        return disasm_jsr_jmp(out, out_sz, instr_sz, instr, offset, code, JsrJmp::kJsr);
    } else if ((instr & 0xffc0) == 0x4ec0) {
        return disasm_jsr_jmp(out, out_sz, instr_sz, instr, offset, code, JsrJmp::kJmp);
    }
    return disasm_verbatim(out, out_sz, instr_sz, instr, offset, code);
}

size_t m68k_render_raw_data_comment(
        char *out, size_t out_sz, uint32_t offset, size_t instr_sz, const DataBuffer &code)
{
    size_t overall_sz = Min(out_sz, snprintf(out, out_sz, " |"));
    for (size_t i = 0; i < instr_sz; i += kInstructionSizeStepBytes)
    {
        overall_sz += Min(
                out_sz - overall_sz,
                snprintf(
                    out + overall_sz,
                    out_sz - overall_sz,
                    " %04x",
                    GetU16BE(code.buffer + offset + i)));
    }
    overall_sz += Min(
            out_sz - overall_sz,
            snprintf(out + overall_sz, out_sz - overall_sz, " @%08x", offset));
    return overall_sz;
}
