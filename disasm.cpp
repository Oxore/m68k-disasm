#include "disasm.h"
#include "data_buffer.h"
#include "common.h"

#include <cstdio>
#include <cstdlib>

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

static size_t disasm_jsr(
        char *out, size_t out_sz, size_t *instr_sz, uint16_t instr, uint32_t offset, const DataBuffer & code)
{
    return disasm_jsr_jmp(out, out_sz, instr_sz, instr, offset, code, JsrJmp::kJsr);
}

static size_t disasm_jmp(
        char *out, size_t out_sz, size_t *instr_sz, uint16_t instr, uint32_t offset, const DataBuffer & code)
{
    return disasm_jsr_jmp(out, out_sz, instr_sz, instr, offset, code, JsrJmp::kJmp);
}

enum class Condition {
    kT = 0,
    kF = 1,
    kHI = 2,
    kLS = 3,
    kCC = 4,
    kCS = 5,
    kNE = 6,
    kEQ = 7,
    kVC = 8,
    kVS = 9,
    kPL = 10,
    kMI = 11,
    kGE = 12,
    kLT = 13,
    kGT = 14,
    kLE = 15,
};

static inline const char *branch_instr_name_by_cond(Condition condition)
{
    switch (condition) {
    case Condition::kT:  return "bra"; // 60xx
    case Condition::kF:  return "bsr"; // 61xx
    case Condition::kHI: return "bhi"; // 62xx
    case Condition::kLS: return "bls"; // 63xx
    case Condition::kCC: return "bcc"; // 64xx
    case Condition::kCS: return "bcs"; // 65xx
    case Condition::kNE: return "bne"; // 66xx
    case Condition::kEQ: return "beq"; // 67xx
    case Condition::kVC: return "bvc"; // 68xx
    case Condition::kVS: return "bvs"; // 69xx
    case Condition::kPL: return "bpl"; // 6axx
    case Condition::kMI: return "bmi"; // 6bxx
    case Condition::kGE: return "bge"; // 6cxx
    case Condition::kLT: return "blt"; // 6dxx
    case Condition::kGT: return "bgt"; // 6exx
    case Condition::kLE: return "ble"; // 6fxx
    }
    return "?";
}

static size_t disasm_bra_bsr_bcc(
        char *out, size_t out_sz, size_t *instr_sz, uint16_t instr, uint32_t offset, const DataBuffer & code)
{
    const char *mnemonic = branch_instr_name_by_cond(static_cast<Condition>((instr >> 8) & 0xf));
    int dispmt = static_cast<int8_t>(instr & 0xff);
    const char *size_spec = "s";
    if (dispmt == 0) {
        dispmt = GetI16BE(code.buffer + offset + kInstructionSizeStepBytes);
        if (instr_sz) {
            *instr_sz = kInstructionSizeStepBytes * 2;
        }
        size_spec = "w";
    } else {
        if (instr_sz) {
            *instr_sz = kInstructionSizeStepBytes;
        }
    }
    dispmt += kInstructionSizeStepBytes;
    const char * const sign = dispmt >= 0 ? "+" : "";
    return Min(out_sz, snprintf(out, out_sz, "  %s%s .%s%d", mnemonic, size_spec, sign, dispmt));
}

size_t m68k_disasm(
        char *out, size_t out_sz, size_t *instr_sz, uint16_t instr, uint32_t offset, const DataBuffer &code)
{
    if ((instr & 0xfff0) == 0x4e70) {
        return disasm_mfff0_v4e70(out, out_sz, instr_sz, instr, offset, code);
    } else if ((instr & 0xffc0) == 0x4e80) {
        return disasm_jsr(out, out_sz, instr_sz, instr, offset, code);
    } else if ((instr & 0xffc0) == 0x4ec0) {
        return disasm_jmp(out, out_sz, instr_sz, instr, offset, code);
    } else if ((instr & 0xf000) == 0x6000) {
        return disasm_bra_bsr_bcc(out, out_sz, instr_sz, instr, offset, code);
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
