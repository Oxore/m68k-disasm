#include "disasm.h"
#include "data_buffer.h"
#include "common.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>

enum class AddrMode: uint8_t {
    kInvalid = 0,
    kDn,
    kAn,
    kAnAddr,
    kAnAddrIncr,
    kAnAddrDecr,
    kD16AnAddr,
    kD8AnXiAddr,
    kWord,
    kLong,
    kD16PCAddr,
    kD8PCXiAddr,
    kImmediate,
};

struct AddrModeArg {
    AddrMode mode{};
    uint8_t m{};
    uint8_t xn{}; /// Xn register number: 0..7
    char r{}; /// Xi register type specifier letter: either 'd' or 'a'
    uint8_t xi{}; /// Xi register number: 0..7
    char s{}; /// Size spec letter of Xi: either 'w' or 'l'
    int32_t value{}; /// Word, Long or Immediate
    /// Size of the extension: 0, 2 or 4 bytes
    constexpr size_t Size() const
    {
        switch (mode) {
        case AddrMode::kInvalid:
        case AddrMode::kDn:
        case AddrMode::kAn:
        case AddrMode::kAnAddr:
        case AddrMode::kAnAddrIncr:
        case AddrMode::kAnAddrDecr:
            return 0;
        case AddrMode::kD16AnAddr:
        case AddrMode::kD8AnXiAddr:
        case AddrMode::kWord:
            return 2;
        case AddrMode::kLong:
            return 4;
        case AddrMode::kD16PCAddr:
        case AddrMode::kD8PCXiAddr:
            return 2;
        case AddrMode::kImmediate:
            // TODO I don't know, need to figure out
            return 2;
        }
        return 0;
    }
    static constexpr AddrModeArg Dn(uint8_t m, uint8_t xn)
    {
        return AddrModeArg{AddrMode::kDn, m, xn};
    }
    static constexpr AddrModeArg An(uint8_t m, uint8_t xn)
    {
        return AddrModeArg{AddrMode::kAn, m, xn};
    }
    static constexpr AddrModeArg AnAddr(uint8_t m, uint8_t xn)
    {
        return AddrModeArg{AddrMode::kAnAddr, m, xn};
    }
    static constexpr AddrModeArg AnAddrIncr(uint8_t m, uint8_t xn)
    {
        return AddrModeArg{AddrMode::kAnAddrIncr, m, xn};
    }
    static constexpr AddrModeArg AnAddrDecr(uint8_t m, uint8_t xn)
    {
        return AddrModeArg{AddrMode::kAnAddrDecr, m, xn};
    }
    static constexpr AddrModeArg D16AnAddr(uint8_t m, uint8_t xn, int16_t d16)
    {
        return AddrModeArg{AddrMode::kD16AnAddr, m, xn, 0, 0, 0, d16};
    }
    static constexpr AddrModeArg D8AnXiAddr(
            uint8_t m, uint8_t xn, char r, uint8_t xi, char s, int8_t d8)
    {
        return AddrModeArg{AddrMode::kD8AnXiAddr, m, xn, r, xi, s, d8};
    }
    static constexpr AddrModeArg Word(uint8_t m, uint8_t xn, int16_t w)
    {
        return AddrModeArg{AddrMode::kWord, m, xn, 0, 0, 0, w};
    }
    static constexpr AddrModeArg Long(uint8_t m, uint8_t xn, int32_t l)
    {
        return AddrModeArg{AddrMode::kLong, m, xn, 0, 0, 0, l};
    }
    static constexpr AddrModeArg D16PCAddr(uint8_t m, uint8_t xn, int16_t d16)
    {
        return AddrModeArg{AddrMode::kD16PCAddr, m, xn, 0, 0, 0, d16};
    }
    static constexpr AddrModeArg D8PCXiAddr(
            uint8_t m, uint8_t xn, char r, uint8_t xi, char s, int8_t d8)
    {
        return AddrModeArg{AddrMode::kD8PCXiAddr, m, xn, r, xi, s, d8};
    }
    static constexpr AddrModeArg Immediate(uint8_t m, uint8_t xn, int32_t value)
    {
        return AddrModeArg{AddrMode::kImmediate, m, xn, 0, 0, 0, value};
    }
    static constexpr AddrModeArg Fetch(
            const uint32_t offset, const DataBuffer &code, int16_t instr)
    {
        const int addrmode = instr & 0x3f;
        const int m = (addrmode >> 3) & 0x7;
        const int xn = addrmode & 0x7;
        return Fetch(offset, code, m, xn);
    }
    static constexpr AddrModeArg Fetch(
            const uint32_t offset, const DataBuffer &code, const int m, const int xn);
    int SNPrint(char *const buf, const size_t bufsz) const
    {
        switch (mode) {
        case AddrMode::kInvalid:
            assert(false);
            break;
        case AddrMode::kDn:
            return snprintf(buf, bufsz, "%%d%d", xn);
        case AddrMode::kAn:
            return snprintf(buf, bufsz, "%%a%d", xn);
        case AddrMode::kAnAddr:
            return snprintf(buf, bufsz, "%%a%d@", xn);
        case AddrMode::kAnAddrIncr:
            return snprintf(buf, bufsz, "%%a%d@+", xn);
        case AddrMode::kAnAddrDecr:
            return snprintf(buf, bufsz, "%%a%d@-", xn);
        case AddrMode::kD16AnAddr:
            return snprintf(buf, bufsz, "%%a%d@(%d:w)", xn, value);
        case AddrMode::kD8AnXiAddr:
            return snprintf(buf, bufsz, "%%a%d@(%d,%%%c%d:%c)", xn, value, r, xi, s);
        case AddrMode::kWord:
            return snprintf(buf, bufsz, "0x%x:w", value);
        case AddrMode::kLong:
            return snprintf(buf, bufsz, "0x%x:l", value);
        case AddrMode::kD16PCAddr:
            return snprintf(buf, bufsz, "%%pc@(%d:w)", value);
        case AddrMode::kD8PCXiAddr:
            return snprintf(buf, bufsz, "%%pc@(%d,%%%c%d:%c)", value, r, xi, s);
        case AddrMode::kImmediate:
            return snprintf(buf, bufsz, "#%d", value);
        }
        assert(false);
        return -1;
    };
};

constexpr AddrModeArg AddrModeArg::Fetch(
        const uint32_t offset, const DataBuffer &code, const int m, const int xn)
{
    switch (m) {
    case 0: // Dn
        return AddrModeArg::Dn(m, xn);
    case 1: // An
        return AddrModeArg::An(m, xn);
    case 2: // (An)
        return AddrModeArg::AnAddr(m, xn);
    case 3: // (An)+
        return AddrModeArg::AnAddrIncr(m, xn);
    case 4: // -(An)
        return AddrModeArg::AnAddrDecr(m, xn);
    case 5: // (d16, An), Additional Word
        if (offset < code.occupied_size) {
            const int16_t d16 = GetI16BE(code.buffer + offset);
            return AddrModeArg::D16AnAddr(m, xn, d16);
        }
        break;
    case 6: // (d8, An, Xi), Brief Extension Word
        if (offset < code.occupied_size) {
            const uint16_t briefext = GetU16BE(code.buffer + offset);
            if (briefext & 0x0700) {
                // briefext must have zeros on 8, 9 an 10-th bits,
                // i.e. xxxx_x000_xxxx_xxxx
                break;
            }
            const char r = ((briefext >> 15) & 1) ? 'a' : 'd';
            const uint8_t xi = (briefext >> 12) & 7;
            const char s = ((briefext >> 11) & 1) ? 'l' : 'w';
            const int8_t d8 = briefext & 0xff;
            return AddrModeArg::D8AnXiAddr(m, xn, r, xi, s, d8);
        }
        break;
    case 7:
        switch (xn) {
        case 0: // (xxx).W, Additional Word
            if (offset < code.occupied_size) {
                const int32_t w = GetI16BE(code.buffer + offset);
                return AddrModeArg::Word(m, xn, w);
            }
            break;
        case 1: // (xxx).L, Additional Long
            if (offset < code.occupied_size) {
                const int32_t l = GetI32BE(code.buffer + offset);
                return AddrModeArg::Long(m, xn, l);
            }
            break;
        case 2: // (d16, PC), Additional Word
            if (offset < code.occupied_size) {
                const int16_t d16 = GetI16BE(code.buffer + offset);
                return AddrModeArg::D16PCAddr(m, xn, d16);
            }
            break;
        case 3: // (d8, PC, Xi), Brief Extension Word
            if (offset < code.occupied_size) {
                const uint16_t briefext = GetU16BE(code.buffer + offset);
                if (briefext & 0x0700) {
                    // briefext must have zeros on 8, 9 an 10-th bits,
                    // i.e. xxxx_x000_xxxx_xxxx
                    return AddrModeArg{};
                }
                const char r = ((briefext >> 15) & 1) ? 'a' : 'd';
                const uint8_t xi = (briefext >> 12) & 7;
                const char s = ((briefext >> 11) & 1) ? 'l' : 'w';
                const int8_t d8 = briefext & 0xff;
                return AddrModeArg::D8PCXiAddr(m, xn, r, xi, s, d8);
            }
            break;
        case 4: // #imm
            // TODO
            return AddrModeArg{};
        case 5: // Does not exist
        case 6: // Does not exist
        case 7: // Does not exist
            break;
        }
        break;
    }
    return AddrModeArg{};
}

static void disasm_verbatim(
        DisasmNode& node, uint16_t instr, const DataBuffer &, const Settings &)
{
    node.size = kInstructionSizeStepBytes;
    snprintf(node.mnemonic, kMnemonicBufferSize, ".short");
    snprintf(node.arguments, kArgsBufferSize, "0x%04x", instr);
}

enum class JsrJmp {
    kJsr,
    kJmp,
};

static void disasm_jsr_jmp(
        DisasmNode& node, uint16_t instr, const DataBuffer &code, const Settings &s, JsrJmp jsrjmp)
{
    const auto a = AddrModeArg::Fetch(node.offset + kInstructionSizeStepBytes, code, instr);
    switch (a.mode) {
    case AddrMode::kInvalid:
    case AddrMode::kDn: // 4e80..4e87 / 4ec0..4ec7
    case AddrMode::kAn: // 4e88..4e8f / 4ec8..4ecf
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kAnAddr: // 4e90..4e97 / 4ed0..4ed7
        // NOTE: dynamic jump, branch_addr may possibly be obtained during the
        // trace
        break;
    case AddrMode::kAnAddrIncr: // 4e98..4e9f / 4ed8..4edf
    case AddrMode::kAnAddrDecr: // 4ea0..4ea7 / 4ee0..4ee7
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kD16AnAddr: // 4ea8..4eaf / 4ee8..4eef
        // NOTE: dynamic jump, branch_addr may possibly be obtained during the
        // trace
        break;
    case AddrMode::kD8AnXiAddr: // 4eb0..4eb7 / 4ef0..4ef7
        // NOTE: dynamic jump, branch_addr may possibly be obtained during the
        // trace
        break;
    case AddrMode::kWord: // 4eb8 / 4ef8
        {
            // FIXME support s.abs_marks option for this instruction
            const uint32_t branch_addr = static_cast<uint32_t>(a.value);
            node.branch_addr = branch_addr;
            node.has_branch_addr = true;
        }
        break;
    case AddrMode::kLong: // 4eb9 / 4ef9
        {
            // FIXME support s.abs_marks option for this instruction
            const uint32_t branch_addr = static_cast<uint32_t>(a.value);
            node.branch_addr = branch_addr;
            node.has_branch_addr = true;
        }
        break;
    case AddrMode::kD16PCAddr: // 4eba / 4efa
        {
            // FIXME support s.abs_marks option for this instruction
            const uint32_t branch_addr = static_cast<uint32_t>(a.value) + kInstructionSizeStepBytes;
            node.branch_addr = branch_addr;
            node.has_branch_addr = true;
        }
        break;
    case AddrMode::kD8PCXiAddr: // 4ebb / 4efb
        // NOTE: dynamic jump, branch_addr may possibly be obtained during the
        // trace
        break;
    case AddrMode::kImmediate: // 4ebc / 4efc
        return disasm_verbatim(node, instr, code, s);
    }
    node.is_call = (jsrjmp == JsrJmp::kJsr);
    node.size = kInstructionSizeStepBytes + a.Size();
    const char *mnemonic = (jsrjmp == JsrJmp::kJsr) ? "jsr" : "jmp";
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s", mnemonic);
    const int ret = a.SNPrint(node.arguments, kArgsBufferSize);
    assert(ret > 0);
    (void) ret;
}

static void disasm_jsr(
        DisasmNode& node, uint16_t instr, const DataBuffer &code, const Settings &s)
{
    return disasm_jsr_jmp(node, instr, code, s, JsrJmp::kJsr);
}

static void disasm_jmp(
        DisasmNode& node, uint16_t instr, const DataBuffer &code, const Settings &s)
{
    return disasm_jsr_jmp(node, instr, code, s, JsrJmp::kJmp);
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

static inline const char *bcc_mnemonic_by_condition(Condition condition)
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
    assert(false);
    return "?";
}

static void disasm_bra_bsr_bcc(
        DisasmNode& node, uint16_t instr, const DataBuffer &code, const Settings &s)
{
    Condition condition = static_cast<Condition>((instr >> 8) & 0xf);
    const char *mnemonic = bcc_mnemonic_by_condition(condition);
    // False condition Indicates BSR
    int dispmt = static_cast<int8_t>(instr & 0xff);
    if (dispmt % kInstructionSizeStepBytes) {
        return disasm_verbatim(node, instr, code, s);
    }
    const char *size_spec = "s";
    if (dispmt == 0) {
        dispmt = GetI16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
        if (dispmt % kInstructionSizeStepBytes) {
            return disasm_verbatim(node, instr, code, s);
        }
        node.size = kInstructionSizeStepBytes * 2;
        size_spec = "w";
    } else {
        node.size = kInstructionSizeStepBytes;
    }
    node.is_call = (condition == Condition::kF);
    dispmt += kInstructionSizeStepBytes;
    const uint32_t branch_addr = static_cast<uint32_t>(node.offset + dispmt);
    node.branch_addr = branch_addr;
    node.has_branch_addr = true;
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s%s", mnemonic, size_spec);
    const char * const sign = dispmt >= 0 ? "+" : "";
    // FIXME support s.rel_marks option for this instruction
    snprintf(node.arguments, kArgsBufferSize, ".%s%d", sign, dispmt);
    return;
}

static void chunk_mf000_v0000(DisasmNode& n, uint16_t i, const DataBuffer &c, const Settings &s)
{
    return disasm_verbatim(n, i, c, s);
}

static void chunk_mf000_v1000(DisasmNode& n, uint16_t i, const DataBuffer &c, const Settings &s)
{
    return disasm_verbatim(n, i, c, s);
}

static void chunk_mf000_v2000(DisasmNode& n, uint16_t i, const DataBuffer &c, const Settings &s)
{
    return disasm_verbatim(n, i, c, s);
}

static void chunk_mf000_v3000(DisasmNode& n, uint16_t i, const DataBuffer &c, const Settings &s)
{
    return disasm_verbatim(n, i, c, s);
}

static void chunk_mf000_v4000(DisasmNode& node, uint16_t i, const DataBuffer &c, const Settings &s)
{
    if (i == 0x4e70) {
        node.size = kInstructionSizeStepBytes;
        snprintf(node.mnemonic, kMnemonicBufferSize, "reset");
        return;
    } else if (i == 0x4e71) {
        node.size = kInstructionSizeStepBytes;
        snprintf(node.mnemonic, kMnemonicBufferSize, "nop");
        return;
    } else if (i == 0x4e73) {
        node.size = kInstructionSizeStepBytes;
        snprintf(node.mnemonic, kMnemonicBufferSize, "rte");
        return;
    } else if (i == 0x4e75) {
        node.size = kInstructionSizeStepBytes;
        snprintf(node.mnemonic, kMnemonicBufferSize, "rts");
        return;
    } else if (i == 0x4e76) {
        node.size = kInstructionSizeStepBytes;
        snprintf(node.mnemonic, kMnemonicBufferSize, "trapv");
        return;
    } else if (i == 0x4e77) {
        node.size = kInstructionSizeStepBytes;
        snprintf(node.mnemonic, kMnemonicBufferSize, "rtr");
        return;
    } else if ((i & 0xffc0) == 0x4e80) {
        return disasm_jsr(node, i, c, s);
    } else if ((i & 0xffc0) == 0x4ec0) {
        return disasm_jmp(node, i, c, s);
    }
    return disasm_verbatim(node, i, c, s);
}

enum class OpSize {
    kByte = 0,
    kWord = 1,
    kLong = 2,
    kInvalid = 3,
};

static char suffix_from_opsize(OpSize opsize)
{
    switch (opsize) {
    case OpSize::kByte: return 'b';
    case OpSize::kWord: return 'w';
    case OpSize::kLong: return 'l';
    case OpSize::kInvalid: return 'l';
    }
    return 'l';
}

static void disasm_addq_subq(
        DisasmNode& node, uint16_t instr, const DataBuffer &code, const Settings &s, int m, OpSize opsize)
{
    const char *mnemonic = (instr >> 8) & 1 ? "subq" : "addq";
    const char suffix = suffix_from_opsize(opsize);
    const unsigned imm = ((uint8_t((instr >> 9) & 7) - 1) & 7) + 1;
    const int xn = (instr & 7);
    switch (m) {
    case 0: // 5x00..5x07 / 5x40..5x47 / 5x80..5x87, Dn
        node.size = kInstructionSizeStepBytes;
        snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
        snprintf(node.arguments, kArgsBufferSize, "#%u,%%d%d", imm, xn);
        return;
    case 1: // 5x08..5x0f / 5x48..5x4f / 5x88..5x8f, An
        if (opsize == OpSize::kByte) {
            // 5x08..5x0f
            // addqb and subqb with An do not exist
            return disasm_verbatim(node, instr, code, s);
        }
        node.size = kInstructionSizeStepBytes;
        snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
        snprintf(node.arguments, kArgsBufferSize, "#%u,%%a%d", imm, xn);
        return;
    case 2: // 5x10..5x17 / 5x50..5x57 / 5x90..5x97, (An)
        node.size = kInstructionSizeStepBytes;
        snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
        snprintf(node.arguments, kArgsBufferSize, "#%u,%%a%d@", imm, xn);
        return;
    case 3: // 5x18..5x1f / 5x58..5x5f / 5x98..5x9f, (An)+
        node.size = kInstructionSizeStepBytes;
        snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
        snprintf(node.arguments, kArgsBufferSize, "#%u,%%a%d@+", imm, xn);
        return;
    case 4: // 5x20..5x27 / 5x60..5x67 / 5xa0..5xa7, -(An)
        node.size = kInstructionSizeStepBytes;
        snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
        snprintf(node.arguments, kArgsBufferSize, "#%u,%%a%d@-", imm, xn);
        return;
    case 5: // 5x28..5x2f / 5x68..5x6f / 5xa8..5xaf, (d16, An), Displacement Word
        if (node.offset + kInstructionSizeStepBytes < code.occupied_size) {
            node.size = kInstructionSizeStepBytes * 2;
            snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
            const int16_t dispmt = GetI16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
            snprintf(node.arguments, kArgsBufferSize, "#%u,%%a%d@(%d:w)", imm, xn, dispmt);
            return;
        }
        break;
    case 6: // 5x30..5x37 / 5x70..5x77 / 5xb0..5xb7, (d16, An, Xi), Brief Extension Word
        if (node.offset + kInstructionSizeStepBytes < code.occupied_size) {
            node.size = kInstructionSizeStepBytes * 2;
            snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
            const uint16_t briefext = GetU16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
            if (briefext & 0x0700) {
                // briefext must have zeros on 8, 9 an 10-th bits,
                // i.e. xxxx_x000_xxxx_xxxx
                break;
            }
            const char reg = ((briefext >> 15) & 1) ? 'a' : 'd';
            const int xi = (briefext >> 12) & 7;
            const char size_spec = ((briefext >> 11) & 1) ? 'l' : 'w';
            const int8_t dispmt = briefext & 0xff;
            snprintf(node.arguments, kArgsBufferSize,
                    "#%u,%%a%d@(%d,%%%c%d:%c)", imm, xn, dispmt, reg, xi, size_spec);
            return;
        }
        break;
    case 7: // 5x38..5x3f / 5x78..5x7f / 5xb8..5xbf
        switch (xn) {
        case 0: // 5x38 / 5x78 / 5xb8 (xxx).W
            if (node.offset + kInstructionSizeStepBytes < code.occupied_size) {
                node.size = kInstructionSizeStepBytes * 2;
                snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
                // This shit is real: it is sign extend value
                const int32_t dispmt = GetI16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
                snprintf(node.arguments, kArgsBufferSize, "#%u,0x%x:w", imm, dispmt);
                return;
            }
            break;
        case 1: // 5x39 / 5x79 / 5xb9 (xxx).L
            if (node.offset + kInstructionSizeStepBytes < code.occupied_size) {
                node.size = kInstructionSizeStepBytes * 3;
                snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
                const int32_t dispmt = GetI32BE(code.buffer + node.offset + kInstructionSizeStepBytes);
                snprintf(node.arguments, kArgsBufferSize, "#%u,0x%x:l", imm, dispmt);
                return;
            }
            break;
        case 2: // 5x3a / 5x7a / 5xba
        case 3: // 5x3b / 5x7b / 5xbb
        case 4: // 5x3c / 5x7c / 5xbc
        case 5: // 5x3d / 5x7d / 5xbd
        case 6: // 5x3e / 5x7e / 5xbe
            // Does not exist
            break;
        }
        break;
    }
    return disasm_verbatim(node, instr, code, s);
}

static inline const char *scc_mnemonic_by_condition(Condition condition)
{
    switch (condition) {
    case Condition::kT:  return "st";  // 50cx..50fx
    case Condition::kF:  return "sf";  // 51cx..51fx
    case Condition::kHI: return "shi"; // 52cx..52fx
    case Condition::kLS: return "sls"; // 53cx..53fx
    case Condition::kCC: return "scc"; // 54cx..54fx
    case Condition::kCS: return "scs"; // 55cx..55fx
    case Condition::kNE: return "sne"; // 56cx..56fx
    case Condition::kEQ: return "seq"; // 57cx..57fx
    case Condition::kVC: return "svc"; // 58cx..58fx
    case Condition::kVS: return "svs"; // 59cx..59fx
    case Condition::kPL: return "spl"; // 5acx..5afx
    case Condition::kMI: return "smi"; // 5bcx..5bfx
    case Condition::kGE: return "sge"; // 5ccx..5cfx
    case Condition::kLT: return "slt"; // 5dcx..5dfx
    case Condition::kGT: return "sgt"; // 5ecx..5efx
    case Condition::kLE: return "sle"; // 5fcx..5ffx
    }
    assert(false);
    return "?";
}

static void disasm_scc(
        DisasmNode& node, const uint16_t instr, const DataBuffer &code, const Settings &s, const int m)
{
    Condition condition = static_cast<Condition>((instr >> 8) & 0xf);
    const char *mnemonic = scc_mnemonic_by_condition(condition);
    const int xn = (instr & 7);
    switch (m) {
    case 0: // 5xc0..5xc7, Dn
        node.size = kInstructionSizeStepBytes;
        snprintf(node.mnemonic, kMnemonicBufferSize, mnemonic);
        snprintf(node.arguments, kArgsBufferSize, "%%d%d", xn);
        return;
    case 1: // 5xc8..5xcf, An
        // Does not exist (used to distinguish DBcc)
        break;
    case 2: // 5xd0..5xd7 (An)
        node.size = kInstructionSizeStepBytes;
        snprintf(node.mnemonic, kMnemonicBufferSize, mnemonic);
        snprintf(node.arguments, kArgsBufferSize, "%%a%d@", xn);
        return;
    case 3: // 5xd8..5xdf (An)+
        node.size = kInstructionSizeStepBytes;
        snprintf(node.mnemonic, kMnemonicBufferSize, mnemonic);
        snprintf(node.arguments, kArgsBufferSize, "%%a%d@+", xn);
        return;
    case 4: // 5xe0..5xe7 -(An)
        node.size = kInstructionSizeStepBytes;
        snprintf(node.mnemonic, kMnemonicBufferSize, mnemonic);
        snprintf(node.arguments, kArgsBufferSize, "%%a%d@-", xn);
        return;
    case 5: // 5xe8..5xef, (d16, An), Displacement Word
        if (node.offset + kInstructionSizeStepBytes < code.occupied_size) {
            node.size = kInstructionSizeStepBytes * 2;
            snprintf(node.mnemonic, kMnemonicBufferSize, mnemonic);
            const int16_t dispmt = GetI16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
            snprintf(node.arguments, kArgsBufferSize, "%%a%d@(%d:w)", xn, dispmt);
            return;
        }
        break;
    case 6: // 5xf0..5xf7, (d16, An, Xi), Brief Extension Word
        if (node.offset + kInstructionSizeStepBytes < code.occupied_size) {
            node.size = kInstructionSizeStepBytes * 2;
            snprintf(node.mnemonic, kMnemonicBufferSize, mnemonic);
            const uint16_t briefext = GetU16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
            if (briefext & 0x0700) {
                // briefext must have zeros on 8, 9 an 10-th bits,
                // i.e. xxxx_x000_xxxx_xxxx
                break;
            }
            const char reg = ((briefext >> 15) & 1) ? 'a' : 'd';
            const int xi = (briefext >> 12) & 7;
            const char size_spec = ((briefext >> 11) & 1) ? 'l' : 'w';
            const int8_t dispmt = briefext & 0xff;
            snprintf(node.arguments, kArgsBufferSize,
                    "%%a%d@(%d,%%%c%d:%c)", xn, dispmt, reg, xi, size_spec);
            return;
        }
        break;
    case 7: // 5xf8..5xff
        switch (xn) {
        case 0: // 5xf8 (xxx).W
            node.size = kInstructionSizeStepBytes * 2;
            snprintf(node.mnemonic, kMnemonicBufferSize, mnemonic);
            if (node.offset + kInstructionSizeStepBytes < code.occupied_size) {
                // This shit is real: it is sign extend value
                const int32_t dispmt = GetI16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
                snprintf(node.arguments, kArgsBufferSize, "0x%x:w", dispmt);
                return;
            }
            break;
        case 1: // 5xf9 (xxx).L
            node.size = kInstructionSizeStepBytes * 3;
            snprintf(node.mnemonic, kMnemonicBufferSize, mnemonic);
            if (node.offset + kInstructionSizeStepBytes < code.occupied_size) {
                const int32_t dispmt = GetI32BE(code.buffer + node.offset + kInstructionSizeStepBytes);
                snprintf(node.arguments, kArgsBufferSize, "0x%x:l", dispmt);
                return;
            }
            break;
        case 2: // 5xfa
        case 3: // 5xfb
        case 4: // 5xfc
        case 5: // 5xfd
        case 6: // 5xfe
            // Does not exist
            break;
        }
        break;
    }
    return disasm_verbatim(node, instr, code, s);
}

static inline const char *dbcc_mnemonic_by_condition(Condition condition)
{
    switch (condition) {
    case Condition::kT:  return "dbt";  // 50c8..50cf
    case Condition::kF:  return "dbf";  // 51c8..51cf
    case Condition::kHI: return "dbhi"; // 52c8..52cf
    case Condition::kLS: return "dbls"; // 53c8..53cf
    case Condition::kCC: return "dbcc"; // 54c8..54cf
    case Condition::kCS: return "dbcs"; // 55c8..55cf
    case Condition::kNE: return "dbne"; // 56c8..56cf
    case Condition::kEQ: return "dbeq"; // 57c8..57cf
    case Condition::kVC: return "dbvc"; // 58c8..58cf
    case Condition::kVS: return "dbvs"; // 59c8..59cf
    case Condition::kPL: return "dbpl"; // 5ac8..5acf
    case Condition::kMI: return "dbmi"; // 5bc8..5bcf
    case Condition::kGE: return "dbge"; // 5cc8..5ccf
    case Condition::kLT: return "dblt"; // 5dc8..5dcf
    case Condition::kGT: return "dbgt"; // 5ec8..5ecf
    case Condition::kLE: return "dble"; // 5fc8..5fcf
    }
    assert(false);
    return "?";
}

static void disasm_dbcc(DisasmNode& node, uint16_t instr, const DataBuffer &code, const Settings &s)
{
    if (node.offset + kInstructionSizeStepBytes >= code.occupied_size) {
        return disasm_verbatim(node, instr, code, s);
    }
    const int16_t dispmt_raw = GetI16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
    if (dispmt_raw % kInstructionSizeStepBytes) {
        return disasm_verbatim(node, instr, code, s);
    }
    node.size = kInstructionSizeStepBytes * 2;
    Condition condition = static_cast<Condition>((instr >> 8) & 0xf);
    const char *mnemonic = dbcc_mnemonic_by_condition(condition);
    const int dn = (instr & 7);
    const uint32_t branch_addr = static_cast<uint32_t>(node.offset + dispmt_raw);
    node.branch_addr = branch_addr;
    node.has_branch_addr = true;
    const int32_t dispmt = dispmt_raw + kInstructionSizeStepBytes;
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s", mnemonic);
    const char * const sign = dispmt >= 0 ? "+" : "";
    // FIXME support s.rel_marks option for this instruction
    snprintf(node.arguments, kArgsBufferSize, "%%d%d,.%s%d", dn, sign, dispmt);
    return;
}

static void chunk_mf000_v5000(DisasmNode& n, uint16_t instr, const DataBuffer &c, const Settings &s)
{
    const auto opsize = static_cast<OpSize>((instr >> 6) & 3);
    const int m = ((instr >> 3) & 7);
    if (opsize == OpSize::kInvalid) {
        if (m == 1) {
            return disasm_dbcc(n, instr, c, s);
        }
        return disasm_scc(n, instr, c, s, m);
    }
    return disasm_addq_subq(n, instr, c, s, m, opsize);
}

static void disasm_moveq(DisasmNode& n, uint16_t i, const DataBuffer &c, const Settings &s)
{
    // TODO
    return disasm_verbatim(n, i, c, s);
}

static void chunk_mf000_v8000(DisasmNode& n, uint16_t i, const DataBuffer &c, const Settings &s)
{
    return disasm_verbatim(n, i, c, s);
}

static void chunk_mf000_v9000(DisasmNode& n, uint16_t i, const DataBuffer &c, const Settings &s)
{
    return disasm_verbatim(n, i, c, s);
}

static void chunk_mf000_vb000(DisasmNode& n, uint16_t i, const DataBuffer &c, const Settings &s)
{
    return disasm_verbatim(n, i, c, s);
}

static void chunk_mf000_vc000(DisasmNode& n, uint16_t i, const DataBuffer &c, const Settings &s)
{
    return disasm_verbatim(n, i, c, s);
}

static void chunk_mf000_vd000(DisasmNode& n, uint16_t i, const DataBuffer &c, const Settings &s)
{
    return disasm_verbatim(n, i, c, s);
}

static void chunk_mf000_ve000(DisasmNode& n, uint16_t i, const DataBuffer &c, const Settings &s)
{
    return disasm_verbatim(n, i, c, s);
}

static void m68k_disasm(DisasmNode& n, uint16_t i, const DataBuffer &c, const Settings &s)
{
    switch ((i & 0xf000) >> 12) {
    case 0x0: return chunk_mf000_v0000(n, i, c, s);
    case 0x1: return chunk_mf000_v1000(n, i, c, s);
    case 0x2: return chunk_mf000_v2000(n, i, c, s);
    case 0x3: return chunk_mf000_v3000(n, i, c, s);
    case 0x4: return chunk_mf000_v4000(n, i, c, s);
    case 0x5: return chunk_mf000_v5000(n, i, c, s);
    case 0x6: return disasm_bra_bsr_bcc(n, i, c, s);
    case 0x7: return disasm_moveq(n, i, c, s);
    case 0x8: return chunk_mf000_v8000(n, i, c, s);
    case 0x9: return chunk_mf000_v9000(n, i, c, s);
    case 0xa: return disasm_verbatim(n, i, c, s);
    case 0xb: return chunk_mf000_vb000(n, i, c, s);
    case 0xc: return chunk_mf000_vc000(n, i, c, s);
    case 0xd: return chunk_mf000_vd000(n, i, c, s);
    case 0xe: return chunk_mf000_ve000(n, i, c, s);
    case 0xf: return disasm_verbatim(n, i, c, s);
    }
    assert(false);
    return disasm_verbatim(n, i, c, s);
}

void DisasmNode::Disasm(const DataBuffer &code, const Settings &s)
{
    // We assume that no MMU and ROM is always starts with 0
    assert(this->offset < code.occupied_size);
    // It is possible to have multiple DisasmNode::Disasm() calls, and there is
    // no point to disassemble it again if it already has mnemonic determined
    if (this->mnemonic[0] != '\0') {
        return;
    }
    const uint16_t instr = GetU16BE(code.buffer + this->offset);
    m68k_disasm(*this, instr, code, s);
}


void DisasmNode::AddReferencedBy(uint32_t offset, ReferenceType type)
{
    ReferenceNode *node{};
    if (this->last_ref_by) {
        node = this->last_ref_by;
    } else {
        node = new ReferenceNode{};
        assert(node);
        this->ref_by = this->last_ref_by = node;
    }
    node->refs[node->refs_count] = ReferenceRecord{type, offset};
    node->refs_count++;
    if (node->refs_count >= kRefsCountPerBuffer) {
        ReferenceNode *new_node = new ReferenceNode{};
        assert(new_node);
        node->next = new_node;
        this->last_ref_by = new_node;
    }
}

DisasmNode::~DisasmNode()
{
    ReferenceNode *ref{this->ref_by};
    while (ref) {
        ReferenceNode *prev = ref;
        ref = ref->next;
        delete prev;
    }
}
