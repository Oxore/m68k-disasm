#include "disasm.h"
#include "data_buffer.h"
#include "common.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

enum class JType {
    kJsr,
    kJmp,
};

enum class MoveDirection: bool {
    kRegisterToMemory = 0,
    kMemoryToRegister = 1,
};

enum class OpSize: int {
    kByte = 0,
    kWord = 1,
    kLong = 2,
    kInvalid = 3,
};

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
    char s{}; /// Size spec letter of Xi or imm: either 'w' or 'l'
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
            return s == 'l' ? 4 : 2;
        }
        return 0;
    }
    static constexpr AddrModeArg Dn(uint8_t xn)
    {
        return AddrModeArg{AddrMode::kDn, 0, xn};
    }
    static constexpr AddrModeArg An(uint8_t xn)
    {
        return AddrModeArg{AddrMode::kAn, 1, xn};
    }
    static constexpr AddrModeArg AnAddr(uint8_t xn)
    {
        return AddrModeArg{AddrMode::kAnAddr, 2, xn};
    }
    static constexpr AddrModeArg AnAddrIncr(uint8_t xn)
    {
        return AddrModeArg{AddrMode::kAnAddrIncr, 3, xn};
    }
    static constexpr AddrModeArg AnAddrDecr(uint8_t xn)
    {
        return AddrModeArg{AddrMode::kAnAddrDecr, 4, xn};
    }
    static constexpr AddrModeArg D16AnAddr(uint8_t xn, int16_t d16)
    {
        return AddrModeArg{AddrMode::kD16AnAddr, 5, xn, 0, 0, 0, d16};
    }
    static constexpr AddrModeArg D8AnXiAddr(
            uint8_t xn, char r, uint8_t xi, char s, int8_t d8)
    {
        return AddrModeArg{AddrMode::kD8AnXiAddr, 6, xn, r, xi, s, d8};
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
    static constexpr AddrModeArg Immediate(uint8_t m, uint8_t xn, char s, int32_t value)
    {
        return AddrModeArg{AddrMode::kImmediate, m, xn, 0, 0, s, value};
    }
    static constexpr AddrModeArg Fetch(
            const uint32_t offset, const DataBuffer &code, int16_t instr, char s)
    {
        const int addrmode = instr & 0x3f;
        const int m = (addrmode >> 3) & 7;
        const int xn = addrmode & 7;
        return Fetch(offset, code, m, xn, s);
    }
    static inline constexpr AddrModeArg Fetch(
            uint32_t offset, const DataBuffer &code, int m, int xn, char s);
    int SNPrint(char *const buf, const size_t bufsz) const
    {
        switch (mode) {
        case AddrMode::kInvalid:
            assert(false);
            break;
        case AddrMode::kDn:
            return snprintf(buf, bufsz, "%%d%d", xn);
        case AddrMode::kAn:
            return snprintf(buf, bufsz, "%%a%u", xn);
        case AddrMode::kAnAddr:
            return snprintf(buf, bufsz, "%%a%u@", xn);
        case AddrMode::kAnAddrIncr:
            return snprintf(buf, bufsz, "%%a%u@+", xn);
        case AddrMode::kAnAddrDecr:
            return snprintf(buf, bufsz, "%%a%u@-", xn);
        case AddrMode::kD16AnAddr:
            return snprintf(buf, bufsz, "%%a%u@(%d:w)", xn, value);
        case AddrMode::kD8AnXiAddr:
            return snprintf(buf, bufsz, "%%a%u@(%d,%%%c%d:%c)", xn, value, r, xi, s);
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
    }
};

constexpr AddrModeArg AddrModeArg::Fetch(
        const uint32_t offset, const DataBuffer &code, const int m, const int xn, const char s)
{
    assert(s == 'b' || s == 'w' || s == 'l');
    switch (m) {
    case 0: // Dn
        return AddrModeArg::Dn(xn);
    case 1: // An
        return AddrModeArg::An(xn);
    case 2: // (An)
        return AddrModeArg::AnAddr(xn);
    case 3: // (An)+
        return AddrModeArg::AnAddrIncr(xn);
    case 4: // -(An)
        return AddrModeArg::AnAddrDecr(xn);
    case 5: // (d16, An), Additional Word
        if (offset < code.occupied_size) {
            const int16_t d16 = GetI16BE(code.buffer + offset);
            return AddrModeArg::D16AnAddr(xn, d16);
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
            return AddrModeArg::D8AnXiAddr(xn, r, xi, s, d8);
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
            if (offset + kInstructionSizeStepBytes < code.occupied_size) {
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
                    break;
                }
                const char r = ((briefext >> 15) & 1) ? 'a' : 'd';
                const uint8_t xi = (briefext >> 12) & 7;
                const char s = ((briefext >> 11) & 1) ? 'l' : 'w';
                const int8_t d8 = briefext & 0xff;
                return AddrModeArg::D8PCXiAddr(m, xn, r, xi, s, d8);
            }
            break;
        case 4: // #imm
            if (s == 'l') {
                if (offset + kInstructionSizeStepBytes < code.occupied_size) {
                    const int32_t value = GetI32BE(code.buffer + offset);
                    return AddrModeArg::Immediate(m, xn, s, value);
                }
            } else if (offset < code.occupied_size) {
                const int16_t value = GetI16BE(code.buffer + offset);
                if (s == 'b') {
                    if (value > 255 || value < -255) {
                        // Invalid immediate value for instruction with .b
                        // suffix
                        break;
                    }
                }
                return AddrModeArg::Immediate(m, xn, s, value);
            }
        case 5: // Does not exist
        case 6: // Does not exist
        case 7: // Does not exist
            break;
        }
        break;
    }
    return AddrModeArg{};
}

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

static inline size_t snprint_reg_mask(
        char *const buf, const size_t bufsz, const uint32_t regmask_arg, const bool predecrement)
{
    const uint32_t regmask = regmask_arg & 0xffff;
    size_t written = 0;
    bool first_printed = 0;
    size_t span = 0;
    // 17-th bit used to close the span with 0 value unconditionaly
    for (int i = 0; i < 17; i++) {
        const uint32_t mask = 1 << (predecrement ? (15 - i) : i);
        const bool hit = regmask & mask;
        const bool span_open = hit && span == 0;
        const bool span_closed = !hit && span > 1;
        const int printable_i = i - (span_closed ? 1 : 0);
        const int id = printable_i % 8;
        const char regtype = (printable_i >= 8) ? 'a' : 'd';
        if (span_open || span_closed) {
            const char *const delimiter = span_open ? (first_printed ? "/" : "") : "-";
            const size_t remaining = bufsz - written;
            const int ret = snprintf(buf + written, remaining, "%s%%%c%d", delimiter, regtype, id);
            assert(ret > 0);
            assert(static_cast<unsigned>(ret) >= strlen("%d0"));
            assert(static_cast<unsigned>(ret) <= strlen("-%d0"));
            written += Min(remaining, ret);
            first_printed = true;
        }
        span = hit ? span + 1 : 0;
    }
    assert(written < bufsz); // Output must not be truncated
    return written;
}

static void disasm_verbatim(
        DisasmNode &node, uint16_t instr, const DataBuffer &, const Settings &)
{
    node.size = kInstructionSizeStepBytes;
    snprintf(node.mnemonic, kMnemonicBufferSize, ".short");
    snprintf(node.arguments, kArgsBufferSize, "0x%04x", instr);
}

static void disasm_jsr_jmp(
        DisasmNode &node, uint16_t instr, const DataBuffer &code, const Settings &s, JType jsrjmp)
{
    const auto a = AddrModeArg::Fetch(node.offset + kInstructionSizeStepBytes, code, instr, 'w');
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
    node.is_call = (jsrjmp == JType::kJsr);
    node.size = kInstructionSizeStepBytes + a.Size();
    const char *mnemonic = (jsrjmp == JType::kJsr) ? "jsr" : "jmp";
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s", mnemonic);
    const int ret = a.SNPrint(node.arguments, kArgsBufferSize);
    assert(ret > 0);
    (void) ret;
}

static void disasm_movem(
        DisasmNode &node, uint16_t instr, const DataBuffer &code, const Settings &s)
{
    if (node.offset + kInstructionSizeStepBytes >= code.occupied_size) {
        // Not enough space for regmask
        return disasm_verbatim(node, instr, code, s);
    }
    const unsigned regmask = GetU16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
    if (regmask == 0) {
        // This is just not representable: at least one register must be specified
        return disasm_verbatim(node, instr, code, s);
    }
    const auto dir = static_cast<MoveDirection>((instr >> 10) & 1);
    const auto opsize = static_cast<OpSize>(((instr >> 6) & 1) + 1);
    const char suffix = suffix_from_opsize(opsize);
    const auto a = AddrModeArg::Fetch(
            node.offset + kInstructionSizeStepBytes * 2, code, instr, suffix);
    switch (a.mode) {
    case AddrMode::kInvalid:
    case AddrMode::kDn: // 4880..4887 / 4c80..4c87 / 48c0..48c7 / 4cc0..4cc7
    case AddrMode::kAn: // 4888..488f / 4c88..4c8f / 48c8..48cf / 4cc8..4ccf
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kAnAddr: // 4890..4897 / 4c90..4c97 / 48d0..48d7 / 4cd0..4cd7
        break;
    case AddrMode::kAnAddrIncr: // 4898..489f / 4c89..4c9f / 48d8..48df / 4cd8..4cdf
        if (dir == MoveDirection::kRegisterToMemory) {
            return disasm_verbatim(node, instr, code, s);
        }
        break;
    case AddrMode::kAnAddrDecr: // 48a0..48a7 / 4ca0..4ca7 / 48e0..48e7 / 4ce0..4ce7
        if (dir == MoveDirection::kMemoryToRegister) {
            return disasm_verbatim(node, instr, code, s);
        }
        break;
    case AddrMode::kD16AnAddr: // 48a8..48af / 4c8a..4caf / 48e8..48ef / 4ce8..4cef
    case AddrMode::kD8AnXiAddr: // 48b0..48b7 / 4cb0..4cb7 / 48f0..48f7 / 4cf0..4cf7
    case AddrMode::kWord: // 48b8 / 4cb8 / 48f8 / 4cf8
    case AddrMode::kLong: // 48b9 / 4cb9 / 48f9 / 4cf9
        break;
    case AddrMode::kD16PCAddr: // 48ba / 4cba / 48fa / 4cfa
    case AddrMode::kD8PCXiAddr: // 48bb / 4cbb / 48fb / 4cfb
        if (dir == MoveDirection::kRegisterToMemory) {
            return disasm_verbatim(node, instr, code, s);
        }
        break;
    case AddrMode::kImmediate: // 4ebc / 4efc
        return disasm_verbatim(node, instr, code, s);
    }
    node.size = kInstructionSizeStepBytes * 2 + a.Size();
    snprintf(node.mnemonic, kMnemonicBufferSize, "movem%c", suffix);
    char regmask_str[48]{};
    char addrmodearg_str[32]{};
    snprint_reg_mask(regmask_str, sizeof(regmask_str), regmask, a.mode == AddrMode::kAnAddrDecr);
    a.SNPrint(addrmodearg_str, sizeof(addrmodearg_str));
    if (dir == MoveDirection::kMemoryToRegister) {
        snprintf(node.arguments, kArgsBufferSize, "%s,%s", addrmodearg_str, regmask_str);
    } else {
        snprintf(node.arguments, kArgsBufferSize, "%s,%s", regmask_str, addrmodearg_str);
    }
}

static void disasm_lea(
        DisasmNode &node, uint16_t instr, const DataBuffer &code, const Settings &s)
{
    const auto addr = AddrModeArg::Fetch(
            node.offset + kInstructionSizeStepBytes, code, instr, 'l');
    switch (addr.mode) {
    case AddrMode::kInvalid:
    case AddrMode::kDn:
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kAnAddr:
        break;
    case AddrMode::kAnAddrIncr:
    case AddrMode::kAnAddrDecr:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kD16AnAddr:
    case AddrMode::kD8AnXiAddr:
    case AddrMode::kWord:
    case AddrMode::kLong:
    case AddrMode::kD16PCAddr:
    case AddrMode::kD8PCXiAddr:
        break;
    case AddrMode::kImmediate:
        return disasm_verbatim(node, instr, code, s);
    }
    const unsigned an = ((instr >> 9) & 7);
    const auto reg = AddrModeArg::An(an);
    char addr_str[32]{};
    char reg_str[32]{};
    addr.SNPrint(addr_str, sizeof(addr_str));
    reg.SNPrint(reg_str, sizeof(reg_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "leal");
    snprintf(node.arguments, kArgsBufferSize, "%s,%s", addr_str, reg_str);
    node.size = kInstructionSizeStepBytes + addr.Size() + reg.Size();
}

static void disasm_chk(
        DisasmNode &node, uint16_t instr, const DataBuffer &code, const Settings &s)
{
    const auto src = AddrModeArg::Fetch(
            node.offset + kInstructionSizeStepBytes, code, instr, 'w');
    switch (src.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kAnAddr:
    case AddrMode::kAnAddrIncr:
    case AddrMode::kAnAddrDecr:
    case AddrMode::kD16AnAddr:
    case AddrMode::kD8AnXiAddr:
    case AddrMode::kWord:
    case AddrMode::kLong:
        break;
    case AddrMode::kD16PCAddr:
    case AddrMode::kD8PCXiAddr:
    case AddrMode::kImmediate:
        return disasm_verbatim(node, instr, code, s);
    }
    const unsigned dn = ((instr >> 9) & 7);
    const auto dst = AddrModeArg::Dn(dn);
    char src_str[32]{};
    char dst_str[32]{};
    src.SNPrint(src_str, sizeof(src_str));
    dst.SNPrint(dst_str, sizeof(dst_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "chkw");
    snprintf(node.arguments, kArgsBufferSize, "%s,%s", src_str, dst_str);
    node.size = kInstructionSizeStepBytes + src.Size() + dst.Size();
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
        DisasmNode &node, uint16_t instr, const DataBuffer &code, const Settings &s)
{
    Condition condition = static_cast<Condition>((instr >> 8) & 0xf);
    const char *mnemonic = bcc_mnemonic_by_condition(condition);
    // False condition Indicates BSR
    int dispmt = static_cast<int8_t>(instr & 0xff);
    if (dispmt % kInstructionSizeStepBytes) {
        return disasm_verbatim(node, instr, code, s);
    }
    const char suffix = dispmt ? 's' : 'w';
    if (dispmt == 0) {
        // Check the boundaries
        if (node.offset + kInstructionSizeStepBytes >= code.occupied_size) {
            return disasm_verbatim(node, instr, code, s);
        }
        dispmt = GetI16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
        if (dispmt % kInstructionSizeStepBytes) {
            return disasm_verbatim(node, instr, code, s);
        }
        node.size = kInstructionSizeStepBytes * 2;
    } else {
        node.size = kInstructionSizeStepBytes;
    }
    node.is_call = (condition == Condition::kF);
    dispmt += kInstructionSizeStepBytes;
    const uint32_t branch_addr = static_cast<uint32_t>(node.offset + dispmt);
    node.branch_addr = branch_addr;
    node.has_branch_addr = true;
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
    const char * const sign = dispmt >= 0 ? "+" : "";
    // FIXME support s.rel_marks option for this instruction
    snprintf(node.arguments, kArgsBufferSize, ".%s%d", sign, dispmt);
    return;
}

static inline const char *mnemonic_for_bitops(unsigned opcode)
{
    switch (opcode) {
    case 0: return "btst";
    case 1: return "bchg";
    case 2: return "bclr";
    case 3: return "bset";
    }
    assert(false);
    return "?";
}

static inline void disasm_movep(
        DisasmNode &node, const uint16_t instr, const DataBuffer &code, const Settings &s)
{
    const unsigned dn = ((instr >> 9) & 7);
    const unsigned an = instr & 7;
    const char suffix = ((instr >> 6) & 1) ? 'l' : 'w';
    const auto dir = static_cast<MoveDirection>(!((instr >> 7) & 1));
    const auto addr = AddrModeArg::Fetch(
            node.offset + kInstructionSizeStepBytes, code, 5, an, suffix);
    if (addr.mode == AddrMode::kInvalid) {
        // Boundary check failed, most likely
        return disasm_verbatim(node, instr, code, s);
    }
    assert(addr.mode == AddrMode::kD16AnAddr);
    const auto reg = AddrModeArg::Dn(dn);
    char addr_str[32]{};
    char reg_str[32]{};
    addr.SNPrint(addr_str, sizeof(addr_str));
    reg.SNPrint(reg_str, sizeof(reg_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "movep%c", suffix);
    if (dir == MoveDirection::kRegisterToMemory) {
        snprintf(node.arguments, kArgsBufferSize, "%s,%s", reg_str, addr_str);
    } else {
        snprintf(node.arguments, kArgsBufferSize, "%s,%s", addr_str, reg_str);
    }
    node.size = kInstructionSizeStepBytes + addr.Size() + reg.Size();
}

static void disasm_src_arg_bitops_movep(
        DisasmNode &node,
        const uint16_t instr,
        const DataBuffer &code,
        const Settings &s,
        const bool has_dn_src = true)
{
    const unsigned m = (instr >> 3) & 7;
    if ((m == 1) && has_dn_src) {
        return disasm_movep(node, instr, code, s);
    }
    const unsigned dn = ((instr >> 9) & 7);
    const unsigned xn = instr & 7;
    // Fetch AddrMode::kDn if has_dn_src, otherwise fetch AddrMode::kImmediate
    // byte
    const auto src = AddrModeArg::Fetch(
            node.offset + kInstructionSizeStepBytes,
            code,
            (has_dn_src) ? 0 : 7,
            dn,
            'b');
    if (src.mode == AddrMode::kInvalid) {
        return disasm_verbatim(node, instr, code, s);
    }
    if (has_dn_src) {
        assert(src.mode == AddrMode::kDn);
    } else {
        assert(dn == 4);
        assert(src.mode == AddrMode::kImmediate);
    }
    const auto dst = AddrModeArg::Fetch(
            node.offset + kInstructionSizeStepBytes + src.Size(), code, m, xn, 'w');
    const unsigned opcode = (instr >> 6) & 3;
    switch (dst.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kAnAddr:
    case AddrMode::kAnAddrIncr:
    case AddrMode::kAnAddrDecr:
    case AddrMode::kD16AnAddr:
    case AddrMode::kD8AnXiAddr:
    case AddrMode::kWord:
    case AddrMode::kLong:
        break;
    case AddrMode::kD16PCAddr:
    case AddrMode::kD8PCXiAddr:
        if (opcode != 0) {
            // PC relative destination address argument available for BTST only
            return disasm_verbatim(node, instr, code, s);
        }
        break;
    case AddrMode::kImmediate:
        return disasm_verbatim(node, instr, code, s);
    }
    char src_str[32]{};
    char dst_str[32]{};
    src.SNPrint(src_str, sizeof(src_str));
    dst.SNPrint(dst_str, sizeof(dst_str));
    const char suffix = dst.mode == AddrMode::kDn ? 'l' : 'b';
    const char *mnemonic = mnemonic_for_bitops(opcode);
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
    snprintf(node.arguments, kArgsBufferSize, "%s,%s", src_str, dst_str);
    node.size = kInstructionSizeStepBytes + src.Size() + dst.Size();
}

static void disasm_bitops(DisasmNode &n, const uint16_t i, const DataBuffer &c, const Settings &s)
{
    return disasm_src_arg_bitops_movep(n, i, c, s, false);
}

static inline void disasm_logical_imm_to(
        DisasmNode &node, const char* mnemonic, const char suffix, const int16_t imm)
{
    const char *reg = suffix == 'b' ? "ccr" : "sr";
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
    snprintf(node.arguments, kArgsBufferSize, "#%d,%%%s", imm, reg);
    node.size = kInstructionSizeStepBytes * 2;
}

static inline const char *mnemonic_for_chunk_mf000_v1000(const unsigned opcode)
{
    switch (opcode) {
    case 0: return "ori";
    case 1: return "andi";
    case 2: return "subi";
    case 3: return "addi";
    case 4: break;
    case 5: return "eori";
    case 6: return "cmpi";
    case 7: break;
    }
    assert(false);
    return "?";
}

static void chunk_mf000_v0000(
        DisasmNode &node, uint16_t instr, const DataBuffer &code, const Settings &s)
{
    const bool has_source_reg = (instr >> 8) & 1;
    if (has_source_reg) {
        return disasm_src_arg_bitops_movep(node, instr, code, s);
    }
    const unsigned opcode = (instr >> 9) & 7;
    if (opcode == 7) {
        // Does not exist
        return disasm_verbatim(node, instr, code, s);
    }
    if (opcode == 4) {
        return disasm_bitops(node, instr, code, s);
    }
    const int m = (instr >> 3) & 7;
    const int xn = instr & 7;
    const auto opsize = static_cast<OpSize>((instr >> 6) & 3);
    if (opsize == OpSize::kInvalid) {
            // Does not exist
            return disasm_verbatim(node, instr, code, s);
    }
    // Anticipating #imm which means "to CCR"/"to SR", depending on OpSize
    if (m == 7 && xn == 4) {
        if (opcode == 2 || opcode == 3 || opcode == 6) {
            // CMPI, SUBI and ANDI neither have immediate destination arguments
            // nor "to CCR"/"to SR" variations
            return disasm_verbatim(node, instr, code, s);
        }
        if (opsize == OpSize::kLong) {
            // Does not exist
            return disasm_verbatim(node, instr, code, s);
        }
    }
    const char suffix = suffix_from_opsize(opsize);
    const auto src = AddrModeArg::Fetch(
            node.offset + kInstructionSizeStepBytes, code, 7, 4, suffix);
    if (src.mode == AddrMode::kInvalid) {
        return disasm_verbatim(node, instr, code, s);
    }
    assert(src.mode == AddrMode::kImmediate);
    const char *mnemonic = mnemonic_for_chunk_mf000_v1000(opcode);
    if (m == 7 && xn == 4) {
        return disasm_logical_imm_to(node, mnemonic, suffix, src.value);
    }
    const auto dst = AddrModeArg::Fetch(
            node.offset + kInstructionSizeStepBytes + src.Size(), code, m, xn, suffix);
    switch (dst.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kAnAddr:
    case AddrMode::kAnAddrIncr:
    case AddrMode::kAnAddrDecr:
    case AddrMode::kD16AnAddr:
    case AddrMode::kD8AnXiAddr:
    case AddrMode::kWord:
    case AddrMode::kLong:
        break;
    case AddrMode::kD16PCAddr:
    case AddrMode::kD8PCXiAddr:
        if (opcode != 6) {
            // PC relative destination address argument available for CMPI only
            return disasm_verbatim(node, instr, code, s);
        }
        break;
    case AddrMode::kImmediate:
        return disasm_verbatim(node, instr, code, s);
    }
    char dst_str[32]{};
    dst.SNPrint(dst_str, sizeof(dst_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
    snprintf(node.arguments, kArgsBufferSize, "#%d,%s", src.value, dst_str);
    node.size = kInstructionSizeStepBytes + src.Size() + dst.Size();
}

static void disasm_move_movea(
        DisasmNode &node, uint16_t instr, const DataBuffer &code, const Settings &s)
{
    const int size_spec = (instr >> 12) & 3;
    const char suffix = size_spec == 1 ? 'b' : (size_spec == 3 ? 'w' : 'l');
    const auto src = AddrModeArg::Fetch(
            node.offset + kInstructionSizeStepBytes, code, instr, suffix);
    if (src.mode == AddrMode::kInvalid) {
        return disasm_verbatim(node, instr, code, s);
    }
    if (suffix == 'b' && src.mode == AddrMode::kAn) {
        // Does not exist
        return disasm_verbatim(node, instr, code, s);
    }
    const int m = (instr >> 6) & 7;
    const int xn = (instr >> 9) & 7;
    const auto dst = AddrModeArg::Fetch(
            node.offset + kInstructionSizeStepBytes + src.Size(), code, m, xn, suffix);
    switch (dst.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        if (suffix == 'b') {
            // Does not exist
            return disasm_verbatim(node, instr, code, s);
        }
    case AddrMode::kAnAddr:
    case AddrMode::kAnAddrIncr:
    case AddrMode::kAnAddrDecr:
    case AddrMode::kD16AnAddr:
    case AddrMode::kD8AnXiAddr:
    case AddrMode::kWord:
    case AddrMode::kLong:
        break;
    case AddrMode::kD16PCAddr:
    case AddrMode::kD8PCXiAddr:
    case AddrMode::kImmediate:
        return disasm_verbatim(node, instr, code, s);
    }
    char src_str[32]{};
    char dst_str[32]{};
    src.SNPrint(src_str, sizeof(src_str));
    dst.SNPrint(dst_str, sizeof(dst_str));
    const char *mnemonic = dst.mode == AddrMode::kAn ? "movea" : "move";
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
    snprintf(node.arguments, kArgsBufferSize, "%s,%s", src_str, dst_str);
    node.size = kInstructionSizeStepBytes + src.Size() + dst.Size();
}

static void disasm_move_from_sr(
        DisasmNode &node, uint16_t instr, const DataBuffer &code, const Settings &s)
{
    const char suffix = 'w';
    const auto dst = AddrModeArg::Fetch(
            node.offset + kInstructionSizeStepBytes, code, instr, suffix);
    switch (dst.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kAnAddr:
    case AddrMode::kAnAddrIncr:
    case AddrMode::kAnAddrDecr:
    case AddrMode::kD16AnAddr:
    case AddrMode::kD8AnXiAddr:
    case AddrMode::kWord:
    case AddrMode::kLong:
        break;
    case AddrMode::kD16PCAddr:
    case AddrMode::kD8PCXiAddr:
    case AddrMode::kImmediate:
        return disasm_verbatim(node, instr, code, s);
    }
    char dst_str[32]{};
    dst.SNPrint(dst_str, sizeof(dst_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "move%c", suffix);
    snprintf(node.arguments, kArgsBufferSize, "%%sr,%s", dst_str);
    node.size = kInstructionSizeStepBytes + dst.Size();
}

static void disasm_move_to(
        DisasmNode &node, uint16_t instr, const DataBuffer &code, const Settings &s, const char* reg)
{
    const char suffix = 'w';
    const auto src = AddrModeArg::Fetch(
            node.offset + kInstructionSizeStepBytes, code, instr, suffix);
    switch (src.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kAnAddr:
    case AddrMode::kAnAddrIncr:
    case AddrMode::kAnAddrDecr:
    case AddrMode::kD16AnAddr:
    case AddrMode::kD8AnXiAddr:
    case AddrMode::kWord:
    case AddrMode::kLong:
    case AddrMode::kD16PCAddr:
    case AddrMode::kD8PCXiAddr:
    case AddrMode::kImmediate:
        break;
    }
    char src_str[32]{};
    src.SNPrint(src_str, sizeof(src_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "move%c", suffix);
    snprintf(node.arguments, kArgsBufferSize, "%s,%%%s", src_str, reg);
    node.size = kInstructionSizeStepBytes + src.Size();
}

static inline const char *mnemonic_for_chunk_mf800_v4000(const unsigned opcode)
{
    switch (opcode) {
    case 0: return "negx";
    case 1: return "clr";
    case 2: return "neg";
    case 3: return "not";
    }
    assert(false);
    return "?";
}

static void chunk_mf900_v4000(
        DisasmNode &node, uint16_t instr, const DataBuffer &code, const Settings &s)
{
    const auto opsize = static_cast<OpSize>((instr >> 6) & 3);
    const unsigned opcode = (instr >> 9) & 3;
    if (opsize == OpSize::kInvalid) {
        switch (opcode) {
        case 0:
            return disasm_move_from_sr(node, instr, code, s);
        case 1:
            return disasm_verbatim(node, instr, code, s);
        case 2:
            return disasm_move_to(node, instr, code, s, "ccr");
        case 3:
            return disasm_move_to(node, instr, code, s, "sr");
        }
        assert(false);
        return disasm_verbatim(node, instr, code, s);
    }
    const char *mnemonic = mnemonic_for_chunk_mf800_v4000(opcode);
    const char suffix = suffix_from_opsize(opsize);
    const auto a = AddrModeArg::Fetch(
            node.offset + kInstructionSizeStepBytes, code, instr, suffix);
    switch (a.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kAnAddr:
    case AddrMode::kAnAddrIncr:
    case AddrMode::kAnAddrDecr:
    case AddrMode::kD16AnAddr:
    case AddrMode::kD8AnXiAddr:
    case AddrMode::kWord:
    case AddrMode::kLong:
        break;
    case AddrMode::kD16PCAddr:
    case AddrMode::kD8PCXiAddr:
    case AddrMode::kImmediate:
        return disasm_verbatim(node, instr, code, s);
    }
    char a_str[32]{};
    a.SNPrint(a_str, sizeof(a_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
    snprintf(node.arguments, kArgsBufferSize, "%s", a_str);
    node.size = kInstructionSizeStepBytes + a.Size();
}

static inline void disasm_trivial(
        DisasmNode &node, uint16_t, const DataBuffer &, const Settings &, const char* mnemonic)
{
    node.size = kInstructionSizeStepBytes;
    snprintf(node.mnemonic, kMnemonicBufferSize, mnemonic);
}

static inline void disasm_tas(
        DisasmNode &node, uint16_t instr, const DataBuffer &code, const Settings &s)
{
    const auto a = AddrModeArg::Fetch(node.offset + kInstructionSizeStepBytes, code, instr, 'w');
    switch (a.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kAnAddr:
    case AddrMode::kAnAddrIncr:
    case AddrMode::kAnAddrDecr:
    case AddrMode::kD16AnAddr:
    case AddrMode::kD8AnXiAddr:
    case AddrMode::kWord:
    case AddrMode::kLong:
        break;
    case AddrMode::kD16PCAddr:
    case AddrMode::kD8PCXiAddr:
    case AddrMode::kImmediate:
        return disasm_verbatim(node, instr, code, s);
    }
    char a_str[32]{};
    a.SNPrint(a_str, sizeof(a_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "tas");
    snprintf(node.arguments, kArgsBufferSize, "%s", a_str);
    node.size = kInstructionSizeStepBytes + a.Size();
}

static void disasm_tst_tas_illegal(
        DisasmNode &node, uint16_t instr, const DataBuffer &code, const Settings &s)
{
    const auto opsize = static_cast<OpSize>((instr >> 6) & 3);
    const int m = (instr >> 3) & 7;
    const int xn = instr & 7;
    if (opsize == OpSize::kInvalid) {
        if (m == 7 && xn == 4){
            return disasm_trivial(node, instr, code, s, "illegal");
        }
        return disasm_tas(node, instr, code, s);
    }
    const char suffix = suffix_from_opsize(opsize);
    const auto a = AddrModeArg::Fetch(node.offset + kInstructionSizeStepBytes, code, m, xn, suffix);
    switch (a.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kAnAddr:
    case AddrMode::kAnAddrIncr:
    case AddrMode::kAnAddrDecr:
    case AddrMode::kD16AnAddr:
    case AddrMode::kD8AnXiAddr:
    case AddrMode::kWord:
    case AddrMode::kLong:
    case AddrMode::kD16PCAddr:
    case AddrMode::kD8PCXiAddr:
        break;
    case AddrMode::kImmediate:
        return disasm_verbatim(node, instr, code, s);
    }
    char a_str[32]{};
    a.SNPrint(a_str, sizeof(a_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "tst%c", suffix);
    snprintf(node.arguments, kArgsBufferSize, "%s", a_str);
    node.size = kInstructionSizeStepBytes + a.Size();
}

static void disasm_trap(
        DisasmNode &node, uint16_t instr, const DataBuffer &, const Settings &)
{
    const unsigned vector = instr & 0xf;
    snprintf(node.mnemonic, kMnemonicBufferSize, "trap");
    snprintf(node.arguments, kArgsBufferSize, "#%u", vector);
    node.size = kInstructionSizeStepBytes;
}

static void disasm_link_unlink(
        DisasmNode &node, uint16_t instr, const DataBuffer &code, const Settings &s)
{
    const bool unlk = (instr >> 3) & 1;
    const unsigned xn = instr & 7;
    if (unlk) {
        snprintf(node.mnemonic, kMnemonicBufferSize, "unlk");
        snprintf(node.arguments, kArgsBufferSize, "%%a%u", xn);
        node.size = kInstructionSizeStepBytes;
        return;
    }
    // Fetch immediate word
    const auto src = AddrModeArg::Fetch(node.offset + kInstructionSizeStepBytes, code, 7, 4, 'w');
    switch (src.mode) {
    case AddrMode::kInvalid:
    case AddrMode::kDn:
    case AddrMode::kAn:
    case AddrMode::kAnAddr:
    case AddrMode::kAnAddrIncr:
    case AddrMode::kAnAddrDecr:
    case AddrMode::kD16AnAddr:
    case AddrMode::kD8AnXiAddr:
    case AddrMode::kWord:
    case AddrMode::kLong:
    case AddrMode::kD16PCAddr:
    case AddrMode::kD8PCXiAddr:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kImmediate:
        break;
    }
    char src_str[32]{};
    src.SNPrint(src_str, sizeof(src_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "linkw");
    snprintf(node.arguments, kArgsBufferSize, "%%a%u,%s", xn, src_str);
    node.size = kInstructionSizeStepBytes + src.Size();
}

static void disasm_move_usp(
        DisasmNode &node, uint16_t instr, const DataBuffer &, const Settings &)
{
    const unsigned xn = instr & 7;
    const auto dir = static_cast<MoveDirection>((instr >> 3) & 1);
    node.size = kInstructionSizeStepBytes;
    snprintf(node.mnemonic, kMnemonicBufferSize, "movel");
    if (dir == MoveDirection::kRegisterToMemory) {
        snprintf(node.arguments, kArgsBufferSize, "%%a%u,%%usp", xn);
    } else {
        snprintf(node.arguments, kArgsBufferSize, "%%usp,%%a%u", xn);
    }
}

static void chunk_mf000_v4000(
        DisasmNode &node, uint16_t instr, const DataBuffer &code, const Settings &s)
{
    if ((instr & 0xf900) == 0x4000) {
        return chunk_mf900_v4000(node, instr, code, s);
    } else if ((instr & 0xff00) == 0x4a00) {
        return disasm_tst_tas_illegal(node, instr, code, s);
    } else if ((instr & 0xfff0) == 0x4e40) {
        return disasm_trap(node, instr, code, s);
    } else if ((instr & 0xfff0) == 0x4e50) {
        return disasm_link_unlink(node, instr, code, s);
    } else if ((instr & 0xfff0) == 0x4e60) {
        return disasm_move_usp(node, instr, code, s);
    } else if (instr == 0x4e70) {
        return disasm_trivial(node, instr, code, s, "reset");
    } else if (instr == 0x4e71) {
        return disasm_trivial(node, instr, code, s, "nop");
    } else if (instr == 0x4e72) {
        if (node.offset + kInstructionSizeStepBytes < code.occupied_size) {
            node.size = kInstructionSizeStepBytes * 2;
            snprintf(node.mnemonic, kMnemonicBufferSize, "stop");
            const uint16_t sr_imm = GetU16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
            snprintf(node.arguments, kArgsBufferSize, "#0x%x:w", sr_imm);
            return;
        }
    } else if (instr == 0x4e73) {
        return disasm_trivial(node, instr, code, s, "rte");
    } else if (instr == 0x4e75) {
        return disasm_trivial(node, instr, code, s, "rts");
    } else if (instr == 0x4e76) {
        return disasm_trivial(node, instr, code, s, "trapv");
    } else if (instr == 0x4e77) {
        return disasm_trivial(node, instr, code, s, "rtr");
    } else if ((instr & 0xffc0) == 0x4e80) {
        return disasm_jsr_jmp(node, instr, code, s, JType::kJsr);
    } else if ((instr & 0xffc0) == 0x4ec0) {
        return disasm_jsr_jmp(node, instr, code, s, JType::kJmp);
    } else if ((instr & 0xfb80) == 0x4880) {
        return disasm_movem(node, instr, code, s);
    } else if ((instr & 0xf1c0) == 0x41c0) {
        return disasm_lea(node, instr, code, s);
    } else if ((instr & 0xf1c0) == 0x4180) {
        return disasm_chk(node, instr, code, s);
    }
    return disasm_verbatim(node, instr, code, s);
}

static void disasm_addq_subq(
        DisasmNode &node, uint16_t instr, const DataBuffer &code, const Settings &s, OpSize opsize)
{
    const char suffix = suffix_from_opsize(opsize);
    const auto a = AddrModeArg::Fetch(node.offset + kInstructionSizeStepBytes, code, instr, suffix);
    switch (a.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kDn: // 5x00..5x07 / 5x40..5x47 / 5x80..5x87
        break;
    case AddrMode::kAn: // 5x08..5x0f / 5x48..5x4f / 5x88..5x8f
        if (opsize == OpSize::kByte) {
            // 5x08..5x0f
            // addqb and subqb with An do not exist
            return disasm_verbatim(node, instr, code, s);
        }
        break;
    case AddrMode::kAnAddr: // 5x10..5x17 / 5x50..5x57 / 5x90..5x97
    case AddrMode::kAnAddrIncr: // 5x18..5x1f / 5x58..5x5f / 5x98..5x9f
    case AddrMode::kAnAddrDecr: // 5x20..5x27 / 5x60..5x67 / 5xa0..5xa7
    case AddrMode::kD16AnAddr: // 5x28..5x2f / 5x68..5x6f / 5xa8..5xaf
    case AddrMode::kD8AnXiAddr: // 5x30..5x37 / 5x70..5x77 / 5xb0..5xb7
    case AddrMode::kWord: // 5x38 / 5x78 / 5xb8
    case AddrMode::kLong: // 5x39 / 5x79 / 5xb9
        break;
    case AddrMode::kD16PCAddr: // 5x3a / 5x7a / 5xba
    case AddrMode::kD8PCXiAddr: // 5x3b / 5x7b / 5xbb
    case AddrMode::kImmediate: // 5x3c / 5x7c / 5xbc
        // Does not exist
        return disasm_verbatim(node, instr, code, s);
    }
    node.size = kInstructionSizeStepBytes + a.Size();
    const char *mnemonic = (instr >> 8) & 1 ? "subq" : "addq";
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
    const unsigned imm = ((uint8_t((instr >> 9) & 7) - 1) & 7) + 1;
    const int ret = snprintf(node.arguments, kArgsBufferSize, "#%u,", imm);
    assert(ret > 0);
    assert(static_cast<unsigned>(ret) == strlen("#8,"));
    a.SNPrint(node.arguments + ret, kArgsBufferSize - ret);
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

static void disasm_dbcc(DisasmNode &node, uint16_t instr, const DataBuffer &code, const Settings &s)
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

static void disasm_scc_dbcc(
        DisasmNode &node, const uint16_t instr, const DataBuffer &code, const Settings &s)
{
    const auto a = AddrModeArg::Fetch(node.offset + kInstructionSizeStepBytes, code, instr, 'w');
    switch (a.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kDn: // 5xc0..5xc7, Dn
        break;
    case AddrMode::kAn: // 5xc8..5xcf, An
        return disasm_dbcc(node, instr, code, s);
    case AddrMode::kAnAddr: // 5xd0..5xd7
    case AddrMode::kAnAddrIncr: // 5xd8..5xdf
    case AddrMode::kAnAddrDecr: // 5xe0..5xe7
    case AddrMode::kD16AnAddr: // 5xe8..5xef
    case AddrMode::kD8AnXiAddr: // 5xf0..5xf7
    case AddrMode::kWord: // 5xf8 (xxx).W
    case AddrMode::kLong: // 5xf9 (xxx).L
        break;
    case AddrMode::kD16PCAddr: // 5xfa
    case AddrMode::kD8PCXiAddr: // 5xfb
    case AddrMode::kImmediate: // 5xfc
        // Does not exist
        return disasm_verbatim(node, instr, code, s);
    }
    node.size = kInstructionSizeStepBytes + a.Size();
    Condition condition = static_cast<Condition>((instr >> 8) & 0xf);
    const char *mnemonic = scc_mnemonic_by_condition(condition);
    snprintf(node.mnemonic, kMnemonicBufferSize, mnemonic);
    a.SNPrint(node.arguments, kArgsBufferSize);
}

static void chunk_mf000_v5000(DisasmNode &n, uint16_t instr, const DataBuffer &c, const Settings &s)
{
    const auto opsize = static_cast<OpSize>((instr >> 6) & 3);
    if (opsize == OpSize::kInvalid) {
        return disasm_scc_dbcc(n, instr, c, s);
    }
    return disasm_addq_subq(n, instr, c, s, opsize);
}

static void disasm_moveq(DisasmNode &node, uint16_t instr, const DataBuffer &code, const Settings &s)
{
    if (instr & 0x100) {
        // Does not exist
        return disasm_verbatim(node, instr, code, s);
    }
    const int xn = (instr >> 9) & 7;
    const auto dst = AddrModeArg::Dn(xn);
    char dst_str[32]{};
    dst.SNPrint(dst_str, sizeof(dst_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "moveq");
    const int8_t data = instr & 0xff;
    snprintf(node.arguments, kArgsBufferSize, "#%d,%s", data, dst_str);
    node.size = kInstructionSizeStepBytes + dst.Size();

}

static void chunk_mf000_v8000(DisasmNode &n, uint16_t i, const DataBuffer &c, const Settings &s)
{
    return disasm_verbatim(n, i, c, s);
}

static void chunk_mf000_v9000(DisasmNode &n, uint16_t i, const DataBuffer &c, const Settings &s)
{
    return disasm_verbatim(n, i, c, s);
}

static void chunk_mf000_vb000(DisasmNode &n, uint16_t i, const DataBuffer &c, const Settings &s)
{
    return disasm_verbatim(n, i, c, s);
}

static void chunk_mf000_vc000(DisasmNode &n, uint16_t i, const DataBuffer &c, const Settings &s)
{
    return disasm_verbatim(n, i, c, s);
}

static inline void disasm_addx(
        DisasmNode &node, const uint16_t instr, const DataBuffer &, const Settings &)
{
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    // Already handled by parent call of `disasm_add_addx_adda`
    assert(opsize != OpSize::kInvalid);
    const int m = (instr >> 3) & 1;
    const int xn = instr & 7;
    const int xi = (instr >> 9) & 7;
    const auto src = m ? AddrModeArg::AnAddrDecr(xn) : AddrModeArg::Dn(xn);
    const auto dst = m ? AddrModeArg::AnAddrDecr(xi) : AddrModeArg::Dn(xi);
    char src_str[32]{};
    char dst_str[32]{};
    src.SNPrint(src_str, sizeof(src_str));
    dst.SNPrint(dst_str, sizeof(dst_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "addx%c", suffix_from_opsize(opsize));
    snprintf(node.arguments, kArgsBufferSize, "%s,%s", src_str, dst_str);
    node.size = kInstructionSizeStepBytes + src.Size() + dst.Size();
}

static inline void disasm_adda(
        DisasmNode &node, const uint16_t instr, const DataBuffer &code, const Settings &s)
{
    const OpSize opsize = static_cast<OpSize>(((instr >> 8) & 1) + 1);
    const char suffix = suffix_from_opsize(opsize);
    assert(suffix != 'b');
    const auto src = AddrModeArg::Fetch(
            node.offset + kInstructionSizeStepBytes, code, instr, suffix);
    switch (src.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kDn:
    case AddrMode::kAn:
    case AddrMode::kAnAddr:
    case AddrMode::kAnAddrIncr:
    case AddrMode::kAnAddrDecr:
    case AddrMode::kD16AnAddr:
    case AddrMode::kD8AnXiAddr:
    case AddrMode::kWord:
    case AddrMode::kLong:
    case AddrMode::kD16PCAddr:
    case AddrMode::kD8PCXiAddr:
    case AddrMode::kImmediate:
        break;
    }
    const unsigned an = (instr >> 9) & 7;
    const auto dst = AddrModeArg::An(an);
    char src_str[32]{};
    char dst_str[32]{};
    src.SNPrint(src_str, sizeof(src_str));
    dst.SNPrint(dst_str, sizeof(dst_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "adda%c", suffix);
    snprintf(node.arguments, kArgsBufferSize, "%s,%s", src_str, dst_str);
    node.size = kInstructionSizeStepBytes + src.Size() + dst.Size();
}

static void disasm_add_addx_adda(
        DisasmNode &node, const uint16_t instr, const DataBuffer &code, const Settings &s)
{
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    if (opsize == OpSize::kInvalid) {
        return disasm_adda(node, instr, code, s);
    }
    const unsigned dir = (instr >> 8) & 1;
    const unsigned m = (instr >> 3) & 7;
    if (dir == 1 && (m == 0 || m == 1)) {
        return disasm_addx(node, instr, code, s);
    }
    const char suffix = suffix_from_opsize(opsize);
    const auto addr = AddrModeArg::Fetch(
            node.offset + kInstructionSizeStepBytes, code, instr, suffix);
    switch (addr.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code, s);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        if (dir == 1 || suffix == 'b') {
            // An cannot be destination and An cannot be used as byte
            return disasm_verbatim(node, instr, code, s);
        }
        /* Fall through */
    case AddrMode::kAnAddr:
    case AddrMode::kAnAddrIncr:
    case AddrMode::kAnAddrDecr:
    case AddrMode::kD16AnAddr:
    case AddrMode::kD8AnXiAddr:
    case AddrMode::kWord:
    case AddrMode::kLong:
        break;
    case AddrMode::kD16PCAddr:
    case AddrMode::kD8PCXiAddr:
    case AddrMode::kImmediate:
        if (dir == 1) {
            // PC relative and immediate cannot be destination
            return disasm_verbatim(node, instr, code, s);
        }
        if (1) {
            // XXX GNU AS always emits ADDI (06xx xxxx [xxxx]) instruction when
            // given ADD with immediate source argument. It may become an
            // option, but for now it is gonna be just plain bytes to keep
            // original and reassembled binaries *identical* as it must be by
            // default.
            return disasm_verbatim(node, instr, code, s);
        }
        break;
    }
    const unsigned dn = (instr >> 9) & 7;
    const auto reg = AddrModeArg::Dn(dn);
    char addr_str[32]{};
    char reg_str[32]{};
    addr.SNPrint(addr_str, sizeof(addr_str));
    reg.SNPrint(reg_str, sizeof(reg_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "add%c", suffix);
    if (dir == 1) {
        snprintf(node.arguments, kArgsBufferSize, "%s,%s", reg_str, addr_str);
    } else {
        snprintf(node.arguments, kArgsBufferSize, "%s,%s", addr_str, reg_str);
    }
    node.size = kInstructionSizeStepBytes + addr.Size() + reg.Size();
}

static void chunk_mf000_ve000(DisasmNode &n, uint16_t i, const DataBuffer &c, const Settings &s)
{
    return disasm_verbatim(n, i, c, s);
}

static void m68k_disasm(DisasmNode &n, uint16_t i, const DataBuffer &c, const Settings &s)
{
    switch ((i & 0xf000) >> 12) {
    case 0x0:
        return chunk_mf000_v0000(n, i, c, s);
    case 0x1:
    case 0x2:
    case 0x3:
        return disasm_move_movea(n, i, c, s);
    case 0x4:
        return chunk_mf000_v4000(n, i, c, s);
    case 0x5:
        return chunk_mf000_v5000(n, i, c, s);
    case 0x6:
        return disasm_bra_bsr_bcc(n, i, c, s);
    case 0x7:
        return disasm_moveq(n, i, c, s);
    case 0x8:
        return chunk_mf000_v8000(n, i, c, s);
    case 0x9:
        return chunk_mf000_v9000(n, i, c, s);
    case 0xa:
        // Does not exist
        return disasm_verbatim(n, i, c, s);
    case 0xb:
        return chunk_mf000_vb000(n, i, c, s);
    case 0xc:
        return chunk_mf000_vc000(n, i, c, s);
    case 0xd:
        return disasm_add_addx_adda(n, i, c, s);
    case 0xe:
        return chunk_mf000_ve000(n, i, c, s);
    case 0xf:
        // Does not exist
        return disasm_verbatim(n, i, c, s);
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
