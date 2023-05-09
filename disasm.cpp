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

enum class ShiftDirection: bool {
    kRight = 0,
    kLeft = 1,
};

enum class ShiftKind: int {
    kArithmeticShift = 0,
    kLogicalShift = 1,
    kRotateX = 2,
    kRotate = 3,
};

enum class Cond {
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



constexpr AddrModeArg FetchAddrModeArg(
        const uint32_t offset, const DataBuffer &code, const int m, const int xn, const OpSize s)
{
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
            const OpSize s = ((briefext >> 11) & 1) ? OpSize::kLong : OpSize::kWord;
            const int8_t d8 = briefext & 0xff;
            return AddrModeArg::D8AnXiAddr(xn, r, xi, s, d8);
        }
        break;
    case 7:
        switch (xn) {
        case 0: // (xxx).W, Additional Word
            if (offset < code.occupied_size) {
                const int32_t w = GetI16BE(code.buffer + offset);
                return AddrModeArg::Word(xn, w);
            }
            break;
        case 1: // (xxx).L, Additional Long
            if (offset + kInstructionSizeStepBytes < code.occupied_size) {
                const int32_t l = GetI32BE(code.buffer + offset);
                return AddrModeArg::Long(xn, l);
            }
            break;
        case 2: // (d16, PC), Additional Word
            if (offset < code.occupied_size) {
                const int16_t d16 = GetI16BE(code.buffer + offset);
                return AddrModeArg::D16PCAddr(xn, d16);
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
                const OpSize s = ((briefext >> 11) & 1) ? OpSize::kLong : OpSize::kWord;
                const int8_t d8 = briefext & 0xff;
                return AddrModeArg::D8PCXiAddr(xn, r, xi, s, d8);
            }
            break;
        case 4: // #imm
            if (s == OpSize::kLong) {
                if (offset + kInstructionSizeStepBytes < code.occupied_size) {
                    const int32_t value = GetI32BE(code.buffer + offset);
                    return AddrModeArg::Immediate(xn, s, value);
                }
            } else if (offset < code.occupied_size) {
                const int16_t value = GetI16BE(code.buffer + offset);
                if (s == OpSize::kByte) {
                    if (value > 255 || value < -255) {
                        // Invalid immediate value for instruction with .b
                        // suffix
                        break;
                    }
                }
                return AddrModeArg::Immediate(xn, s, value);
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

static inline AddrModeArg FetchAddrModeArg(
        const uint32_t offset, const DataBuffer &code, int16_t instr, OpSize s)
{
    const int addrmode = instr & 0x3f;
    const int m = (addrmode >> 3) & 7;
    const int xn = addrmode & 7;
    return FetchAddrModeArg(offset, code, m, xn, s);
}

static char suffix_from_opsize(OpSize opsize)
{
    switch (opsize) {
    case OpSize::kByte: return 'b';
    case OpSize::kWord: return 'w';
    case OpSize::kLong: return 'l';
    case OpSize::kInvalid: return 'w';
    }
    return 'w';
}

static size_t disasm_verbatim(
        DisasmNode &node, uint16_t instr, const DataBuffer &)
{
    node.opcode = OpCode::kRaw;
    node.arg1 = Arg::Raw(instr);
    return node.size;
}

static size_t disasm_jsr_jmp(
        DisasmNode &node, uint16_t instr, const DataBuffer &code, JType jtype)
{
    const auto a = FetchAddrModeArg(node.offset + kInstructionSizeStepBytes, code, instr, OpSize::kWord);
    switch (a.mode) {
    case AddrMode::kInvalid:
    case AddrMode::kDn: // 4e80..4e87 / 4ec0..4ec7
    case AddrMode::kAn: // 4e88..4e8f / 4ec8..4ecf
        return disasm_verbatim(node, instr, code);
    case AddrMode::kAnAddr: // 4e90..4e97 / 4ed0..4ed7
        // NOTE: dynamic jump, branch_addr may possibly be obtained during the
        // trace
        break;
    case AddrMode::kAnAddrIncr: // 4e98..4e9f / 4ed8..4edf
    case AddrMode::kAnAddrDecr: // 4ea0..4ea7 / 4ee0..4ee7
        return disasm_verbatim(node, instr, code);
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
        return disasm_verbatim(node, instr, code);
    }
    node.is_call = (jtype == JType::kJsr);
    node.opcode = (jtype == JType::kJsr) ? OpCode::kJSR : OpCode::kJMP;
    node.arg1 = Arg::FromAddrModeArg(a);
    return node.size = kInstructionSizeStepBytes + a.Size();
}

static inline SizeSpec ToSizeSpec(OpSize opsize) {
    switch (opsize) {
    case OpSize::kByte: return SizeSpec::kByte;
    case OpSize::kWord: return SizeSpec::kWord;
    case OpSize::kLong: return SizeSpec::kLong;
    case OpSize::kInvalid: return SizeSpec::kNone;
    }
    return SizeSpec::kNone;
}

static inline size_t disasm_ext(
        DisasmNode &node,
        const OpSize opsize,
        const AddrModeArg arg)
{
    assert(arg.mode == AddrMode::kDn);
    node.opcode = OpCode::kEXT;
    node.size_spec = ToSizeSpec(opsize);
    node.arg1 = Arg::FromAddrModeArg(arg);
    return node.size = kInstructionSizeStepBytes + arg.Size();
}

static size_t disasm_ext_movem(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    const auto dir = static_cast<MoveDirection>((instr >> 10) & 1);
    const unsigned m = (instr >> 3) & 7;
    const unsigned xn = instr & 7;
    const auto opsize = static_cast<OpSize>(((instr >> 6) & 1) + 1);
    if (m == 0 && dir == MoveDirection::kRegisterToMemory) {
        return disasm_ext(node, opsize, AddrModeArg::Dn(xn));
    }
    if (node.offset + kInstructionSizeStepBytes >= code.occupied_size) {
        // Not enough space for regmask, but maybe it is just EXT?
        return disasm_verbatim(node, instr, code);
    }
    const unsigned regmask = GetU16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
    if (regmask == 0) {
        // This is just not representable: at least one register must be specified
        return disasm_verbatim(node, instr, code);
    }
    const auto a = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes * 2, code, m, xn, opsize);
    switch (a.mode) {
    case AddrMode::kInvalid:
    case AddrMode::kDn: // 4880..4887 / 4c80..4c87 / 48c0..48c7 / 4cc0..4cc7
    case AddrMode::kAn: // 4888..488f / 4c88..4c8f / 48c8..48cf / 4cc8..4ccf
        return disasm_verbatim(node, instr, code);
    case AddrMode::kAnAddr: // 4890..4897 / 4c90..4c97 / 48d0..48d7 / 4cd0..4cd7
        break;
    case AddrMode::kAnAddrIncr: // 4898..489f / 4c89..4c9f / 48d8..48df / 4cd8..4cdf
        if (dir == MoveDirection::kRegisterToMemory) {
            return disasm_verbatim(node, instr, code);
        }
        break;
    case AddrMode::kAnAddrDecr: // 48a0..48a7 / 4ca0..4ca7 / 48e0..48e7 / 4ce0..4ce7
        if (dir == MoveDirection::kMemoryToRegister) {
            return disasm_verbatim(node, instr, code);
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
            return disasm_verbatim(node, instr, code);
        }
        break;
    case AddrMode::kImmediate: // 4ebc / 4efc
        return disasm_verbatim(node, instr, code);
    }
    node.size_spec = ToSizeSpec(opsize);
    node.opcode = OpCode::kMOVEM;
    if (dir == MoveDirection::kMemoryToRegister) {
        node.arg1 = Arg::FromAddrModeArg(a);
        node.arg2 = (a.mode == AddrMode::kAnAddrDecr) ? Arg::RegMaskPredecrement(regmask) : Arg::RegMask(regmask);
    } else {
        node.arg1 = (a.mode == AddrMode::kAnAddrDecr) ? Arg::RegMaskPredecrement(regmask) : Arg::RegMask(regmask);
        node.arg2 = Arg::FromAddrModeArg(a);
    }
    return node.size = kInstructionSizeStepBytes * 2 + a.Size();
}

static size_t disasm_lea(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    const auto addr = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes, code, instr, OpSize::kLong);
    switch (addr.mode) {
    case AddrMode::kInvalid:
    case AddrMode::kDn:
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code);
    case AddrMode::kAnAddr:
        break;
    case AddrMode::kAnAddrIncr:
    case AddrMode::kAnAddrDecr:
        return disasm_verbatim(node, instr, code);
    case AddrMode::kD16AnAddr:
    case AddrMode::kD8AnXiAddr:
    case AddrMode::kWord:
    case AddrMode::kLong:
    case AddrMode::kD16PCAddr:
    case AddrMode::kD8PCXiAddr:
        break;
    case AddrMode::kImmediate:
        return disasm_verbatim(node, instr, code);
    }
    const unsigned an = ((instr >> 9) & 7);
    const auto reg = AddrModeArg::An(an);
    char addr_str[32]{};
    char reg_str[32]{};
    addr.SNPrint(addr_str, sizeof(addr_str));
    reg.SNPrint(reg_str, sizeof(reg_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "leal");
    snprintf(node.arguments, kArgsBufferSize, "%s,%s", addr_str, reg_str);
    return node.size = kInstructionSizeStepBytes + addr.Size() + reg.Size();
}

static size_t disasm_chk(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    const auto src = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes, code, instr, OpSize::kWord);
    switch (src.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code);
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
        return disasm_verbatim(node, instr, code);
    }
    const unsigned dn = ((instr >> 9) & 7);
    const auto dst = AddrModeArg::Dn(dn);
    char src_str[32]{};
    char dst_str[32]{};
    src.SNPrint(src_str, sizeof(src_str));
    dst.SNPrint(dst_str, sizeof(dst_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "chkw");
    snprintf(node.arguments, kArgsBufferSize, "%s,%s", src_str, dst_str);
    return node.size = kInstructionSizeStepBytes + src.Size() + dst.Size();
}

static inline const char *bcc_mnemonic_by_condition(Cond condition)
{
    switch (condition) {
    case Cond::kT:  return "bra"; // 60xx
    case Cond::kF:  return "bsr"; // 61xx
    case Cond::kHI: return "bhi"; // 62xx
    case Cond::kLS: return "bls"; // 63xx
    case Cond::kCC: return "bcc"; // 64xx
    case Cond::kCS: return "bcs"; // 65xx
    case Cond::kNE: return "bne"; // 66xx
    case Cond::kEQ: return "beq"; // 67xx
    case Cond::kVC: return "bvc"; // 68xx
    case Cond::kVS: return "bvs"; // 69xx
    case Cond::kPL: return "bpl"; // 6axx
    case Cond::kMI: return "bmi"; // 6bxx
    case Cond::kGE: return "bge"; // 6cxx
    case Cond::kLT: return "blt"; // 6dxx
    case Cond::kGT: return "bgt"; // 6exx
    case Cond::kLE: return "ble"; // 6fxx
    }
    assert(false);
    return "?";
}

static size_t disasm_bra_bsr_bcc(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    Cond condition = static_cast<Cond>((instr >> 8) & 0xf);
    const char *mnemonic = bcc_mnemonic_by_condition(condition);
    // False condition Indicates BSR
    int dispmt = static_cast<int8_t>(instr & 0xff);
    if (dispmt % kInstructionSizeStepBytes) {
        return disasm_verbatim(node, instr, code);
    }
    const char suffix = dispmt ? 's' : 'w';
    if (dispmt == 0) {
        // Check the boundaries
        if (node.offset + kInstructionSizeStepBytes >= code.occupied_size) {
            return disasm_verbatim(node, instr, code);
        }
        dispmt = GetI16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
        if (dispmt % kInstructionSizeStepBytes) {
            return disasm_verbatim(node, instr, code);
        }
        node.size = kInstructionSizeStepBytes * 2;
    } else {
        node.size = kInstructionSizeStepBytes;
    }
    node.is_call = (condition == Cond::kF);
    dispmt += kInstructionSizeStepBytes;
    const uint32_t branch_addr = static_cast<uint32_t>(node.offset + dispmt);
    node.branch_addr = branch_addr;
    node.has_branch_addr = true;
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
    const char * const sign = dispmt >= 0 ? "+" : "";
    // FIXME support s.rel_marks option for this instruction
    snprintf(node.arguments, kArgsBufferSize, ".%s%d", sign, dispmt);
    return node.size;
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

static inline size_t disasm_movep(
        DisasmNode &node, const uint16_t instr, const DataBuffer &code)
{
    const unsigned dn = ((instr >> 9) & 7);
    const unsigned an = instr & 7;
    const OpSize opsize = ((instr >> 6) & 1) ? OpSize::kLong : OpSize::kWord;
    const auto dir = static_cast<MoveDirection>(!((instr >> 7) & 1));
    const auto addr = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes, code, 5, an, opsize);
    if (addr.mode == AddrMode::kInvalid) {
        // Boundary check failed, most likely
        return disasm_verbatim(node, instr, code);
    }
    assert(addr.mode == AddrMode::kD16AnAddr);
    const auto reg = AddrModeArg::Dn(dn);
    char addr_str[32]{};
    char reg_str[32]{};
    addr.SNPrint(addr_str, sizeof(addr_str));
    reg.SNPrint(reg_str, sizeof(reg_str));
    const char suffix = (opsize == OpSize::kLong) ? 'l' : 'w';
    snprintf(node.mnemonic, kMnemonicBufferSize, "movep%c", suffix);
    if (dir == MoveDirection::kRegisterToMemory) {
        snprintf(node.arguments, kArgsBufferSize, "%s,%s", reg_str, addr_str);
    } else {
        snprintf(node.arguments, kArgsBufferSize, "%s,%s", addr_str, reg_str);
    }
    return node.size = kInstructionSizeStepBytes + addr.Size() + reg.Size();
}

static size_t disasm_src_arg_bitops_movep(
        DisasmNode &node,
        const uint16_t instr,
        const DataBuffer &code,
        const bool has_dn_src = true)
{
    const unsigned m = (instr >> 3) & 7;
    if ((m == 1) && has_dn_src) {
        return disasm_movep(node, instr, code);
    }
    const unsigned dn = ((instr >> 9) & 7);
    const unsigned xn = instr & 7;
    // FetchAddrModeArg AddrMode::kDn if has_dn_src, otherwise fetch AddrMode::kImmediate
    // byte
    const auto src = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes,
            code,
            (has_dn_src) ? 0 : 7,
            dn,
            OpSize::kByte);
    if (src.mode == AddrMode::kInvalid) {
        return disasm_verbatim(node, instr, code);
    }
    if (has_dn_src) {
        assert(src.mode == AddrMode::kDn);
    } else {
        assert(dn == 4);
        assert(src.mode == AddrMode::kImmediate);
    }
    const auto dst = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes + src.Size(), code, m, xn, OpSize::kWord);
    const unsigned opcode = (instr >> 6) & 3;
    switch (dst.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code);
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
            return disasm_verbatim(node, instr, code);
        }
        break;
    case AddrMode::kImmediate:
        return disasm_verbatim(node, instr, code);
    }
    char src_str[32]{};
    char dst_str[32]{};
    src.SNPrint(src_str, sizeof(src_str));
    dst.SNPrint(dst_str, sizeof(dst_str));
    const char suffix = dst.mode == AddrMode::kDn ? 'l' : 'b';
    const char *mnemonic = mnemonic_for_bitops(opcode);
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
    snprintf(node.arguments, kArgsBufferSize, "%s,%s", src_str, dst_str);
    return node.size = kInstructionSizeStepBytes + src.Size() + dst.Size();
}

static size_t disasm_bitops(DisasmNode &n, const uint16_t i, const DataBuffer &c)
{
    return disasm_src_arg_bitops_movep(n, i, c, false);
}

static inline size_t disasm_logical_immediate_to(
        DisasmNode &node, const char* mnemonic, const char suffix, const int16_t imm)
{
    const char *reg = suffix == 'b' ? "ccr" : "sr";
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
    snprintf(node.arguments, kArgsBufferSize, "#%d,%%%s", imm, reg);
    return node.size = kInstructionSizeStepBytes * 2;
}

static inline const char *mnemonic_logical_immediate(const unsigned opcode)
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

static size_t disasm_bitops_movep(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    const bool has_source_reg = (instr >> 8) & 1;
    if (has_source_reg) {
        return disasm_src_arg_bitops_movep(node, instr, code);
    }
    const unsigned opcode = (instr >> 9) & 7;
    if (opcode == 7) {
        // Does not exist
        return disasm_verbatim(node, instr, code);
    }
    if (opcode == 4) {
        return disasm_bitops(node, instr, code);
    }
    const int m = (instr >> 3) & 7;
    const int xn = instr & 7;
    const auto opsize = static_cast<OpSize>((instr >> 6) & 3);
    if (opsize == OpSize::kInvalid) {
            // Does not exist
            return disasm_verbatim(node, instr, code);
    }
    // Anticipating #imm which means "to CCR"/"to SR", depending on OpSize
    if (m == 7 && xn == 4) {
        if (opcode == 2 || opcode == 3 || opcode == 6) {
            // CMPI, SUBI and ANDI neither have immediate destination arguments
            // nor "to CCR"/"to SR" variations
            return disasm_verbatim(node, instr, code);
        }
        if (opsize == OpSize::kLong) {
            // Does not exist
            return disasm_verbatim(node, instr, code);
        }
    }
    const auto src = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes, code, 7, 4, opsize);
    if (src.mode == AddrMode::kInvalid) {
        return disasm_verbatim(node, instr, code);
    }
    assert(src.mode == AddrMode::kImmediate);
    const char *mnemonic = mnemonic_logical_immediate(opcode);
    const char suffix = suffix_from_opsize(opsize);
    if (m == 7 && xn == 4) {
        return disasm_logical_immediate_to(node, mnemonic, suffix, src.value);
    }
    const auto dst = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes + src.Size(), code, m, xn, opsize);
    switch (dst.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code);
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
            return disasm_verbatim(node, instr, code);
        }
        break;
    case AddrMode::kImmediate:
        return disasm_verbatim(node, instr, code);
    }
    char dst_str[32]{};
    dst.SNPrint(dst_str, sizeof(dst_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
    snprintf(node.arguments, kArgsBufferSize, "#%d,%s", src.value, dst_str);
    return node.size = kInstructionSizeStepBytes + src.Size() + dst.Size();
}

static size_t disasm_move_movea(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    const int size_spec = (instr >> 12) & 3;
    const char suffix = size_spec == 1 ? 'b' : (size_spec == 3 ? 'w' : 'l');
    const OpSize opsize = size_spec == 1 ? OpSize::kByte : (size_spec == 3 ? OpSize::kWord : OpSize::kLong);
    const auto src = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes, code, instr, opsize);
    if (src.mode == AddrMode::kInvalid) {
        return disasm_verbatim(node, instr, code);
    }
    if (suffix == 'b' && src.mode == AddrMode::kAn) {
        // Does not exist
        return disasm_verbatim(node, instr, code);
    }
    const int m = (instr >> 6) & 7;
    const int xn = (instr >> 9) & 7;
    const auto dst = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes + src.Size(), code, m, xn, opsize);
    switch (dst.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        if (suffix == 'b') {
            // Does not exist
            return disasm_verbatim(node, instr, code);
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
        return disasm_verbatim(node, instr, code);
    }
    char src_str[32]{};
    char dst_str[32]{};
    src.SNPrint(src_str, sizeof(src_str));
    dst.SNPrint(dst_str, sizeof(dst_str));
    const char *mnemonic = dst.mode == AddrMode::kAn ? "movea" : "move";
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
    snprintf(node.arguments, kArgsBufferSize, "%s,%s", src_str, dst_str);
    return node.size = kInstructionSizeStepBytes + src.Size() + dst.Size();
}

static size_t disasm_move_from_sr(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    const auto opsize = OpSize::kWord;
    const auto dst = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes, code, instr, opsize);
    switch (dst.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code);
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
        return disasm_verbatim(node, instr, code);
    }
    char dst_str[32]{};
    dst.SNPrint(dst_str, sizeof(dst_str));
    const char suffix = suffix_from_opsize(opsize);
    snprintf(node.mnemonic, kMnemonicBufferSize, "move%c", suffix);
    snprintf(node.arguments, kArgsBufferSize, "%%sr,%s", dst_str);
    return node.size = kInstructionSizeStepBytes + dst.Size();
}

static size_t disasm_move_to(
        DisasmNode &node, uint16_t instr, const DataBuffer &code, const char* reg)
{
    const auto opsize = OpSize::kWord;
    const auto src = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes, code, instr, opsize);
    switch (src.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code);
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
    const char suffix = suffix_from_opsize(opsize);
    char src_str[32]{};
    src.SNPrint(src_str, sizeof(src_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "move%c", suffix);
    snprintf(node.arguments, kArgsBufferSize, "%s,%%%s", src_str, reg);
    return node.size = kInstructionSizeStepBytes + src.Size();
}

static inline const char *mnemonic_for_negx_clr_neg_not(const unsigned opcode)
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

static size_t disasm_move_negx_clr_neg_not(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    const auto opsize = static_cast<OpSize>((instr >> 6) & 3);
    const unsigned opcode = (instr >> 9) & 3;
    if (opsize == OpSize::kInvalid) {
        switch (opcode) {
        case 0:
            return disasm_move_from_sr(node, instr, code);
        case 1:
            return disasm_verbatim(node, instr, code);
        case 2:
            return disasm_move_to(node, instr, code, "ccr");
        case 3:
            return disasm_move_to(node, instr, code, "sr");
        }
        assert(false);
        return disasm_verbatim(node, instr, code);
    }
    const char *mnemonic = mnemonic_for_negx_clr_neg_not(opcode);
    const char suffix = suffix_from_opsize(opsize);
    const auto a = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes, code, instr, opsize);
    switch (a.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code);
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
        return disasm_verbatim(node, instr, code);
    }
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
    a.SNPrint(node.arguments, kArgsBufferSize);
    return node.size = kInstructionSizeStepBytes + a.Size();
}

static inline size_t disasm_trivial(
        DisasmNode &node, uint16_t, const DataBuffer &, const char* mnemonic)
{
    snprintf(node.mnemonic, kMnemonicBufferSize, mnemonic);
    return node.size = kInstructionSizeStepBytes;
}

static inline size_t disasm_tas(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    const auto a = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes, code, instr, OpSize::kWord);
    switch (a.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code);
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
        return disasm_verbatim(node, instr, code);
    }
    snprintf(node.mnemonic, kMnemonicBufferSize, "tas");
    a.SNPrint(node.arguments, kArgsBufferSize);
    return node.size = kInstructionSizeStepBytes + a.Size();
}

static size_t disasm_tst_tas_illegal(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    const auto opsize = static_cast<OpSize>((instr >> 6) & 3);
    const int m = (instr >> 3) & 7;
    const int xn = instr & 7;
    if (opsize == OpSize::kInvalid) {
        if (m == 7 && xn == 4){
            return disasm_trivial(node, instr, code, "illegal");
        }
        return disasm_tas(node, instr, code);
    }
    const char suffix = suffix_from_opsize(opsize);
    const auto a = FetchAddrModeArg(node.offset + kInstructionSizeStepBytes, code, m, xn, opsize);
    switch (a.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code);
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
        return disasm_verbatim(node, instr, code);
    }
    snprintf(node.mnemonic, kMnemonicBufferSize, "tst%c", suffix);
    a.SNPrint(node.arguments, kArgsBufferSize);
    return node.size = kInstructionSizeStepBytes + a.Size();
}

static size_t disasm_trap(
        DisasmNode &node, uint16_t instr, const DataBuffer &)
{
    const unsigned vector = instr & 0xf;
    snprintf(node.mnemonic, kMnemonicBufferSize, "trap");
    snprintf(node.arguments, kArgsBufferSize, "#%u", vector);
    return node.size = kInstructionSizeStepBytes;
}

static size_t disasm_link_unlink(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    const bool unlk = (instr >> 3) & 1;
    const unsigned xn = instr & 7;
    if (unlk) {
        snprintf(node.mnemonic, kMnemonicBufferSize, "unlk");
        snprintf(node.arguments, kArgsBufferSize, "%%a%u", xn);
        return node.size = kInstructionSizeStepBytes;
    }
    // FetchAddrModeArg immediate word
    const auto src = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes, code, 7, 4, OpSize::kWord);
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
        return disasm_verbatim(node, instr, code);
    case AddrMode::kImmediate:
        break;
    }
    char src_str[32]{};
    src.SNPrint(src_str, sizeof(src_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "linkw");
    snprintf(node.arguments, kArgsBufferSize, "%%a%u,%s", xn, src_str);
    return node.size = kInstructionSizeStepBytes + src.Size();
}

static size_t disasm_move_usp(
        DisasmNode &node, uint16_t instr, const DataBuffer &)
{
    const unsigned xn = instr & 7;
    const auto dir = static_cast<MoveDirection>((instr >> 3) & 1);
    snprintf(node.mnemonic, kMnemonicBufferSize, "movel");
    if (dir == MoveDirection::kRegisterToMemory) {
        snprintf(node.arguments, kArgsBufferSize, "%%a%u,%%usp", xn);
    } else {
        snprintf(node.arguments, kArgsBufferSize, "%%usp,%%a%u", xn);
    }
    return node.size = kInstructionSizeStepBytes;
}

static size_t disasm_nbcd_swap_pea(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    const bool is_nbcd = !((instr >> 6) & 1);
    const auto arg = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes, code, instr, OpSize::kWord);
    bool is_swap{};
    switch (arg.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code);
    case AddrMode::kDn:
        if (!is_nbcd) {
            is_swap = true;
        }
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code);
    case AddrMode::kAnAddr:
        break;
    case AddrMode::kAnAddrIncr:
    case AddrMode::kAnAddrDecr:
        if (!is_nbcd) {
            return disasm_verbatim(node, instr, code);
        }
        break;
    case AddrMode::kD16AnAddr:
    case AddrMode::kD8AnXiAddr:
    case AddrMode::kWord:
    case AddrMode::kLong:
        break;
    case AddrMode::kD16PCAddr:
    case AddrMode::kD8PCXiAddr:
        if (is_nbcd) {
            return disasm_verbatim(node, instr, code);
        }
        break;
    case AddrMode::kImmediate:
        return disasm_verbatim(node, instr, code);
    }
    const char *mnemonic = is_nbcd ? "nbcdb" : is_swap ? "swapw" : "peal";
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s", mnemonic);
    arg.SNPrint(node.arguments, kArgsBufferSize);
    return node.size = kInstructionSizeStepBytes + arg.Size();
}

static size_t disasm_chunk_4(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    if ((instr & 0xf900) == 0x4000) {
        return disasm_move_negx_clr_neg_not(node, instr, code);
    } else if ((instr & 0xff80) == 0x4800) {
        // NOTE EXT is handled with MOVEM
        return disasm_nbcd_swap_pea(node, instr, code);
    } else if ((instr & 0xff00) == 0x4a00) {
        return disasm_tst_tas_illegal(node, instr, code);
    } else if ((instr & 0xfff0) == 0x4e40) {
        return disasm_trap(node, instr, code);
    } else if ((instr & 0xfff0) == 0x4e50) {
        return disasm_link_unlink(node, instr, code);
    } else if ((instr & 0xfff0) == 0x4e60) {
        return disasm_move_usp(node, instr, code);
    } else if (instr == 0x4e70) {
        return disasm_trivial(node, instr, code, "reset");
    } else if (instr == 0x4e71) {
        return disasm_trivial(node, instr, code, "nop");
    } else if (instr == 0x4e72) {
        if (node.offset + kInstructionSizeStepBytes < code.occupied_size) {
            snprintf(node.mnemonic, kMnemonicBufferSize, "stop");
            const uint16_t sr_imm = GetU16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
            snprintf(node.arguments, kArgsBufferSize, "#0x%x:w", sr_imm);
            return node.size = kInstructionSizeStepBytes * 2;
        }
    } else if (instr == 0x4e73) {
        return disasm_trivial(node, instr, code, "rte");
    } else if (instr == 0x4e75) {
        return disasm_trivial(node, instr, code, "rts");
    } else if (instr == 0x4e76) {
        return disasm_trivial(node, instr, code, "trapv");
    } else if (instr == 0x4e77) {
        return disasm_trivial(node, instr, code, "rtr");
    } else if ((instr & 0xffc0) == 0x4e80) {
        return disasm_jsr_jmp(node, instr, code, JType::kJsr);
    } else if ((instr & 0xffc0) == 0x4ec0) {
        return disasm_jsr_jmp(node, instr, code, JType::kJmp);
    } else if ((instr & 0xfb80) == 0x4880) {
        return disasm_ext_movem(node, instr, code);
    } else if ((instr & 0xf1c0) == 0x41c0) {
        return disasm_lea(node, instr, code);
    } else if ((instr & 0xf1c0) == 0x4180) {
        return disasm_chk(node, instr, code);
    }
    return disasm_verbatim(node, instr, code);
}

static size_t disasm_addq_subq(
        DisasmNode &node, uint16_t instr, const DataBuffer &code, OpSize opsize)
{
    const char suffix = suffix_from_opsize(opsize);
    const auto a = FetchAddrModeArg(node.offset + kInstructionSizeStepBytes, code, instr, opsize);
    switch (a.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code);
    case AddrMode::kDn: // 5x00..5x07 / 5x40..5x47 / 5x80..5x87
        break;
    case AddrMode::kAn: // 5x08..5x0f / 5x48..5x4f / 5x88..5x8f
        if (opsize == OpSize::kByte) {
            // 5x08..5x0f
            // addqb and subqb with An do not exist
            return disasm_verbatim(node, instr, code);
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
        return disasm_verbatim(node, instr, code);
    }
    const char *mnemonic = (instr >> 8) & 1 ? "subq" : "addq";
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
    const unsigned imm = ((uint8_t((instr >> 9) & 7) - 1) & 7) + 1;
    const int ret = snprintf(node.arguments, kArgsBufferSize, "#%u,", imm);
    assert(ret > 0);
    assert(static_cast<unsigned>(ret) == strlen("#8,"));
    a.SNPrint(node.arguments + ret, kArgsBufferSize - ret);
    return node.size = kInstructionSizeStepBytes + a.Size();
}

static inline const char *dbcc_mnemonic_by_condition(Cond condition)
{
    switch (condition) {
    case Cond::kT:  return "dbt";  // 50c8..50cf
    case Cond::kF:  return "dbf";  // 51c8..51cf
    case Cond::kHI: return "dbhi"; // 52c8..52cf
    case Cond::kLS: return "dbls"; // 53c8..53cf
    case Cond::kCC: return "dbcc"; // 54c8..54cf
    case Cond::kCS: return "dbcs"; // 55c8..55cf
    case Cond::kNE: return "dbne"; // 56c8..56cf
    case Cond::kEQ: return "dbeq"; // 57c8..57cf
    case Cond::kVC: return "dbvc"; // 58c8..58cf
    case Cond::kVS: return "dbvs"; // 59c8..59cf
    case Cond::kPL: return "dbpl"; // 5ac8..5acf
    case Cond::kMI: return "dbmi"; // 5bc8..5bcf
    case Cond::kGE: return "dbge"; // 5cc8..5ccf
    case Cond::kLT: return "dblt"; // 5dc8..5dcf
    case Cond::kGT: return "dbgt"; // 5ec8..5ecf
    case Cond::kLE: return "dble"; // 5fc8..5fcf
    }
    assert(false);
    return "?";
}

static size_t disasm_dbcc(DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    if (node.offset + kInstructionSizeStepBytes >= code.occupied_size) {
        return disasm_verbatim(node, instr, code);
    }
    const int16_t dispmt_raw = GetI16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
    if (dispmt_raw % kInstructionSizeStepBytes) {
        return disasm_verbatim(node, instr, code);
    }
    Cond condition = static_cast<Cond>((instr >> 8) & 0xf);
    const char *mnemonic = dbcc_mnemonic_by_condition(condition);
    const int dn = (instr & 7);
    const uint32_t branch_addr = static_cast<uint32_t>(
            node.offset + dispmt_raw + kInstructionSizeStepBytes);
    node.branch_addr = branch_addr;
    node.has_branch_addr = true;
    const int32_t dispmt = dispmt_raw + kInstructionSizeStepBytes;
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s", mnemonic);
    const char * const sign = dispmt >= 0 ? "+" : "";
    // FIXME support s.rel_marks option for this instruction
    snprintf(node.arguments, kArgsBufferSize, "%%d%d,.%s%d", dn, sign, dispmt);
    return node.size = kInstructionSizeStepBytes * 2;
}

static inline const char *scc_mnemonic_by_condition(Cond condition)
{
    switch (condition) {
    case Cond::kT:  return "st";  // 50cx..50fx
    case Cond::kF:  return "sf";  // 51cx..51fx
    case Cond::kHI: return "shi"; // 52cx..52fx
    case Cond::kLS: return "sls"; // 53cx..53fx
    case Cond::kCC: return "scc"; // 54cx..54fx
    case Cond::kCS: return "scs"; // 55cx..55fx
    case Cond::kNE: return "sne"; // 56cx..56fx
    case Cond::kEQ: return "seq"; // 57cx..57fx
    case Cond::kVC: return "svc"; // 58cx..58fx
    case Cond::kVS: return "svs"; // 59cx..59fx
    case Cond::kPL: return "spl"; // 5acx..5afx
    case Cond::kMI: return "smi"; // 5bcx..5bfx
    case Cond::kGE: return "sge"; // 5ccx..5cfx
    case Cond::kLT: return "slt"; // 5dcx..5dfx
    case Cond::kGT: return "sgt"; // 5ecx..5efx
    case Cond::kLE: return "sle"; // 5fcx..5ffx
    }
    assert(false);
    return "?";
}

static size_t disasm_scc_dbcc(
        DisasmNode &node, const uint16_t instr, const DataBuffer &code)
{
    const auto a = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes, code, instr, OpSize::kWord);
    switch (a.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code);
    case AddrMode::kDn: // 5xc0..5xc7, Dn
        break;
    case AddrMode::kAn: // 5xc8..5xcf, An
        return disasm_dbcc(node, instr, code);
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
        return disasm_verbatim(node, instr, code);
    }
    Cond condition = static_cast<Cond>((instr >> 8) & 0xf);
    const char *mnemonic = scc_mnemonic_by_condition(condition);
    snprintf(node.mnemonic, kMnemonicBufferSize, mnemonic);
    a.SNPrint(node.arguments, kArgsBufferSize);
    return node.size = kInstructionSizeStepBytes + a.Size();
}

static size_t disasm_addq_subq_scc_dbcc(DisasmNode &n, uint16_t instr, const DataBuffer &c)
{
    const auto opsize = static_cast<OpSize>((instr >> 6) & 3);
    if (opsize == OpSize::kInvalid) {
        return disasm_scc_dbcc(n, instr, c);
    }
    return disasm_addq_subq(n, instr, c, opsize);
}

static size_t disasm_moveq(DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    if (instr & 0x100) {
        // Does not exist
        return disasm_verbatim(node, instr, code);
    }
    const int xn = (instr >> 9) & 7;
    const auto dst = AddrModeArg::Dn(xn);
    char dst_str[32]{};
    dst.SNPrint(dst_str, sizeof(dst_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "moveq");
    const int8_t data = instr & 0xff;
    snprintf(node.arguments, kArgsBufferSize, "#%d,%s", data, dst_str);
    return node.size = kInstructionSizeStepBytes + dst.Size();

}

static size_t disasm_divu_divs_mulu_muls(
        DisasmNode &node,
        uint16_t instr,
        const DataBuffer &code,
        const char *mnemonic)
{
    const auto opsize = OpSize::kWord;
    const auto src = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes, code, instr, opsize);
    switch (src.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code);
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
        break;
    }
    const unsigned dn = (instr >> 9) & 7;
    const auto dst = AddrModeArg::Dn(dn);
    char dst_str[32]{};
    char src_str[32]{};
    dst.SNPrint(dst_str, sizeof(dst_str));
    src.SNPrint(src_str, sizeof(src_str));
    const bool is_signed = (instr >> 8) & 1;
    const char sign_suffix = is_signed ? 's' : 'u';
    const char suffix = suffix_from_opsize(opsize);
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c%c", mnemonic, sign_suffix, suffix);
    snprintf(node.arguments, kArgsBufferSize, "%s,%s", src_str, dst_str);
    return node.size = kInstructionSizeStepBytes + dst.Size() + src.Size();
}

static size_t disasm_addx_subx_abcd_sbcd(
        DisasmNode &node,
        const uint16_t instr,
        const char *mnemonic,
        const char *msuffix,
        const bool skip_suffix = false)
{
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    // Must be already handled by parent call
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
    const char suffix = suffix_from_opsize(opsize);
    if (skip_suffix) {
        // XXX GNU AS does not know ABCD.B, it only knows ABCD, but happily
        // consumes SBCD.B and others. That's why `skip_suffix` flag is needed,
        // specifically for ABCD mnemonic. It is probably a bug in GNU AS.
        snprintf(node.mnemonic, kMnemonicBufferSize, "%s%s", mnemonic, msuffix);
    } else {
        snprintf(node.mnemonic, kMnemonicBufferSize, "%s%s%c", mnemonic, msuffix, suffix);
    }
    snprintf(node.arguments, kArgsBufferSize, "%s,%s", src_str, dst_str);
    return node.size = kInstructionSizeStepBytes + src.Size() + dst.Size();
}

static size_t disasm_or_and(
        DisasmNode &node,
        uint16_t instr,
        const DataBuffer &code,
        const OpSize opsize,
        const char* mnemonic)
{
    const char suffix = suffix_from_opsize(opsize);
    const bool dir_to_addr = (instr >> 8) & 1;
    const auto addr = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes, code, instr, opsize);
    switch (addr.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code);
    case AddrMode::kDn:
        if (dir_to_addr) {
            // Switching dir when bot operands are data registers is not allowed
            return disasm_verbatim(node, instr, code);
        }
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code);
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
        if (dir_to_addr) {
            // PC relative cannot be destination
            return disasm_verbatim(node, instr, code);
        }
        break;
    case AddrMode::kImmediate:
        if (dir_to_addr) {
            // immediate cannot be destination
            return disasm_verbatim(node, instr, code);
        }
        if (1) {
            // XXX GNU AS always emits ORI (04xx xxxx [xxxx]) or ANDI (02xx
            // xxxx [xxxx]) instruction when given OR or AND correspondingly
            // with immediate source argument. It may become an option like
            // -fpedantic to generate instruction in this case, but for now it
            // is gonna be just plain bytes to keep original and reassembled
            // binaries *identical* as it must be by default.
            return disasm_verbatim(node, instr, code);
        }
        break;
    }
    const unsigned dn = (instr >> 9) & 7;
    const auto reg = AddrModeArg::Dn(dn);
    char addr_str[32]{};
    char reg_str[32]{};
    addr.SNPrint(addr_str, sizeof(addr_str));
    reg.SNPrint(reg_str, sizeof(reg_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
    if (dir_to_addr) {
        snprintf(node.arguments, kArgsBufferSize, "%s,%s", reg_str, addr_str);
    } else {
        snprintf(node.arguments, kArgsBufferSize, "%s,%s", addr_str, reg_str);
    }
    return node.size = kInstructionSizeStepBytes + addr.Size() + reg.Size();
}

static size_t disasm_divu_divs_sbcd_or(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    if ((instr & 0x1f0) == 0x100) {
        return disasm_addx_subx_abcd_sbcd(node, instr, "sbcd", "");
    }
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    if (opsize == OpSize::kInvalid) {
        return disasm_divu_divs_mulu_muls(node, instr, code, "div");
    }
    return disasm_or_and(node, instr, code, opsize, "or");
}

static inline size_t disasm_adda_suba_cmpa(
        DisasmNode &node, const uint16_t instr, const DataBuffer &code, const char *mnemonic)
{
    const OpSize opsize = static_cast<OpSize>(((instr >> 8) & 1) + 1);
    const char suffix = suffix_from_opsize(opsize);
    assert(suffix != 'b');
    const auto src = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes, code, instr, opsize);
    switch (src.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code);
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
    snprintf(node.mnemonic, kMnemonicBufferSize, "%sa%c", mnemonic, suffix);
    snprintf(node.arguments, kArgsBufferSize, "%s,%s", src_str, dst_str);
    return node.size = kInstructionSizeStepBytes + src.Size() + dst.Size();
}

static size_t disasm_add_sub_cmp(
        DisasmNode &node,
        const uint16_t instr,
        const DataBuffer &code,
        const char *mnemonic,
        const OpSize opsize,
        const bool dir_to_addr)
{
    const char suffix = suffix_from_opsize(opsize);
    const auto addr = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes, code, instr, opsize);
    switch (addr.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        if (dir_to_addr || suffix == 'b') {
            // An cannot be destination and An cannot be used as byte
            return disasm_verbatim(node, instr, code);
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
        if (dir_to_addr) {
            // PC relative cannot be destination
            return disasm_verbatim(node, instr, code);
        }
        break;
    case AddrMode::kImmediate:
        if (dir_to_addr) {
            // immediate cannot be destination
            return disasm_verbatim(node, instr, code);
        }
        if (1) {
            // XXX GNU AS always emits ADDI (06xx xxxx [xxxx]) instruction when
            // given ADD with immediate source argument. It also emits SUBQ when
            // given SUB with immediate source argument. It may become an
            // option like -fpedantic to generate instruction in this case, but
            // for now it is gonna be just plain bytes to keep original and
            // reassembled binaries *identical* as it must be by default.
            return disasm_verbatim(node, instr, code);
        }
        break;
    }
    const unsigned dn = (instr >> 9) & 7;
    const auto reg = AddrModeArg::Dn(dn);
    char addr_str[32]{};
    char reg_str[32]{};
    addr.SNPrint(addr_str, sizeof(addr_str));
    reg.SNPrint(reg_str, sizeof(reg_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c", mnemonic, suffix);
    if (dir_to_addr) {
        snprintf(node.arguments, kArgsBufferSize, "%s,%s", reg_str, addr_str);
    } else {
        snprintf(node.arguments, kArgsBufferSize, "%s,%s", addr_str, reg_str);
    }
    return node.size = kInstructionSizeStepBytes + addr.Size() + reg.Size();
}

static size_t disasm_cmpm(
        DisasmNode &node, const uint16_t instr, const DataBuffer &)
{
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    // Must be already handled by parent call
    assert(opsize != OpSize::kInvalid);
    const int m = (instr >> 3) & 3;
    assert(m == 1);
    (void) m;
    const int xn = instr & 7;
    const int xi = (instr >> 9) & 7;
    const auto src = AddrModeArg::AnAddrIncr(xn);
    const auto dst = AddrModeArg::AnAddrIncr(xi);
    char src_str[32]{};
    char dst_str[32]{};
    src.SNPrint(src_str, sizeof(src_str));
    dst.SNPrint(dst_str, sizeof(dst_str));
    const char suffix = suffix_from_opsize(opsize);
    snprintf(node.mnemonic, kMnemonicBufferSize, "cmpm%c", suffix);
    snprintf(node.arguments, kArgsBufferSize, "%s,%s", src_str, dst_str);
    return node.size = kInstructionSizeStepBytes + src.Size() + dst.Size();
}

static size_t disasm_eor(
        DisasmNode &node, const uint16_t instr, const DataBuffer &code)
{
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    const char suffix = suffix_from_opsize(opsize);
    const auto addr = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes, code, instr, opsize);
    switch (addr.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr, code);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr, code);
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
        // PC relative and immediate cannot be destination
        return disasm_verbatim(node, instr, code);
    }
    const unsigned dn = (instr >> 9) & 7;
    const auto reg = AddrModeArg::Dn(dn);
    char addr_str[32]{};
    char reg_str[32]{};
    addr.SNPrint(addr_str, sizeof(addr_str));
    reg.SNPrint(reg_str, sizeof(reg_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "eor%c", suffix);
    snprintf(node.arguments, kArgsBufferSize, "%s,%s", reg_str, addr_str);
    return node.size = kInstructionSizeStepBytes + addr.Size() + reg.Size();
}

static size_t disasm_eor_cmpm_cmp_cmpa(
        DisasmNode &node, const uint16_t instr, const DataBuffer &code)
{
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    if (opsize == OpSize::kInvalid) {
        return disasm_adda_suba_cmpa(node, instr, code, "cmp");
    }
    const bool dir_to_addr = ((instr >> 8) & 1);
    if (!dir_to_addr) {
        return disasm_add_sub_cmp(node, instr, code, "cmp", opsize, dir_to_addr);
    }
    const int m = (instr >> 3) & 7;
    if (m == 1) {
        return disasm_cmpm(node, instr, code);
    }
    return disasm_eor(node, instr, code);
}

static inline size_t disasm_exg(DisasmNode &node, uint16_t instr)
{
    assert((instr & 0x130) == 0x100);
    const int m1 = (instr >> 3) & 1;
    const int m2 = (instr >> 6) & 3;
    assert(m2 != 0); // Therefore m == 0 and m == 1 are impossible
    assert(m2 != 3); // Therefore m == 6 and m == 7 are impossible
    const int m = (m2 << 1) | m1;
    assert(m != 4); // Only m == 2, m == 3 and m == 5 values are allowed
    const int xn = instr & 7;
    const int xi = (instr >> 9) & 7;
    const auto src = (m == 3) ? AddrModeArg::An(xi) : AddrModeArg::Dn(xi);
    const auto dst = (m == 2) ? AddrModeArg::Dn(xn) : AddrModeArg::An(xn);
    char src_str[32]{};
    char dst_str[32]{};
    src.SNPrint(src_str, sizeof(src_str));
    dst.SNPrint(dst_str, sizeof(dst_str));
    snprintf(node.mnemonic, kMnemonicBufferSize, "exg");
    snprintf(node.arguments, kArgsBufferSize, "%s,%s", src_str, dst_str);
    return node.size = kInstructionSizeStepBytes + src.Size() + dst.Size();
}

static size_t disasm_chunk_c(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    if ((instr & 0x1f0) == 0x100) {
        // XXX GNU AS does not know ABCD.B, it only knows ABCD, but happily
        // consumes SBCD.B and others. That's why `skip_suffix` flag is needed,
        // specifically for ABCD mnemonic. It is probably a bug in GNU AS.
        const bool skip_size_suffix = true;
        return disasm_addx_subx_abcd_sbcd(node, instr, "abcd", "", skip_size_suffix);
    }
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    if (opsize == OpSize::kInvalid) {
        return disasm_divu_divs_mulu_muls(node, instr, code, "mul");
    }
    const unsigned m_split = instr & 0x1f8;
    if (m_split == 0x188 || m_split == 0x148 || m_split == 0x140) {
        return disasm_exg(node, instr);
    }
    return disasm_or_and(node, instr, code, opsize, "and");
}

static size_t disasm_add_sub_x_a(
        DisasmNode &node, const uint16_t instr, const DataBuffer &code, const char *mnemonic)
{
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    if (opsize == OpSize::kInvalid) {
        return disasm_adda_suba_cmpa(node, instr, code, mnemonic);
    }
    const bool dir_to_addr = (instr >> 8) & 1;
    const unsigned m = (instr >> 3) & 7;
    if (dir_to_addr && (m == 0 || m == 1)) {
        return disasm_addx_subx_abcd_sbcd(node, instr, mnemonic, "x");
    }
    return disasm_add_sub_cmp(node, instr, code, mnemonic, opsize, dir_to_addr);
}

static inline const char *ShiftKindToMnemonic(const ShiftKind k)
{
    switch (k) {
    case ShiftKind::kArithmeticShift: return "as";
    case ShiftKind::kLogicalShift: return "ls";
    case ShiftKind::kRotateX: return "rox";
    case ShiftKind::kRotate: return "ro";
    }
    assert(false);
    return "?";
}

static inline bool IsValidShiftKind(const ShiftKind k)
{
    return static_cast<int>(k) < 4;
}

static size_t disasm_shift_rotate(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    const unsigned xn = instr & 7;
    const uint8_t rotation = (instr >> 9) & 7;
    const ShiftKind kind = (opsize == OpSize::kInvalid)
        ? static_cast<ShiftKind>(rotation)
        : static_cast<ShiftKind>((instr >> 3) & 3);
    if (!IsValidShiftKind(kind)) {
        return disasm_verbatim(node, instr, code);
    }
    const unsigned m = (instr >> 5) & 1;
    const auto dst = (opsize == OpSize::kInvalid)
        ? FetchAddrModeArg(node.offset + kInstructionSizeStepBytes, code, instr, opsize)
        : AddrModeArg::Dn(xn);
    if (opsize == OpSize::kInvalid) {
        switch (dst.mode) {
        case AddrMode::kInvalid:
            return disasm_verbatim(node, instr, code);
        case AddrMode::kDn:
            // Intersects with situation when args are "#1,%dx". GNU AS would
            // not understand shift instruction with single argument of "%dx".
            return disasm_verbatim(node, instr, code);
            break;
        case AddrMode::kAn:
            return disasm_verbatim(node, instr, code);
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
            return disasm_verbatim(node, instr, code);
        }
    }
    const char suffix = suffix_from_opsize(opsize);
    const unsigned imm = ((rotation - 1) & 7) + 1;
    const unsigned src = (opsize == OpSize::kInvalid) ? 1 : rotation;
    const auto dir = static_cast<ShiftDirection>((instr >> 8) & 1);
    char dst_str[32]{};
    dst.SNPrint(dst_str, sizeof(dst_str));
    const char *mnemonic = ShiftKindToMnemonic(kind);
    const char dirchar = (dir == ShiftDirection::kRight) ? 'r' : 'l';
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s%c%c", mnemonic, dirchar, suffix);
    if (opsize == OpSize::kInvalid) {
        snprintf(node.arguments, kArgsBufferSize, "%s", dst_str);
    } else if (m == 1) {
        snprintf(node.arguments, kArgsBufferSize, "%%d%u,%s", src, dst_str);
    } else {
        snprintf(node.arguments, kArgsBufferSize, "#%u,%s", imm, dst_str);
    }
    return node.size = kInstructionSizeStepBytes + dst.Size();
}

static size_t m68k_disasm(DisasmNode &n, uint16_t i, const DataBuffer &c)
{
    switch ((i & 0xf000) >> 12) {
    case 0x0:
        return disasm_bitops_movep(n, i, c);
    case 0x1:
    case 0x2:
    case 0x3:
        return disasm_move_movea(n, i, c);
    case 0x4:
        return disasm_chunk_4(n, i, c);
    case 0x5:
        return disasm_addq_subq_scc_dbcc(n, i, c);
    case 0x6:
        return disasm_bra_bsr_bcc(n, i, c);
    case 0x7:
        return disasm_moveq(n, i, c);
    case 0x8:
        return disasm_divu_divs_sbcd_or(n, i, c);
    case 0x9:
        return disasm_add_sub_x_a(n, i, c, "sub");
    case 0xa:
        // Does not exist
        return disasm_verbatim(n, i, c);
    case 0xb:
        return disasm_eor_cmpm_cmp_cmpa(n, i, c);
    case 0xc:
        return disasm_chunk_c(n, i, c);
    case 0xd:
        return disasm_add_sub_x_a(n, i, c, "add");
    case 0xe:
        return disasm_shift_rotate(n, i, c);
    case 0xf:
        // Does not exist
        return disasm_verbatim(n, i, c);
    }
    assert(false);
    return disasm_verbatim(n, i, c);
}

size_t DisasmNode::Disasm(const DataBuffer &code)
{
    // We assume that machine have no MMU and ROM data always starts with 0
    assert(this->offset < code.occupied_size);
    // It is possible to have multiple DisasmNode::Disasm() calls, and there is
    // no point to disassemble it again if it already has mnemonic determined
    if (this->mnemonic[0] != '\0') {
        return this->size;
    }
    const uint16_t instr = GetU16BE(code.buffer + this->offset);
    return m68k_disasm(*this, instr, code);
}

static const char *ToString(const OpCode opcode, const Condition condition)
{
    switch (opcode) {
    case OpCode::kNone:
        assert(false);
        break;
    case OpCode::kRaw: return ".short";
    case OpCode::kORI: return "ori";
    case OpCode::kANDI: return "andi";
    case OpCode::kSUBI: return "subi";
    case OpCode::kADDI: return "addi";
    case OpCode::kEORI: return "eori";
    case OpCode::kCMPI: return "cmpi";
    case OpCode::kBTST: return "btst";
    case OpCode::kBCHG: return "bchg";
    case OpCode::kBCLR: return "bclr";
    case OpCode::kBSET: return "bset";
    case OpCode::kMOVEP: return "movep";
    case OpCode::kMOVEA: return "movea";
    case OpCode::kMOVE: return "move";
    case OpCode::kNEGX: return "negx";
    case OpCode::kCLR: return "clr";
    case OpCode::kNEG: return "neg";
    case OpCode::kNOT: return "not";
    case OpCode::kEXT: return "ext";
    case OpCode::kNBCD: return "nbcd";
    case OpCode::kSWAP: return "swap";
    case OpCode::kPEA: return "pea";
    case OpCode::kILLEGAL: return "illegal";
    case OpCode::kTAS: return "tas";
    case OpCode::kTST: return "tst";
    case OpCode::kTRAP: return "trap";
    case OpCode::kLINK: return "link";
    case OpCode::kUNLK: return "unkl";
    case OpCode::kRESET: return "reset";
    case OpCode::kNOP: return "nop";
    case OpCode::kSTOP: return "stop";
    case OpCode::kRTE: return "rte";
    case OpCode::kRTS: return "rts";
    case OpCode::kTRAPV: return "trapv";
    case OpCode::kRTR: return "rtr";
    case OpCode::kJSR: return "jsr";
    case OpCode::kJMP: return "jmp";
    case OpCode::kMOVEM: return "movem";
    case OpCode::kLEA: return "lea";
    case OpCode::kCHK: return "chk";
    case OpCode::kADDQ: return "addq";
    case OpCode::kSUBQ: return "subq";
    case OpCode::kScc:
        switch(condition) {
        case Condition::kT : return "st";
        case Condition::kF:  return "sf";
        case Condition::kHI: return "shi";
        case Condition::kLS: return "sls";
        case Condition::kCC: return "scc";
        case Condition::kCS: return "scs";
        case Condition::kNE: return "sne";
        case Condition::kEQ: return "seq";
        case Condition::kVC: return "svc";
        case Condition::kVS: return "svs";
        case Condition::kPL: return "spl";
        case Condition::kMI: return "smi";
        case Condition::kGE: return "sge";
        case Condition::kLT: return "slt";
        case Condition::kGT: return "sgt";
        case Condition::kLE: return "sle";
        }
        assert(false);
        break;
    case OpCode::kDBcc:
        switch (condition) {
        case Condition::kT:  return "dbt";
        case Condition::kF:  return "dbf";
        case Condition::kHI: return "dbhi";
        case Condition::kLS: return "dbls";
        case Condition::kCC: return "dbcc";
        case Condition::kCS: return "dbcs";
        case Condition::kNE: return "dbne";
        case Condition::kEQ: return "dbeq";
        case Condition::kVC: return "dbvc";
        case Condition::kVS: return "dbvs";
        case Condition::kPL: return "dbpl";
        case Condition::kMI: return "dbmi";
        case Condition::kGE: return "dbge";
        case Condition::kLT: return "dblt";
        case Condition::kGT: return "dbgt";
        case Condition::kLE: return "dble";
        }
        assert(false);
        break;
    case OpCode::kBcc:
        switch (condition) {
        case Condition::kT:  return "bras";
        case Condition::kF:  return "bsrs";
        case Condition::kHI: return "bhis";
        case Condition::kLS: return "blss";
        case Condition::kCC: return "bccs";
        case Condition::kCS: return "bcss";
        case Condition::kNE: return "bnes";
        case Condition::kEQ: return "beqs";
        case Condition::kVC: return "bvcs";
        case Condition::kVS: return "bvss";
        case Condition::kPL: return "bpls";
        case Condition::kMI: return "bmis";
        case Condition::kGE: return "bges";
        case Condition::kLT: return "blts";
        case Condition::kGT: return "bgts";
        case Condition::kLE: return "bles";
        }
        assert(false);
        break;
    case OpCode::kMOVEQ: return "moveq";
    case OpCode::kDIVU: return "divu";
    case OpCode::kDIVS: return "divs";
    case OpCode::kSBCD: return "sbcd";
    case OpCode::kOR: return "or";
    case OpCode::kSUB: return "sub";
    case OpCode::kSUBX: return "subx";
    case OpCode::kSUBA: return "suba";
    case OpCode::kEOR: return "eor";
    case OpCode::kCMPM: return "cmpm";
    case OpCode::kCMP: return "cmp";
    case OpCode::kCMPA: return "cmpa";
    case OpCode::kMULU: return "mulu";
    case OpCode::kMULS: return "muls";
    case OpCode::kABCD: return "abcd";
    case OpCode::kEXG: return "exg";
    case OpCode::kAND: return "and";
    case OpCode::kADD: return "add";
    case OpCode::kADDX: return "addx";
    case OpCode::kADDA: return "adda";
    case OpCode::kASR: return "asr";
    case OpCode::kASL: return "asl";
    case OpCode::kLSR: return "lsr";
    case OpCode::kLSL: return "lsl";
    case OpCode::kROXR: return "roxr";
    case OpCode::kROXL: return "roxl";
    case OpCode::kROR: return "ror";
    case OpCode::kROL: return "rol";
    }
    assert(false);
    return "?";
}

static const char *ToString(const SizeSpec s)
{
    switch (s) {
    case SizeSpec::kNone: return "";
    case SizeSpec::kByte: return "b";
    case SizeSpec::kWord: return "w";
    case SizeSpec::kLong: return "l";
    }
    assert(false);
    return "";
}

static int OpcodeSNPrintf(
        char *buf, size_t bufsz, const OpCode opcode, const Condition condition, const SizeSpec size_spec)
{
    return snprintf(buf, bufsz, "%s%s", ToString(opcode, condition), ToString(size_spec));
}

static char RegChar(RegKind k)
{
    switch (k) {
    case RegKind::kDnWord:
    case RegKind::kDnLong:
        return 'd';
    case RegKind::kAnWord:
    case RegKind::kAnLong:
        return 'a';
    }
    assert(false);
    return 'd';
}

static char SizeSpecChar(RegKind k)
{
    switch (k) {
    case RegKind::kDnWord:
        return 'w';
    case RegKind::kDnLong:
        return 'l';
    case RegKind::kAnWord:
        return 'w';
    case RegKind::kAnLong:
        return 'l';
    }
    assert(false);
    return 'w';
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

int Arg::SNPrint(char *buf, size_t bufsz, const Settings &) const
{
    switch (type) {
    case ArgType::kNone:
        assert(false);
        break;
    case ArgType::kRaw:
        return snprintf(buf, bufsz, "0x%04x", uword);
    case ArgType::kDn:
        return snprintf(buf, bufsz, "%%d%d", xn);
    case ArgType::kAn:
        return snprintf(buf, bufsz, "%%a%u", xn);
    case ArgType::kAnAddr:
        return snprintf(buf, bufsz, "%%a%u@", xn);
    case ArgType::kAnAddrIncr:
        return snprintf(buf, bufsz, "%%a%u@+", xn);
    case ArgType::kAnAddrDecr:
        return snprintf(buf, bufsz, "%%a%u@-", xn);
    case ArgType::kD16AnAddr:
        return snprintf(buf, bufsz, "%%a%u@(%d:w)", d16_an.an, d16_an.d16);
    case ArgType::kD8AnXiAddr:
        return snprintf(
                buf, bufsz, "%%a%u@(%d,%%%c%d:%c)",
                d8_an_xi.an,
                d8_an_xi.d8,
                RegChar(d8_an_xi.kind),
                d8_an_xi.xi,
                SizeSpecChar(d8_an_xi.kind));
    case ArgType::kWord:
        return snprintf(buf, bufsz, "0x%x:w", lword);
    case ArgType::kLong:
        return snprintf(buf, bufsz, "0x%x:l", lword);
    case ArgType::kD16PCAddr:
        return snprintf(buf, bufsz, "%%pc@(%d:w)", d16_pc.d16);
    case ArgType::kD8PCXiAddr:
        return snprintf(
                buf, bufsz, "%%pc@(%d,%%%c%d:%c)",
                d8_pc_xi.d8,
                RegChar(d8_pc_xi.kind),
                d8_pc_xi.xi,
                SizeSpecChar(d8_pc_xi.kind));
    case ArgType::kImmediate:
        return snprintf(buf, bufsz, "#%d", lword);
    case ArgType::kRegMask:
        return snprint_reg_mask(buf, bufsz, uword, false);
    case ArgType::kRegMaskPredecrement:
        return snprint_reg_mask(buf, bufsz, uword, true);
    case ArgType::kDisplacement:
        return snprintf(buf, bufsz,  ".%s%d", lword >= 0 ? "+" : "", lword);
    case ArgType::kCCR:
        return snprintf(buf, bufsz,  "%%ccr");
    case ArgType::kSR:
        return snprintf(buf, bufsz,  "%%sr");
    case ArgType::kUSP:
        return snprintf(buf, bufsz,  "%%usp");
    }
    assert(false);
    return -1;
}

int DisasmNode::FPrint(FILE* stream, const Settings &settings) const
{
    assert(opcode != OpCode::kNone);
    char mnemonic_str[kMnemonicBufferSize]{};
    OpcodeSNPrintf(mnemonic_str, kMnemonicBufferSize, opcode, condition, size_spec);
    if (arg1.type != ArgType::kNone) {
        char arg1_str[kArgsBufferSize]{};
        arg1.SNPrint(arg1_str, kArgsBufferSize, settings);
        if (arg2.type != ArgType::kNone) {
            char arg2_str[kArgsBufferSize]{};
            arg2.SNPrint(arg2_str, kArgsBufferSize, settings);
            return fprintf(stream, "  %s %s,%s", mnemonic_str, arg1_str, arg2_str);
        } else {
            return fprintf(stream, "  %s %s", mnemonic_str, arg1_str);
        }
    } else {
        return fprintf(stream, "  %s", mnemonic_str);
    }
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
