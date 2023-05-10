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

enum class Cond: uint8_t {
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

constexpr AddrModeArg FetchImmediate(const uint32_t offset, const DataBuffer &code, const OpSize s)
{
    if (s == OpSize::kInvalid) {
        return AddrModeArg{};
    } else if (s == OpSize::kLong) {
        if (offset + kInstructionSizeStepBytes < code.occupied_size) {
            const int32_t value = GetI32BE(code.buffer + offset);
            return AddrModeArg::Immediate(s, value);
        }
    } else if (offset < code.occupied_size) {
        const int16_t value = GetI16BE(code.buffer + offset);
        if (s == OpSize::kByte) {
            if (value > 255 || value < -255) {
                // Invalid immediate value for instruction with .b suffix
                return AddrModeArg{};
            }
        }
        return AddrModeArg::Immediate(s, value);
    }
    return AddrModeArg{};
}

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
                return AddrModeArg::Word(w);
            }
            break;
        case 1: // (xxx).L, Additional Long
            if (offset + kInstructionSizeStepBytes < code.occupied_size) {
                const int32_t l = GetI32BE(code.buffer + offset);
                return AddrModeArg::Long(l);
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
            return FetchImmediate(offset, code, s);
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
    node.size_spec = SizeSpec::kNone;
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
    node.size_spec = SizeSpec::kNone;
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
    node.opcode = OpCode::kMOVEM;
    node.size_spec = ToSizeSpec(opsize);
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
    node.opcode = OpCode::kLEA;
    node.size_spec = SizeSpec::kLong;
    node.arg1 = Arg::FromAddrModeArg(addr);
    node.arg2 = Arg::FromAddrModeArg(reg);
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
    node.opcode = OpCode::kCHK;
    node.size_spec = SizeSpec::kWord;
    node.arg1 = Arg::FromAddrModeArg(src);
    node.arg2 = Arg::FromAddrModeArg(dst);
    return node.size = kInstructionSizeStepBytes + src.Size() + dst.Size();
}

static Condition ToCondition(Cond cond)
{
    switch (cond) {
    case Cond::kT:  return Condition::kT;
    case Cond::kF:  return Condition::kF;
    case Cond::kHI: return Condition::kHI;
    case Cond::kLS: return Condition::kLS;
    case Cond::kCC: return Condition::kCC;
    case Cond::kCS: return Condition::kCS;
    case Cond::kNE: return Condition::kNE;
    case Cond::kEQ: return Condition::kEQ;
    case Cond::kVC: return Condition::kVC;
    case Cond::kVS: return Condition::kVS;
    case Cond::kPL: return Condition::kPL;
    case Cond::kMI: return Condition::kMI;
    case Cond::kGE: return Condition::kGE;
    case Cond::kLT: return Condition::kLT;
    case Cond::kGT: return Condition::kGT;
    case Cond::kLE: return Condition::kLE;
    }
    return Condition::kT;
}

static size_t disasm_bra_bsr_bcc(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    int16_t dispmt = static_cast<int8_t>(instr & 0xff);
    if (dispmt % static_cast<int16_t>(kInstructionSizeStepBytes)) {
        return disasm_verbatim(node, instr, code);
    }
    node.size_spec = dispmt ? SizeSpec::kShort : SizeSpec::kWord;
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
    dispmt += kInstructionSizeStepBytes;
    const uint32_t branch_addr = static_cast<uint32_t>(node.offset + dispmt);
    Cond condition = static_cast<Cond>((instr >> 8) & 0xf);
    // False condition Indicates BSR
    node.is_call = (condition == Cond::kF);
    node.opcode = OpCode::kBcc;
    node.condition = ToCondition(condition);
    node.arg1 = Arg::Displacement(dispmt);
    node.branch_addr = branch_addr;
    node.has_branch_addr = true;
    // FIXME support s.rel_marks option for this instruction
    return node.size;
}

static OpCode OpCodeForBitOps(unsigned opcode)
{
    switch (opcode) {
    case 0: return OpCode::kBTST;
    case 1: return OpCode::kBCHG;
    case 2: return OpCode::kBCLR;
    case 3: return OpCode::kBSET;
    }
    assert(false);
    return OpCode::kNone;
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
    node.opcode = OpCode::kMOVEP;
    node.size_spec = ToSizeSpec(opsize);
    if (dir == MoveDirection::kRegisterToMemory) {
        node.arg1 = Arg::FromAddrModeArg(reg);
        node.arg2 = Arg::FromAddrModeArg(addr);
    } else {
        node.arg1 = Arg::FromAddrModeArg(addr);
        node.arg2 = Arg::FromAddrModeArg(reg);
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
    node.opcode = OpCodeForBitOps(opcode);
    node.size_spec = dst.mode == AddrMode::kDn ? SizeSpec::kLong : SizeSpec::kByte;
    node.arg1 = Arg::FromAddrModeArg(src);
    node.arg2 = Arg::FromAddrModeArg(dst);
    return node.size = kInstructionSizeStepBytes + src.Size() + dst.Size();
}

static size_t disasm_bitops(DisasmNode &n, const uint16_t i, const DataBuffer &c)
{
    return disasm_src_arg_bitops_movep(n, i, c, false);
}

static size_t disasm_logical_immediate_to(
        DisasmNode &node, OpCode opcode, OpSize opsize, AddrModeArg imm)
{
    node.opcode = opcode;
    node.size_spec = ToSizeSpec(opsize);
    node.arg1 = Arg::FromAddrModeArg(imm);
    node.arg2 = (opsize == OpSize::kByte) ? Arg::CCR() : Arg::SR();
    return node.size = kInstructionSizeStepBytes * 2;
}

static OpCode OpCodeForLogicalImmediate(const unsigned opcode)
{
    switch (opcode) {
    case 0: return OpCode::kORI;
    case 1: return OpCode::kANDI;
    case 2: return OpCode::kSUBI;
    case 3: return OpCode::kADDI;
    case 4: break;
    case 5: return OpCode::kEORI;
    case 6: return OpCode::kCMPI;
    case 7: break;
    }
    assert(false);
    return OpCode::kNone;
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
    const auto src = FetchImmediate(node.offset + kInstructionSizeStepBytes, code, opsize);
    if (src.mode == AddrMode::kInvalid) {
        return disasm_verbatim(node, instr, code);
    }
    assert(src.mode == AddrMode::kImmediate);
    const OpCode mnemonic = OpCodeForLogicalImmediate(opcode);
    if (m == 7 && xn == 4) {
        return disasm_logical_immediate_to(node, mnemonic, opsize, src);
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
    node.opcode = mnemonic;
    node.size_spec = ToSizeSpec(opsize);
    node.arg1 = Arg::FromAddrModeArg(src);
    node.arg2 = Arg::FromAddrModeArg(dst);
    return node.size = kInstructionSizeStepBytes + src.Size() + dst.Size();
}

static size_t disasm_move_movea(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    const int opsize_raw = (instr >> 12) & 3;
    const OpSize opsize = (opsize_raw == 1)
        ? OpSize::kByte : (opsize_raw == 3 ? OpSize::kWord : OpSize::kLong);
    const auto src = FetchAddrModeArg(
            node.offset + kInstructionSizeStepBytes, code, instr, opsize);
    if (src.mode == AddrMode::kInvalid) {
        return disasm_verbatim(node, instr, code);
    }
    if (opsize == OpSize::kByte && src.mode == AddrMode::kAn) {
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
        if (opsize == OpSize::kByte) {
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
    node.opcode = (dst.mode == AddrMode::kAn) ? OpCode::kMOVEA : OpCode::kMOVE;
    node.size_spec = ToSizeSpec(opsize);
    node.arg1 = Arg::FromAddrModeArg(src);
    node.arg2 = Arg::FromAddrModeArg(dst);
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
    node.opcode = OpCode::kMOVE;
    node.size_spec = ToSizeSpec(opsize);
    node.arg1 = Arg::SR();
    node.arg2 = Arg::FromAddrModeArg(dst);
    return node.size = kInstructionSizeStepBytes + dst.Size();
}

static size_t disasm_move_to(
        DisasmNode &node, uint16_t instr, const DataBuffer &code, const ArgType reg)
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
    node.opcode = OpCode::kMOVE;
    node.size_spec = ToSizeSpec(opsize);
    node.arg1 = Arg::FromAddrModeArg(src);
    node.arg2 = Arg{reg, 0};
    return node.size = kInstructionSizeStepBytes + src.Size();
}

static OpCode opcode_for_negx_clr_neg_not(const unsigned opcode)
{
    switch (opcode) {
    case 0: return OpCode::kNEGX;
    case 1: return OpCode::kCLR;
    case 2: return OpCode::kNEG;
    case 3: return OpCode::kNOT;
    }
    assert(false);
    return OpCode::kNone;
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
            return disasm_move_to(node, instr, code, ArgType::kCCR);
        case 3:
            return disasm_move_to(node, instr, code, ArgType::kSR);
        }
        assert(false);
        return disasm_verbatim(node, instr, code);
    }
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
    node.opcode = opcode_for_negx_clr_neg_not(opcode);
    node.size_spec = ToSizeSpec(opsize);
    node.arg1 = Arg::FromAddrModeArg(a);
    return node.size = kInstructionSizeStepBytes + a.Size();
}

static inline size_t disasm_trivial(
        DisasmNode &node, uint16_t, const DataBuffer &, const OpCode opcode)
{
    node.opcode = opcode;
    node.size_spec = SizeSpec::kNone;
    return node.size = kInstructionSizeStepBytes;
}

static inline size_t disasm_tas(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    const auto opsize = OpSize::kByte;
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
    node.opcode = OpCode::kTAS;
    node.size_spec = ToSizeSpec(opsize);
    node.arg1 = Arg::FromAddrModeArg(a);
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
            return disasm_trivial(node, instr, code, OpCode::kILLEGAL);
        }
        return disasm_tas(node, instr, code);
    }
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
    node.opcode = OpCode::kTST;
    node.size_spec = ToSizeSpec(opsize);
    node.arg1 = Arg::FromAddrModeArg(a);
    return node.size = kInstructionSizeStepBytes + a.Size();
}

static size_t disasm_trap(
        DisasmNode &node, uint16_t instr, const DataBuffer &)
{
    const unsigned vector = instr & 0xf;
    node.opcode = OpCode::kTRAP;
    node.size_spec = SizeSpec::kNone;
    node.arg1 = Arg::Immediate(vector);
    return node.size = kInstructionSizeStepBytes;
}

static size_t disasm_link_unlink(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    const bool unlk = (instr >> 3) & 1;
    const unsigned xn = instr & 7;
    if (unlk) {
        node.opcode = OpCode::kUNLK;
        node.size_spec = SizeSpec::kNone;
        node.arg1 = Arg::AddrModeXn(ArgType::kAn, xn);
        return node.size = kInstructionSizeStepBytes;
    }
    const auto opsize = OpSize::kWord;
    const auto src = FetchImmediate(node.offset + kInstructionSizeStepBytes, code, opsize);
    if (src.mode != AddrMode::kImmediate) {
        return disasm_verbatim(node, instr, code);
    }
    node.opcode = OpCode::kLINK;
    node.size_spec = ToSizeSpec(opsize);
    node.arg1 = Arg::AddrModeXn(ArgType::kAn, xn);
    node.arg2 = Arg::FromAddrModeArg(src);
    return node.size = kInstructionSizeStepBytes + src.Size();
}

static size_t disasm_move_usp(
        DisasmNode &node, uint16_t instr, const DataBuffer &)
{
    const unsigned xn = instr & 7;
    const auto dir = static_cast<MoveDirection>((instr >> 3) & 1);
    node.opcode = OpCode::kMOVE;
    node.size_spec = SizeSpec::kLong;
    if (dir == MoveDirection::kRegisterToMemory) {
        node.arg1 = Arg::AddrModeXn(ArgType::kAn, xn);
        node.arg2 = Arg::USP();
    } else {
        node.arg1 = Arg::USP();
        node.arg2 = Arg::AddrModeXn(ArgType::kAn, xn);
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
    node.opcode = is_nbcd ? OpCode::kNBCD : is_swap ? OpCode::kSWAP : OpCode::kPEA;
    node.size_spec = is_nbcd ? SizeSpec::kByte : is_swap ? SizeSpec::kWord : SizeSpec::kLong;
    node.arg1 = Arg::FromAddrModeArg(arg);
    return node.size = kInstructionSizeStepBytes + arg.Size();
}

static size_t disasm_stop(DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    const auto a = FetchImmediate(node.offset + kInstructionSizeStepBytes, code, OpSize::kWord);
    if (a.mode != AddrMode::kImmediate) {
        return disasm_verbatim(node, instr, code);
    }
    node.opcode = OpCode::kSTOP;
    node.size_spec = SizeSpec::kNone;
    node.arg1 = Arg::FromAddrModeArg(a);
    return node.size = kInstructionSizeStepBytes * 2;
}

static size_t disasm_chunk_4(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    if ((instr & 0xf900) == 0x4000) {
        return disasm_move_negx_clr_neg_not(node, instr, code);
    } else if ((instr & 0xff80) == 0x4800) {
        // NOTE: EXT is handled with MOVEM
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
        return disasm_trivial(node, instr, code, OpCode::kRESET);
    } else if (instr == 0x4e71) {
        return disasm_trivial(node, instr, code, OpCode::kNOP);
    } else if (instr == 0x4e72) {
        return disasm_stop(node, instr, code);
    } else if (instr == 0x4e73) {
        return disasm_trivial(node, instr, code, OpCode::kRTE);
    } else if (instr == 0x4e75) {
        return disasm_trivial(node, instr, code, OpCode::kRTS);
    } else if (instr == 0x4e76) {
        return disasm_trivial(node, instr, code, OpCode::kTRAPV);
    } else if (instr == 0x4e77) {
        return disasm_trivial(node, instr, code, OpCode::kRTR);
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
    const unsigned imm = ((uint8_t((instr >> 9) & 7) - 1) & 7) + 1;
    node.opcode = ((instr >> 8) & 1) ? OpCode::kSUBQ : OpCode::kADDQ;
    node.size_spec = ToSizeSpec(opsize);
    node.arg1 = Arg::Immediate(imm);
    node.arg2 = Arg::FromAddrModeArg(a);
    return node.size = kInstructionSizeStepBytes + a.Size();
}

static size_t disasm_dbcc(DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    if (node.offset + kInstructionSizeStepBytes >= code.occupied_size) {
        return disasm_verbatim(node, instr, code);
    }
    const int16_t dispmt_raw = GetI16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
    if (dispmt_raw % static_cast<int16_t>(kInstructionSizeStepBytes)) {
        return disasm_verbatim(node, instr, code);
    }
    const int32_t dispmt = dispmt_raw + kInstructionSizeStepBytes;
    node.branch_addr = static_cast<uint32_t>(node.offset + dispmt);
    node.has_branch_addr = true;
    node.opcode = OpCode::kDBcc;
    node.condition = ToCondition(static_cast<Cond>((instr >> 8) & 0xf));
    node.size_spec = SizeSpec::kNone;
    node.arg1 = Arg::AddrModeXn(ArgType::kDn, (instr & 7));
    node.arg2 = Arg::Displacement(dispmt);
    // FIXME support s.rel_marks option for this instruction
    return node.size = kInstructionSizeStepBytes * 2;
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
    node.opcode = OpCode::kScc;
    node.condition = ToCondition(static_cast<Cond>((instr >> 8) & 0xf));
    node.size_spec = SizeSpec::kNone;
    node.arg1 = Arg::FromAddrModeArg(a);
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
    const int8_t data = instr & 0xff;
    node.opcode = OpCode::kMOVEQ;
    node.size_spec = SizeSpec::kLong;
    node.arg1 = Arg::Immediate(data);
    node.arg2 = Arg::FromAddrModeArg(dst);
    return node.size = kInstructionSizeStepBytes + dst.Size();

}

static size_t disasm_divu_divs_mulu_muls(
        DisasmNode &node,
        uint16_t instr,
        const DataBuffer &code,
        OpCode opcode)
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
    node.opcode = opcode;
    node.size_spec = ToSizeSpec(opsize);
    node.arg1 = Arg::FromAddrModeArg(src);
    node.arg2 = Arg::FromAddrModeArg(dst);
    return node.size = kInstructionSizeStepBytes + dst.Size() + src.Size();
}

static size_t disasm_addx_subx_abcd_sbcd(
        DisasmNode &node, const uint16_t instr, const OpCode opcode)
{
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    // Must be already handled by parent call
    assert(opsize != OpSize::kInvalid);
    const int m = (instr >> 3) & 1;
    const int xn = instr & 7;
    const int xi = (instr >> 9) & 7;
    const auto src = m ? AddrModeArg::AnAddrDecr(xn) : AddrModeArg::Dn(xn);
    const auto dst = m ? AddrModeArg::AnAddrDecr(xi) : AddrModeArg::Dn(xi);
    node.opcode = opcode;
    // XXX GNU AS does not know ABCD.B, it only knows ABCD, but happily consumes
    // SBCD.B and others. That's why `skip_suffix` flag is needed, specifically
    // for ABCD mnemonic. It is probably a bug in GNU AS.
    node.size_spec = (opcode == OpCode::kABCD) ? SizeSpec::kNone : ToSizeSpec(opsize);
    node.arg1 = Arg::FromAddrModeArg(src);
    node.arg2 = Arg::FromAddrModeArg(dst);
    return node.size = kInstructionSizeStepBytes + src.Size() + dst.Size();
}

static size_t disasm_or_and(
        DisasmNode &node,
        const uint16_t instr,
        const DataBuffer &code,
        const OpSize opsize,
        const OpCode opcode)
{
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
        break;
    }
    const auto reg = AddrModeArg::Dn((instr >> 9) & 7);
    node.opcode = opcode;
    node.size_spec = ToSizeSpec(opsize);
    if (dir_to_addr) {
        node.arg1 = Arg::FromAddrModeArg(reg);
        node.arg2 = Arg::FromAddrModeArg(addr);
    } else {
        node.arg1 = Arg::FromAddrModeArg(addr);
        node.arg2 = Arg::FromAddrModeArg(reg);
    }
    return node.size = kInstructionSizeStepBytes + addr.Size() + reg.Size();
}

static size_t disasm_divu_divs_sbcd_or(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    // Also ensures that opsize == OpSize::kByte, i.e. 0b00
    if ((instr & 0x1f0) == 0x100) {
        return disasm_addx_subx_abcd_sbcd(node, instr, OpCode::kSBCD);
    }
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    if (opsize == OpSize::kInvalid) {
        const bool is_signed = (instr >> 8) & 1;
        const auto opcode = is_signed ? OpCode::kDIVS : OpCode::kDIVU;
        return disasm_divu_divs_mulu_muls(node, instr, code, opcode);
    }
    return disasm_or_and(node, instr, code, opsize, OpCode::kOR);
}

static inline size_t disasm_adda_suba_cmpa(
        DisasmNode &node, const uint16_t instr, const DataBuffer &code, const OpCode opcode)
{
    const OpSize opsize = static_cast<OpSize>(((instr >> 8) & 1) + 1);
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
    node.opcode = opcode;
    node.size_spec = ToSizeSpec(opsize);
    node.arg1 = Arg::FromAddrModeArg(src);
    node.arg2 = Arg::FromAddrModeArg(dst);
    return node.size = kInstructionSizeStepBytes + src.Size() + dst.Size();
}

static size_t disasm_add_sub_cmp(
        DisasmNode &node,
        const uint16_t instr,
        const DataBuffer &code,
        const OpCode opcode,
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
        break;
    }
    const unsigned dn = (instr >> 9) & 7;
    const auto reg = AddrModeArg::Dn(dn);
    node.opcode = opcode;
    node.size_spec = ToSizeSpec(opsize);
    if (dir_to_addr) {
        node.arg1 = Arg::FromAddrModeArg(reg);
        node.arg2 = Arg::FromAddrModeArg(addr);
    } else {
        node.arg1 = Arg::FromAddrModeArg(addr);
        node.arg2 = Arg::FromAddrModeArg(reg);
    }
    return node.size = kInstructionSizeStepBytes + addr.Size() + reg.Size();
}

static size_t disasm_cmpm(
        DisasmNode &node, const uint16_t instr, const DataBuffer &)
{
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    // Must be already handled by parent call
    assert(opsize != OpSize::kInvalid);
    const int m = (instr >> 3) & 7;
    assert(m == 1);
    (void) m;
    const int xn = instr & 7;
    const int xi = (instr >> 9) & 7;
    const auto src = AddrModeArg::AnAddrIncr(xn);
    const auto dst = AddrModeArg::AnAddrIncr(xi);
    node.opcode = OpCode::kCMPM;
    node.size_spec = ToSizeSpec(opsize);
    node.arg1 = Arg::FromAddrModeArg(src);
    node.arg2 = Arg::FromAddrModeArg(dst);
    return node.size = kInstructionSizeStepBytes + src.Size() + dst.Size();
}

static size_t disasm_eor(
        DisasmNode &node, const uint16_t instr, const DataBuffer &code)
{
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
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
    const auto reg = AddrModeArg::Dn((instr >> 9) & 7);
    node.opcode = OpCode::kEOR;
    node.size_spec = ToSizeSpec(opsize);
    node.arg1 = Arg::FromAddrModeArg(reg);
    node.arg2 = Arg::FromAddrModeArg(addr);
    return node.size = kInstructionSizeStepBytes + addr.Size() + reg.Size();
}

static size_t disasm_eor_cmpm_cmp_cmpa(
        DisasmNode &node, const uint16_t instr, const DataBuffer &code)
{
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    if (opsize == OpSize::kInvalid) {
        return disasm_adda_suba_cmpa(node, instr, code, OpCode::kCMPA);
    }
    const bool dir_to_addr = ((instr >> 8) & 1);
    if (!dir_to_addr) {
        return disasm_add_sub_cmp(node, instr, code, OpCode::kCMP, opsize, dir_to_addr);
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
    node.opcode = OpCode::kEXG;
    node.size_spec = SizeSpec::kNone;
    node.arg1 = Arg::FromAddrModeArg(src);
    node.arg2 = Arg::FromAddrModeArg(dst);
    return node.size = kInstructionSizeStepBytes + src.Size() + dst.Size();
}

static size_t disasm_chunk_c(
        DisasmNode &node, uint16_t instr, const DataBuffer &code)
{
    if ((instr & 0x1f0) == 0x100) {
        return disasm_addx_subx_abcd_sbcd(node, instr, OpCode::kABCD);
    }
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    if (opsize == OpSize::kInvalid) {
        const bool is_signed = (instr >> 8) & 1;
        const auto opcode = is_signed ? OpCode::kMULS : OpCode::kMULU;
        return disasm_divu_divs_mulu_muls(node, instr, code, opcode);
    }
    const unsigned m_split = instr & 0x1f8;
    if (m_split == 0x188 || m_split == 0x148 || m_split == 0x140) {
        return disasm_exg(node, instr);
    }
    return disasm_or_and(node, instr, code, opsize, OpCode::kAND);
}

static size_t disasm_add_sub_x_a(
        DisasmNode &node, const uint16_t instr, const DataBuffer &code, const OpCode opcode)
{
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    if (opsize == OpSize::kInvalid) {
        return disasm_adda_suba_cmpa(node, instr, code, (opcode == OpCode::kSUB) ? OpCode::kSUBA : OpCode::kADDA);
    }
    const bool dir_to_addr = (instr >> 8) & 1;
    const unsigned m = (instr >> 3) & 7;
    if (dir_to_addr && (m == 0 || m == 1)) {
        return disasm_addx_subx_abcd_sbcd(node, instr, (opcode == OpCode::kSUB) ? OpCode::kSUBX : OpCode::kADDX);
    }
    return disasm_add_sub_cmp(node, instr, code, opcode, opsize, dir_to_addr);
}

static OpCode ShiftKindToOpcode(const ShiftKind k, const ShiftDirection d)
{
    switch (k) {
    case ShiftKind::kArithmeticShift:
        return d == ShiftDirection::kLeft ? OpCode::kASL : OpCode::kASR;
    case ShiftKind::kLogicalShift:
        return d == ShiftDirection::kLeft ? OpCode::kLSL : OpCode::kLSR;
    case ShiftKind::kRotateX:
        return d == ShiftDirection::kLeft ? OpCode::kROXL : OpCode::kROXR;
    case ShiftKind::kRotate:
        return d == ShiftDirection::kLeft ? OpCode::kROL : OpCode::kROR;
    }
    assert(false);
    return OpCode::kNone;
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
    const unsigned imm = ((rotation - 1) & 7) + 1;
    const unsigned src = (opsize == OpSize::kInvalid) ? 1 : rotation;
    const auto dir = static_cast<ShiftDirection>((instr >> 8) & 1);
    node.opcode = ShiftKindToOpcode(kind, dir);
    node.size_spec = ToSizeSpec(opsize);
    if (opsize == OpSize::kInvalid) {
        node.arg1 = Arg::FromAddrModeArg(dst);
    } else {
        const unsigned m = (instr >> 5) & 1;
        node.arg1 = m ? Arg::AddrModeXn(ArgType::kDn, src) : Arg::Immediate(imm);
        node.arg2 = Arg::FromAddrModeArg(dst);
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
        return disasm_add_sub_x_a(n, i, c, OpCode::kSUB);
    case 0xa:
        // Does not exist
        return disasm_verbatim(n, i, c);
    case 0xb:
        return disasm_eor_cmpm_cmp_cmpa(n, i, c);
    case 0xc:
        return disasm_chunk_c(n, i, c);
    case 0xd:
        return disasm_add_sub_x_a(n, i, c, OpCode::kADD);
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
    // no point to disassemble it again if it already has opcode determined
    if (this->opcode != OpCode::kNone) {
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
    case OpCode::kUNLK: return "unlk";
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
        case Condition::kT:  return "bra";
        case Condition::kF:  return "bsr";
        case Condition::kHI: return "bhi";
        case Condition::kLS: return "bls";
        case Condition::kCC: return "bcc";
        case Condition::kCS: return "bcs";
        case Condition::kNE: return "bne";
        case Condition::kEQ: return "beq";
        case Condition::kVC: return "bvc";
        case Condition::kVS: return "bvs";
        case Condition::kPL: return "bpl";
        case Condition::kMI: return "bmi";
        case Condition::kGE: return "bge";
        case Condition::kLT: return "blt";
        case Condition::kGT: return "bgt";
        case Condition::kLE: return "ble";
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
    case SizeSpec::kShort: return "s";
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
