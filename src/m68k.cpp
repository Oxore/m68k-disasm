/* SPDX-License-Identifier: Unlicense
 */

#include "disasm.h"
#include "m68k.h"
#include "data_buffer.h"
#include "common.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

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

constexpr Arg FetchImmediate(
        const uint32_t address, const DataView &code, const Settings &s, const OpSize opsize)
{
    if (opsize == OpSize::kInvalid) {
        return Arg{};
    } else if (opsize == OpSize::kLong) {
        if (address + kInstructionSizeStepBytes < code.size) {
            const int32_t value = GetI32BE(code.buffer + address);
            return Arg::Immediate(value);
        }
    } else if (address < code.size) {
        const int16_t value = GetI16BE(code.buffer + address);
        if (opsize == OpSize::kByte) {
            if (s.target_asm == TargetAssembler::kSierraAsm68) {
                // Sierra does not allow 0xffffffffxx as negative value for byte
                // size operations. It basically never fills the high byte in
                // this case.
                if (uint16_t(value) & 0xff00u) {
                    return Arg::ImmediateInvalid(uint16_t(value) & 0xffu);
                }
                return Arg::Immediate(int8_t(uint16_t(value) & 0xffu));
            }
            // Technically it is impossible to have value lower that -128 in 8
            // bits signed integer, but the second byte being 0xff is actually
            // a valid thing and it is how values from -255 to -129 are
            // represented.
            if (value > 255 || value < -255) {
                // Invalid immediate value for instruction with .b suffix
                return Arg::ImmediateInvalid(value);
            }
        }
        return Arg::Immediate(value);
    }
    return Arg{};
}

constexpr Arg FetchArg(
        const uint32_t address,
        const DataView &code,
        const Settings &s,
        const int m,
        const int xn,
        const OpSize opsize)
{
    switch (m) {
    case 0: // Dn
        return Arg::Dn(xn);
    case 1: // An
        return Arg::An(xn);
    case 2: // (An)
        return Arg::AnAddr(xn);
    case 3: // (An)+
        return Arg::AnAddrIncr(xn);
    case 4: // -(An)
        return Arg::AnAddrDecr(xn);
    case 5: // (d16, An), Additional Word
        if (address < code.size) {
            const int16_t d16 = GetI16BE(code.buffer + address);
            if (s.target_asm == TargetAssembler::kSierraAsm68 && d16 == 0) {
                return Arg::D16AnAddrInvalid(xn, d16);
            }
            return Arg::D16AnAddr(xn, d16);
        }
        break;
    case 6: // (d8, An, Xi), Brief Extension Word
        if (address < code.size) {
            const uint16_t briefext = GetU16BE(code.buffer + address);
            if (briefext & 0x0700) {
                // briefext must have zeros on 8, 9 an 10-th bits,
                // i.e. xxxx_x000_xxxx_xxxx
                break;
            }
            // Xi number (lower 3 bits, mask 0x7) with An/Dn bit (mask 0x8)
            const uint8_t xi = (briefext >> 12) & 0xf;
            const OpSize s2 = ((briefext >> 11) & 1) ? OpSize::kLong : OpSize::kWord;
            const int8_t d8 = briefext & 0xff;
            return Arg::D8AnXiAddr(xn, xi, s2, d8);
        }
        break;
    case 7:
        switch (xn) {
        case 0: // (xxx).W, Additional Word
            if (address < code.size) {
                const int32_t w = GetI16BE(code.buffer + address);
                return Arg::Word(w);
            }
            break;
        case 1: // (xxx).L, Additional Long
            if (address + kInstructionSizeStepBytes < code.size) {
                const int32_t l = GetI32BE(code.buffer + address);
                return Arg::Long(l);
            }
            break;
        case 2: // (d16, PC), Additional Word
            if (address < code.size) {
                const int16_t d16 = GetI16BE(code.buffer + address);
                return Arg::D16PCAddr(d16);
            }
            break;
        case 3: // (d8, PC, Xi), Brief Extension Word
            if (address < code.size) {
                const uint16_t briefext = GetU16BE(code.buffer + address);
                if (briefext & 0x0700) {
                    // briefext must have zeros on 8, 9 an 10-th bits,
                    // i.e. xxxx_x000_xxxx_xxxx
                    break;
                }
                // Xi number (lower 3 bits, mask 0x7) with An/Dn bit (mask 0x8)
                const uint8_t xi = (briefext >> 12) & 0xf;
                const OpSize s2 = ((briefext >> 11) & 1) ? OpSize::kLong : OpSize::kWord;
                const int8_t d8 = briefext & 0xff;
                return Arg::D8PCXiAddr(xn, xi, s2, d8);
            }
            break;
        case 4: // #imm
            return FetchImmediate(address, code, s, opsize);
        case 5: // Does not exist
        case 6: // Does not exist
        case 7: // Does not exist
            break;
        }
        break;
    }
    return Arg{};
}

static Arg FetchArg(
        const uint32_t address,
        const DataView &code,
        const Settings &s,
        const uint16_t instr,
        const OpSize opsize)
{
    const int addrmode = instr & 0x3f;
    const int m = (addrmode >> 3) & 7;
    const int xn = addrmode & 7;
    return FetchArg(address, code, s, m, xn, opsize);
}

static size_t disasm_verbatim(DisasmNode &node, const uint16_t instr)
{
    node.op = Op::Raw(instr);
    return node.size;
}

static size_t disasm_jsr_jmp(
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    const OpSize opsize = OpSize::kWord;
    const auto a = FetchArg(node.address + kInstructionSizeStepBytes, code, s, instr, opsize);
    switch (a.mode) {
    case AddrMode::kInvalid:
    case AddrMode::kDn: // 4e80..4e87 / 4ec0..4ec7
    case AddrMode::kAn: // 4e88..4e8f / 4ec8..4ecf
        return disasm_verbatim(node, instr);
    case AddrMode::kAnAddr: // 4e90..4e97 / 4ed0..4ed7
        // NOTE: dynamic jump, ref_addr may possibly be obtained during the
        // trace
        break;
    case AddrMode::kAnAddrIncr: // 4e98..4e9f / 4ed8..4edf
    case AddrMode::kAnAddrDecr: // 4ea0..4ea7 / 4ee0..4ee7
        return disasm_verbatim(node, instr);
    case AddrMode::kD16AnAddr: // 4ea8..4eaf / 4ee8..4eef
        // NOTE: dynamic jump, ref_addr may possibly be obtained during the
        // trace
        break;
    case AddrMode::kD8AnXiAddr: // 4eb0..4eb7 / 4ef0..4ef7
        // NOTE: dynamic jump, ref_addr may possibly be obtained during the
        // trace
        break;
    case AddrMode::kWord: // 4eb8 / 4ef8
        {
            const uint32_t ref_addr = static_cast<uint32_t>(a.lword);
            node.ref1_addr = ref_addr;
            node.ref_kinds = kRef1AbsMask;
        }
        break;
    case AddrMode::kLong: // 4eb9 / 4ef9
        {
            const uint32_t ref_addr = static_cast<uint32_t>(a.lword);
            node.ref1_addr = ref_addr;
            node.ref_kinds = kRef1AbsMask;
        }
        break;
    case AddrMode::kD16PCAddr: // 4eba / 4efa
        {
            const uint32_t ref_addr = node.address + kInstructionSizeStepBytes +
                static_cast<uint32_t>(a.d16_pc.d16);
            node.ref1_addr = ref_addr;
            node.ref_kinds = kRef1RelMask;
        }
        break;
    case AddrMode::kD8PCXiAddr: // 4ebb / 4efb
        // NOTE: dynamic jump, ref_addr may possibly be obtained during the
        // trace
        break;
    case AddrMode::kImmediate: // 4ebc / 4efc
        return disasm_verbatim(node, instr);
    }
    const bool is_jmp = instr & 0x40;
    node.ref_kinds |= is_jmp ? 0 : kRefCallMask;
    node.op = Op::Typical(is_jmp ? OpCode::kJMP : OpCode::kJSR, OpSize::kNone, a);
    return node.size = kInstructionSizeStepBytes + a.Size(opsize);
}

static size_t disasm_ext(DisasmNode &node, const OpSize opsize, const Arg arg)
{
    assert(arg.mode == AddrMode::kDn);
    node.op = Op::Typical(OpCode::kEXT, opsize, arg);
    return node.size = kInstructionSizeStepBytes + arg.Size(opsize);
}

static size_t disasm_ext_movem(
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    const auto dir = static_cast<MoveDirection>((instr >> 10) & 1);
    const unsigned m = (instr >> 3) & 7;
    const unsigned xn = instr & 7;
    const auto opsize = static_cast<OpSize>(((instr >> 6) & 1) + 1);
    if (m == 0 && dir == MoveDirection::kRegisterToMemory) {
        return disasm_ext(node, opsize, Arg::Dn(xn));
    }
    if (node.address + kInstructionSizeStepBytes >= code.size) {
        // Not enough space for regmask, but maybe it is just EXT?
        return disasm_verbatim(node, instr);
    }
    const unsigned regmask = GetU16BE(code.buffer + node.address + kInstructionSizeStepBytes);
    if (regmask == 0) {
        // This is just not representable: at least one register must be specified
        return disasm_verbatim(node, instr);
    }
    const auto a = FetchArg(
            node.address + kInstructionSizeStepBytes * 2, code, s, m, xn, opsize);
    switch (a.mode) {
    case AddrMode::kInvalid:
    case AddrMode::kDn: // 4880..4887 / 4c80..4c87 / 48c0..48c7 / 4cc0..4cc7
    case AddrMode::kAn: // 4888..488f / 4c88..4c8f / 48c8..48cf / 4cc8..4ccf
        return disasm_verbatim(node, instr);
    case AddrMode::kAnAddr: // 4890..4897 / 4c90..4c97 / 48d0..48d7 / 4cd0..4cd7
        break;
    case AddrMode::kAnAddrIncr: // 4898..489f / 4c89..4c9f / 48d8..48df / 4cd8..4cdf
        if (dir == MoveDirection::kRegisterToMemory) {
            return disasm_verbatim(node, instr);
        }
        break;
    case AddrMode::kAnAddrDecr: // 48a0..48a7 / 4ca0..4ca7 / 48e0..48e7 / 4ce0..4ce7
        if (dir == MoveDirection::kMemoryToRegister) {
            return disasm_verbatim(node, instr);
        }
        break;
    case AddrMode::kD16AnAddr: // 48a8..48af / 4c8a..4caf / 48e8..48ef / 4ce8..4cef
    case AddrMode::kD8AnXiAddr: // 48b0..48b7 / 4cb0..4cb7 / 48f0..48f7 / 4cf0..4cf7
        break;
    case AddrMode::kWord: // 48b8 / 4cb8 / 48f8 / 4cf8
    case AddrMode::kLong: // 48b9 / 4cb9 / 48f9 / 4cf9
        if (dir == MoveDirection::kRegisterToMemory) {
            node.ref2_addr = static_cast<uint32_t>(a.lword);
            node.ref_kinds = kRef2AbsMask | kRef2WriteMask;
        } else {
            node.ref1_addr = static_cast<uint32_t>(a.lword);
            node.ref_kinds = kRef1AbsMask | kRef1ReadMask;
        }
        break;
    case AddrMode::kD16PCAddr: // 48ba / 4cba / 48fa / 4cfa
    case AddrMode::kD8PCXiAddr: // 48bb / 4cbb / 48fb / 4cfb
        if (dir == MoveDirection::kRegisterToMemory) {
            return disasm_verbatim(node, instr);
        } else if (a.mode == AddrMode::kD16PCAddr) {
            // XXX: kRefPcRelFix2Bytes flag is a hack that needed to correctly
            // print label for PC relative referenced value of MOVEM. Alongside
            // with *NOT* adding kInstructionSizeStepBytes to ref1_addr. Still
            // figuring that out.
            node.ref1_addr = node.address + kInstructionSizeStepBytes * 2 +
                static_cast<uint32_t>(a.d16_pc.d16);
            node.ref_kinds = kRef1RelMask | kRef1ReadMask | kRefPcRelFix2Bytes;
        }
        break;
    case AddrMode::kImmediate: // 4ebc / 4efc
        return disasm_verbatim(node, instr);
    }
    if (dir == MoveDirection::kMemoryToRegister) {
        const auto arg2 = (a.mode == AddrMode::kAnAddrDecr)
            ? Arg::RegMaskPredecrement(regmask) : Arg::RegMask(regmask);
        node.op = Op::Typical(OpCode::kMOVEM, opsize, a, arg2);
    } else {
        const auto arg1 = (a.mode == AddrMode::kAnAddrDecr)
            ? Arg::RegMaskPredecrement(regmask) : Arg::RegMask(regmask);
        node.op = Op::Typical(OpCode::kMOVEM, opsize, arg1, a);
    }
    return node.size = kInstructionSizeStepBytes * 2 + a.Size(opsize);
}

static size_t disasm_lea(
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    const OpSize opsize = OpSize::kLong;
    const auto addr = FetchArg(
            node.address + kInstructionSizeStepBytes, code, s, instr, opsize);
    switch (addr.mode) {
    case AddrMode::kInvalid:
    case AddrMode::kDn:
    case AddrMode::kAn:
        return disasm_verbatim(node, instr);
    case AddrMode::kAnAddr:
        break;
    case AddrMode::kAnAddrIncr:
    case AddrMode::kAnAddrDecr:
        return disasm_verbatim(node, instr);
    case AddrMode::kD16AnAddr:
    case AddrMode::kD8AnXiAddr:
        break;
    case AddrMode::kWord:
    case AddrMode::kLong:
        node.ref1_addr = static_cast<uint32_t>(addr.lword);
        node.ref_kinds = kRef1AbsMask | kRef1ReadMask;
        break;
    case AddrMode::kD16PCAddr:
        node.ref1_addr = node.address + kInstructionSizeStepBytes +
            static_cast<uint32_t>(addr.d16_pc.d16);
        node.ref_kinds = kRef1RelMask | kRef1ReadMask;
        break;
    case AddrMode::kD8PCXiAddr:
        break;
    case AddrMode::kImmediate:
        return disasm_verbatim(node, instr);
    }
    const unsigned an = ((instr >> 9) & 7);
    const auto reg = Arg::An(an);
    node.op = Op::Typical(OpCode::kLEA, opsize, addr, reg);
    return node.size = kInstructionSizeStepBytes + addr.Size(opsize) + reg.Size(opsize);
}

static size_t disasm_chk(
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    const OpSize opsize = OpSize::kWord;
    const auto src = FetchArg(
            node.address + kInstructionSizeStepBytes, code, s, instr, opsize);
    switch (src.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr);
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
        return disasm_verbatim(node, instr);
    }
    const unsigned dn = ((instr >> 9) & 7);
    const auto dst = Arg::Dn(dn);
    node.op = Op::Typical(OpCode::kCHK, opsize, src, dst);
    return node.size = kInstructionSizeStepBytes + src.Size(opsize) + dst.Size(opsize);
}

static size_t disasm_bra_bsr_bcc(
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings& s)
{
    const int16_t dispmt0 = static_cast<int8_t>(instr & 0xff);
    if (dispmt0 == -1) {
        // This will definitely lead to executing invalid instruction and is
        // also invalid for GNU AS to assemble
        return disasm_verbatim(node, instr);
    }
    const auto opsize = dispmt0 ? OpSize::kShort : OpSize::kWord;
    if (dispmt0 == 0) {
        // Check the boundaries
        if (node.address + kInstructionSizeStepBytes >= code.size) {
            return disasm_verbatim(node, instr);
        }
        node.size = kInstructionSizeStepBytes * 2;
    } else {
        node.size = kInstructionSizeStepBytes;
    }
    const int16_t dispmt = kInstructionSizeStepBytes + (dispmt0
        ? dispmt0 : GetI16BE(code.buffer + node.address + kInstructionSizeStepBytes));
    const uint32_t ref_addr = static_cast<uint32_t>(node.address + dispmt);
    Condition condition = static_cast<Condition>((instr >> 8) & 0xf);
    // "short branch to next instruction is illegal" in Sierra.
    const bool branch_to_next = dispmt == kInstructionSizeStepBytes;
    // Sierra wont take odd displacement and will spit out the following:
    // "branch to/from odd address: destination address is odd"
    const bool odd = dispmt % int16_t(2);
    if (s.target_asm == TargetAssembler::kSierraAsm68 && (branch_to_next || odd)) {
        node.op = Op{OpCode::kBcc, opsize, condition, Arg::DisplacementInvalid(dispmt)};
    } else {
        node.ref1_addr = ref_addr;
        // False condition Indicates BSR
        node.ref_kinds = kRef1RelMask | ((condition == Condition::kF) ? kRefCallMask : 0);
        node.op = Op{OpCode::kBcc, opsize, condition, Arg::Displacement(dispmt)};
    }
    return node.size;
}

static OpCode OpCodeForBitOps(const unsigned opcode)
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

static size_t disasm_movep(
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    const unsigned dn = ((instr >> 9) & 7);
    const unsigned an = instr & 7;
    const OpSize opsize = ((instr >> 6) & 1) ? OpSize::kLong : OpSize::kWord;
    const auto dir = static_cast<MoveDirection>(!((instr >> 7) & 1));
    const auto addr = FetchArg(
            node.address + kInstructionSizeStepBytes, code, s, 5, an, opsize);
    if (addr.mode == AddrMode::kInvalid) {
        // Boundary check failed, most likely
        return disasm_verbatim(node, instr);
    }
    assert(addr.mode == AddrMode::kD16AnAddr);
    const auto reg = Arg::Dn(dn);
    if (dir == MoveDirection::kRegisterToMemory) {
        node.op = Op::Typical(OpCode::kMOVEP, opsize, reg, addr);
    } else {
        node.op = Op::Typical(OpCode::kMOVEP, opsize, addr, reg);
    }
    return node.size = kInstructionSizeStepBytes + addr.Size(opsize) + reg.Size(opsize);
}

static size_t disasm_src_arg_bitops_movep(
        DisasmNode &node,
        const uint16_t instr,
        const DataView &code,
        const Settings &s,
        const bool has_dn_src = true)
{
    const unsigned m = (instr >> 3) & 7;
    if ((m == 1) && has_dn_src) {
        return disasm_movep(node, instr, code, s);
    }
    const unsigned dn = ((instr >> 9) & 7);
    const unsigned xn = instr & 7;
    const OpSize opsize0 = OpSize::kByte;
    // Fetch AddrMode::kDn if has_dn_src, otherwise fetch AddrMode::kImmediate
    // byte
    const auto src = FetchArg(
            node.address + kInstructionSizeStepBytes,
            code,
            s,
            (has_dn_src) ? 0 : 7,
            dn,
            opsize0);
    if (src.mode == AddrMode::kInvalid) {
        return disasm_verbatim(node, instr);
    }
    if (has_dn_src) {
        assert(src.mode == AddrMode::kDn);
    } else {
        assert(dn == 4);
        assert(src.mode == AddrMode::kImmediate);
    }
    const uint32_t addr = node.address + kInstructionSizeStepBytes + src.Size(opsize0);
    const auto dst = FetchArg(addr, code, s, m, xn, opsize0);
    const unsigned opcode = (instr >> 6) & 3;
    switch (dst.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr);
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
            return disasm_verbatim(node, instr);
        }
        break;
    case AddrMode::kImmediate:
        return disasm_verbatim(node, instr);
    }
    const auto opsize = dst.mode == AddrMode::kDn ? OpSize::kLong : OpSize::kByte;
    node.op = Op::Typical(OpCodeForBitOps(opcode), opsize, src, dst);
    return node.size = kInstructionSizeStepBytes + src.Size(opsize0) + dst.Size(opsize0);
}

static size_t disasm_bitops(DisasmNode &n, const uint16_t i, const DataView &c, const Settings &s)
{
    return disasm_src_arg_bitops_movep(n, i, c, s, false);
}

static size_t disasm_logical_immediate_to_ccr_or_sr(
        DisasmNode &node, OpCode opcode, OpSize opsize, Arg imm)
{
    node.op = Op::Typical(opcode, opsize, imm, (opsize == OpSize::kByte) ? Arg::CCR() : Arg::SR());
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
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    const bool has_source_reg = (instr >> 8) & 1;
    if (has_source_reg) {
        return disasm_src_arg_bitops_movep(node, instr, code, s);
    }
    const unsigned opcode = (instr >> 9) & 7;
    if (opcode == 7) {
        // Does not exist
        return disasm_verbatim(node, instr);
    }
    if (opcode == 4) {
        return disasm_bitops(node, instr, code, s);
    }
    const int m = (instr >> 3) & 7;
    const int xn = instr & 7;
    const auto opsize = static_cast<OpSize>((instr >> 6) & 3);
    if (opsize == OpSize::kInvalid) {
            // Does not exist
            return disasm_verbatim(node, instr);
    }
    // Anticipating #imm which means "to CCR"/"to SR", depending on OpSize
    if (m == 7 && xn == 4) {
        if (opcode == 2 || opcode == 3 || opcode == 6) {
            // CMPI, SUBI and ANDI neither have immediate destination arguments
            // nor "to CCR"/"to SR" variations
            return disasm_verbatim(node, instr);
        }
        if (opsize == OpSize::kLong) {
            // Does not exist
            return disasm_verbatim(node, instr);
        }
    }
    auto src = FetchImmediate(node.address + kInstructionSizeStepBytes, code, s, opsize);
    if (src.mode == AddrMode::kInvalid) {
        return disasm_verbatim(node, instr);
    }
    assert(src.mode == AddrMode::kImmediate);
    const OpCode mnemonic = OpCodeForLogicalImmediate(opcode);
    if (m == 7 && xn == 4) {
        return disasm_logical_immediate_to_ccr_or_sr(node, mnemonic, opsize, src);
    }
    auto dst = FetchArg(
            node.address + kInstructionSizeStepBytes + src.Size(opsize), code, s, m, xn, opsize);
    switch (dst.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr);
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
        // According to "The 68000 Instruction Set" documentation I own, PC
        // relative destination address argument *is* available for CMPI and for
        // CMPI only, but neither GNU nor Sierra allow it for 68000 ISA. GNU AS
        // considers it to be a feature of 68020, which is currently not
        // supported.
        //
        // Hence, if 68020 will ever be supported, the next line should be
        // wrapped with conditional expression based on an ISA choice.
        dst.is_invalid = true;
        break;
    case AddrMode::kImmediate:
        return disasm_verbatim(node, instr);
    }
    if (s.target_asm == TargetAssembler::kSierraAsm68) {
        // For ADDI and SUBI Sierra will emit ADDQ and SUBQ if immediate value
        // is positive and is less than or equal 8, i.e. if it fits ADDQ or SUBQ
        // respectively.
        if (mnemonic == OpCode::kADDI || mnemonic == OpCode::kSUBI) {
            if (src.lword > 0 && src.lword <= 8) {
                src.is_invalid = true;
            }
        }
    }
    node.op = Op::Typical(mnemonic, opsize, src, dst);
    return node.size = kInstructionSizeStepBytes + src.Size(opsize) + dst.Size(opsize);
}

static size_t disasm_move_movea(
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    const int opsize_raw = (instr >> 12) & 3;
    const OpSize opsize = (opsize_raw == 1)
        ? OpSize::kByte : (opsize_raw == 3 ? OpSize::kWord : OpSize::kLong);
    const auto src = FetchArg(
            node.address + kInstructionSizeStepBytes, code, s, instr, opsize);
    switch (src.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        if (opsize == OpSize::kByte) {
            // Does not exist
            return disasm_verbatim(node, instr);
        }
    case AddrMode::kAnAddr:
    case AddrMode::kAnAddrIncr:
    case AddrMode::kAnAddrDecr:
    case AddrMode::kD16AnAddr:
    case AddrMode::kD8AnXiAddr:
        break;
    case AddrMode::kWord:
    case AddrMode::kLong:
        node.ref1_addr = static_cast<uint32_t>(src.lword);
        node.ref_kinds |= kRef1AbsMask | kRef1ReadMask;
        break;
    case AddrMode::kD16PCAddr:
        node.ref1_addr = node.address + kInstructionSizeStepBytes +
            static_cast<uint32_t>(src.d16_pc.d16);
        node.ref_kinds |= kRef1RelMask | kRef1ReadMask;
        break;
    case AddrMode::kD8PCXiAddr:
    case AddrMode::kImmediate:
        break;
    }
    const int m = (instr >> 6) & 7;
    const int xn = (instr >> 9) & 7;
    const auto dst = FetchArg(
            node.address + kInstructionSizeStepBytes + src.Size(opsize), code, s, m, xn, opsize);
    switch (dst.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        if (opsize == OpSize::kByte) {
            // Does not exist
            return disasm_verbatim(node, instr);
        }
    case AddrMode::kAnAddr:
    case AddrMode::kAnAddrIncr:
    case AddrMode::kAnAddrDecr:
    case AddrMode::kD16AnAddr:
    case AddrMode::kD8AnXiAddr:
        break;
    case AddrMode::kWord:
    case AddrMode::kLong:
        node.ref2_addr = static_cast<uint32_t>(dst.lword);
        node.ref_kinds |= kRef2AbsMask | kRef2WriteMask;
        break;
    case AddrMode::kD16PCAddr:
    case AddrMode::kD8PCXiAddr:
    case AddrMode::kImmediate:
        return disasm_verbatim(node, instr);
    }
    // XXX Assuming that moving long immediate value into address register is
    // basically a sneaky LEA. It may not be true in some cases.
    if (src.type == ArgType::kImmediate && dst.type == ArgType::kAn) {
        if (opsize == OpSize::kLong) {
            node.ref1_addr = static_cast<uint32_t>(src.lword);
            node.ref_kinds |= kRef1ImmMask | kRef1ReadMask;
        } else if (opsize == OpSize::kWord) {
            node.ref1_addr = static_cast<int16_t>(static_cast<uint16_t>(src.lword));
            node.ref_kinds |= kRef1ImmMask | kRef1ReadMask;
        }
    }
    const auto opcode = (dst.mode == AddrMode::kAn) ? OpCode::kMOVEA : OpCode::kMOVE;
    node.op = Op::Typical(opcode, opsize, src, dst);
    return node.size = kInstructionSizeStepBytes + src.Size(opsize) + dst.Size(opsize);
}

static size_t disasm_move_from_sr(
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    const auto opsize = OpSize::kWord;
    const auto dst = FetchArg(
            node.address + kInstructionSizeStepBytes, code, s, instr, opsize);
    switch (dst.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr);
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
        return disasm_verbatim(node, instr);
    }
    node.op = Op::Typical(OpCode::kMOVE, opsize, Arg::SR(), dst);
    return node.size = kInstructionSizeStepBytes + dst.Size(opsize);
}

static size_t disasm_move_to(
        DisasmNode &node,
        const uint16_t instr,
        const DataView &code,
        const Settings &s,
        const ArgType reg)
{
    const auto opsize = OpSize::kWord;
    const auto src = FetchArg(
            node.address + kInstructionSizeStepBytes, code, s, instr, opsize);
    switch (src.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr);
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
    node.op = Op::Typical(OpCode::kMOVE, opsize, src, Arg{{reg}, false, {0}});
    return node.size = kInstructionSizeStepBytes + src.Size(opsize);
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
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    const auto opsize = static_cast<OpSize>((instr >> 6) & 3);
    const unsigned opcode = (instr >> 9) & 3;
    if (opsize == OpSize::kInvalid) {
        switch (opcode) {
        case 0:
            return disasm_move_from_sr(node, instr, code, s);
        case 1:
            return disasm_verbatim(node, instr);
        case 2:
            return disasm_move_to(node, instr, code, s, ArgType::kCCR);
        case 3:
            return disasm_move_to(node, instr, code, s, ArgType::kSR);
        }
        assert(false);
        return disasm_verbatim(node, instr);
    }
    const auto a = FetchArg(
            node.address + kInstructionSizeStepBytes, code, s, instr, opsize);
    switch (a.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr);
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
        return disasm_verbatim(node, instr);
    }
    node.op = Op::Typical(opcode_for_negx_clr_neg_not(opcode), opsize, a);
    return node.size = kInstructionSizeStepBytes + a.Size(opsize);
}

static size_t disasm_trivial(
        DisasmNode &node, const OpCode opcode)
{
    node.op = Op::Typical(opcode, OpSize::kNone);
    return node.size;
}

static size_t disasm_tas(
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    const auto opsize = OpSize::kByte;
    const auto a = FetchArg(
            node.address + kInstructionSizeStepBytes, code, s, instr, opsize);
    switch (a.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr);
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
        return disasm_verbatim(node, instr);
    }
    node.op = Op::Typical(OpCode::kTAS, opsize, a);
    return node.size = kInstructionSizeStepBytes + a.Size(opsize);
}

static size_t disasm_tst_tas_illegal(
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    const auto opsize = static_cast<OpSize>((instr >> 6) & 3);
    const int m = (instr >> 3) & 7;
    const int xn = instr & 7;
    if (opsize == OpSize::kInvalid) {
        if (m == 7 && xn == 4){
            return disasm_trivial(node, OpCode::kILLEGAL);
        }
        return disasm_tas(node, instr, code, s);
    }
    auto a = FetchArg(node.address + kInstructionSizeStepBytes, code, s, m, xn, opsize);
    switch (a.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr);
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
        // According to "The 68000 Instruction Set" documentation I own, PC
        // relative destination address argument *is* available for TST, but
        // neither GNU nor Sierra allow it for 68000 ISA. GNU AS considers it to
        // be a feature of 68020, which is currently not supported.
        //
        // Hence, if 68020 will ever be supported, the next line should be
        // wrapped with conditional expression based on an ISA choice.
        a.is_invalid = true;
        break;
    case AddrMode::kImmediate:
        return disasm_verbatim(node, instr);
    }
    node.op = Op::Typical(OpCode::kTST, opsize, a);
    return node.size = kInstructionSizeStepBytes + a.Size(opsize);
}

static size_t disasm_trap(DisasmNode &node, const uint16_t instr)
{
    const unsigned vector = instr & 0xf;
    node.op = Op::Typical(OpCode::kTRAP, OpSize::kNone, Arg::Immediate(vector));
    return node.size = kInstructionSizeStepBytes;
}

static size_t disasm_link_unlink(
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    const bool unlk = (instr >> 3) & 1;
    const unsigned xn = instr & 7;
    if (unlk) {
        node.op = Op::Typical(OpCode::kUNLK, OpSize::kNone, Arg::AddrModeXn(ArgType::kAn, xn));
        return node.size = kInstructionSizeStepBytes;
    }
    const auto opsize = OpSize::kWord;
    const auto src = FetchImmediate(
            node.address + kInstructionSizeStepBytes, code, s, opsize);
    if (src.mode != AddrMode::kImmediate) {
        return disasm_verbatim(node, instr);
    }
    node.op = Op::Typical(OpCode::kLINK, opsize, Arg::AddrModeXn(ArgType::kAn, xn), src);
    return node.size = kInstructionSizeStepBytes + src.Size(opsize);
}

static size_t disasm_move_usp(DisasmNode &node, const uint16_t instr)
{
    const unsigned xn = instr & 7;
    const auto dir = static_cast<MoveDirection>((instr >> 3) & 1);
    if (dir == MoveDirection::kRegisterToMemory) {
        node.op = Op::Typical(
                OpCode::kMOVE, OpSize::kLong, Arg::An(xn), Arg::USP());
    } else {
        node.op = Op::Typical(
                OpCode::kMOVE, OpSize::kLong, Arg::USP(), Arg::An(xn));
    }
    return node.size = kInstructionSizeStepBytes;
}

static size_t disasm_nbcd_swap_pea(
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    const bool is_nbcd = !((instr >> 6) & 1);
    const OpSize opsize0 = OpSize::kWord;
    const auto arg = FetchArg(
            node.address + kInstructionSizeStepBytes, code, s, instr, opsize0);
    bool is_swap{};
    switch (arg.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr);
    case AddrMode::kDn:
        if (!is_nbcd) {
            is_swap = true;
        }
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr);
    case AddrMode::kAnAddr:
        break;
    case AddrMode::kAnAddrIncr:
    case AddrMode::kAnAddrDecr:
        if (!is_nbcd) {
            return disasm_verbatim(node, instr);
        }
        break;
    case AddrMode::kD16AnAddr:
    case AddrMode::kD8AnXiAddr:
        break;
    case AddrMode::kWord:
    case AddrMode::kLong:
        node.ref1_addr = static_cast<uint32_t>(arg.lword);
        node.ref_kinds = kRef1AbsMask | kRef1ReadMask;
        break;
    case AddrMode::kD16PCAddr:
    case AddrMode::kD8PCXiAddr:
        if (is_nbcd) {
            return disasm_verbatim(node, instr);
        }
        if (arg.mode == AddrMode::kD16PCAddr) {
            node.ref1_addr = node.address + kInstructionSizeStepBytes +
                static_cast<uint32_t>(arg.d16_pc.d16);
            node.ref_kinds = kRef1RelMask | kRef1ReadMask;
        }
        break;
    case AddrMode::kImmediate:
        return disasm_verbatim(node, instr);
    }
    const auto opcode = is_nbcd ? OpCode::kNBCD : is_swap ? OpCode::kSWAP : OpCode::kPEA;
    const auto opsize = is_nbcd ? OpSize::kByte : is_swap ? OpSize::kWord : OpSize::kLong;
    node.op = Op::Typical(opcode, opsize, arg);
    return node.size = kInstructionSizeStepBytes + arg.Size(opsize0);
}

static size_t disasm_stop(
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    const auto a = FetchImmediate(node.address + kInstructionSizeStepBytes, code, s, OpSize::kWord);
    if (a.mode != AddrMode::kImmediate) {
        return disasm_verbatim(node, instr);
    }
    node.op = Op::Typical(OpCode::kSTOP, OpSize::kNone, a);
    return node.size = kInstructionSizeStepBytes * 2;
}

static size_t disasm_chunk_4(
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    if ((instr & 0xf900) == 0x4000) {
        return disasm_move_negx_clr_neg_not(node, instr, code, s);
    } else if ((instr & 0xff80) == 0x4800) {
        // NOTE: EXT is handled with MOVEM
        return disasm_nbcd_swap_pea(node, instr, code, s);
    } else if ((instr & 0xff00) == 0x4a00) {
        return disasm_tst_tas_illegal(node, instr, code, s);
    } else if ((instr & 0xfff0) == 0x4e40) {
        return disasm_trap(node, instr);
    } else if ((instr & 0xfff0) == 0x4e50) {
        return disasm_link_unlink(node, instr, code, s);
    } else if ((instr & 0xfff0) == 0x4e60) {
        return disasm_move_usp(node, instr);
    } else if ((instr & 0xfff8) == 0x4e70) {
        if (instr == 0x4e70) {
            return disasm_trivial(node, OpCode::kRESET);
        } else if (instr == 0x4e71) {
            return disasm_trivial(node, OpCode::kNOP);
        } else if (instr == 0x4e72) {
            return disasm_stop(node, instr, code, s);
        } else if (instr == 0x4e73) {
            return disasm_trivial(node, OpCode::kRTE);
        } else if (instr == 0x4e75) {
            return disasm_trivial(node, OpCode::kRTS);
        } else if (instr == 0x4e76) {
            return disasm_trivial(node, OpCode::kTRAPV);
        } else if (instr == 0x4e77) {
            return disasm_trivial(node, OpCode::kRTR);
        }
    } else if ((instr & 0xff80) == 0x4e80) {
        return disasm_jsr_jmp(node, instr, code, s);
    } else if ((instr & 0xfb80) == 0x4880) {
        return disasm_ext_movem(node, instr, code, s);
    } else if ((instr & 0xf1c0) == 0x41c0) {
        return disasm_lea(node, instr, code, s);
    } else if ((instr & 0xf1c0) == 0x4180) {
        return disasm_chk(node, instr, code, s);
    }
    return disasm_verbatim(node, instr);
}

static size_t disasm_addq_subq(
        DisasmNode &node,
        const uint16_t instr,
        const DataView &code,
        const Settings &s,
        const OpSize opsize)
{
    const auto a = FetchArg(node.address + kInstructionSizeStepBytes, code, s, instr, opsize);
    switch (a.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr);
    case AddrMode::kDn: // 5x00..5x07 / 5x40..5x47 / 5x80..5x87
        break;
    case AddrMode::kAn: // 5x08..5x0f / 5x48..5x4f / 5x88..5x8f
        if (opsize == OpSize::kByte) {
            // 5x08..5x0f
            // addqb and subqb with An do not exist
            return disasm_verbatim(node, instr);
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
        return disasm_verbatim(node, instr);
    }
    const unsigned imm = ((uint8_t((instr >> 9) & 7) - 1) & 7) + 1;
    const auto opcode = ((instr >> 8) & 1) ? OpCode::kSUBQ : OpCode::kADDQ;
    node.op = Op::Typical(opcode, opsize, Arg::Immediate(imm), a);
    return node.size = kInstructionSizeStepBytes + a.Size(opsize);
}

static size_t disasm_dbcc(
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    if (node.address + kInstructionSizeStepBytes >= code.size) {
        return disasm_verbatim(node, instr);
    }
    const int16_t dispmt_raw = GetI16BE(code.buffer + node.address + kInstructionSizeStepBytes);
    const int32_t dispmt = dispmt_raw + kInstructionSizeStepBytes;
    // Sierra wont take odd displacement and will spit out the following:
    // "branch to/from odd address: destination address is odd"
    const bool invalid_dispmt = (s.target_asm == TargetAssembler::kSierraAsm68) &&
        (dispmt % int32_t(2));
    node.ref2_addr = static_cast<uint32_t>(node.address + dispmt);
    node.ref_kinds = kRef2RelMask;
    node.op = Op{
        OpCode::kDBcc,
        OpSize::kWord,
        static_cast<Condition>((instr >> 8) & 0xf),
        Arg::AddrModeXn(ArgType::kDn, (instr & 7)),
        invalid_dispmt ? Arg::DisplacementInvalid(dispmt) : Arg::Displacement(dispmt),
    };
    return node.size = kInstructionSizeStepBytes * 2;
}

static size_t disasm_scc_dbcc(
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    const OpSize opsize = OpSize::kWord;
    const auto a = FetchArg(
            node.address + kInstructionSizeStepBytes, code, s, instr, opsize);
    switch (a.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr);
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
        return disasm_verbatim(node, instr);
    }
    node.op = Op{OpCode::kScc, OpSize::kByte, static_cast<Condition>((instr >> 8) & 0xf), a};
    return node.size = kInstructionSizeStepBytes + a.Size(opsize);
}

static size_t disasm_addq_subq_scc_dbcc(
        DisasmNode &n, const uint16_t instr, const DataView &c, const Settings &s)
{
    const auto opsize = static_cast<OpSize>((instr >> 6) & 3);
    if (opsize == OpSize::kInvalid) {
        return disasm_scc_dbcc(n, instr, c, s);
    }
    return disasm_addq_subq(n, instr, c, s, opsize);
}

static size_t disasm_moveq(DisasmNode &node, const uint16_t instr)
{
    if (instr & 0x100) {
        // Does not exist
        return disasm_verbatim(node, instr);
    }
    const int xn = (instr >> 9) & 7;
    const auto dst = Arg::Dn(xn);
    const int8_t data = instr & 0xff;
    const OpSize opsize = OpSize::kLong;
    node.op = Op::Typical(OpCode::kMOVEQ, opsize, Arg::Immediate(data), dst);
    return node.size = kInstructionSizeStepBytes + dst.Size(opsize);
}

static size_t disasm_divu_divs_mulu_muls(
        DisasmNode &node,
        const uint16_t instr,
        const DataView &code,
        const Settings &s,
        const OpCode opcode)
{
    const auto opsize = OpSize::kWord;
    const auto src = FetchArg(
            node.address + kInstructionSizeStepBytes, code, s, instr, opsize);
    switch (src.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr);
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
    const auto dst = Arg::Dn(dn);
    node.op = Op::Typical(opcode, opsize, src, dst);
    return node.size = kInstructionSizeStepBytes + dst.Size(opsize) + src.Size(opsize);
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
    const auto src = m ? Arg::AnAddrDecr(xn) : Arg::Dn(xn);
    const auto dst = m ? Arg::AnAddrDecr(xi) : Arg::Dn(xi);
    node.op = Op::Typical(opcode, opsize, src, dst);
    return node.size = kInstructionSizeStepBytes + src.Size(opsize) + dst.Size(opsize);
}

static size_t disasm_or_and(
        DisasmNode &node,
        const uint16_t instr,
        const DataView &code,
        const Settings &s,
        const OpSize opsize,
        const OpCode opcode)
{
    const bool dir_to_addr = (instr >> 8) & 1;
    const auto addr = FetchArg(
            node.address + kInstructionSizeStepBytes, code, s, instr, opsize);
    switch (addr.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr);
    case AddrMode::kDn:
        if (dir_to_addr) {
            // Switching dir when bot operands are data registers is not allowed
            return disasm_verbatim(node, instr);
        }
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr);
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
            return disasm_verbatim(node, instr);
        }
        break;
    case AddrMode::kImmediate:
        if (dir_to_addr) {
            // immediate cannot be destination
            return disasm_verbatim(node, instr);
        }
        break;
    }
    const auto reg = Arg::Dn((instr >> 9) & 7);
    if (dir_to_addr) {
        node.op = Op::Typical(opcode, opsize, reg, addr);
    } else {
        node.op = Op::Typical(opcode, opsize, addr, reg);
    }
    return node.size = kInstructionSizeStepBytes + addr.Size(opsize) + reg.Size(opsize);
}

static size_t disasm_divu_divs_sbcd_or(
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    // Also ensures that opsize == OpSize::kByte, i.e. 0b00
    if ((instr & 0x1f0) == 0x100) {
        return disasm_addx_subx_abcd_sbcd(node, instr, OpCode::kSBCD);
    }
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    if (opsize == OpSize::kInvalid) {
        const bool is_signed = (instr >> 8) & 1;
        const auto opcode = is_signed ? OpCode::kDIVS : OpCode::kDIVU;
        return disasm_divu_divs_mulu_muls(node, instr, code, s, opcode);
    }
    return disasm_or_and(node, instr, code, s, opsize, OpCode::kOR);
}

static size_t disasm_adda_suba_cmpa(
        DisasmNode &node,
        const uint16_t instr,
        const DataView &code,
        const Settings &s,
        const OpCode opcode)
{
    const OpSize opsize = static_cast<OpSize>(((instr >> 8) & 1) + 1);
    const auto src = FetchArg(
            node.address + kInstructionSizeStepBytes, code, s, instr, opsize);
    switch (src.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr);
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
    const auto dst = Arg::An(an);
    node.op = Op::Typical(opcode, opsize, src, dst);
    return node.size = kInstructionSizeStepBytes + src.Size(opsize) + dst.Size(opsize);
}

static size_t disasm_add_sub_cmp(
        DisasmNode &node,
        const uint16_t instr,
        const DataView &code,
        const Settings &s,
        const OpCode opcode,
        const OpSize opsize,
        const bool dir_to_addr)
{
    const auto addr = FetchArg(
            node.address + kInstructionSizeStepBytes, code, s, instr, opsize);
    switch (addr.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        if (dir_to_addr || opsize == OpSize::kByte) {
            // An cannot be destination and An cannot be used as byte
            return disasm_verbatim(node, instr);
        }
        /* Fall through */
    case AddrMode::kAnAddr:
    case AddrMode::kAnAddrIncr:
    case AddrMode::kAnAddrDecr:
    case AddrMode::kD16AnAddr:
    case AddrMode::kD8AnXiAddr:
        break;
    case AddrMode::kWord:
    case AddrMode::kLong:
        if (dir_to_addr) {
            node.ref2_addr = static_cast<uint32_t>(addr.lword);
            node.ref_kinds = kRef2AbsMask | kRef2ReadMask;
        } else {
            node.ref1_addr = static_cast<uint32_t>(addr.lword);
            node.ref_kinds = kRef1AbsMask | kRef1ReadMask;
        }
        break;
    case AddrMode::kD16PCAddr:
    case AddrMode::kD8PCXiAddr:
        if (dir_to_addr) {
            // PC relative cannot be destination
            return disasm_verbatim(node, instr);
        }
        if (addr.mode == AddrMode::kD16PCAddr) {
            node.ref1_addr = node.address + kInstructionSizeStepBytes +
                static_cast<uint32_t>(addr.d16_pc.d16);
            node.ref_kinds = kRef1RelMask | kRef1ReadMask;
        }
        break;
    case AddrMode::kImmediate:
        if (dir_to_addr) {
            // immediate cannot be destination
            return disasm_verbatim(node, instr);
        }
        break;
    }
    const unsigned dn = (instr >> 9) & 7;
    const auto reg = Arg::Dn(dn);
    if (dir_to_addr) {
        node.op = Op::Typical(opcode, opsize, reg, addr);
    } else {
        node.op = Op::Typical(opcode, opsize, addr, reg);
    }
    return node.size = kInstructionSizeStepBytes + addr.Size(opsize) + reg.Size(opsize);
}

static size_t disasm_cmpm(DisasmNode &node, const uint16_t instr)
{
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    // Must be already handled by parent call
    assert(opsize != OpSize::kInvalid);
    // M has to be set to 0b001
    assert(((instr >> 3) & 7) == 1);
    const int xn = instr & 7;
    const int xi = (instr >> 9) & 7;
    const auto src = Arg::AnAddrIncr(xn);
    const auto dst = Arg::AnAddrIncr(xi);
    node.op = Op::Typical(OpCode::kCMPM, opsize, src, dst);
    return node.size = kInstructionSizeStepBytes + src.Size(opsize) + dst.Size(opsize);
}

static size_t disasm_eor(
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    const auto addr = FetchArg(
            node.address + kInstructionSizeStepBytes, code, s, instr, opsize);
    switch (addr.mode) {
    case AddrMode::kInvalid:
        return disasm_verbatim(node, instr);
    case AddrMode::kDn:
        break;
    case AddrMode::kAn:
        return disasm_verbatim(node, instr);
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
        return disasm_verbatim(node, instr);
    }
    const auto reg = Arg::Dn((instr >> 9) & 7);
    node.op = Op::Typical(OpCode::kEOR, opsize, reg, addr);
    return node.size = kInstructionSizeStepBytes + addr.Size(opsize) + reg.Size(opsize);
}

static size_t disasm_eor_cmpm_cmp_cmpa(
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    if (opsize == OpSize::kInvalid) {
        return disasm_adda_suba_cmpa(node, instr, code, s, OpCode::kCMPA);
    }
    const bool dir_to_addr = ((instr >> 8) & 1);
    if (!dir_to_addr) {
        return disasm_add_sub_cmp(node, instr, code, s, OpCode::kCMP, opsize, dir_to_addr);
    }
    const int m = (instr >> 3) & 7;
    if (m == 1) {
        return disasm_cmpm(node, instr);
    }
    return disasm_eor(node, instr, code, s);
}

static size_t disasm_exg(DisasmNode &node, const uint16_t instr)
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
    const auto src = (m == 3) ? Arg::An(xi) : Arg::Dn(xi);
    const auto dst = (m == 2) ? Arg::Dn(xn) : Arg::An(xn);
    const auto opsize = OpSize::kLong;
    node.op = Op::Typical(OpCode::kEXG, opsize, src, dst);
    return node.size = kInstructionSizeStepBytes + src.Size(opsize) + dst.Size(opsize);
}

static size_t disasm_chunk_c(
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    if ((instr & 0x1f0) == 0x100) {
        return disasm_addx_subx_abcd_sbcd(node, instr, OpCode::kABCD);
    }
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    if (opsize == OpSize::kInvalid) {
        const bool is_signed = (instr >> 8) & 1;
        const auto opcode = is_signed ? OpCode::kMULS : OpCode::kMULU;
        return disasm_divu_divs_mulu_muls(node, instr, code, s, opcode);
    }
    const unsigned m_split = instr & 0x1f8;
    if (m_split == 0x188 || m_split == 0x148 || m_split == 0x140) {
        return disasm_exg(node, instr);
    }
    return disasm_or_and(node, instr, code, s, opsize, OpCode::kAND);
}

static size_t disasm_add_sub_x_a(
        DisasmNode &node,
        const uint16_t instr,
        const DataView &code,
        const Settings &s,
        const OpCode opcode)
{
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3);
    if (opsize == OpSize::kInvalid) {
        return disasm_adda_suba_cmpa(
                node, instr, code, s, (opcode == OpCode::kSUB) ? OpCode::kSUBA : OpCode::kADDA);
    }
    const bool dir_to_addr = (instr >> 8) & 1;
    const unsigned m = (instr >> 3) & 7;
    if (dir_to_addr && (m == 0 || m == 1)) {
        return disasm_addx_subx_abcd_sbcd(
                node, instr, (opcode == OpCode::kSUB) ? OpCode::kSUBX : OpCode::kADDX);
    }
    return disasm_add_sub_cmp(node, instr, code, s, opcode, opsize, dir_to_addr);
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

static bool IsValidShiftKind(const ShiftKind k)
{
    return static_cast<unsigned>(k) < 4u;
}

static size_t disasm_shift_rotate(
        DisasmNode &node, const uint16_t instr, const DataView &code, const Settings &s)
{
    const OpSize opsize = static_cast<OpSize>((instr >> 6) & 3u);
    const unsigned xn = instr & 7;
    const uint8_t rotation = (instr >> 9) & 7u;
    const ShiftKind kind = (opsize == OpSize::kInvalid)
        ? static_cast<ShiftKind>(rotation)
        : static_cast<ShiftKind>((instr >> 3) & 3u);
    if (!IsValidShiftKind(kind)) {
        return disasm_verbatim(node, instr);
    }
    const auto dir = static_cast<ShiftDirection>((instr >> 8) & 1u);
    const auto dst = (opsize == OpSize::kInvalid)
        ? FetchArg(node.address + kInstructionSizeStepBytes, code, s, instr, opsize)
        : Arg::Dn(xn);
    if (opsize == OpSize::kInvalid) {
        switch (dst.mode) {
        case AddrMode::kInvalid:
            return disasm_verbatim(node, instr);
        case AddrMode::kDn:
            // Intersects with situation when args are "#1,%dx". GNU AS would
            // not understand shift instruction with single argument of "%dx".
            return disasm_verbatim(node, instr);
            break;
        case AddrMode::kAn:
            return disasm_verbatim(node, instr);
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
            return disasm_verbatim(node, instr);
        }
        node.op = Op::Typical(ShiftKindToOpcode(kind, dir), OpSize::kWord, dst);
    } else {
        const unsigned imm = ((rotation - 1) & 7u) + 1u;
        const unsigned m = (instr >> 5) & 1u;
        const auto arg1 = m ? Arg::AddrModeXn(ArgType::kDn, rotation) : Arg::Immediate(imm);
        node.op = Op::Typical(ShiftKindToOpcode(kind, dir), opsize, arg1, dst);
    }
    return node.size = kInstructionSizeStepBytes + dst.Size(opsize);
}

static size_t m68k_disasm(DisasmNode &n, uint16_t i, const DataView &c, const Settings &s)
{
    switch ((i & 0xf000) >> 12) {
    case 0x0:
        return disasm_bitops_movep(n, i, c, s);
    case 0x1:
    case 0x2:
    case 0x3:
        return disasm_move_movea(n, i, c, s);
    case 0x4:
        return disasm_chunk_4(n, i, c, s);
    case 0x5:
        return disasm_addq_subq_scc_dbcc(n, i, c, s);
    case 0x6:
        return disasm_bra_bsr_bcc(n, i, c, s);
    case 0x7:
        return disasm_moveq(n, i);
    case 0x8:
        return disasm_divu_divs_sbcd_or(n, i, c, s);
    case 0x9:
        return disasm_add_sub_x_a(n, i, c, s, OpCode::kSUB);
    case 0xa:
        // Does not exist
        return disasm_verbatim(n, i);
    case 0xb:
        return disasm_eor_cmpm_cmp_cmpa(n, i, c, s);
    case 0xc:
        return disasm_chunk_c(n, i, c, s);
    case 0xd:
        return disasm_add_sub_x_a(n, i, c, s, OpCode::kADD);
    case 0xe:
        return disasm_shift_rotate(n, i, c, s);
    case 0xf:
        // Does not exist
        return disasm_verbatim(n, i);
    }
    assert(false);
    return disasm_verbatim(n, i);
}

size_t DisasmNode::Disasm(const DataView &code, const Settings &s)
{
    // We assume that machine have no MMU and ROM data always starts at 0
    assert(this->address < code.size);
    size = kInstructionSizeStepBytes;
    ref_kinds = 0;
    ref1_addr = 0;
    ref2_addr = 0;
    const uint16_t instr = GetU16BE(code.buffer + this->address);
    if (IsInstruction(this->type)) {
        return m68k_disasm(*this, instr, code, s);
    } else {
        // Data should not be disassembled
        return disasm_verbatim(*this, instr);
    }
}

size_t DisasmNode::DisasmAsRaw(const DataView &code)
{
    // We assume that machine have no MMU and ROM data always starts at 0
    assert(this->address < code.size);
    size = kInstructionSizeStepBytes;
    ref_kinds = 0;
    ref1_addr = 0;
    ref2_addr = 0;
    const uint16_t instr = GetU16BE(code.buffer + this->address);
    return disasm_verbatim(*this, instr);
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

static const char *ToString(const OpSize s, bool with_dot)
{
    if (with_dot) {
        switch (s) {
        case OpSize::kNone: return "";
        case OpSize::kByte: return ".b";
        case OpSize::kShort: return ".s";
        case OpSize::kWord: return ".w";
        case OpSize::kLong: return ".l";
        }
        assert(false);
        return "";
    }
    switch (s) {
    case OpSize::kNone: return "";
    case OpSize::kByte: return "b";
    case OpSize::kShort: return "s";
    case OpSize::kWord: return "w";
    case OpSize::kLong: return "l";
    }
    assert(false);
    return "";
}

static char RegChar(const uint8_t xi)
{
    return (xi & 0x08) ? 'a' : 'd';
}

static char SizeSpecChar(const uint8_t xi)
{
    return (xi & 0x10) ? 'l' : 'w';
}

static unsigned RegNum(const uint8_t xi)
{
    return xi & 0x7;
}

static size_t snprint_reg_mask_gnu(
        char *const buf, const size_t bufsz, const uint32_t regmask_arg, const ArgType arg_type)
{
    const uint32_t regmask = regmask_arg & 0xffff;
    size_t written = 0;
    size_t span = 0;
    bool first_printed = false;
    // 17-th bit used to close the span with 0 value unconditionally
    for (int i = 0; i < 17; i++) {
        const uint32_t mask = (i <= 15)
            ? (1 << ((arg_type == ArgType::kRegMaskPredecrement) ? (15 - i) : i))
            : 0;
        const bool hit = regmask & mask;
        const bool span_open = hit && span == 0;
        const bool span_closed = (!hit && span > 1);
        const int printable_i = i - (span_closed ? 1 : 0);
        const int id = printable_i % 8;
        const char regtype = (printable_i >= 8) ? 'a' : 'd';
        if (span_open || span_closed) {
            const char *const delimiter = span_open ? (first_printed ? "/" : "") : "-";
            const size_t remaining = bufsz - written;
            const int ret = snprintf(buf + written, remaining, "%s%%%c%d", delimiter, regtype, id);
            assert(ret > 0);
            assert(static_cast<unsigned>(ret) >= sizeof("%d0")-1);
            assert(static_cast<unsigned>(ret) <= sizeof("-%d0")-1);
            written += Min(remaining, ret);
            first_printed = true;
        }
        span = hit ? span + 1 : 0;
    }
    assert(written < bufsz); // Output must not be truncated
    return written;
}

/*! _.
 *
 * This function splits spans of d0-d7 and a0-a7, unlike snprint_reg_mask_gnu,
 * which may produce spans across d-regs and a-regs like d0-a7.
 */
static size_t snprint_reg_mask_sierra(
        char *const buf, const size_t bufsz, const uint32_t regmask_arg, const ArgType arg_type)
{
    const uint32_t regmask = regmask_arg & 0xffff;
    size_t written = 0;
    size_t span = 0;
    bool first_printed = false;
    bool dn_passed = false;
    // 17-th bit used to close the span with 0 value unconditionally
    for (int i = 0; i < 17; i++) {
        const uint32_t mask = (i <= 15)
            ? (1 << ((arg_type == ArgType::kRegMaskPredecrement) ? (15 - i) : i))
            : 0;
        const bool hit = regmask & mask;
        if (dn_passed && i == 8) {
            span = 0;
        }
        const bool span_open = (hit && span == 0) && !(!dn_passed && i == 8);
        const bool span_closed = !hit || (!dn_passed && i == 8);
        const int printable_i = i - (span_closed ? 1 : 0);
        const int id = printable_i % 8;
        const char regtype = (printable_i >= 8) ? 'a' : 'd';
        if (span_open || (span_closed && span > 1)) {
            const char *const delimiter = span_open ? (first_printed ? "/" : "") : "-";
            const size_t remaining = bufsz - written;
            const int ret = snprintf(buf + written, remaining, "%s%c%d", delimiter, regtype, id);
            assert(ret > 0);
            assert(static_cast<unsigned>(ret) >= sizeof("d0")-1);
            assert(static_cast<unsigned>(ret) <= sizeof("-d0")-1);
            written += Min(remaining, ret);
            first_printed = true;
        }
        span = hit ? span + 1 : 0;
        if (!dn_passed && i == 8) {
            // We need to repeat the iteration on a0 (i == 8) because we closed
            // the span and it will get open again
            i--;
            dn_passed = true;
        }
    }
    assert(written < bufsz); // Output must not be truncated
    return written;
}

int SNPrintArgRaw(char *const buf, const size_t bufsz, const Arg &arg)
{
    return snprintf(buf, bufsz, "0x%04x", arg.uword);
}

static int SNPrintArg(
            char *const buf,
            const size_t bufsz,
            const Arg &arg,
            const OpCode opcode,
            const bool imm_as_hex,
            const TargetAssembler target_asm,
            const RefKindMask ref_kinds,
            const char *const label,
            const uint32_t self_addr,
            const uint32_t ref_addr)
{
    switch (arg.type) {
    case ArgType::kNone:
        assert(false);
        break;
    case ArgType::kRaw:
        return SNPrintArgRaw(buf, bufsz, arg);
    case ArgType::kDn:
        if (TargetAssembler::kSierraAsm68 == target_asm) {
            return snprintf(buf, bufsz, "d%d", arg.xn);
        }
        return snprintf(buf, bufsz, "%%d%d", arg.xn);
    case ArgType::kAn:
        if (TargetAssembler::kSierraAsm68 == target_asm) {
            return snprintf(buf, bufsz, "a%u", arg.xn);
        }
        return snprintf(buf, bufsz, "%%a%u", arg.xn);
    case ArgType::kAnAddr:
        if (TargetAssembler::kSierraAsm68 == target_asm) {
            return snprintf(buf, bufsz, "(a%u)", arg.xn);
        }
        return snprintf(buf, bufsz, "%%a%u@", arg.xn);
    case ArgType::kAnAddrIncr:
        if (TargetAssembler::kSierraAsm68 == target_asm) {
            return snprintf(buf, bufsz, "(a%u)+", arg.xn);
        }
        return snprintf(buf, bufsz, "%%a%u@+", arg.xn);
    case ArgType::kAnAddrDecr:
        if (TargetAssembler::kSierraAsm68 == target_asm) {
            return snprintf(buf, bufsz, "-(a%u)", arg.xn);
        }
        return snprintf(buf, bufsz, "%%a%u@-", arg.xn);
    case ArgType::kD16AnAddr:
        if (TargetAssembler::kSierraAsm68 == target_asm) {
            return snprintf(buf, bufsz, "%d(a%u)", arg.d16_an.d16, arg.d16_an.an);
        }
        return snprintf(buf, bufsz, "%%a%u@(%d:w)", arg.d16_an.an, arg.d16_an.d16);
    case ArgType::kD8AnXiAddr:
        if (TargetAssembler::kSierraAsm68 == target_asm) {
            return snprintf(
                    buf, bufsz, "%d(a%u,%c%u.%c)",
                    arg.d8_an_xi.d8,
                    arg.d8_an_xi.an,
                    RegChar(arg.d8_an_xi.xi),
                    RegNum(arg.d8_an_xi.xi),
                    SizeSpecChar(arg.d8_an_xi.xi));
        }
        return snprintf(
                buf, bufsz, "%%a%u@(%d,%%%c%u:%c)",
                arg.d8_an_xi.an,
                arg.d8_an_xi.d8,
                RegChar(arg.d8_an_xi.xi),
                RegNum(arg.d8_an_xi.xi),
                SizeSpecChar(arg.d8_an_xi.xi));
    case ArgType::kWord:
    case ArgType::kLong:
        {
            const char c = arg.type == ArgType::kLong ? 'l' : 'w';
            if (ref_kinds & kRefAbsMask) {
                if (static_cast<uint32_t>(arg.lword) == ref_addr) {
                    if (TargetAssembler::kSierraAsm68 == target_asm) {
                        return snprintf(buf, bufsz, "%s.%c", label, c);
                    }
                    return snprintf(buf, bufsz, "%s:%c", label, c);
                } else {
                    // It has to be AFTER the label we are gonna reference here
                    assert(static_cast<uint32_t>(arg.lword) > ref_addr);
                    if (TargetAssembler::kSierraAsm68 == target_asm) {
                        return snprintf(buf, bufsz, "%s+%d.%c", label, arg.lword - ref_addr, c);
                    }
                    return snprintf(buf, bufsz, "%s+%d:%c", label, arg.lword - ref_addr, c);
                }
            } else {
                if (TargetAssembler::kSierraAsm68 == target_asm) {
                    return snprintf(buf, bufsz, "0x%x.%c", arg.lword, c);
                }
                return snprintf(buf, bufsz, "0x%x:%c", arg.lword, c);
            }
        }
    case ArgType::kD16PCAddr:
        if (ref_kinds & kRefRelMask) {
            // XXX: Most of instructions with PC relative values have 2 bytes
            // added to the offset, some does not. Still figuring that out.
            const bool has_fix = ref_kinds & kRefPcRelFix2Bytes;
            // XXX: I should try (self_addr + instruction_size - ext_word_size)
            // universally instead of hacky fix flag, but it requires some
            // overhaul of the instruction printing functions.
            const uint32_t arg_addr = self_addr + arg.d16_pc.d16 + kInstructionSizeStepBytes +
                (has_fix ? kInstructionSizeStepBytes : 0);
            if (arg_addr == ref_addr) {
                if (TargetAssembler::kSierraAsm68 == target_asm) {
                    return snprintf(buf, bufsz, "%s(pc)", label);
                }
                return snprintf(buf, bufsz, "%%pc@(%s:w)", label);
            } else {
                assert(arg_addr > ref_addr);
                if (TargetAssembler::kSierraAsm68 == target_asm) {
                    return snprintf(buf, bufsz,  "%s+%d(pc)", label, arg_addr - ref_addr);
                }
                return snprintf(buf, bufsz,  "%%pc@(%s+%d:w)", label, arg_addr - ref_addr);
            }
        } else {
            if (TargetAssembler::kSierraAsm68 == target_asm) {
                // XXX: It may depend on the current instruction size, so adding
                // kInstructionSizeStepBytes may be invalid in some cases.
                const int displacement = arg.d16_pc.d16 + BasePartSize(opcode);
                if (displacement == 0) {
                    return snprintf(buf, bufsz, ".(pc)");
                }
                return snprintf(buf, bufsz, ".%s%d(pc)",
                        displacement >= 0 ? "+" : "",
                        displacement);
            }
            return snprintf(buf, bufsz, "%%pc@(%d:w)", arg.d16_pc.d16);
        }
    case ArgType::kD8PCXiAddr:
        if (TargetAssembler::kSierraAsm68 == target_asm) {
            // XXX: It may depend on the current instruction size, so adding
            // kInstructionSizeStepBytes may be invalid in some cases.
            const int displacement = arg.d8_pc_xi.d8 + BasePartSize(opcode);
            if (displacement == 0) {
                return snprintf(
                        buf, bufsz, ".(pc,%c%u.%c)",
                        RegChar(arg.d8_pc_xi.xi),
                        RegNum(arg.d8_pc_xi.xi),
                        SizeSpecChar(arg.d8_pc_xi.xi));
            }
            return snprintf(
                    buf, bufsz, ".%s%d(pc,%c%u.%c)",
                    displacement >= 0 ? "+" : "",
                    displacement,
                    RegChar(arg.d8_pc_xi.xi),
                    RegNum(arg.d8_pc_xi.xi),
                    SizeSpecChar(arg.d8_pc_xi.xi));
        }
        return snprintf(
                buf, bufsz, "%%pc@(%d,%%%c%u:%c)",
                arg.d8_pc_xi.d8,
                RegChar(arg.d8_pc_xi.xi),
                RegNum(arg.d8_pc_xi.xi),
                SizeSpecChar(arg.d8_pc_xi.xi));
    case ArgType::kImmediate:
        if (ref_kinds & kRef1ImmMask) {
            if (static_cast<uint32_t>(arg.lword) == ref_addr) {
                return snprintf(buf, bufsz, "#%s", label);
            } else {
                // It has to be AFTER the label we are gonna reference here
                assert(static_cast<uint32_t>(arg.lword) > ref_addr);
                return snprintf(buf, bufsz, "#%s+%d", label, arg.lword - ref_addr);
            }
        } else if (imm_as_hex) {
            return snprintf(buf, bufsz, "#0x%x", arg.lword);
        } else {
            return snprintf(buf, bufsz, "#%d", arg.lword);
        }
    case ArgType::kRegMask:
    case ArgType::kRegMaskPredecrement:
        if (target_asm == TargetAssembler::kGnuAs) {
            return snprint_reg_mask_gnu(buf, bufsz, arg.uword, arg.type);
        } else {
            return snprint_reg_mask_sierra(buf, bufsz, arg.uword, arg.type);
        }
    case ArgType::kDisplacement:
        if (ref_kinds & kRefRelMask) {
            if (static_cast<uint32_t>(self_addr + arg.lword) == ref_addr) {
                return snprintf(buf, bufsz,  "%s", label);
            } else {
                assert(static_cast<uint32_t>(self_addr + arg.lword) > ref_addr);
                return snprintf(buf, bufsz,  "%s+%d", label, (self_addr + arg.lword) - ref_addr);
            }
        } else {
            if (arg.lword == 0) {
                return snprintf(buf, bufsz,  ".");
            }
            return snprintf(buf, bufsz,  ".%s%d", arg.lword >= 0 ? "+" : "", arg.lword);
        }
    case ArgType::kCCR:
        if (TargetAssembler::kSierraAsm68 == target_asm) {
            return snprintf(buf, bufsz,  "ccr");
        }
        return snprintf(buf, bufsz,  "%%ccr");
    case ArgType::kSR:
        if (TargetAssembler::kSierraAsm68 == target_asm) {
            return snprintf(buf, bufsz,  "sr");
        }
        return snprintf(buf, bufsz,  "%%sr");
    case ArgType::kUSP:
        if (TargetAssembler::kSierraAsm68 == target_asm) {
            return snprintf(buf, bufsz,  "usp");
        }
        return snprintf(buf, bufsz,  "%%usp");
    }
    assert(false);
    return -1;
}

int FPrintOp(
        FILE *const stream,
        const Op &op,
        const Settings &s,
        const RefKindMask ref_kinds,
        const char *const ref1_label,
        const char *const ref2_label,
        const uint32_t self_addr,
        const uint32_t ref1_addr,
        const uint32_t ref2_addr)
{
    assert(op.opcode != OpCode::kNone);
    char mnemonic_str[kMnemonicBufferSize]{};
    const bool gnu = s.target_asm == TargetAssembler::kGnuAs;
    // XXX GNU AS does not know ABCD.B, it only knows ABCD, but happily consumes
    // SBCD.B and others. That's why it is OpSize::kNone specifically for ABCD
    // mnemonic. It is probably a bug in GNU AS.
    const bool abcd = op.opcode == OpCode::kABCD;
    // XXX GNU AS does not accept size suffix for EXG, although it's size is
    // always long word.
    const bool exg = op.opcode == OpCode::kEXG;
    const OpSize size_spec{(gnu && (abcd || exg)) ? OpSize::kNone : op.size_spec};
    const bool with_dot = TargetAssembler::kSierraAsm68 == s.target_asm || s.dot_size_spec;
    snprintf(
            mnemonic_str,
            kMnemonicBufferSize,
            "%s%s",
            ToString(op.opcode, op.condition),
            ToString(size_spec, with_dot));
    if (op.arg1.type != ArgType::kNone) {
        char arg1_str[kArgsBufferSize]{};
        const RefKindMask ref1_kinds = ref_kinds & (kRef1Mask | kRefPcRelFix2Bytes);
        // It is useful to have immediate value printed as hex if destination
        // argument is plain address register, status register or condition code
        // register. USP is not the case because it's value may be moved only to
        // or from An register.
        const bool imm_as_hex = s.imm_hex ||
            op.arg1.type == ArgType::kAn ||
            op.arg1.type == ArgType::kCCR ||
            op.arg1.type == ArgType::kSR ||
            op.arg2.type == ArgType::kAn ||
            op.arg2.type == ArgType::kCCR ||
            op.arg2.type == ArgType::kSR;
        SNPrintArg(
                arg1_str,
                kArgsBufferSize,
                op.arg1,
                op.opcode,
                imm_as_hex,
                s.target_asm,
                ref1_kinds,
                ref1_label,
                self_addr,
                ref1_addr);
        if (op.arg2.type != ArgType::kNone) {
            char arg2_str[kArgsBufferSize]{};
            const RefKindMask ref2_kinds = ref_kinds & (kRef2Mask | kRefPcRelFix2Bytes);
            SNPrintArg(
                    arg2_str,
                    kArgsBufferSize,
                    op.arg2,
                    op.opcode,
                    // Second arg may be immediate when dealing with "link", so
                    // imm_as_hex is relevant here as well.
                    imm_as_hex,
                    s.target_asm,
                    ref2_kinds,
                    ref2_label,
                    self_addr,
                    ref2_addr);
            return fprintf(stream, "%s%s %s,%s", s.indent, mnemonic_str, arg1_str, arg2_str);
        } else {
            return fprintf(stream, "%s%s %s", s.indent, mnemonic_str, arg1_str);
        }
    } else {
        return fprintf(stream, "%s%s", s.indent, mnemonic_str);
    }
}
