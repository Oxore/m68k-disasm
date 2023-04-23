#include "disasm.h"
#include "data_buffer.h"
#include "common.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>

static void disasm_verbatim(
        DisasmNode& node, uint16_t instr, const DataBuffer &, const Settings &)
{
    node.size = kInstructionSizeStepBytes;
    snprintf(node.mnemonic, kMnemonicBufferSize, ".short");
    snprintf(node.arguments, kArgsBufferSize, "0x%04x", instr);
}

static void disasm_mfff0_v4e70(
        DisasmNode& node, uint16_t instr, const DataBuffer &code, const Settings &s)
{
    node.size = kInstructionSizeStepBytes;
    if (instr == 0x4e70) {
        snprintf(node.mnemonic, kMnemonicBufferSize, "reset");
    } else if (instr == 0x4e71) {
        snprintf(node.mnemonic, kMnemonicBufferSize, "nop");
    } else if (instr == 0x4e73) {
        snprintf(node.mnemonic, kMnemonicBufferSize, "rte");
    } else if (instr == 0x4e75) {
        snprintf(node.mnemonic, kMnemonicBufferSize, "rts");
    } else if (instr == 0x4e76) {
        snprintf(node.mnemonic, kMnemonicBufferSize, "trapv");
    } else if (instr == 0x4e77) {
        snprintf(node.mnemonic, kMnemonicBufferSize, "rtr");
    } else {
        disasm_verbatim(node, instr, code, s);
    }
}

enum class JsrJmp {
    kJsr,
    kJmp,
};

static void disasm_jsr_jmp(
        DisasmNode& node, uint16_t instr, const DataBuffer &code, const Settings &s, JsrJmp jsrjmp)
{
    const char *mnemonic = (jsrjmp == JsrJmp::kJsr) ? "jsr" : "jmp";
    node.is_call = (jsrjmp == JsrJmp::kJsr);
    const int addrmode = instr & 0x3f;
    const int m = (addrmode >> 3) & 0x7;
    const int xn = addrmode & 0x7;
    switch (m) {
    case 0: // 4e80 .. 4e87
    case 1: // 4e88 .. 4e8f
        break;
    case 2: // 4e90 .. 4e97
        // NOTE: dynamic jump, branch_addr may possibly be obtained during the
        // trace
        node.size = kInstructionSizeStepBytes;
        snprintf(node.mnemonic, kMnemonicBufferSize, "%s", mnemonic);
        snprintf(node.arguments, kArgsBufferSize, "%%a%d@", xn);
        return;
    case 3: // 4e98 .. 4e9f
    case 4: // 4ea0 .. 4ea7
        break;
    case 5: // 4ea8 .. 4eaf, Displacement
        {
            // NOTE: dynamic jump, branch_addr may possibly be obtained during
            // the trace
            node.size = kInstructionSizeStepBytes * 2;
            const int16_t dispmt = GetI16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
            snprintf(node.mnemonic, kMnemonicBufferSize, "%s", mnemonic);
            snprintf(node.arguments, kArgsBufferSize, "%%a%d@(%d:w)", xn, dispmt);
            return;
        }
    case 6: // 4eb0 .. 4eb7, Brief Extension Word
        {
            // NOTE: dynamic jump, branch_addr may possibly be obtained during
            // the trace
            node.size = kInstructionSizeStepBytes * 2;
            const uint16_t briefext = GetU16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
            const char reg = ((briefext >> 15) & 1) ? 'a' : 'd';
            const int xn2 = (briefext >> 12) & 7;
            const char size_spec = ((briefext >> 11) & 1) ? 'l' : 'w';
            const int8_t dispmt = briefext & 0xff;
            snprintf(node.mnemonic, kMnemonicBufferSize, "%s", mnemonic);
            snprintf(node.arguments, kArgsBufferSize,
                    "%%a%d@(%d,%%%c%d:%c)", xn, dispmt, reg, xn2, size_spec);
            return;
        }
    case 7: // 4eb8 .. 4ebf, some are with Brief Extension Word
        switch (xn) {
        case 0: // 4eb8 (xxx).W
            {
                node.size = kInstructionSizeStepBytes * 2;
                // This shit is real: it is sign extend value
                const int32_t dispmt = GetI16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
                // So jumping to negative value will land PC on something like
                // 0xffff8a0c, effectively making jump possible only to lowest
                // 32K range 0..0x7fff and highest 32K range
                // 0xffff8000...0xffffffff
                node.branch_addr = static_cast<uint32_t>(dispmt);
                node.has_branch_addr = true;
                snprintf(node.mnemonic, kMnemonicBufferSize, "%s", mnemonic);
                snprintf(node.arguments, kArgsBufferSize, "0x%x:w", dispmt);
                return;
            }
        case 1: // 4eb9 (xxx).L
            {
                node.size = kInstructionSizeStepBytes * 3;
                const int32_t dispmt = GetI32BE(code.buffer + node.offset + kInstructionSizeStepBytes);
                node.branch_addr = static_cast<uint32_t>(dispmt);
                node.has_branch_addr = true;
                snprintf(node.mnemonic, kMnemonicBufferSize, "%s", mnemonic);
                snprintf(node.arguments, kArgsBufferSize, "0x%x:l", dispmt);
                return;
            }
        case 2: // 4eba, Displacement
            {
                const int16_t dispmt = GetI16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
                // Add 2 to current PC, as usual
                node.branch_addr = node.offset + dispmt + kInstructionSizeStepBytes;
                node.has_branch_addr = true;
                node.size = kInstructionSizeStepBytes * 2;
                snprintf(node.mnemonic, kMnemonicBufferSize, "%s", mnemonic);
                snprintf(node.arguments, kArgsBufferSize, "%%pc@(%d:w)", dispmt);
                return;
            }
        case 3: // 4ebb
            {
                // NOTE: dynamic jump, branch_addr may possibly be obtained
                // during the trace
                node.size = kInstructionSizeStepBytes * 2;
                const uint16_t briefext = GetU16BE(
                        code.buffer + node.offset + kInstructionSizeStepBytes);
                const char reg = ((briefext >> 15) & 1) ? 'a' : 'd';
                const int xn2 = (briefext >> 12) & 7;
                const char size_spec = ((briefext >> 11) & 1) ? 'l' : 'w';
                const int8_t dispmt = briefext & 0xff;
                snprintf(node.mnemonic, kMnemonicBufferSize, "%s", mnemonic);
                snprintf(node.arguments, kArgsBufferSize,
                        "%%pc@(%d,%%%c%d:%c)", dispmt, reg, xn2, size_spec);
                return;
            }
        case 4: // 4ebc
        case 5: // 4ebd
        case 6: // 4ebe
            break;
        }
        break;
    }
    return disasm_verbatim(node, instr, code, s);
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

static void disasm_bra_bsr_bcc(
        DisasmNode& node, uint16_t instr, const DataBuffer &code, const Settings &)
{
    Condition condition = static_cast<Condition>((instr >> 8) & 0xf);
    const char *mnemonic = branch_instr_name_by_cond(condition);
    // False condition Indicates BSR
    node.is_call = (condition == Condition::kF);
    int dispmt = static_cast<int8_t>(instr & 0xff);
    const char *size_spec = "s";
    if (dispmt == 0) {
        dispmt = GetI16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
        node.size = kInstructionSizeStepBytes * 2;
        size_spec = "w";
    } else {
        node.size = kInstructionSizeStepBytes;
    }
    dispmt += kInstructionSizeStepBytes;
    node.branch_addr = node.offset + dispmt;
    node.has_branch_addr = true;
    const char * const sign = dispmt >= 0 ? "+" : "";
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s%s", mnemonic, size_spec);
    snprintf(node.arguments, kArgsBufferSize, ".%s%d", sign, dispmt);
    return;
}

static void m68k_disasm(
        DisasmNode& node, uint16_t instr, const DataBuffer &code, const Settings &s)
{
    if ((instr & 0xfff0) == 0x4e70) {
        return disasm_mfff0_v4e70(node, instr, code, s);
    } else if ((instr & 0xffc0) == 0x4e80) {
        return disasm_jsr(node, instr, code, s);
    } else if ((instr & 0xffc0) == 0x4ec0) {
        return disasm_jmp(node, instr, code, s);
    } else if ((instr & 0xf000) == 0x6000) {
        return disasm_bra_bsr_bcc(node, instr, code, s);
    }
    return disasm_verbatim(node, instr, code, s);
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
