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
    case 0: // 4e80..4e87 / 4ec0..4ec7
    case 1: // 4e88..4e8f / 4ec8..4ecf
        break;
    case 2: // 4e90..4e97 / 4ed0..4ed7
        // NOTE: dynamic jump, branch_addr may possibly be obtained during the
        // trace
        node.size = kInstructionSizeStepBytes;
        snprintf(node.mnemonic, kMnemonicBufferSize, "%s", mnemonic);
        snprintf(node.arguments, kArgsBufferSize, "%%a%d@", xn);
        return;
    case 3: // 4e98..4e9f / 4ed8..4edf
    case 4: // 4ea0..4ea7 / 4ee0..4ee7
        break;
    case 5: // 4ea8..4eaf / 4ee8..4eef, Displacement
        {
            // NOTE: dynamic jump, branch_addr may possibly be obtained during
            // the trace
            node.size = kInstructionSizeStepBytes * 2;
            const int16_t dispmt = GetI16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
            snprintf(node.mnemonic, kMnemonicBufferSize, "%s", mnemonic);
            snprintf(node.arguments, kArgsBufferSize, "%%a%d@(%d:w)", xn, dispmt);
            return;
        }
    case 6: // 4eb0..4eb7 / 4ef0..4ef7, Brief Extension Word
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
    case 7: // 4eb8..4ebf / 4ef8..4eff, some are with Brief Extension Word
        switch (xn) {
        case 0: // 4eb8 / 4ef8 (xxx).W
            {
                node.size = kInstructionSizeStepBytes * 2;
                // This shit is real: it is sign extend value
                const int32_t dispmt = GetI16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
                // So jumping to negative value will land PC on something like
                // 0xffff8a0c, effectively making jump possible only to lowest
                // 32K range 0..0x7fff and highest 32K range
                // 0xffff8000...0xffffffff
                const uint32_t branch_addr = static_cast<uint32_t>(dispmt);
                node.branch_addr = branch_addr;
                node.has_branch_addr = true;
                snprintf(node.mnemonic, kMnemonicBufferSize, "%s", mnemonic);
                // FIXME support s.abs_marks option for this instruction
                snprintf(node.arguments, kArgsBufferSize, "0x%x:w", dispmt);
                return;
            }
        case 1: // 4eb9 / 4ef9 (xxx).L
            {
                node.size = kInstructionSizeStepBytes * 3;
                const int32_t dispmt = GetI32BE(code.buffer + node.offset + kInstructionSizeStepBytes);
                const uint32_t branch_addr = static_cast<uint32_t>(dispmt);
                node.branch_addr = branch_addr;
                node.has_branch_addr = true;
                snprintf(node.mnemonic, kMnemonicBufferSize, "%s", mnemonic);
                // FIXME support s.abs_marks option for this instruction
                snprintf(node.arguments, kArgsBufferSize, "0x%x:l", dispmt);
                return;
            }
        case 2: // 4eba / 4efa, Displacement
            {
                const int16_t dispmt = GetI16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
                // Add 2 to current PC, as usual
                const uint32_t branch_addr = static_cast<uint32_t>(
                        node.offset + dispmt + kInstructionSizeStepBytes);
                node.branch_addr = branch_addr;
                node.has_branch_addr = true;
                node.size = kInstructionSizeStepBytes * 2;
                snprintf(node.mnemonic, kMnemonicBufferSize, "%s", mnemonic);
                // FIXME support s.abs_marks option for this instruction
                snprintf(node.arguments, kArgsBufferSize, "%%pc@(%d:w)", dispmt);
                return;
            }
        case 3: // 4ebb / 4efb
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
        case 4: // 4ebc / 4efb
        case 5: // 4ebd / 4efd
        case 6: // 4ebe / 4efe
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
        DisasmNode& node, uint16_t instr, const DataBuffer &code, const Settings &)
{
    Condition condition = static_cast<Condition>((instr >> 8) & 0xf);
    const char *mnemonic = bcc_mnemonic_by_condition(condition);
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

static void disasm_subq(
        DisasmNode& n, uint16_t instr, const DataBuffer &c, const Settings &s, int m, OpSize opsize)
{
    (void) m;
    (void) opsize;
    return disasm_verbatim(n, instr, c, s);
}

static void disasm_addq(
        DisasmNode& n, uint16_t instr, const DataBuffer &c, const Settings &s, int m, OpSize opsize)
{
    (void) m;
    (void) opsize;
    return disasm_verbatim(n, instr, c, s);
}

static void disasm_scc(DisasmNode& n, uint16_t instr, const DataBuffer &c, const Settings &s, int m)
{
    (void) m;
    return disasm_verbatim(n, instr, c, s);
}

static inline const char *dbcc_mnemonic_by_condition(Condition condition)
{
    switch (condition) {
    case Condition::kT:  return "dbt"; // 50xx
    case Condition::kF:  return "dbf"; // 51xx
    case Condition::kHI: return "dbhi"; // 52xx
    case Condition::kLS: return "dbls"; // 53xx
    case Condition::kCC: return "dbcc"; // 54xx
    case Condition::kCS: return "dbcs"; // 55xx
    case Condition::kNE: return "dbne"; // 56xx
    case Condition::kEQ: return "dbeq"; // 57xx
    case Condition::kVC: return "dbvc"; // 58xx
    case Condition::kVS: return "dbvs"; // 59xx
    case Condition::kPL: return "dbpl"; // 5axx
    case Condition::kMI: return "dbmi"; // 5bxx
    case Condition::kGE: return "dbge"; // 5cxx
    case Condition::kLT: return "dblt"; // 5dxx
    case Condition::kGT: return "dbgt"; // 5exx
    case Condition::kLE: return "dble"; // 5fxx
    }
    assert(false);
    return "?";
}

static void disasm_dbcc(DisasmNode& node, uint16_t instr, const DataBuffer &code, const Settings &)
{
    node.size = kInstructionSizeStepBytes * 2;
    Condition condition = static_cast<Condition>((instr >> 8) & 0xf);
    const char *mnemonic = dbcc_mnemonic_by_condition(condition);
    const int regnum = (instr & 7);
    int16_t dispmt = GetI16BE(code.buffer + node.offset + kInstructionSizeStepBytes);
    const uint32_t branch_addr = static_cast<uint32_t>(node.offset + dispmt);
    node.branch_addr = branch_addr;
    node.has_branch_addr = true;
    dispmt += kInstructionSizeStepBytes;
    snprintf(node.mnemonic, kMnemonicBufferSize, "%s", mnemonic);
    const char * const sign = dispmt >= 0 ? "+" : "";
    // FIXME support s.rel_marks option for this instruction
    snprintf(node.arguments, kArgsBufferSize, "%%d%d,.%s%d", regnum, sign, dispmt);
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
    if ((instr >> 8) & 1) {
        return disasm_subq(n, instr, c, s, m, opsize);
    }
    return disasm_addq(n, instr, c, s, m, opsize);
}

static void chunk_mf000_v6000(DisasmNode& n, uint16_t i, const DataBuffer &c, const Settings &s)
{
    return disasm_bra_bsr_bcc(n, i, c, s);
}

static void chunk_mf000_v7000(DisasmNode& n, uint16_t i, const DataBuffer &c, const Settings &s)
{
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

static void chunk_mf000_va000(DisasmNode& n, uint16_t i, const DataBuffer &c, const Settings &s)
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

static void chunk_mf000_vf000(DisasmNode& n, uint16_t i, const DataBuffer &c, const Settings &s)
{
    return disasm_verbatim(n, i, c, s);
}

static void (*disasm_mf000[16])(DisasmNode&, uint16_t, const DataBuffer &, const Settings &s) = {
    chunk_mf000_v0000,
    chunk_mf000_v1000,
    chunk_mf000_v2000,
    chunk_mf000_v3000,
    chunk_mf000_v4000,
    chunk_mf000_v5000,
    chunk_mf000_v6000,
    chunk_mf000_v7000,
    chunk_mf000_v8000,
    chunk_mf000_v9000,
    chunk_mf000_va000,
    chunk_mf000_vb000,
    chunk_mf000_vc000,
    chunk_mf000_vd000,
    chunk_mf000_ve000,
    chunk_mf000_vf000,
};

static void m68k_disasm(DisasmNode& n, uint16_t i, const DataBuffer &c, const Settings &s)
{
    const size_t selector = (i & 0xf000) >> 12;
    assert(selector < 16);
    return (disasm_mf000[selector])(n, i, c, s);
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
