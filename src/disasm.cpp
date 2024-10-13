/* SPDX-License-Identifier: Unlicense
 */

#include "disasm.h"
#include "m68k.h"

#include <cassert>
#include <cstring>
#include <cerrno>

void DisasmNode::AddReferencedBy(const uint32_t address_from, const ReferenceType ref_type)
{
    ReferenceNode *node{};
    if (this->last_ref_by) {
        node = this->last_ref_by;
    } else {
        node = new ReferenceNode{};
        assert(node);
        this->ref_by = this->last_ref_by = node;
    }
    node->refs[node->refs_count] = ReferenceRecord{ref_type, address_from};
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

static constexpr uint32_t AlignInstructionAddress(const uint32_t address)
{
    return address & ~1UL;
}

DisasmNode &DisasmMap::insertNode(uint32_t address, NodeType type)
{
    auto *node = findNodeByAddress(address);
    if (node) {
        // Instruction nodes take precedence over data nodes. If a node that
        // was previously accessed only as data now turns out to be an
        // instruction, then it must become an instruction node.
        if (IsInstruction(type) && !IsInstruction(node->type)) {
            *const_cast<NodeType*>(&node->type) = type;
            // Make sure it is OpCode::kNone so it will be properly disassembled
            node->op = Op{};
        }
        return *node;
    }
    node = new DisasmNode(DisasmNode{type, AlignInstructionAddress(address)});
    assert(node);
    _map[address / kInstructionSizeStepBytes] = node;
    return *node;
}

DisasmNode &DisasmMap::insertReferencedBy(
        const uint32_t by_addr,
        const uint32_t ref_addr,
        const NodeType type,
        const ReferenceType ref_type)
{
    auto &ref_node = insertNode(ref_addr, type);
    ref_node.AddReferencedBy(by_addr, ref_type);
    return ref_node;
}

void DisasmMap::InsertNode(uint32_t address, NodeType type)
{
    assert(_type == DisasmMapType::kTraced);
    insertNode(address, type);
}

constexpr SymbolType SymbolTypeFromElf32SymbolType(const ELF::Symbol32Type &t)
{
    if (t == ELF::Symbol32Type::kObject) {
        return SymbolType::kObject;
    }
    if (t == ELF::Symbol32Type::kFunc) {
        return SymbolType::kFunction;
    }
    return SymbolType::kNone;
}

static int cmpsym(const void *p1, const void *p2)
{
    const Symbol *sym1 = reinterpret_cast<const Symbol *>(p1);
    const Symbol *sym2 = reinterpret_cast<const Symbol *>(p2);
    if (sym1->address == sym2->address) {
        return strcmp(sym1->name, sym2->name);
    }
    return sym1->address < sym2->address ? -1 : 1;
}

bool DisasmMap::ApplySymbolsFromElf(const ELF::Image &elf)
{
    const ELF::SectionHeader32 symtab = elf.GetSectionHeaderByName(".symtab");
    if (!symtab.IsValid()) {
        fprintf(stderr, "Warning: \".symtab\" is invalid, skipping symbols\n");
        return true;
    }
    FILE *symtab_stream = open_memstream(reinterpret_cast<char**>(&_symtab), &_symtab_size);
    if (symtab_stream == nullptr) {
        const int err = errno;
        fprintf(stderr,
                "open_memstream() for symtab failed: Error (%d): \"%s\"\n",
                err, strerror(err));
        return false;
    }
    const Symbol null_symbol{};
    if (null_symbol.name != nullptr && *null_symbol.name != '\0') {
        const size_t ret = fwrite(
                &null_symbol, sizeof null_symbol, 1, symtab_stream);
        (void) ret;
        assert(ret == 1);
    }
    const size_t nentries = symtab.size/symtab.entsize;
    for (size_t i = 0; i < nentries; i++) {
        const ELF::Symbol32 elfsym = elf.GetSymbolByIndex(i);
        const bool has_proper_type = (elfsym.type() == ELF::Symbol32Type::kNoType) ||
            (elfsym.type() == ELF::Symbol32Type::kObject) ||
            (elfsym.type() == ELF::Symbol32Type::kFunc);
        if (has_proper_type) {
            // XXX: Is it possible that it may have binding other than
            // Symbol32Bind::kGlobal when it is kFunc?
            // XXX: Yes, it is possible. It may be kLocal or kWeak for sure.
            const auto type = SymbolTypeFromElf32SymbolType(elfsym.type());
            const auto symbol = Symbol{elfsym.value, type, elfsym.name, elfsym.size};
            if (symbol.name != nullptr && *symbol.name != '\0') {
                const size_t ret = fwrite(&symbol, sizeof symbol, 1, symtab_stream);
                (void) ret;
                assert(ret == 1);
            }
        }
    }
    // No more symbols are going to be added further, so it may be closed now.
    fclose(symtab_stream);
    // The RenderNodeDisassembly() function expects the symbol table to be
    // sorted.
    qsort(_symtab, symbolsCount(), sizeof *_symtab, cmpsym);
    return true;
}

static constexpr bool IsNextLikelyAnInstruction(const Op &op)
{
    return (op.opcode != OpCode::kNone &&
            op.opcode != OpCode::kRaw &&
            !IsBRA(op) &&
            op.opcode != OpCode::kJMP &&
            op.opcode != OpCode::kRTS &&
            op.opcode != OpCode::kRTE &&
            op.opcode != OpCode::kSTOP);
}

void DisasmMap::Disasm(
        const DataView &code, const Settings &s, size_t at, bool nested)
{
    // Some of logic of this function is covered by integration tests in
    // `test_walk_and_follow_jumps.bash`.
    bool inside_code_span = nested;
    while (at < Min(kRomSizeBytes, code.size)) {
        DisasmNode *node;
        if (_type == DisasmMapType::kTraced) {
            node = _map[at / kInstructionSizeStepBytes];
            if (!node) {
                if (inside_code_span) {
                    node = &insertNode(at, NodeType::kTracedInstruction);
                } else {
                    at += kInstructionSizeStepBytes;
                    continue;
                }
            }
        } else {
            node = &insertNode(at, NodeType::kTracedInstruction);
        }
        if (node->op.opcode == OpCode::kNone || inside_code_span) {
            const auto size = node->Disasm(code);
            assert(size >= kInstructionSizeStepBytes);
            if (canBeAllocated(*node)) {
                // Spread across the size
                for (size_t o = kInstructionSizeStepBytes; o < size; o++) {
                    _map[(node->address + o) / kInstructionSizeStepBytes] = node;
                }
            } else {
                node->DisasmAsRaw(code);
            }
        }
        inside_code_span = s.walk && IsNextLikelyAnInstruction(node->op);
        at += node->size;
        // NOTE: There is not much information about a reference passed further,
        // so just don't add a reference of immediate if s.imm_labels is false
        // enabled.
        const bool has_ref1 = (node->ref_kinds & kRef1ImmMask)
            ? s.imm_labels
            : (node->ref_kinds & kRef1Mask);
        const bool has_code_ref1 = node->ref1_addr < code.size && has_ref1;
        if (has_code_ref1) {
            const NodeType type = (node->ref_kinds & (kRef1ReadMask | kRef1WriteMask))
                ? NodeType::kData : NodeType::kRefInstruction;
            const auto ref_type = ReferenceTypeFromRefKindMask1(node->ref_kinds);
            auto &ref_node = insertReferencedBy(
                    node->address, node->ref1_addr, type, ref_type);
            if (ref_node.op.opcode == OpCode::kNone) {
                if (s.follow_jumps) {
                    Disasm(code, s, ref_node.address, true);
                } else {
                    ref_node.DisasmAsRaw(code);
                }
            }
        }
        const bool has_ref2 = (node->ref_kinds & kRef2Mask);
        const bool has_code_ref2 = (has_ref2 && node->ref2_addr < code.size);
        if (has_code_ref2) {
            const NodeType type = (node->ref_kinds & (kRef2ReadMask | kRef2WriteMask))
                ? NodeType::kData : NodeType::kRefInstruction;
            const auto ref_type = ReferenceTypeFromRefKindMask2(node->ref_kinds);
            auto &ref_node = insertReferencedBy(
                    node->address, node->ref2_addr, type, ref_type);
            if (ref_node.op.opcode == OpCode::kNone) {
                if (s.follow_jumps) {
                    Disasm(code, s, ref_node.address, true);
                } else {
                    ref_node.DisasmAsRaw(code);
                }
            }
        }
        if (nested && !inside_code_span) {
            return;
        }
    }
}

DisasmMap::~DisasmMap()
{
    for (size_t i = 0; i < kDisasmMapSizeElements; i++) {
        auto *const node = _map[i];
        if (!node) {
            continue;
        }
        const auto size = node->size / kInstructionSizeStepBytes;
        for (size_t o = 0; o < size; o++) {
            assert(_map[i + o] == node);
            _map[i + o] = nullptr;
        }
        delete node;
        i += size - 1;
    }
    if (_symtab != nullptr) {
        free(_symtab);
    }
}
