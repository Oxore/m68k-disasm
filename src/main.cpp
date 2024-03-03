/* SPDX-License-Identifier: Unlicense
 */

#include "elf_image.h"
#include "data_buffer.h"
#include "disasm.h"
#include "common.h"

#define OPTPARSE_IMPLEMENTATION
#define OPTPARSE_API static
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wshadow"
#endif
#include "optparse/optparse.h"
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

#include <cassert>
#include <cinttypes>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <climits>

enum class SymbolType: int {
    kNone = 0,
    kFunction,
    kObject,
};

struct Symbol {
    uint32_t address{};
    SymbolType type{};
    const char *name{};
    size_t size{};
};

enum class DisasmMapType {
    kTraced,
    kRaw,
};

class DisasmMap {
    const DisasmMapType _type;
    DisasmNode *_map[kDisasmMapSizeElements]{};
    Symbol *_symtab{};
    size_t _symtab_size{};
    constexpr DisasmNode *findNodeByAddress(uint32_t address) const;
    constexpr size_t findFirstSymbolAtAddress(
            uint32_t address, bool return_last_considered=false) const;
    DisasmNode &insertNode(uint32_t address, NodeType);
    void insertSymbol(uint32_t address, ReferenceType ref_type);
    DisasmNode &insertReferencedBy(
            const uint32_t by_addr,
            const uint32_t ref_addr,
            const NodeType type,
            const ReferenceType ref_type);
    constexpr bool canBeAllocated(const DisasmNode& node) const;
    constexpr size_t symbolsCount() const { return _symtab_size / sizeof *_symtab; }
public:
    constexpr const Symbol *Symtab() const { return _symtab; }
    constexpr size_t SymbolsCount() const { return symbolsCount(); }
    constexpr const char *GetFirstSuitableSymbol(const DisasmNode &, bool is_call) const;
    constexpr bool HasSymbolsInRange(uint32_t at, size_t length) const;
    constexpr const DisasmNode *FindNodeByAddress(uint32_t address) const
    {
        return findNodeByAddress(address);
    };
    void InsertNode(uint32_t address, NodeType type)
    {
        assert(_type == DisasmMapType::kTraced);
        insertNode(address, type);
    }
    bool ApplySymbolsFromElf(const ELF::Image &);
    void Disasm(const DataView &code, const Settings &, size_t from=0, bool nested=false);
    DisasmMap(DisasmMapType type): _type(type) {}
    ~DisasmMap();
};

constexpr DisasmNode *DisasmMap::findNodeByAddress(uint32_t address) const
{
    if (address < kRomSizeBytes)
        return _map[address / kInstructionSizeStepBytes];
    return nullptr;
}

constexpr size_t DisasmMap::findFirstSymbolAtAddress(
        uint32_t address, bool return_last_considered) const
{
    if (_symtab == nullptr || symbolsCount() < 1) {
        return 0;
    }
    // A symbol at index 0 is a special null symbol and it must be skipped.
    size_t start = 1, len = symbolsCount() - start, middle = start, index = 0;
    while (1) {
        if (len == 0) {
            if (return_last_considered && index == 0) {
                index = start;
            }
            break;
        }
        middle = start + len / 2;
        if (_symtab[middle].address >= address) {
            if (_symtab[middle].address == address) {
                index = middle;
            }
            // Look at the span right before the middle one on the next step
            len = middle - start;
        } else {
            // Look at the span right after the middle one on the next step
            len -= middle + 1 - start;
            start = middle + 1;
        }
    }
    return index;
}

static constexpr bool IsWithinRange(uint32_t const value, uint32_t at, size_t length)
{
    return value >= at && value < at + length;
}

constexpr bool DisasmMap::HasSymbolsInRange(
        uint32_t const address, size_t const length) const
{
    size_t index = findFirstSymbolAtAddress(address, true);
    if (index == 0) {
        // The symtab is empty
        return false;
    }
    if (IsWithinRange(_symtab[index].address, address, length)) {
        // The symbol is found right at the address, which is unlikely
        return true;
    }
    if (_symtab[index].address < address) {
        // Maybe the next symbol falls into the range?
        if (index + 1 >= symbolsCount()) {
            // No more symbols after the index
            return false;
        }
        index++;
    } else {
        // Maybe the previous symbol falls into the range? (unlikely at all)
        if (index < 2) {
            // No more symbols before the index
            return false;
        }
        index--;
    }
    if (IsWithinRange(_symtab[index].address, address, length)) {
        return true;
    }
    return false;
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

constexpr bool DisasmMap::canBeAllocated(const DisasmNode& node) const
{
    const auto size = node.size / kInstructionSizeStepBytes;
    const auto *const node_real = findNodeByAddress(node.address);
    for (size_t i = 1; i < size; i++) {
        const auto *const ptr = _map[node.address / kInstructionSizeStepBytes + i];
        if (ptr != nullptr && ptr != node_real) {
            return false;
        }
    }
    return true;
}

static constexpr ReferenceType ReferenceTypeFromRefKindMask1(const RefKindMask ref_kinds)
{
    return (ref_kinds & kRefCallMask)
        ? ReferenceType::kCall
        : (ref_kinds & kRef1ReadMask)
            ? ReferenceType::kRead
            : (ref_kinds & kRef1WriteMask)
                ? ReferenceType::kWrite
                : ReferenceType::kBranch;
}

static constexpr ReferenceType ReferenceTypeFromRefKindMask2(const RefKindMask ref_kinds)
{
    // FIXME: AFAIK it is impossible for a call instruction to have second
    // argument. I can probably drop the first condition, but it needs testing
    return (ref_kinds & kRefCallMask)
        ? ReferenceType::kCall
        : (ref_kinds & kRef2ReadMask)
            ? ReferenceType::kRead
            : (ref_kinds & kRef2WriteMask)
                ? ReferenceType::kWrite
                : ReferenceType::kBranch;
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

static int cmpsym(const void *p1, const void *p2)
{
    const Symbol *sym1 = reinterpret_cast<const Symbol *>(p1);
    const Symbol *sym2 = reinterpret_cast<const Symbol *>(p2);
    if (sym1->address == sym2->address) {
        return strcmp(sym1->name, sym2->name);
    }
    return sym1->address < sym2->address ? -1 : 1;
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
        if (nested && !inside_code_span) {
            return;
        }
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

static size_t RenderRawDataComment(
        char *out, size_t out_sz, uint32_t address, size_t instr_sz, const DataView &code)
{
    size_t overall_sz{};
    for (size_t i = 0; i < instr_sz; i += kInstructionSizeStepBytes)
    {
        overall_sz += Min(
                out_sz - overall_sz,
                snprintf(
                    out + overall_sz,
                    out_sz - overall_sz,
                    " %04x",
                    GetU16BE(code.buffer + address + i)));
    }
    overall_sz += Min(
            out_sz - overall_sz,
            snprintf(out + overall_sz, out_sz - overall_sz, " @%08x", address));
    return overall_sz;
}

static constexpr const char *ReferenceTypeToString(ReferenceType type)
{
    switch (type) {
    case ReferenceType::kUnknown: return "UNKNOWN";
    case ReferenceType::kCall: return "CALL";
    case ReferenceType::kBranch: return "BRANCH";
    case ReferenceType::kRead: return "READ";
    case ReferenceType::kWrite: return "WRITE";
    }
    return "UNKN";
}

static constexpr bool ShouldPrintAsRaw(const Op& op)
{
    if (op.arg1.type == ArgType::kImmediate) {
        if (op.opcode == OpCode::kADD || op.opcode == OpCode::kSUB ||
                op.opcode == OpCode::kAND || op.opcode == OpCode::kOR ||
                op.opcode == OpCode::kEOR || op.opcode == OpCode::kCMP)
        {
            return true;
        }
    }
    return false;
}

static constexpr bool HasCallReference(const DisasmNode &node)
{
    for (const ReferenceNode *ref{node.ref_by}; ref; ref = ref->next) {
        for (size_t i = 0; i < ref->refs_count; i++) {
            if (ref->refs[i].type == ReferenceType::kCall) {
                return true;
            }
        }
    }
    return false;
}

static constexpr size_t GetNodeSizeByAddress(const DisasmMap &disasm_map, const uint32_t address)
{
    const auto *node = disasm_map.FindNodeByAddress(address);
    if (node == nullptr) {
        return kInstructionSizeStepBytes;
    }
    return node->size;
}

static constexpr bool IsLocalLocation(const DisasmMap &disasm_map, const DisasmNode &node)
{
    for (const ReferenceNode *ref{node.ref_by}; ref; ref = ref->next) {
        for (size_t i = 0; i < ref->refs_count; i++) {
            // Check symtab, because we may be crossing a symbol
            const DisasmNode *ref_node = disasm_map.FindNodeByAddress(ref->refs[i].address);
            if (ref_node != nullptr) {
                // We won't cross a symbol at the address if the reference is
                // backwards ('1b') and we will cross a symbol if the reference
                // is forwards ('1f') - that's why we shift the range one
                // instruction forward by adding a size to the address and the
                // length.
                // TODO write tests for it
                uint32_t const address = (node.address < ref_node->address)
                    ? node.address + node.size
                    : ref_node->address + ref_node->size;
                size_t const length = (node.address < ref_node->address)
                    ? ref_node->address + ref_node->size - (node.address + node.size)
                    : node.address + node.size - (ref_node->address + ref_node->size);
                if (disasm_map.HasSymbolsInRange(address, length)) {
                    return false;
                }
            }
            const ReferenceRecord &ref_rec = ref->refs[i];
            if (ref_rec.type == ReferenceType::kCall) {
                // Locals are definitely not made for calls
                return false;
            }
            const bool forward = ref_rec.address < node.address;
            const size_t min_addr = forward ? ref_rec.address : node.address;
            const size_t start = min_addr + GetNodeSizeByAddress(disasm_map, min_addr);
            const size_t max_addr = forward ? node.address : ref_rec.address;
            const size_t end = max_addr + (forward ? 0 : GetNodeSizeByAddress(disasm_map, min_addr));
            for (size_t addr = start; addr < end;) {
                const auto *intermediate_node = disasm_map.FindNodeByAddress(addr);
                if (intermediate_node) {
                    if (intermediate_node->ref_by) {
                        // Another labeled node detected on the jump path, hence
                        // current node's location cannot be considered local
                        return false;
                    }
                    addr += intermediate_node->size;
                } else {
                    addr += kInstructionSizeStepBytes;
                }
            }
        }
    }
    return true;
}

static constexpr const char *StringWihoutFristNChars(const char *str, const size_t n)
{
    for (size_t i = 0, tab = 0; i < n && *str; i++, str++) {
        if (*str == '\t') {
            tab++;
            if (tab == 7) {
                tab = 0;
                str++;
            }
        } else {
            str++;
        }
    }
    return str;
}

constexpr const char *DisasmMap::GetFirstSuitableSymbol(
        const DisasmNode &node, bool is_call) const
{
    const size_t index = findFirstSymbolAtAddress(node.address);
    if (index == 0) {
        return nullptr;
    }
    if (!is_call) {
        return _symtab[index].name;
    }
    for (size_t i = index; i < symbolsCount() && _symtab[i].address == node.address; i++) {
        if (_symtab[i].type == SymbolType::kFunction) {
            return _symtab[i].name;
        }
    }
    return nullptr;
}

struct PendingObjectSize {
    PendingObjectSize *next{};
    uint32_t at{};
    const char *name{};
};

struct PendingObjectSizeList {
    PendingObjectSize *_first{}, *_last{};
    void Add(uint32_t at, const char *name)
    {
        assert(name && *name);
        // Last in first out
        PendingObjectSize *pending = new PendingObjectSize{_first, at, name};
        assert(pending);
        if (_last == nullptr) {
            _last = pending;
        }
        _first = pending;
    }
    const char *TakeNext(uint32_t at)
    {
        for (PendingObjectSize *cur = _first, *prev = nullptr; cur;) {
            // Last in first out
            if (cur->at == at) {
                const char *name = cur->name;
                if (prev) {
                    prev->next = cur->next;
                } else {
                    _first = cur->next;
                }
                if (_last == cur) {
                    _last = prev;
                }
                delete cur;
                return name;
            }
            prev = cur;
            cur = cur->next;
        }
        return nullptr;
    }
    ~PendingObjectSizeList()
    {
        while (_first) {
            auto *cur = _first;
            _first = _first->next;
            delete cur;
        }
        _last = nullptr;
    }
};

static constexpr const char *SymbolTypeToElfTypeString(SymbolType t)
{
    switch (t) {
        case SymbolType::kNone: return nullptr;
        case SymbolType::kFunction: return "function";
        case SymbolType::kObject: return "object";
    }
    return nullptr;
}

static void RenderNodeDisassembly(
        FILE *const output,
        const DisasmMap &disasm_map,
        const DataView &code,
        const Settings &s,
        const DisasmNode &node,
        size_t &symbol_index,
        PendingObjectSizeList &pending_size)
{
    for (const char *name = pending_size.TakeNext(node.address); name;) {
        fprintf(output, "%s.size\t%s,.-%s\n", s.indent, name, name);
        name = pending_size.TakeNext(node.address);
    }
    const size_t symtab_size = disasm_map.SymbolsCount();
    bool have_rendered_label_already = false;
    bool have_rendered_function_label_already = false;
    if (disasm_map.Symtab() != nullptr && symtab_size > 0) {
        for (; symbol_index < symtab_size; symbol_index++) {
            if (disasm_map.Symtab()[symbol_index].address >= node.address) {
                break;
            }
        }
        for (; symbol_index < symtab_size; symbol_index++) {
            const auto &symbol = disasm_map.Symtab()[symbol_index];
            if (symbol.address != node.address) {
                break;
            }
            if (symbol.name != nullptr || *symbol.name == '\0') {
                fprintf(output, "\n%s.globl\t%s\n", s.indent, symbol.name);
                if (symbol.type == SymbolType::kFunction) {
                    have_rendered_function_label_already = true;
                }
                const char *const type = SymbolTypeToElfTypeString(symbol.type);
                if (type) {
                    fprintf(output, "%s.type\t%s, @%s\n", s.indent, symbol.name, type);
                }
                if (symbol.size > 0) {
                    pending_size.Add(node.address + symbol.size, symbol.name);
                }
                fprintf(output, "%s:\n", disasm_map.Symtab()[symbol_index].name);
                have_rendered_label_already = true;
            }
        }
    }
    const bool is_local = s.short_ref_local_labels && IsLocalLocation(disasm_map, node);
    do {
        // Skip generating label or short jump label in-place in case if there
        // are no referrers or we already have a suitable label from ELF's
        // symtab or some other sources, that has been printed in the code
        // section above.
        if (node.ref_by == nullptr) {
            break;
        }
        const bool have_call_reference = HasCallReference(node);
        if (have_call_reference && have_rendered_function_label_already) {
            break;
        }
        if (have_rendered_label_already) {
            break;
        }
        // If we got here it must be that there is no suitable symbol found in
        // the symtab, so it must be generated in-place.
        constexpr auto generated_name_length = sizeof "L00000000";
        char name[generated_name_length + 1] = {0};
        snprintf(name, generated_name_length, "L%08x", node.address);
        if (s.labels && !is_local) {
            const bool export_this_function = s.export_functions && have_call_reference;
            const bool export_this_label = s.export_all_labels ||
                (s.export_labels && node.ref_by && (node.ref_by->refs_count > 1)) ||
                export_this_function;
            if (export_this_label) {
                fprintf(output, "\n%s.globl\t%s\n", s.indent, name);
                if (export_this_function) {
                    fprintf(output, "%s.type\t%s, @function\n", s.indent, name);
                }
            }
        }
        if (s.labels) {
            if (is_local) {
                fprintf(output, "1:%s", StringWihoutFristNChars(s.indent, (sizeof "1:") - 1));
            } else {
                fprintf(output, "%s:\n", name);
            }
        }
    } while (0);
    if (s.xrefs_from && !(is_local && !have_rendered_label_already)) {
        fprintf(output, "| XREFS:\n");
        for (const ReferenceNode *ref{node.ref_by}; ref; ref = ref->next) {
            if (ref->refs_count == 0) {
                continue;
            }
            fprintf(output, "|");
            for (size_t i = 0; i < ref->refs_count; i++) {
                const ReferenceRecord r = ref->refs[i];
                fprintf(output, " %s @%08x", ReferenceTypeToString(r.type), r.address);
            }
            fprintf(output, "\n");
        }
    }
    assert(node.op.opcode != OpCode::kNone);
    if (ShouldPrintAsRaw(node.op)) {
        auto raw = Op::Raw(GetU16BE(code.buffer + node.address));
        raw.FPrint(output, s.indent, s.imm_hex);
        uint32_t i = kInstructionSizeStepBytes;
        for (; i < node.size; i += kInstructionSizeStepBytes) {
            char arg_str[kArgsBufferSize]{};
            const auto arg = Arg::Raw(GetU16BE(code.buffer + node.address + i));
            arg.SNPrint(arg_str, kArgsBufferSize);
            fprintf(output, ", %s", arg_str);
        }
    } else {
        const bool with_ref = node.ref_kinds && s.labels && (s.abs_labels || s.rel_labels);
        const auto *ref1 = (node.ref_kinds & kRef1Mask)
            ? disasm_map.FindNodeByAddress(node.ref1_addr) : nullptr;
        const auto *ref2 = (node.ref_kinds & kRef2Mask)
            ? disasm_map.FindNodeByAddress(node.ref2_addr) : nullptr;
        const uint32_t ref1_addr = (with_ref && ref1) ? ref1->address : 0;
        const uint32_t ref2_addr = (with_ref && ref2) ? ref2->address : 0;
        if (with_ref && (ref1 || ref2)) {
            const RefKindMask ref_kinds =
                (s.abs_labels
                 ? ((ref1 ? (node.ref_kinds & kRef1AbsMask) : 0) |
                     (ref2 ? (node.ref_kinds & kRef2AbsMask) : 0))
                 : 0) |
                (s.rel_labels
                 ? ((ref1 ? (node.ref_kinds & kRef1RelMask) : 0) |
                     (ref2 ? (node.ref_kinds & kRef2RelMask) : 0))
                 : 0) |
                ((s.imm_labels && ref1) ? (node.ref_kinds & kRef1ImmMask) : 0) |
                (node.ref_kinds & (kRefDataMask | kRefPcRelFix2Bytes));
            const bool ref1_is_local = s.short_ref_local_labels &&
                ref1 && IsLocalLocation(disasm_map, *ref1);
            char ref1_label[32]{};
            if (ref1) {
                const bool is_call =
                    ReferenceType::kCall == ReferenceTypeFromRefKindMask1(ref_kinds);
                const char *sym_name = disasm_map.GetFirstSuitableSymbol(*ref1, is_call);
                if (sym_name) {
                    snprintf(ref1_label, (sizeof ref1_label), "%s", sym_name);
                } else if (ref1_is_local) {
                    const char dir = ref1_addr <= node.address ? 'b' : 'f';
                    snprintf(ref1_label, (sizeof ref1_label), "1%c", dir);
                } else {
                    snprintf(ref1_label, (sizeof ref1_label),  "L%08x", ref1_addr);
                }
            }
            const bool ref2_is_local = s.short_ref_local_labels &&
                ref2 && IsLocalLocation(disasm_map, *ref2);
            char ref2_label[32]{};
            if (ref2) {
                const bool is_call =
                    ReferenceType::kCall == ReferenceTypeFromRefKindMask2(ref_kinds);
                const char *sym_name = disasm_map.GetFirstSuitableSymbol(*ref2, is_call);
                if (sym_name) {
                    snprintf(ref2_label, (sizeof ref2_label), "%s", sym_name);
                } else if (ref2_is_local) {
                    const char dir = ref2_addr <= node.address ? 'b' : 'f';
                    snprintf(ref2_label, (sizeof ref2_label), "1%c", dir);
                } else {
                    snprintf(ref2_label, (sizeof ref2_label), "L%08x", ref2_addr);
                }
            }
            node.op.FPrint(
                    output,
                    s.indent,
                    s.imm_hex,
                    ref_kinds,
                    ref1_label,
                    ref2_label,
                    node.address,
                    ref1_addr,
                    ref2_addr);
            const bool ref1_from_imm_ok = ((node.ref_kinds & kRef1ImmMask) ? s.imm_labels : true);
            if (s.xrefs_to && ref1 && !ref1_is_local && ref1_from_imm_ok) {
                fprintf(output, " | XREF1 @%08x", ref1_addr);
            }
            if (s.xrefs_to && ref2 && !ref2_is_local) {
                fprintf(output, " | XREF2 @%08x", ref2_addr);
            }
        } else {
            node.op.FPrint(output, s.indent, s.imm_hex);
        }
    }
    if (s.raw_data_comment) {
        char raw_data_comment[100]{};
        RenderRawDataComment(
                raw_data_comment,
                (sizeof raw_data_comment) - 1,
                node.address,
                node.size, code);
        fprintf(output, " |%s", raw_data_comment);
    }
    fprintf(output, "\n");
}

static void RenderNonCodeSymbols(
        FILE *const output, const DisasmMap &disasm_map, const DataView &code, const Settings &s)
{
    const size_t symtab_size = disasm_map.SymbolsCount();
    for (size_t i = 0; i < symtab_size; i++) {
        const auto &symbol = disasm_map.Symtab()[i];
        if (symbol.address <= code.size) {
            continue;
        }
        fprintf(output, "\n%s.globl\t%s\n", s.indent, symbol.name);
        const char *const type = SymbolTypeToElfTypeString(symbol.type);
        if (type) {
            fprintf(output, "%s.type\t%s, @%s\n", s.indent, symbol.name, type);
        }
        fprintf(output, "%s = 0x%08x\n", symbol.name, symbol.address);
        if (symbol.size) {
            fprintf(output, "%s.size\t%s, 0x%zx\n", s.indent, symbol.name, symbol.size);
        }
    }
}

static void RenderDisassembly(
        FILE *const output, const DisasmMap &disasm_map, const DataView &code, const Settings &s)
{
    // This list is used to track all places where ".size fnname, .-fnname"
    // directives must be put.
    PendingObjectSizeList pending_size{};
    // sym_i starts with 1 because 0 is a special null symbol
    for (size_t i = 0, sym_i = 1; i < code.size;) {
        const DisasmNode raw = DisasmNode{
            /* .type        = */ NodeType::kTracedInstruction,
            /* .address     = */ static_cast<uint32_t>(i),
            /* .size        = */ 2,
            /* .ref_kinds   = */ 0,
            /* .ref1_addr   = */ 0,
            /* .ref2_addr   = */ 0,
            /* .ref_by      = */ nullptr,
            /* .last_ref_by = */ nullptr,
            /* .op          = */ Op::Raw(GetU16BE(code.buffer + i)),
        };
        const DisasmNode *node = disasm_map.FindNodeByAddress(i);
        if (node == nullptr) {
            node = &raw;
        }
        RenderNodeDisassembly(output, disasm_map, code, s, *node, sym_i, pending_size);
        i += node->size;
    }
    RenderNonCodeSymbols(output, disasm_map, code, s);
}

static void ParseTraceData(DisasmMap &disasm_map, const DataView &trace_data)
{
    // FIXME make a full blown parser with various radixes support and different
    // trace types support
    bool parse = true;
    for (size_t i = 0; i < trace_data.size; i++) {
        if (trace_data.buffer[i] == '\n' || trace_data.buffer[i] == '\r') {
            parse = true;
        } else if (parse) {
            errno = 0;
            const char *startptr = reinterpret_cast<const char *>(trace_data.buffer + i);
            char *endptr = nullptr;
            const long address = strtol(startptr, &endptr, 10);
            if ((address == LONG_MAX || address == LONG_MIN) && errno == ERANGE) {
                // Parsing error, just skip
            } else if (startptr == endptr) {
                // Parsing error, just skip
            } else if (address % 2) {
                fprintf(stderr, "Error: Uneven PC values are not supported (got PC=0x%08lx), exiting\n", address);
                exit(1);
            } else if (static_cast<unsigned long>(address) > kRomSizeBytes) {
                fprintf(stderr, "Error: PC values > 4MiB are not supported (got PC=0x%08lx), exiting\n", address);
                exit(1);
            } else {
                // Valid value
                disasm_map.InsertNode(address, NodeType::kTracedInstruction);
            }
            if (startptr != endptr) {
                i += endptr - startptr - 1;
            }
            parse = false;
        }
    }
}

static size_t ReadFromStream(DataBuffer &db, FILE *stream)
{
    assert(db.buffer && db.buffer_size >= db.kInitialSize);
    while (1) {
        const size_t read_size = db.buffer_size - db.occupied_size;
        const size_t fread_ret = fread(
                db.buffer + db.occupied_size, sizeof(*db.buffer), read_size, stream);
        db.occupied_size += fread_ret;
        if (fread_ret >= db.buffer_size) {
            assert(fread_ret == db.buffer_size);
            db.Expand(db.buffer_size * 2);
        } else {
            const int err = errno;
            if (feof(stream)) {
                break;
            } else if (ferror(stream)) {
                fprintf(stderr, "ReadFromStream: fread(%zu): Error (%d): \"%s\"\n", read_size, err, strerror(err));
                return EXIT_FAILURE;
            } else if (db.buffer_size == db.occupied_size) {
                db.Expand(db.buffer_size * 2);
            } else {
                assert(false);
            }
        }
    }
    return db.occupied_size;
}

static DisasmMap *NewDisasmMap(FILE *trace_stream)
{
    if (trace_stream == nullptr) {
        DisasmMap *disasm_map = new DisasmMap{DisasmMapType::kRaw};
        assert(disasm_map);
        return disasm_map;
    }
    // Read trace file into buffer
    DataBuffer trace_data{};
    const size_t trace_size = ReadFromStream(trace_data, trace_stream);
    if (trace_size == 0) {
        fprintf(stderr, "ReadFromStream(trace_data, trace_stream): Error: No data has been read\n");
        return nullptr;
    }
    // Parse trace file into map
    DisasmMap *disasm_map = new DisasmMap{DisasmMapType::kTraced};
    assert(disasm_map != nullptr);
    ParseTraceData(*disasm_map, trace_data.View());
    return disasm_map;
}

static int M68kDisasm(
        FILE *input_stream, FILE *output_stream, FILE *trace_stream, const Settings &s)
{
    // Read input file into buffer
    DataBuffer input{};
    const size_t input_size = ReadFromStream(input, input_stream);
    if (input_size == 0) {
        fprintf(stderr, "ReadFromStream(input, input_stream): Error: No data has been read\n");
        return EXIT_FAILURE;
    }
    const ELF::Image elf(static_cast<DataBuffer&&>(input));
    if (s.bfd == BFDTarget::kELF && !elf.IsValid()) {
        fprintf(stderr, "Error: ELF image is not valid: %s\n", elf.Error());
        return EXIT_FAILURE;
    }
    const bool from_elf = s.bfd == BFDTarget::kELF || (s.bfd == BFDTarget::kAuto && elf.IsValid());
    const DataView code(from_elf ? elf.ProgramView() : elf.Data().View());
    assert(code.buffer != nullptr);
    assert(code.size != 0);
    // It is not worth it to check this somewhere while disassembling or
    // emitting. Odd size is just not supported.
    if (code.size % 2) {
        fprintf(stderr, "M68kDisasm: Error: code blob must be of even size\n");
        return EXIT_FAILURE;
    }
    auto *disasm_map = NewDisasmMap(trace_stream);
    if (disasm_map == nullptr) {
        return EXIT_FAILURE;
    }
    if (from_elf && s.symbols) {
        if (false == disasm_map->ApplySymbolsFromElf(elf)) {
            return EXIT_FAILURE;
        }
    }
    // Disasm into output map
    disasm_map->Disasm(code, s);
    // Print output into output_stream
    RenderDisassembly(output_stream, *disasm_map, code, s);
    delete disasm_map;
    return EXIT_SUCCESS;
}

static bool FeatureStringHasPrefixNo(const char *feature)
{
    assert(feature);
    // There is also implicit, embedded and free check for null terminator
    if (feature[0] == 'n' && feature[1] == 'o' && feature[2] == '-') {
        return true;
    }
    return false;
}

static bool ApplyFeature(Settings& s, const char *feature_arg)
{
    struct {
        bool Settings::* setting;
        const char* feature_name;
    } const features[]{
        { &Settings::raw_data_comment, "rdc" },
        { &Settings::labels, "labels" },
        { &Settings::rel_labels, "rel-labels" },
        { &Settings::abs_labels, "abs-labels" },
        { &Settings::imm_labels, "imm-labels" },
        { &Settings::short_ref_local_labels, "short-ref-local-labels" },
        { &Settings::export_labels, "export-labels" },
        { &Settings::export_all_labels, "export-all-labels" },
        { &Settings::export_functions, "export-functions" },
        { &Settings::xrefs_from, "xrefs-from" },
        { &Settings::xrefs_to, "xrefs-to" },
        { &Settings::imm_hex, "imm-hex" },
        { &Settings::follow_jumps, "follow-jumps" },
        { &Settings::walk, "walk" },
        { &Settings::symbols, "symbols" },
    };
    constexpr size_t sizeof_no_prefix = (sizeof "no-") - 1;
    const bool disable = FeatureStringHasPrefixNo(feature_arg);
    const char *const feature = feature_arg + (disable ? sizeof_no_prefix : 0);
    for (size_t i = 0; i < (sizeof features) / (sizeof *features); i++) {
        if (0 == strcmp(feature, features[i].feature_name)) {
            s.*(features[i].setting) = !disable;
            return true;
        }
    }
    return false;
}

static void PrintUsage(FILE *s, const char *argv0)
{
    // Please, keep all lines in 80 columns range when printed.
    fprintf(s,
    "Usage: %s [options] <input-file-name>\n"
    "Options:\n"
    "  -h, --help,           Show this message.\n"
    "  -o, --output,         Where to write disassembly to (stdout if not set)\n"
    "  -t, --pc-trace,       File containing PC trace\n"
    "      --indent,         Specify instruction indentation, e.g. \"\t\",\n"
    "                        Single tab is used by default.\n"
    "  -f, --feature=[no-]<feature>\n"
    "                        Enable or disable (with \"no-\" prefix) a feature.\n"
    "                        Available features described below under the\n"
    "                        \"Feature flags\" section.\n"
    "  -b, --bfd-target=bfdname\n"
    "                        Specify target object format as `bfdname`. Will attempt\n"
    "                        to detect automatically if not set. Only `auto,\n"
    "                        `binary` and `elf` are currently supported.\n"
    "  <input_file_name>     Binary or elf file with the machine code to disassemble\n"
    "Feature flags:\n"
    "  rdc                   Print raw data comment.\n"
    "  labels                Print labels above all places that have jumps from\n"
    "                        somewhere.\n"
    "  rel-labels            Use label instead of number on relative branch or call.\n"
    "  abs-labels            Use label instead of number on absolute branch or call.\n"
    "  imm-labels            Use label instead of number when immediate value moved\n"
    "                        to address register.\n"
    "  short-ref-local-labels\n"
    "                        Use local labels (numbers) for short jumps or loops.\n"
    "                        Jump is considered short when it does not cross other\n"
    "                        labels and has no calls.\n"
    "  export-labels         Add `.globl` preamble to labels referenced two or more\n"
    "                        times.\n"
    "  export-all-labels     Add `.globl` preamble to all labels.\n"
    "  export-functions      Add `.globl` and `.type @funciton` preamble to a label\n"
    "                        referenced as a call.\n"
    "  xrefs-from            Print xrefs comments above all places that have xrefs.\n"
    "  xrefs-to              Print xrefs comments after all branch instructions.\n"
    "  imm-hex               Print all immediate values as hexadecimal numbers.\n"
    "  follow-jumps          Follow jumps to statically known locations.\n"
    "  walk                  Try best to detect further instructions following known\n"
    "                        traced locations without overcommitting.\n"
    "  symbols               Extract and apply symbols from input file if available.\n"
    "                        ELF symbols only are currently supported.\n"
    , argv0);
}

int main(int, char* argv[])
{
    struct optparse_long longopts[] = {
        {"help", 'h', OPTPARSE_NONE},
        {"output", 'o', OPTPARSE_REQUIRED},
        {"pc-trace", 't', OPTPARSE_REQUIRED},
        {"feature", 'f', OPTPARSE_REQUIRED},
        {"bfd-target", 'b', OPTPARSE_REQUIRED},
        {"indent", 80, OPTPARSE_REQUIRED},
        {},
    };
    const char *trace_file_name = nullptr;
    const char *output_file_name = nullptr;
    const char *input_file_name = nullptr;
    Settings s{};
    struct optparse options;
    optparse_init(&options, argv);
    // Parse opts
    int option;
    while ((option = optparse_long(&options, longopts, NULL)) != -1) {
        switch (option) {
        case 'h':
            PrintUsage(stdout, argv[0]);
            return EXIT_SUCCESS;
            break;
        case 'o':
            output_file_name = options.optarg;
            break;
        case 't':
            trace_file_name = options.optarg;
            break;
        case 'f':
            if (!ApplyFeature(s, options.optarg)) {
                fprintf(stderr, "main: Error: Unknown feature \"%s\", exiting\n", options.optarg);
                return EXIT_FAILURE;
            }
            break;
        case 'b':
            {
                const auto *bfd_str = options.optarg;
                if (0 == strcmp(bfd_str, "auto")) {
                    s.bfd = BFDTarget::kAuto;
                } else if (0 == strcmp(bfd_str, "binary")) {
                    s.bfd = BFDTarget::kBinary;
                } else if (0 == strcmp(bfd_str, "elf")) {
                    s.bfd = BFDTarget::kELF;
                } else {
                    fprintf(
                            stderr,
                            "Unknown BFD target specified: \"%s\". "
                            "Refer to usage below to find correct BFD values.\n",
                            bfd_str);
                    PrintUsage(stderr, argv[0]);
                    return EXIT_FAILURE;
                }
            }
            break;
        case 80:
            s.indent = options.optarg;
            break;
        case '?':
            fprintf(stderr, "main: optparse_long: Error: \"%s\"\n", options.errmsg);
            return EXIT_FAILURE;
        }
    }
    // Parse input file name
    char *arg;
    while ((arg = optparse_arg(&options))) {
        if (input_file_name == nullptr) {
            input_file_name = arg;
        } else {
            fprintf(stderr, "error: too many free arguments provided\n");
            return EXIT_FAILURE;
        }
    }
    // Open the files
    FILE *input_stream = nullptr;
    FILE *output_stream = stdout;
    FILE *trace_stream = nullptr;
    if (input_file_name) {
        if (0 == strcmp(input_file_name, "-")) {
            input_stream = stdin;
        } else {
            input_stream = fopen(input_file_name, "r");
        }
        if (input_stream == nullptr) {
            const int err = errno;
            fprintf(stderr, "main: fopen(\"%s\", \"r\"): Error (%d): \"%s\"\n", input_file_name, err, strerror(err));
            return EXIT_FAILURE;
        }
    } else {
        fprintf(stderr, "main: Error: no input file name specified, see usage below.\n");
        PrintUsage(stderr, argv[0]);
        return EXIT_FAILURE;
    }
    if (output_file_name) {
        output_stream = fopen(output_file_name, "w");
        if (output_stream == nullptr) {
            const int err = errno;
            fprintf(stderr, "main: fopen(\"%s\", \"w\"): Error (%d): \"%s\"\n", output_file_name, err, strerror(err));
            fclose(input_stream);
            return EXIT_FAILURE;
        }
    }
    if (trace_file_name) {
        if (0 == strcmp(trace_file_name, "-")) {
            if (input_stream == stdin) {
                fprintf(stderr, "error: trace stream and input stream cannot be both stdin\n");
                return EXIT_FAILURE;
            }
            trace_stream = stdin;
        } else {
            trace_stream = fopen(trace_file_name, "r");
        }
        if (trace_stream == nullptr) {
            const int err = errno;
            fprintf(stderr, "main: fopen(\"%s\", \"r\"): Error (%d): \"%s\"\n", trace_file_name, err, strerror(err));
            fclose(input_stream);
            fclose(output_stream);
            return EXIT_FAILURE;
        }
    }
    // Run the program
    const int ret = M68kDisasm(input_stream, output_stream, trace_stream, s);
    if (trace_stream != nullptr) {
        fclose(trace_stream);
    }
    fclose(output_stream);
    fclose(input_stream);
    return ret;
}
