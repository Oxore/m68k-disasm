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
#include <sys/stat.h>

static size_t EmitRawDataComment(
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
    if (op.arg1.is_invalid || op.arg2.is_invalid) {
        return true;
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
    constexpr bool IsEmpty() const { return _first == nullptr; }
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

static FILE *OpenNewPartFile(const char *dir, uint32_t address)
{
    size_t file_name_size{};
    char *file_name{};
    FILE *const file_name_stream = open_memstream(&file_name, &file_name_size);
    if (file_name_stream == nullptr) {
        const int err = errno;
        fprintf(stderr,
                "open_memstream() for symtab failed: Error (%d): \"%s\"\n",
                err, strerror(err));
        return nullptr;
    }
    fprintf(file_name_stream, "%s/%06" PRIx32 ".S", dir, address);
    fclose(file_name_stream);
    FILE *output = fopen(file_name, "w");
    if (output == nullptr) {
        const int err = errno;
        fprintf(stderr, "OpenNewPartFile: fopen(\"%s\", \"w\"): Error (%d): \"%s\"\n", file_name, err, strerror(err));
        free(file_name);
        return nullptr;;
    }
    free(file_name);
    return output;
}

static constexpr const char *SymbolTypeToElfTypeString(SymbolType t)
{
    switch (t) {
    case SymbolType::kNone: return nullptr;
    case SymbolType::kFunction: return "function";
    case SymbolType::kObject: return "object";
    }
    return nullptr;
}

static constexpr unsigned SymbolTypeToSierraTypeNumber(SymbolType t)
{
    switch (t) {
    case SymbolType::kNone: return 0;
    case SymbolType::kFunction: return 0x20;
    case SymbolType::kObject: return 0x30;
    }
    return 0;
}

static void EmitSymbolMetadata(FILE *out, const Symbol &symbol, const Settings &s)
{
    switch (s.target_asm) {
    case TargetAssembler::kGnuAs:
        {
            const char *const type = SymbolTypeToElfTypeString(symbol.type);
            if (type) {
                fprintf(out, "%s.type\t%s, @%s\n", s.indent, symbol.name, type);
            }
        }
        return;
    case TargetAssembler::kSierraAsm68:
        {
            // TODO figure out what is 17-th bit
            const unsigned type = 0x10000 | SymbolTypeToSierraTypeNumber(symbol.type);
            // TODO figure out how to determine storage class
            const int storage_class = 2;
            fprintf(out, "%s.def\t%s\\\t.val\t%s\\\t.scl\t%d\\\t.type\t0x%x\\\t.endef\n",
                    s.indent, symbol.name, symbol.name, storage_class, type);
        }
        return;
    }
    assert(0);
}

static void EmitSymbolSize(FILE *out, const char *sym_name, const Settings &s)
{
    switch (s.target_asm) {
    case TargetAssembler::kGnuAs:
        fprintf(out, "%s.size\t%s,.-%s\n", s.indent, sym_name, sym_name);
        return;
    case TargetAssembler::kSierraAsm68:
        fprintf(out, "%s.def\t%s\\\t.val\t.\\\t.scl\t-1\\\t.endef\n", s.indent, sym_name);
        return;
    }
    assert(0);
}

struct EmitContext {
    FILE *output{};
    // symbol_index starts with 1 because 0 is a special null symbol
    size_t symbol_index{1};
    // This list is used to track all places where ".size fnname, .-fnname"
    // directives must be put.
    PendingObjectSizeList pending_size{};
    size_t last_rendered_symbol_addr{SIZE_MAX};
    size_t last_rendered_function_symbol_addr{SIZE_MAX};
};

static bool EmitNodeDisassembly(
        const EmitContext &ctx,
        const DisasmMap &disasm_map,
        const DataView &code,
        const Settings &s,
        const DisasmNode &node,
        const bool traced)
{
    FILE *const output = ctx.output;
    const bool have_symbol = ctx.last_rendered_symbol_addr == node.address;
    const bool is_local = s.short_ref_local_labels && IsLocalLocation(disasm_map, node);
    do {
        // Skip generating label or short jump label in-place in case if there
        // are no referrers or we already have a suitable label from ELF's
        // symtab or some other sources, that has been printed in
        // EmitDisassembly function.
        if (node.ref_by == nullptr) {
            break;
        }
        const bool have_call_reference = HasCallReference(node);
        if (have_call_reference && ctx.last_rendered_function_symbol_addr == node.address) {
            break;
        }
        if (have_symbol) {
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
                    const auto symbol = Symbol{0, SymbolType::kFunction, name, 0};
                    EmitSymbolMetadata(output, symbol, s);
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
    if (s.xrefs_from && (have_symbol || !is_local)) {
        if (s.target_asm == TargetAssembler::kGnuAs) {
            fprintf(output, "| XREFS:\n");
        } else {
            fprintf(output, "; XREFS:\n");
        }
        for (const ReferenceNode *ref{node.ref_by}; ref; ref = ref->next) {
            if (ref->refs_count == 0) {
                continue;
            }
            if (s.target_asm == TargetAssembler::kGnuAs) {
                fprintf(output, "|");
            } else {
                fprintf(output, ";");
            }
            for (size_t i = 0; i < ref->refs_count; i++) {
                const ReferenceRecord r = ref->refs[i];
                fprintf(output, " %s @%08x", ReferenceTypeToString(r.type), r.address);
            }
            fprintf(output, "\n");
        }
    }
    assert(node.op.opcode != OpCode::kNone);
    if (ShouldPrintAsRaw(node.op)) {
        FPrintOp(output, Op::Raw(GetU16BE(code.buffer + node.address)), s);
        uint32_t i = kInstructionSizeStepBytes;
        for (; i < node.size; i += kInstructionSizeStepBytes) {
            char arg_str[kArgsBufferSize]{};
            const auto arg = Arg::Raw(GetU16BE(code.buffer + node.address + i));
            SNPrintArgRaw(arg_str, kArgsBufferSize, arg);
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
            FPrintOp(
                    output,
                    node.op,
                    s,
                    ref_kinds,
                    ref1_label,
                    ref2_label,
                    node.address,
                    ref1_addr,
                    ref2_addr);
            const bool ref1_from_imm_ok = ((node.ref_kinds & kRef1ImmMask) ? s.imm_labels : true);
            if (s.xrefs_to && ref1 && !ref1_is_local && ref1_from_imm_ok) {
                if (s.target_asm == TargetAssembler::kGnuAs) {
                    fprintf(output, " | XREF1 @%08x", ref1_addr);
                } else {
                    fprintf(output, " ; XREF1 @%08x", ref1_addr);
                }
            }
            if (s.xrefs_to && ref2 && !ref2_is_local) {
                if (s.target_asm == TargetAssembler::kGnuAs) {
                    fprintf(output, " | XREF2 @%08x", ref2_addr);
                } else {
                    fprintf(output, " ; XREF2 @%08x", ref2_addr);
                }
            }
        } else {
            FPrintOp(output, node.op, s);
        }
    }
    if (s.raw_data_comment && (traced || s.raw_data_comment_all)) {
        char raw_data_comment[100]{};
        EmitRawDataComment(
                raw_data_comment,
                (sizeof raw_data_comment) - 1,
                node.address,
                node.size, code);
        if (s.target_asm == TargetAssembler::kGnuAs) {
            fprintf(output, " |%s", raw_data_comment);
        } else {
            fprintf(output, " ;%s", raw_data_comment);
        }
    }
    fprintf(output, "\n");
    return true;
}

static void EmitNonCodeSymbols(
        FILE *const output, const DisasmMap &disasm_map, const DataView &code, const Settings &s)
{
    const size_t symtab_size = disasm_map.SymbolsCount();
    for (size_t i = 0; i < symtab_size; i++) {
        const auto &symbol = disasm_map.Symtab()[i];
        if (symbol.address <= code.size) {
            continue;
        }
        fprintf(output, "\n%s.globl\t%s\n", s.indent, symbol.name);
        EmitSymbolMetadata(output, symbol, s);
        fprintf(output, "%s = 0x%08x\n", symbol.name, symbol.address);
        EmitSymbolSize(output, symbol.name, s);
    }
}

constexpr const char *kSplitMarker =
        "\n| ---------------- >8 split_marker %08" PRIx32 " 8< ----------------\n";

static FILE *SplitIfRequired(
        const EmitContext &ctx,
        const DisasmMap &disasm_map,
        const Settings &s,
        const DisasmNode &node)
{
    // Not aligned - definitely should not split here
    if (node.address % s.split.alignment != 0) {
        return ctx.output;
    }
    // Won't split inside an object of known size
    if (false == ctx.pending_size.IsEmpty()) {
        return ctx.output;
    }
    // If there any suitable symbol, we should split
    for (size_t i = 0; i < disasm_map.SymbolsCount(); i++) {
        const auto &symbol = disasm_map.Symtab()[i];
        if (symbol.address != node.address) {
            break;
        }
        const bool should_split = s.split.type == SplitPointType::kLabel ||
             (s.split.type == SplitPointType::kFunction &&
              symbol.type == SymbolType::kFunction);
        if (should_split) {
            if (s.output_dir_path) {
                return OpenNewPartFile(s.output_dir_path, node.address);
            } else {
                fprintf(ctx.output, kSplitMarker, node.address);
                return ctx.output;
            }
        }
    }
    // No labels allowed or no references
    if (s.labels == false || node.ref_by == nullptr) {
        return ctx.output;
    }
    // If there any suitable label, we should split
    if (s.split.type == SplitPointType::kFunction && HasCallReference(node)) {
        if (s.output_dir_path) {
            return OpenNewPartFile(s.output_dir_path, node.address);
        } else {
            fprintf(ctx.output, kSplitMarker, node.address);
            return ctx.output;
        }
    }
    const bool is_local = s.short_ref_local_labels && IsLocalLocation(disasm_map, node);
    if (s.split.type == SplitPointType::kLabel && !is_local) {
        if (s.output_dir_path) {
            return OpenNewPartFile(s.output_dir_path, node.address);
        } else {
            fprintf(ctx.output, kSplitMarker, node.address);
            return ctx.output;
        }
    }
    return ctx.output;
}

static bool EmitDisassembly(
        FILE *const out, const DisasmMap &disasm_map, const DataView &code, const Settings &s)
{
    EmitContext ctx{out};
    if (s.split.alignment && s.output_dir_path) {
        FILE *const output = OpenNewPartFile(s.output_dir_path, 0);
        if (output == nullptr) {
            return false;
        }
        ctx.output = output;
    }
    for (size_t address = 0; address < code.size;) {
        const DisasmNode raw = DisasmNode{
            /* .type        = */ NodeType::kTracedInstruction,
            /* .address     = */ static_cast<uint32_t>(address),
            /* .size        = */ 2,
            /* .ref_kinds   = */ 0,
            /* .ref1_addr   = */ 0,
            /* .ref2_addr   = */ 0,
            /* .ref_by      = */ nullptr,
            /* .last_ref_by = */ nullptr,
            /* .op          = */ Op::Raw(GetU16BE(code.buffer + address)),
        };
        const DisasmNode *node = disasm_map.FindNodeByAddress(address);
        const bool traced = node;
        if (node == nullptr) {
            node = &raw;
        }
        const size_t symtab_size = disasm_map.SymbolsCount();
        if (disasm_map.Symtab() != nullptr && symtab_size > 0) {
            for (const char *name = ctx.pending_size.TakeNext(address); name;) {
                EmitSymbolSize(ctx.output, name, s);
                name = ctx.pending_size.TakeNext(address);
            }
            for (; ctx.symbol_index < symtab_size; ctx.symbol_index++) {
                if (disasm_map.Symtab()[ctx.symbol_index].address >= address) {
                    break;
                }
            }
        }
        if (s.split.alignment) {
            FILE *const output = SplitIfRequired(ctx, disasm_map, s, *node);
            if (output == nullptr) {
                return false;
            }
            if (output != ctx.output) {
                fclose(ctx.output);
                ctx.output = output;
            }
        }
        if (disasm_map.Symtab() != nullptr && symtab_size > 0) {
            for (size_t i = ctx.symbol_index; i < symtab_size; i++) {
                const auto &symbol = disasm_map.Symtab()[i];
                if (symbol.address != address) {
                    break;
                }
                if (symbol.name != nullptr || *symbol.name == '\0') {
                    fprintf(ctx.output, "\n%s.globl\t%s\n", s.indent, symbol.name);
                    if (symbol.type == SymbolType::kFunction) {
                        ctx.last_rendered_function_symbol_addr = address;
                    }
                    EmitSymbolMetadata(out, symbol, s);
                    if (symbol.size > 0) {
                        ctx.pending_size.Add(address + symbol.size, symbol.name);
                    }
                    fprintf(ctx.output, "%s:\n", disasm_map.Symtab()[i].name);
                    ctx.last_rendered_symbol_addr = address;
                }
            }
        }
        EmitNodeDisassembly(ctx, disasm_map, code, s, *node, traced);
        address += node->size;
    }
    if (s.split.alignment) {
        if (s.output_dir_path) {
            FILE *const output = OpenNewPartFile(s.output_dir_path, kRomSizeBytes);
            if (output == nullptr) {
                return false;
            }
            fclose(ctx.output);
            ctx.output = output;
        } else {
            fprintf(ctx.output, kSplitMarker, kRomSizeBytes);
        }
    }
    EmitNonCodeSymbols(ctx.output, disasm_map, code, s);
    if (ctx.output != out) {
        fclose(ctx.output);
    }
    return true;
}

static void ParseTraceData(DisasmMap &disasm_map, const DataView &trace_data)
{
    bool parse = true;
    for (size_t i = 0; i < trace_data.size; i++) {
        if (trace_data.buffer[i] == '\n' || trace_data.buffer[i] == '\r') {
            parse = true;
        } else if (parse) {
            errno = 0;
            // Base 0 enabled strtol to parse octal and hexadecimal numbers with
            // prefixes like 0 or 0x. See `man strtol.3p`.
            constexpr int base = 0;
            const char *startptr = reinterpret_cast<const char *>(trace_data.buffer + i);
            char *endptr = nullptr;
            const long address = strtol(startptr, &endptr, base);
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

static DisasmMap *NewDisasmMap(FILE *trace_stream)
{
    if (trace_stream == nullptr) {
        DisasmMap *disasm_map = new DisasmMap{DisasmMapType::kRaw};
        assert(disasm_map);
        return disasm_map;
    }
    // Read trace file into buffer
    auto trace_data = DataBuffer::FromStream(trace_stream);
    const size_t trace_size = trace_data.occupied_size;
    if (trace_size == 0) {
        fprintf(stderr, "DataBuffer::FromStream(trace_data, trace_stream): "
                "Error: No data has been read\n");
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
    auto input = DataBuffer::FromStream(input_stream);
    const size_t input_size = input.occupied_size;
    if (input_size == 0) {
        fprintf(stderr, "DataBuffer::FromStream(input, input_stream): "
                "Error: No data has been read\n");
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
    const bool success = EmitDisassembly(output_stream, *disasm_map, code, s);
    delete disasm_map;
    if (success == false) {
        return EXIT_FAILURE;
    }
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
        { &Settings::raw_data_comment_all, "rdc-all" },
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
        { &Settings::dot_size_spec, "dot-size-spec" },
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
    "  -h, --help            Show this message.\n"
    "  -o, --output FILE     Where to write disassembly to (stdout if not set).\n"
    "  -d, --output-dir DIR  Where to place split disassembly parts to (current\n"
    "                        directory if not set).\n"
    "  -t, --pc-trace FILE   A file containing a PC trace table.\n"
    "  --split=[TYPE,]ALIGN  Try to split the disassembly output into multiple files\n"
    "                        at every label of specified TYPE and ALIGNment. If no\n"
    "                        --output-dir is set, then split markers are placed.\n"
    "                        Supported TYPEs are `label` (default) and `function`.\n"
    "  --indent=STRING       Specify instruction indentation, e.g. \"\t\", single tab\n"
    "                        is used by default.\n"
    "  -f, --feature=[no-]FEATURE\n"
    "                        Enable or disable (with \"no-\" prefix) a feature.\n"
    "                        Available features described below under the\n"
    "                        \"Feature flags\" section.\n"
    "  -b, --bfd-target=BFD  Specify target object format. Will attempt to detect\n"
    "                        automatically if not set. Only `auto`, `binary` and\n"
    "                        `elf` are currently supported.\n"
    "  --sierra-asm68        Produce assembly listing for Sierra ASM68.EXE.\n"
    "  <input_file_name>     Binary or elf file with the machine code to disassemble\n"
    "                        ('-' means stdin).\n"
    "Feature flags:\n"
    "  rdc                   Print raw data comment for traced locations.\n"
    "  rdc-all               Print raw data comment for every location (requires\n"
    "                        -frdc).\n"
    "  labels                Print labels above all places that have jumps from\n"
    "                        somewhere.\n"
    "  rel-labels            Use label instead of number on relative branch or call\n"
    "                        (requires -flabels).\n"
    "  abs-labels            Use label instead of number on absolute branch or call.\n"
    "                        (requires -flabels).\n"
    "  imm-labels            Use label instead of number when immediate value moved\n"
    "                        to address register (requires -flabels).\n"
    "  short-ref-local-labels\n"
    "                        Use local labels (numbers) for short jumps or loops.\n"
    "                        Jump is considered short when it does not cross other\n"
    "                        labels and has no calls (requires -flabels).\n"
    "  export-labels         Add `.globl` preamble to labels referenced two or more\n"
    "                        times (requires -flabels).\n"
    "  export-all-labels     Add `.globl` preamble to all labels (requires -flabels).\n"
    "  export-functions      Add `.globl` and `.type @funciton` preamble to a label\n"
    "                        referenced as a call (requires -flabels).\n"
    "  xrefs-from            Print xrefs comments above all places that have xrefs.\n"
    "  xrefs-to              Print xrefs comments after all branch instructions.\n"
    "  imm-hex               Print all immediate values as hexadecimal numbers.\n"
    "  follow-jumps          Follow jumps to statically known locations.\n"
    "  walk                  Try best to detect further instructions following known\n"
    "                        traced locations without overcommitting.\n"
    "  symbols               Extract and apply symbols from input file if available.\n"
    "                        ELF symbols only are currently supported.\n"
    "  dot-size-spec         Use dot to separate mnemonic and size specifier.\n"
    "                        E.g.: \"cmpm.l\" instead of \"cmpml\".\n"
    , argv0);
}

static constexpr bool IsPowerOfTwo(size_t x)
{
    return (x != 0) && (0 == (x & (x - 1)));
}

static SplitParams ParseSplitOptionParameters(char *params)
{
    SplitPointType type{};
    char *comma = strchr(params, ',');
    if (comma != nullptr) {
        // Null-terminate the first token
        *comma = '\0';
        if (0 == strcmp(params, "function")) {
            type = SplitPointType::kFunction;
        } else if (0 != strcmp(params, "label")) {
            fprintf(stderr, "--split: Error: invalid TYPE specified\n");
            return SplitParams{};
        }
        // Next token
        params = comma + 1;
    }
    const int alignment = atoi(params);
    if (alignment < 0 || !IsPowerOfTwo(size_t(alignment))) {
        fprintf(stderr, "--split: Error: ALIGN must be a result of a non-negative integer power of two\n");
        return SplitParams{};
    }
    return SplitParams{type, size_t(alignment)};
}

int main(int, char* argv[])
{
    struct optparse_long longopts[] = {
        {"help", 'h', OPTPARSE_NONE},
        {"output", 'o', OPTPARSE_REQUIRED},
        {"output-dir", 'd', OPTPARSE_REQUIRED},
        {"pc-trace", 't', OPTPARSE_REQUIRED},
        {"split", 81, OPTPARSE_REQUIRED},
        {"feature", 'f', OPTPARSE_REQUIRED},
        {"bfd-target", 'b', OPTPARSE_REQUIRED},
        {"indent", 80, OPTPARSE_REQUIRED},
        {"sierra-asm68", 82, OPTPARSE_NONE},
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
        case 'd':
            s.output_dir_path = options.optarg;
            {
                struct stat sb{};
                if (stat(s.output_dir_path, &sb) != 0) {
                    const int err = errno;
                    fprintf(stderr,
                            "main: stat(\"%s\"): Error(%d): \"%s\"\n",
                            s.output_dir_path, err, strerror(err));
                    return EXIT_FAILURE;
                }
                if (!S_ISDIR(sb.st_mode)) {
                    printf("main: Error: \"%s\" is not a directory\n", s.output_dir_path);
                    return EXIT_FAILURE;
                }
            }
            break;
        case 't':
            trace_file_name = options.optarg;
            break;
        case 81:
            s.split = ParseSplitOptionParameters(options.optarg);
            if (s.split.alignment == 0) {
                return EXIT_FAILURE;
            }
            break;
        case 82:
            s.target_asm = TargetAssembler::kSierraAsm68;
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
    if (s.target_asm != TargetAssembler::kGnuAs) {
        // This is a GNU specific feature
        s.short_ref_local_labels = false;
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
