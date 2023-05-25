/* SPDX-License-Identifier: Unlicense
 */

#include "disasm.h"
#include "data_buffer.h"
#include "common.h"

#define OPTPARSE_IMPLEMENTATION
#define OPTPARSE_API static
#include "optparse/optparse.h"

#include <cassert>
#include <cinttypes>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <climits>

enum class DisasmMapType {
    kTraced,
    kRaw,
};

class DisasmMap {
    const DisasmMapType _type;
    DisasmNode *_map[kDisasmMapSizeElements]{};
    DisasmNode *findNodeByOffset(uint32_t offset) const;
    DisasmNode *insertTracedNode(uint32_t offset, TracedNodeType);
    void insertReferencedBy(
            const uint32_t by_addr,
            const uint32_t ref_addr,
            const TracedNodeType type,
            const DataBuffer &code,
            const ReferenceType ref_type);
    bool canBeAllocated(const DisasmNode& node) const;
public:
    const DisasmNode *FindNodeByOffset(uint32_t offset) const
    {
        return findNodeByOffset(offset);
    };
    // Returns true if node inserted, false if node already exist and has not
    // been changed
    bool InsertTracedNode(uint32_t offset, TracedNodeType type)
    {
        assert(_type == DisasmMapType::kTraced);
        return nullptr != insertTracedNode(offset, type);
    }
    void Disasm(const DataBuffer &code, const Settings &);
    DisasmMap(DisasmMapType type): _type(type) {}
    ~DisasmMap();
};

DisasmNode *DisasmMap::findNodeByOffset(uint32_t offset) const
{
    if (offset < kRomSizeBytes)
        return _map[offset / kInstructionSizeStepBytes];
    return nullptr;
}

static uint32_t AlignInstructionAddress(const uint32_t offset)
{
    return offset & ~1UL;
}

DisasmNode *DisasmMap::insertTracedNode(const uint32_t offset, const TracedNodeType type)
{
    auto *node = findNodeByOffset(offset);
    if (node) {
        // Instruction nodes take precedence over data nodes. If a node that
        // was previously accessed only as data now turns out to be an
        // instruction, then it must become an instruction node.
        if (type == TracedNodeType::kInstruction && node->type != TracedNodeType::kInstruction) {
            *const_cast<TracedNodeType*>(&node->type) = type;
            // Make sure it is OpCode::kNone so it will be properly disassembled
            node->op = Op{};
        }
        return node;
    }
    node = new DisasmNode(DisasmNode{type, AlignInstructionAddress(offset)});
    assert(node);
    _map[offset / kInstructionSizeStepBytes] = node;
    return node;
}

void DisasmMap::insertReferencedBy(
        const uint32_t by_addr,
        const uint32_t ref_addr,
        const TracedNodeType type,
        const DataBuffer &code,
        const ReferenceType ref_type)
{
    auto *const ref_node = insertTracedNode(ref_addr, type);
    const auto size = ref_node->Disasm(code);
    assert(size >= kInstructionSizeStepBytes);
    if (canBeAllocated(*ref_node)) {
        // Spread across the size
        for (size_t o = kInstructionSizeStepBytes; o < size; o++) {
            _map[(ref_node->offset + o) / kInstructionSizeStepBytes] = ref_node;
        }
    } else {
        ref_node->DisasmAsRaw(code);
    }
    ref_node->AddReferencedBy(by_addr, ref_type);
}

bool DisasmMap::canBeAllocated(const DisasmNode& node) const
{
    const auto size = node.size / kInstructionSizeStepBytes;
    const auto *const node_real = findNodeByOffset(node.offset);
    for (size_t i = 1; i < size; i++) {
        const auto *const ptr = _map[node.offset / kInstructionSizeStepBytes + i];
        if (ptr != nullptr && ptr != node_real) {
            return false;
        }
    }
    return true;
}

static ReferenceType ReferenceTypeFromRefKindMask1(const RefKindMask ref_kinds)
{
    return (ref_kinds & kRefCallMask)
        ? ReferenceType::kCall
        : (ref_kinds & kRef1ReadMask)
            ? ReferenceType::kRead
            : (ref_kinds & kRef1WriteMask)
                ? ReferenceType::kWrite
                : ReferenceType::kBranch;
}

static ReferenceType ReferenceTypeFromRefKindMask2(const RefKindMask ref_kinds)
{
    return (ref_kinds & kRefCallMask)
        ? ReferenceType::kCall
        : (ref_kinds & kRef2ReadMask)
            ? ReferenceType::kRead
            : (ref_kinds & kRef2WriteMask)
                ? ReferenceType::kWrite
                : ReferenceType::kBranch;
}

void DisasmMap::Disasm(const DataBuffer &code, const Settings &)
{
    DisasmNode *node;
    for (size_t i = 0; i < Min(kRomSizeBytes, code.occupied_size);) {
        if (_type == DisasmMapType::kTraced) {
            node = _map[i / kInstructionSizeStepBytes];
            if (!node) {
                i += kInstructionSizeStepBytes;
                continue;
            }
        } else {
            node = insertTracedNode(i, TracedNodeType::kInstruction);
        }
        const auto size = node->Disasm(code);
        assert(size >= kInstructionSizeStepBytes);
        if (canBeAllocated(*node)) {
            // Spread across the size
            for (size_t o = kInstructionSizeStepBytes; o < size; o++) {
                _map[(node->offset + o) / kInstructionSizeStepBytes] = node;
            }
        } else {
            node->DisasmAsRaw(code);
        }
        // FIXME implement deep graph walk for DisasmMapType::kTraced case
        const bool has_code_ref1 =
            ((node->ref_kinds & kRef1Mask) && node->ref1_addr < code.occupied_size);
        if (has_code_ref1) {
            const TracedNodeType type = (node->ref_kinds & (kRef1ReadMask | kRef1WriteMask))
                ? TracedNodeType::kData : TracedNodeType::kInstruction;
            const auto ref_type = ReferenceTypeFromRefKindMask1(node->ref_kinds);
            insertReferencedBy(node->offset, node->ref1_addr, type, code, ref_type);
        }
        const bool has_code_ref2 =
            ((node->ref_kinds & kRef2Mask) && node->ref2_addr < code.occupied_size);
        if (has_code_ref2) {
            const TracedNodeType type = (node->ref_kinds & (kRef2ReadMask | kRef2WriteMask))
                ? TracedNodeType::kData : TracedNodeType::kInstruction;
            const auto ref_type = ReferenceTypeFromRefKindMask2(node->ref_kinds);
            insertReferencedBy(node->offset, node->ref2_addr, type, code, ref_type);
        }
        i += node->size;
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
}

static size_t RenderRawDataComment(
        char *out, size_t out_sz, uint32_t offset, size_t instr_sz, const DataBuffer &code)
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
                    GetU16BE(code.buffer + offset + i)));
    }
    overall_sz += Min(
            out_sz - overall_sz,
            snprintf(out + overall_sz, out_sz - overall_sz, " @%08x", offset));
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

static void RenderNodeDisassembly(
        FILE *const output,
        const DisasmMap &disasm_map,
        const DataBuffer &code,
        const Settings &s,
        const DisasmNode &node)
{
    if (node.ref_by) {
        if (s.marks) {
            const bool export_this_function = s.export_functions && HasCallReference(node);
            const bool export_this_mark = s.export_all_marks ||
                (s.export_marks && node.ref_by && (node.ref_by->refs_count > 1)) ||
                export_this_function;
            if (export_this_mark) {
                fprintf(output, "\n%s.globl\tL%08x\n", s.indent, node.offset);
                if (export_this_function) {
                    fprintf(output, "%s.type\tL%08x, @function\n", s.indent, node.offset);
                }
            }
        }
        if (s.xrefs_from) {
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
        if (s.marks) {
            fprintf(output, "L%08x:\n", node.offset);
        }
    }
    assert(node.op.opcode != OpCode::kNone);
    if (ShouldPrintAsRaw(node.op)) {
        auto raw = Op::Raw(GetU16BE(code.buffer + node.offset));
        raw.FPrint(output, s.indent);
        uint32_t i = kInstructionSizeStepBytes;
        for (; i < node.size; i += kInstructionSizeStepBytes) {
            char arg_str[kArgsBufferSize]{};
            const auto arg = Arg::Raw(GetU16BE(code.buffer + node.offset + i));
            arg.SNPrint(arg_str, kArgsBufferSize);
            fprintf(output, ", %s", arg_str);
        }
        fprintf(output, "\n");
    } else {
        const bool with_ref = node.ref_kinds && s.marks && (s.abs_marks || s.rel_marks);
        const auto *ref1 = (node.ref_kinds & kRef1Mask)
            ? disasm_map.FindNodeByOffset(node.ref1_addr) : nullptr;
        const auto *ref2 = (node.ref_kinds & kRef2Mask)
            ? disasm_map.FindNodeByOffset(node.ref2_addr) : nullptr;
        const uint32_t ref1_addr = (with_ref && ref1) ? ref1->offset : 0;
        const uint32_t ref2_addr = (with_ref && ref2) ? ref2->offset : 0;
        if (with_ref && (ref1 || ref2)) {
            const RefKindMask ref_kinds =
                (s.abs_marks
                 ? ((ref1 ? (node.ref_kinds & kRef1AbsMask) : 0) |
                     (ref2 ? (node.ref_kinds & kRef2AbsMask) : 0))
                 : 0) |
                (s.rel_marks
                 ? ((ref1 ? (node.ref_kinds & kRef1RelMask) : 0) |
                     (ref2 ? (node.ref_kinds & kRef2RelMask) : 0))
                 : 0) |
                ((s.imm_marks && ref1) ? (node.ref_kinds & kRef1ImmMask) : 0) |
                (node.ref_kinds & (kRefDataMask | kRefPcRelFix2Bytes));
            node.op.FPrint(output, s.indent, ref_kinds, node.offset, ref1_addr, ref2_addr);
            if (s.xrefs_to && ref1) {
                char ref_addr_str[12]{};
                snprintf(ref_addr_str, (sizeof ref_addr_str), "L%08x", ref1_addr);
                fprintf(output, " | %s", ref_addr_str);
            }
            if (s.xrefs_to && ref2) {
                char ref_addr_str[12]{};
                snprintf(ref_addr_str, (sizeof ref_addr_str), "L%08x", ref2_addr);
                fprintf(output, " | %s", ref_addr_str);
            }
        } else {
            node.op.FPrint(output, s.indent);
        }
    }
    if (s.raw_data_comment) {
        char raw_data_comment[100]{};
        RenderRawDataComment(
                raw_data_comment,
                (sizeof raw_data_comment) - 1,
                node.offset,
                node.size, code);
        fprintf(output, " |%s", raw_data_comment);
    }
    fprintf(output, "\n");
}

static void RenderDisassembly(
        FILE *const output, const DisasmMap &disasm_map, const DataBuffer &code, const Settings &s)
{
    for (size_t i = 0; i < code.occupied_size;) {
        const DisasmNode *node = disasm_map.FindNodeByOffset(i);
        if (node) {
            RenderNodeDisassembly(output, disasm_map, code, s, *node);
            i += node->size;
        } else {
            auto raw = Op::Raw(GetU16BE(code.buffer + i));
            raw.FPrint(output, s.indent);
            fprintf(output, "\n");
            i += kInstructionSizeStepBytes;
        }
    }
}

static void ParseTraceData(DisasmMap &disasm_map, const DataBuffer &trace_data)
{
    // FIXME make a full blown parser with various radixes support and different
    // trace types support
    bool parse = true;
    for (size_t i = 0; i < trace_data.occupied_size; i++) {
        if (trace_data.buffer[i] == '\n' || trace_data.buffer[i] == '\r') {
            parse = true;
        } else if (parse) {
            errno = 0;
            char *startptr = reinterpret_cast<char *>(trace_data.buffer + i);
            char *endptr = startptr;
            const long offset = strtol(startptr, &endptr, 10);
            if ((offset == LONG_MAX || offset == LONG_MIN) && errno == ERANGE) {
                // Parsing error, just skip
            } else if (startptr == endptr) {
                // Parsing error, just skip
            } else if (offset % 2) {
                fprintf(stderr, "Error: Uneven PC values are not supported (got PC=0x%08lx), exiting\n", offset);
                exit(1);
            } else if (static_cast<unsigned long>(offset) > kRomSizeBytes) {
                fprintf(stderr, "Error: PC values > 4MiB are not supported (got PC=0x%08lx), exiting\n", offset);
                exit(1);
            } else {
                // Valid value
                disasm_map.InsertTracedNode(offset, TracedNodeType::kInstruction);
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

static int M68kDisasmByTrace(FILE *input_stream, FILE *output_stream, FILE *trace_stream, const Settings &s)
{
    // Read machine code into buffer
    DataBuffer code{};
    const size_t input_size = ReadFromStream(code, input_stream);
    if (input_size == 0) {
        fprintf(stderr, "ReadFromStream(code, input_stream): Error: No data has been read\n");
        return EXIT_FAILURE;
    }
    // It just not worth it to check this somewhere while disassebling or
    // emitting. Odd size is just not supported.
    if (code.occupied_size % 2) {
        fprintf(stderr, "Error: code blob must be of even size\n");
        return EXIT_FAILURE;
    }
    // Read trace file into buffer
    DataBuffer trace_data{};
    const size_t trace_size = ReadFromStream(trace_data, trace_stream);
    if (trace_size == 0) {
        fprintf(stderr, "ReadFromStream(trace_data, trace_stream): Error: No data has been read\n");
        return EXIT_FAILURE;
    }
    // Parse trace file into map
    DisasmMap *disasm_map = new DisasmMap{DisasmMapType::kTraced};
    assert(disasm_map);
    ParseTraceData(*disasm_map, trace_data);
    // Disasm into output map
    disasm_map->Disasm(code, s);
    // Print output into output_stream
    RenderDisassembly(output_stream, *disasm_map, code, s);
    delete disasm_map;
    return EXIT_SUCCESS;
}

static int M68kDisasmAll(FILE *input_stream, FILE *output_stream, const Settings &s)
{
    // Read machine code into buffer
    DataBuffer code{};
    const size_t input_size = ReadFromStream(code, input_stream);
    if (input_size == 0) {
        fprintf(stderr, "ReadFromStream(code, input_stream): Error: No data has been read\n");
        return EXIT_FAILURE;
    }
    // It just not worth it to check this somewhere while disassebling or
    // emitting. Odd size is just not supported.
    if (code.occupied_size % 2) {
        fprintf(stderr, "Error: code blob must be of even size\n");
        return EXIT_FAILURE;
    }
    // Create the map and disasseble
    DisasmMap *disasm_map = new DisasmMap{DisasmMapType::kRaw};
    assert(disasm_map);
    // Disasm into output map
    disasm_map->Disasm(code, s);
    // Print output into output_stream
    RenderDisassembly(output_stream, *disasm_map, code, s);
    delete disasm_map;
    return EXIT_SUCCESS;
}

static bool IsValidFeature(const char *feature)
{
    constexpr size_t sizeof_no_prefix = sizeof("no-")-1;
    if (0 == memcmp(feature, "no-", sizeof_no_prefix)) {
        feature += sizeof_no_prefix;
    }
    if (0 == strcmp(feature, "rdc")) {
        return true;
    } else if (0 == strcmp(feature, "marks")) {
        return true;
    } else if (0 == strcmp(feature, "rel-marks")) {
        return true;
    } else if (0 == strcmp(feature, "abs-marks")) {
        return true;
    } else if (0 == strcmp(feature, "imm-marks")) {
        return true;
    } else if (0 == strcmp(feature, "export-marks")) {
        return true;
    } else if (0 == strcmp(feature, "export-all-marks")) {
        return true;
    } else if (0 == strcmp(feature, "export-functions")) {
        return true;
    } else if (0 == strcmp(feature, "xrefs-from")) {
        return true;
    } else if (0 == strcmp(feature, "xrefs-to")) {
        return true;
    }
    return false;
}

static void ApplyFeature(Settings& s, const char *feature_arg)
{
    constexpr size_t sizeof_no_prefix = (sizeof "no-") - 1;
    const bool disable = (0 == memcmp(feature_arg, "no-", sizeof_no_prefix));
    const char *const feature = feature_arg + (disable ? sizeof_no_prefix : 0);
    if (0 == strcmp(feature, "rdc")) {
        s.raw_data_comment = !disable;
    } else if (0 == strcmp(feature, "marks")) {
        s.marks = !disable;
    } else if (0 == strcmp(feature, "rel-marks")) {
        s.rel_marks = !disable;
    } else if (0 == strcmp(feature, "abs-marks")) {
        s.abs_marks = !disable;
    } else if (0 == strcmp(feature, "imm-marks")) {
        s.imm_marks = !disable;
    } else if (0 == strcmp(feature, "export-marks")) {
        s.export_marks = !disable;
    } else if (0 == strcmp(feature, "export-all-marks")) {
        s.export_all_marks = !disable;
    } else if (0 == strcmp(feature, "export-functions")) {
        s.export_functions = !disable;
    } else if (0 == strcmp(feature, "xrefs-from")) {
        s.xrefs_from = !disable;
    } else if (0 == strcmp(feature, "xrefs-to")) {
        s.xrefs_to = !disable;
    }
}

static void PrintUsage(FILE *s, const char *argv0)
{
    // Please, keep all lines in 80 columns range when printed.
    fprintf(s, "Usage: %s [options] [<input-file-name>]\n", argv0);
    fprintf(s, "Options:\n");
    fprintf(s, "  -h, --help,           Show this message.\n");
    fprintf(s, "  -o, --output,         Where to write disassembly to (stdout if not set)\n");
    fprintf(s, "  -t, --pc-trace,       File containing PC trace\n");
    fprintf(s, "      --indent,         Specify instruction indentation, e.g. \"\t\",\n");
    fprintf(s, "                        Single tab is used by default.\n");
    fprintf(s, "  -f, --feature=[no-]<feature>\n");
    fprintf(s, "                        Enable or disable (with \"no-\" prefix) a feature.\n");
    fprintf(s, "                        Available features described below under the\n");
    fprintf(s, "                        \"Feature flags\" mark.\n");
    fprintf(s, "  <input_file_name>     Binary file with machine code (stdin if not set)\n");
    fprintf(s, "Feature flags:\n");
    fprintf(s, "  rdc                   Print raw data comment.\n");
    fprintf(s, "  marks                 Print marks above all places that have jumps from\n");
    fprintf(s, "                        somewhere.\n");
    fprintf(s, "  rel-marks             Use mark instead of number on relative branch or call.\n");
    fprintf(s, "  abs-marks             Use mark instead of number on absolute branch or call.\n");
    fprintf(s, "  imm-marks             Use mark instead of number when immediate value moved to\n");
    fprintf(s, "                        address register.\n");
    fprintf(s, "  export-marks          Add `.globl` preamble to marks referenced two or more\n");
    fprintf(s, "                        times.\n");
    fprintf(s, "  export-all-marks      Add `.globl` preamble to all marks.\n");
    fprintf(s, "  export-functions      Add `.globl` and `.type @funciton` preamble to marks\n");
    fprintf(s, "                        referenced as call.\n");
    fprintf(s, "  xrefs-from            Print xrefs comments above all places that have xrefs.\n");
    fprintf(s, "  xrefs-to              Print xrefs comments after all branch instructions.\n");
}

int main(int, char* argv[])
{
    struct optparse_long longopts[] = {
        {"help", 'h', OPTPARSE_NONE},
        {"output", 'o', OPTPARSE_REQUIRED},
        {"pc-trace", 't', OPTPARSE_REQUIRED},
        {"feature", 'f', OPTPARSE_OPTIONAL},
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
            if (!IsValidFeature(options.optarg)) {
                fprintf(stderr, "main: Error: Unknown feature \"%s\", exiting\n", options.optarg);
                return EXIT_FAILURE;
            }
            ApplyFeature(s, options.optarg);
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
    FILE *input_stream = stdin;
    FILE *output_stream = stdout;
    FILE *trace_stream = nullptr;
    if (input_file_name) {
        input_stream = fopen(input_file_name, "r");
        if (input_stream == nullptr) {
            const int err = errno;
            fprintf(stderr, "main: fopen(\"%s\", \"r\"): Error (%d): \"%s\"\n", input_file_name, err, strerror(err));
            return EXIT_FAILURE;
        }
    }
    if (output_file_name) {
        output_stream = fopen(output_file_name, "w");
        if (output_stream == nullptr) {
            const int err = errno;
            fprintf(stderr, "main: fopen(\"%s\", \"w\"): Error (%d): \"%s\"\n", output_file_name, err, strerror(err));
            return EXIT_FAILURE;
        }
    }
    if (trace_file_name) {
        trace_stream = fopen(trace_file_name, "r");
        if (trace_stream == nullptr) {
            const int err = errno;
            fprintf(stderr, "main: fopen(\"%s\", \"r\"): Error (%d): \"%s\"\n", trace_file_name, err, strerror(err));
            return EXIT_FAILURE;
        }
    }
    // Run the program
    const int ret = trace_stream
        ? M68kDisasmByTrace(input_stream, output_stream, trace_stream, s)
        : M68kDisasmAll(input_stream, output_stream, s);
    if (trace_stream != nullptr) {
        fclose(trace_stream);
    }
    if (output_stream != stdout) {
        fclose(output_stream);
    }
    if (input_stream != stdin) {
        fclose(input_stream);
    }
    return ret;
}
