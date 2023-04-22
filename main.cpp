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

/*
 * We need to be able to modify output to place a mark when some jumping back
 * is found, hence we should build output table instead of emitting asm right
 * away into the output stream.
 *
 * I think the output should be an ordered map of decoded instructions. When the
 * output is built according to the map we must walk through all the binary file
 * again alongside with the output map and emit the final output right into the
 * output stream.
 *
 * Trace data parser is needed. Maybe just using atol(3) will be ok.
 */

enum class TracedNodeType {
    kInstruction,
    kData,
};

struct DisasmNode {
    DisasmNode *next{}; // Next node in the linked list
    TracedNodeType type{};
    uint32_t offset{};
    size_t size{kInstructionSizeStepBytes};
    char *asm_string{}; // Disassembly of an instruction at the current offset
    void Disasm(const DataBuffer &code);
    ~DisasmNode();
};

void DisasmNode::Disasm(const DataBuffer &code)
{
    constexpr size_t kBufferSize = 100;
    char *asm_str = new char [kBufferSize]{};
    assert(asm_str);
    this->asm_string = asm_str;
    // We assume that no MMU and ROM is always starts with 0
    assert(this->offset < code.occupied_size);
    const uint16_t instr = GetU16BE(code.buffer + this->offset);
    const size_t rendered_sz = m68k_disasm(
            asm_str, kBufferSize, &this->size, instr, this->offset, code);
    const size_t comment_rendered_sz = m68k_render_raw_data_comment(
            asm_str + rendered_sz, kBufferSize - rendered_sz, this->offset, this->size, code);
    (void) comment_rendered_sz;
}

DisasmNode::~DisasmNode()
{
    if (asm_string) {
        delete [] asm_string;
        asm_string = nullptr;
    }
}

class DisasmMap {
    DisasmNode *_first{};
    DisasmNode *_last{};
    DisasmNode *findNodeByOffset(uint32_t offset) const;
public:
    const DisasmNode *FindNodeByOffset(uint32_t offset) const
    {
        return findNodeByOffset(offset);
    };
    // Returns true if node inserted, false if node already exist and has not
    // been changed
    bool InsertTracedNode(uint32_t offset, TracedNodeType);
    // This function disassembles everything that has been traced
    void DisasmAll(const DataBuffer &code);
    ~DisasmMap();
};

DisasmNode *DisasmMap::findNodeByOffset(uint32_t offset) const
{
    for (DisasmNode *node{_first}; node; node = node->next)
        if (node->offset == offset)
            return node;
    return nullptr;
}

bool DisasmMap::InsertTracedNode(uint32_t offset, TracedNodeType type)
{
    if (findNodeByOffset(offset))
        return false;
    auto *node = new DisasmNode(DisasmNode{nullptr, type, offset});
    assert(node);
    if (_first) {
        _last->next = node;
        _last = node;
    } else {
        _first = node;
        _last = node;
    }
    return true;
}

void DisasmMap::DisasmAll(const DataBuffer &code)
{
    for (DisasmNode *node{_first}; node; node = node->next) {
        node->Disasm(code);
    }
}

DisasmMap::~DisasmMap()
{
    DisasmNode *prev = nullptr, *node = _first;
    while (node) {
        prev = node;
        node = node->next;
        delete prev;
    }
    _first = nullptr;
    _last = nullptr;
}

static void RenderDisassembly(FILE *output, const DisasmMap &disasm_map, const DataBuffer &code)
{
    for (size_t i = 0; i < code.occupied_size;) {
        const DisasmNode *node = disasm_map.FindNodeByOffset(i);
        if (node) {
            assert(node->asm_string);
            fputs(node->asm_string, output);
            fputc('\n', output);
            i += node->size;
        } else {
            fprintf(output, "  .short 0x%02x%02x\n", code.buffer[i], code.buffer[i + 1]);
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
                // Error, just skip
            } else if (startptr == endptr) {
                // Error, just skip
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

static int M68kDisasmByTrace(FILE *input_stream, FILE *output_stream, FILE *trace_stream)
{
    // Read machine code into buffer
    DataBuffer code{};
    const size_t input_size = ReadFromStream(code, input_stream);
    if (input_size == 0) {
        fprintf(stderr, "ReadFromStream(code, input_stream): Error: No data has been read\n");
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
    DisasmMap disasm_map{};
    ParseTraceData(disasm_map, trace_data);
    // Disasm into output map
    disasm_map.DisasmAll(code);
    // Print output into output_stream
    RenderDisassembly(output_stream, disasm_map, code);
    return 0;
}

static int M68kDisasmAll(FILE *input_stream, FILE *output_stream)
{
    uint8_t instruction[kInstructionSizeStepBytes]{};
    const size_t read_size = kInstructionSizeStepBytes;
    while (1) {
        const size_t fread_ret = fread(instruction, 1, read_size, input_stream);
        if (fread_ret == 0) {
            const int err = errno;
            if (feof(input_stream)) {
                break;
            } else {
                fprintf(stderr, "ReadFromStream: fread(%zu): Error (%d): \"%s\"\n", read_size, err, strerror(err));
                return EXIT_FAILURE;
            }
        }
        fprintf(output_stream, "  .short 0x%02x%02x\n", instruction[0], instruction[1]);
    }
    return 0;
}

static void PrintUsage(FILE *stream, const char *argv0)
{
    fprintf(stream, "Usage: %s [options] [<input-file-name>]\n", argv0);
    fprintf(stream, "  -h, --help,           Show this message\n");
    fprintf(stream, "  -o, --output,         Where to write disassembly to (stdout if not set)\n");
    fprintf(stream, "  -t, --pc-trace,       File containing PC trace\n");
    fprintf(stream, "  <input_file_name>     Binary file with machine code (stdin if not set)\n");
}

int main(int, char* argv[])
{
    struct optparse_long longopts[] = {
        {"help", 'h', OPTPARSE_NONE},
        {"output", 'o', OPTPARSE_REQUIRED},
        {"pc-trace", 't', OPTPARSE_REQUIRED},
        {},
    };
    const char *trace_file_name = nullptr;
    const char *output_file_name = nullptr;
    const char *input_file_name = nullptr;
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
        ? M68kDisasmByTrace(input_stream, output_stream, trace_stream)
        : M68kDisasmAll(input_stream, output_stream);
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
