/* SPDX-License-Identifier: Unlicense
 */

#define OPTPARSE_IMPLEMENTATION
#define OPTPARSE_API static
#include "optparse/optparse.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
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

constexpr size_t kInstructionSizeStepBytes = 2;

struct DataBuffer {
    static constexpr size_t kInitialSize = 4 * 1024;
    uint8_t *buffer{new uint8_t[kInitialSize]};
    size_t buffer_size{kInitialSize};
    size_t occupied_size{};
    void Expand(size_t new_size) {
        if (new_size <= buffer_size) {
            return;
        }
        uint8_t *new_buffer{new uint8_t[new_size]};
        assert(new_buffer);
        memcpy(new_buffer, buffer, occupied_size);
        delete [] buffer;
        buffer = new_buffer;
    }
    ~DataBuffer() {
        delete [] buffer;
        buffer = nullptr;
        buffer_size = 0;
        occupied_size = 0;
    }
};

enum class TracedNodeType {
    kInstruction,
    kData,
};

class DisasmMap {
public:
    // Returns true if node inserted, false if node already exist and has not
    // been changed
    bool InsertTracedNode(unsigned long offset, TracedNodeType);
    // This function disassembles everything that has been traced
    void DisasmAll(const DataBuffer &code);
};

bool DisasmMap::InsertTracedNode(unsigned long offset, TracedNodeType type)
{
    (void) offset;
    (void) type;
    // TODO
    return true;
}

void DisasmMap::DisasmAll(const DataBuffer &code)
{
    (void) code;
    // TODO
}

static void RenderDisassembly(FILE *output, const DisasmMap &disasm_map, const DataBuffer &code)
{
    (void) disasm_map;
    (void) code;
    (void) output;
    // TODO
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
            const long offset = strtol(startptr, &endptr, 16);
            if ((offset == LONG_MAX || offset == LONG_MIN) && errno == ERANGE) {
                // Error, just skip
            } else if (startptr == endptr) {
                // Error, just skip
            } else {
                // Valid value
                disasm_map.InsertTracedNode(offset, TracedNodeType::kInstruction);
                // TODO remove debug log
                fprintf(stderr, "[%zu] InsertTracedNode(%lu, kInstruction)\n", i, offset);
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
                assert (false);
            }
        }
    }
    return db.occupied_size;
}

static int M68kDisasmByTrace(FILE *input_stream, FILE *output_stream, FILE *trace_stream)
{
    // Read machine code into buffer
    DataBuffer code{};
    assert(ReadFromStream(code, input_stream));
    // Read trace file into buffer
    DataBuffer trace_data{};
    assert(ReadFromStream(trace_data, trace_stream));
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
    uint8_t instruction[2]{};
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
