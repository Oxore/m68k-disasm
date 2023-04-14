/* SPDX-License-Identifier: Unlicense
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cerrno>
#define OPTPARSE_IMPLEMENTATION
#define OPTPARSE_API static
#include "optparse/optparse.h"

constexpr size_t kInstructionSizeStepBytes = 2;

static int M68kDisasm(FILE *input_fd, FILE *output_fd, FILE *trace_fd)
{
    (void) input_fd;
    (void) output_fd;
    (void) trace_fd;
    uint8_t instruction[100]{};
    const size_t read_size = kInstructionSizeStepBytes;
    while (1) {
        const size_t fread_ret = fread(instruction, 1, read_size, input_fd);
        if (fread_ret <= 0) {
            if (feof(input_fd)) {
                break;
            } else {
                fprintf(stderr, "Error reading: %s", strerror(errno));
                return EXIT_FAILURE;
            }
        }
        fprintf(stdout, "  .short 0x%02x%02x\n", instruction[0], instruction[1]);
    }
    return 0;
}

static void PrintUsage(FILE *fd, const char *argv0)
{
    fprintf(fd, "Usage: %s [options] [<input-file-name>]\n", argv0);
    fprintf(fd, "  -h, --help,           Show this message\n");
    fprintf(fd, "  -o, --output,         Where to write disassembly to (stdout if not set)\n");
    fprintf(fd, "  -t, --pc-trace,       File containing PC trace\n");
    fprintf(fd, "  <input_file_name>     Binary file with machine code (stdin if not set)\n");
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
            exit(EXIT_SUCCESS);
            break;
        case 'o':
            output_file_name = options.optarg;
            break;
        case 't':
            trace_file_name = options.optarg;
            break;
        case '?':
            fprintf(stderr, "%s: %s\n", argv[0], options.errmsg);
            exit(EXIT_FAILURE);
        }
    }
    // Parse input file name
    char *arg;
    while ((arg = optparse_arg(&options))) {
        if (input_file_name == nullptr) {
            input_file_name = arg;
        } else {
            fprintf(stderr, "error: too many free arguments provided\n");
            exit(EXIT_FAILURE);
        }
    }
    // TODO remove debug
    fprintf(stdout, "input_file_name=%s\n", input_file_name ? input_file_name : "<stdin>");
    fprintf(stdout, "output_file_name=%s\n", output_file_name ? output_file_name : "<stdout>");
    if (trace_file_name) {
        fprintf(stdout, "trace_file_name=%s\n", output_file_name);
    }
    // Open the files
    FILE *input_fd = stdin; // TODO open file
    FILE *output_fd = stdout; // TODO open file
    FILE *trace_fd = nullptr; // TODO open file
    // Run the program
    const int ret = M68kDisasm(input_fd, output_fd, trace_fd);
    if (trace_fd != nullptr) {
        fclose(trace_fd);
    }
    if (output_fd != stdout) {
        fclose(output_fd);
    }
    if (input_fd != stdin) {
        fclose(input_fd);
    }
    return ret;
}
