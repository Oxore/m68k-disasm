/* SPDX-License-Identifier: Unlicense
 */

#include "coff_image.h"
#include "data_buffer.h"

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
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static int Coff2Bin(FILE *input_stream, FILE *output_stream)
{
    auto input = DataBuffer::FromStream(input_stream);
    const size_t input_size = input.occupied_size;
    if (input_size == 0) {
        fprintf(stderr, "DataBuffer::FromStream(input, input_stream): "
                "Error: No data has been read\n");
        return EXIT_FAILURE;
    }
    const COFF::Image coff(static_cast<DataBuffer&&>(input));
    if (!coff.IsValid()) {
        fprintf(stderr, "Error: COFF image is not valid: %s\n", coff.Error());
        return EXIT_FAILURE;
    }
    const auto &file_header = coff.FileHeader();
    if (file_header.nsections == 0) {
        fprintf(stderr, "Error: COFF image does not contain sections\n");
        return EXIT_FAILURE;
    }
    for (size_t i = 0; i < file_header.nsections; i++) {
        const auto section = coff.GetSectionHeader(i);
        const auto type = static_cast<COFF::SectionType>(section.flags & 0x8ff);
        if (COFF::SectionType::Text == type) {
            const auto data = coff.GetSectionDataView(section);
            const size_t ret = fwrite(
                    data.buffer, data.size, 1, output_stream);
            (void) ret;
            assert(ret == 1);
            break;
        }
    }
    return EXIT_SUCCESS;
}

static void PrintUsage(FILE *s, const char *argv0)
{
    // Please, keep all lines in 80 columns range when printed.
    fprintf(s,
    "Usage: %s [options] <input-file-name>\n"
    "Options:\n"
    "  -h, --help            Show this message.\n"
    "  -o, --output FILE     Where to write binary data to (stdout if not set).\n"
    "  <input_file_name>     COFF file with the machine code to extract\n"
    "                        ('-' means stdin).\n"
    , argv0);
}

int main(int, char* argv[])
{
    struct optparse_long longopts[] = {
        {"help", 'h', OPTPARSE_NONE},
        {"output", 'o', OPTPARSE_OPTIONAL},
        {},
    };
    const char *input_file_name = nullptr;
    const char *output_file_name = nullptr;
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
    if (input_file_name) {
        if (0 == strcmp(input_file_name, "-")) {
            input_stream = stdin;
        } else {
            input_stream = fopen(input_file_name, "r");
        }
        if (input_stream == nullptr) {
            const int err = errno;
            fprintf(stderr,
                    "main: fopen(\"%s\", \"r\"): Error (%d): \"%s\"\n",
                    input_file_name, err, strerror(err));
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
            fprintf(stderr,
                    "main: fopen(\"%s\", \"w\"): Error (%d): \"%s\"\n",
                    output_file_name, err, strerror(err));
            fclose(input_stream);
            return EXIT_FAILURE;
        }
    }
    // Run the program
    const int ret = Coff2Bin(input_stream, output_stream);
    fclose(output_stream);
    fclose(input_stream);
    return ret;
}
