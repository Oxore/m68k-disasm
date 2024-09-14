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

static bool g_print_header = false;
static bool g_print_optional_header = false;
static bool g_print_section_headers = false;

static void PrintCoffHeader(FILE *output_stream, const COFF::FileHeader &header)
{
    fprintf(output_stream, "COFF Header:\n");
    fprintf(output_stream, "  Magic:   %02x %02x (0x%x as big endian)\n",
            (header.magic >> 8) & 0xff, header.magic & 0xff, header.magic);
    fprintf(output_stream, "  Number of section headers:   %u\n", header.nsections);
    // TODO proper time with year, month, day, hour, minute and second
    fprintf(output_stream, "  Time and date:               %u\n", header.timedate);
    fprintf(output_stream, "  Symbol table file offset:    %u (0x%x)\n",
            header.symtable_offset, header.symtable_offset);
    fprintf(output_stream, "  Number of symbols:           %u (0x%x)\n",
            header.nsymbols, header.nsymbols);
    fprintf(output_stream, "  Optional header size, bytes: %u (0x%x)\n",
            header.optional_header_nbytes, header.optional_header_nbytes);
    // TODO Print detailed flags information
    fprintf(output_stream, "  Flags:                       0x%x\n", header.flags);
}

static void PrintOptionalHeader(FILE *output_stream, const COFF::OptionalHeader &header)
{
    fprintf(output_stream, "Optional Header:\n");
    fprintf(output_stream, "  Magic:   %02x %02x (0x%x as big endian)\n",
            (header.magic >> 8) & 0xff, header.magic & 0xff, header.magic);
    fprintf(output_stream, "  Version:                           0x%04x\n", header.version);
    fprintf(output_stream, "  Size of text, bytes:               %u\n", header.tsize);
    fprintf(output_stream, "  Size of initialized data, bytes:   %u\n", header.dsize);
    fprintf(output_stream, "  Size of uninitialized data, bytes: %u\n", header.bsize);
    fprintf(output_stream, "  Program entry point:               %u (0x%x)\n",
            header.entry, header.entry);
    fprintf(output_stream, "  Base address of text:              %u (0x%x)\n",
            header.text_start, header.text_start);
    fprintf(output_stream, "  Base address of daata:             %u (0x%x)\n",
            header.data_start, header.data_start);
}

static const char *SectionTypeStr(COFF::SectionType type)
{
    switch (type) {
    case COFF::SectionType::Regular:
        return "Regular  ARL";
    case COFF::SectionType::Dummy:
        return "Dubby     R";
    case COFF::SectionType::NoLoad:
        return "NoLoad   AR";
    case COFF::SectionType::Grouped:
        return "Grouped";
    case COFF::SectionType::Padding:
        return "Padding    L";
    case COFF::SectionType::Copy:
        return "Cppy     A L";
    case COFF::SectionType::Text:
        return "Text     ARL";
    case COFF::SectionType::Data:
        return "Data     ARL";
    case COFF::SectionType::Bss:
        return "BSS      ARL";
    case COFF::SectionType::Org:
        return "Org      ARL";
    case COFF::SectionType::Info:
        return "Info";
    case COFF::SectionType::Overlay:
        return "Ovsrlay   R";
    case COFF::SectionType::Lib:
        return "Lib      ARL";
    }
    return "Unknwon";
}

static void PrintSectionHeader(FILE *output_stream, size_t index, const COFF::SectionHeader &header)
{
    fprintf(output_stream,
            "  [%2zu] %-8s ""%08x "  "%08x "  "%08x "  "%08x "   "%08x " "\n",
            index,
            header.name,
            header.paddr,
            header.vaddr,
            header.size,
            header.section_offset,
            header.reloc_offset);
    fprintf(output_stream,
            "       %08x "  "    %04x     %04x %08x "  "%s\n",
            header.lineno_offset,
            header.nreloc,
            header.nlineno,
            header.flags,
            SectionTypeStr(static_cast<COFF::SectionType>(header.flags & 0x8ff)));
}

static int ReadCoff(FILE *input_stream, FILE *output_stream)
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
    if (g_print_header) {
        PrintCoffHeader(output_stream, file_header);
    }
    if (g_print_optional_header && coff.HasOptionalHeader()) {
        PrintOptionalHeader(output_stream, coff.OptionalHeader());
    }
    if (g_print_section_headers && file_header.nsections) {
        fprintf(output_stream, "Section headers:\n");
        fprintf(output_stream,
                "  [Nr] Name     PhysAddr VirtAddr Size     DatOffst RelOffst\n"
                "       LnNoOfft NReloc   NLineNo  Flags    Type     Alloc/Reloc/Load\n");
        for (size_t i = 0; i < file_header.nsections; i++) {
            PrintSectionHeader(output_stream, i, coff.GetSectionHeader(i));
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
    "  -H, --help            Show this message.\n"
    "  -a --all              Equivalent to: -h -o -S\n"
    "  -h --file-header      Display the COFF file header\n"
    "  -o --optional-header  Display the optional COFF file header\n"
    "  -S --section-headers  Display the sections' header\n"
    "     --sections         An alias for --section-headers\n"
    "  -e --headers          Equivalent to: -h -o -S\n"
    "  <input_file_name>     COFF file with the machine code to extract\n"
    "                        ('-' means stdin).\n"
    , argv0);
}

int main(int, char* argv[])
{
    struct optparse_long longopts[] = {
        {"help", 'H', OPTPARSE_NONE},
        {"all", 'a', OPTPARSE_NONE},
        {"file-header", 'h', OPTPARSE_NONE},
        {"optional-header", 'o', OPTPARSE_NONE},
        {"section-headers", 'S', OPTPARSE_NONE},
        {"sections", 0x80, OPTPARSE_NONE},
        {"headers", 'e', OPTPARSE_NONE},
        {},
    };
    const char *input_file_name = nullptr;
    struct optparse options;
    optparse_init(&options, argv);
    // Parse opts
    int option;
    while ((option = optparse_long(&options, longopts, NULL)) != -1) {
        switch (option) {
        case 'H':
            PrintUsage(stdout, argv[0]);
            return EXIT_SUCCESS;
            break;
        case 'h':
            g_print_header = true;
            break;
        case 'o':
            g_print_optional_header = true;
            break;
        case 0x80:
        case 'S':
            g_print_section_headers = true;
            break;
        case 'a':
        case 'e':
            g_print_header = true;
            g_print_optional_header = true;
            g_print_section_headers = true;
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
            fprintf(stderr, "main: fopen(\"%s\", \"r\"): Error (%d): \"%s\"\n", input_file_name, err, strerror(err));
            return EXIT_FAILURE;
        }
    } else {
        fprintf(stderr, "main: Error: no input file name specified, see usage below.\n");
        PrintUsage(stderr, argv[0]);
        return EXIT_FAILURE;
    }
    if (!g_print_header && !g_print_optional_header && !g_print_section_headers) {
        fprintf(stderr, "main: Error: no display options specified, see usage below.\n");
        PrintUsage(stdout, argv[0]);
        return EXIT_FAILURE;
    }
    // Run the program
    const int ret = ReadCoff(input_stream, output_stream);
    fclose(output_stream);
    fclose(input_stream);
    return ret;
}
