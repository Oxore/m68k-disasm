/* SPDX-License-Identifier: Unlicense
 */

#include "coff_image.h"

#include <cassert>
#include <cstdarg>
#include <cstdlib>
#include <cstring>

#ifdef __GNUC__
#define _PRINTF(strindex, first) __attribute__((format(printf, strindex, first)))
#else
#define _PRINTF(strindex, first)
#endif


static _PRINTF(1, 2) char *Error(const char *fmt, ...)
{
    if (0 == strlen(fmt)) {
        return nullptr;
    }
    char *error{};
    size_t size{};
    FILE *error_stream = open_memstream(&error, &size);
    assert(error_stream);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(error_stream, fmt, ap);
    va_end(ap);
    fclose(error_stream);
    assert(error != nullptr);
    assert(*error != '\0');
    return error;
}

static char *ValidateCOFF(const DataView& d)
{
    using namespace COFF;
    size_t expected_size = kFileHeaderSize;
    if (d.size < expected_size) {
        return Error(
                "data size (%zu) is too low, expected at least %zu: "
                "COFF header could not fit",
                d.size,
                expected_size);
    }
    const auto header = FileHeader::FromBytes(d.buffer);
    if (header.magic != FileHeader::kMagicSierraM68k) {
        return Error(
                "COFF Magic is invalid: expected 0x%04x, got 0x%04x",
                FileHeader::kMagicSierraM68k,
                header.magic);
    }
    const size_t oh_nbytes = header.optional_header_nbytes;
    if (oh_nbytes && oh_nbytes < kOptionalHeaderSize) {
        return Error(
                "COFF optional header size is invalid: expected 0 or at least %zu, got %zu",
                kOptionalHeaderSize,
                oh_nbytes);
    }
    expected_size += oh_nbytes;
    if (d.size < expected_size) {
        return Error(
                "data size (%zu) is too low, expected at least %zu: "
                "COFF optional header could not fit",
                d.size,
                expected_size);
    }
    expected_size += header.nsections * kSectionHeaderSize;
    if (d.size < expected_size) {
        return Error(
                "data size (%zu) is too low, expected at least %zu: "
                "%u sections headers could not fit",
                d.size,
                expected_size,
                header.nsections);
    }
    if (header.symtable_offset > d.size) {
        return Error(
                "COFF symbol table offset is too big to fit into the file: "
                "expected (<=%zu), got (%zu)",
                size_t(d.size),
                size_t(header.symtable_offset));
    }
    for (size_t i = 0; i < header.nsections; i++) {
        const auto section = SectionHeader::FromBytes(d.buffer + COFF::kFileHeaderSize +
                header.optional_header_nbytes + COFF::kSectionHeaderSize * i);
        const size_t section_end = section.section_offset + section.size;
        if (section_end > d.size) {
            return Error(
                    "data size (%zu) is too low, expected at least %zu: "
                    "section %zu (%.8s) data could not fit",
                    d.size,
                    section_end,
                    i,
                    section.name);
        }
    }
    return nullptr;
}

COFF::Image::Image(DataBuffer&& data)
    : _data(static_cast<DataBuffer&&>(data))
    , _error(ValidateCOFF(_data.View()))
    , _file_header(_error ? COFF::FileHeader{} : COFF::FileHeader::FromBytes(_data.View().buffer))
    , _has_optional_header(_error ? false : _file_header.optional_header_nbytes >= kOptionalHeaderSize)
    , _optional_header(_has_optional_header
            ? COFF::OptionalHeader::FromBytes(_data.View().buffer)
            : COFF::OptionalHeader{})
{}

COFF::Image::~Image()
{
    if (_error) {
        free(_error);
    }
}
