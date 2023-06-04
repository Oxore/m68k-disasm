/* SPDX-License-Identifier: Unlicense
 */

#include "elf_image.h"

#include <cassert>
#include <cstdio>

ELF::ProgramHeader32Table ELF::ProgramHeader32Table::FromBytes(
        const DataView &d, const DataEncoding e)
{
    if (d.buffer == nullptr || d.size == 0) {
        return ELF::ProgramHeader32Table{};
    }
    assert(d.size % kProgramHeaderSize == 0);
    const size_t size = d.size / kProgramHeaderSize;
    auto *headers = new ProgramHeader32[size];
    assert(headers != nullptr);
    for (size_t i = 0; i < size; i++) {
        headers[i] = ProgramHeader32::FromBytes(d.buffer + i * kProgramHeaderSize, e);
    }
    return ELF::ProgramHeader32Table{ headers, size, };
}

static char *ValidateELF(const DataView& d)
{
    char *error;
    size_t size;
    FILE *s = open_memstream(&error, &size);
    assert(s);
    using namespace ELF;
    if (d.size < kHeaderSize) {
        fprintf(
                s,
                "data size (%zu) is lower than minimum ELF header size (%zu): "
                "ELF header could not fit",
                d.size,
                kHeaderSize);
        fclose(s);
        return error;
    }
    const auto header_raw = Header32Raw::FromBytes(d.buffer);
    const auto header = Header32::FromBytes(d.buffer);
    if (!MagicIsValid(header.ident.magic)) {
        const uint8_t *m = header.ident.magic;
        fprintf(
                s,
                "ELF Magic is invalid: expected [%02x %02x %02x %02x], got [%02x %02x %02x %02x]",
                0x7f, 'E', 'L', 'F',
                m[0], m[1], m[2], m[3]);
        fclose(s);
        return error;
    }
    if (header.ident.version != Version::kCurrent) {
        fprintf(
                s,
                "version (0x%02x) of ELF header.ident.version is not supported, "
                "only \"Current\" version (0x%02x) is supported",
                header_raw.ident.version,
                static_cast<int>(Version::kCurrent));
        fclose(s);
        return error;
    }
    if (header.version != Version::kCurrent) {
        fprintf(
                s,
                "version (0x%02x) of ELF header.version is not supported, "
                "only \"Current\" version (0x%02x) is supported",
                header_raw.version,
                static_cast<int>(Version::kCurrent));
        fclose(s);
        return error;
    }
    if (header.type != ObjectType::kExec) {
        fprintf(
                s,
                "object type (0x%02x) is not supported, "
                "only Exec (0x%02x) object type is supported",
                header_raw.type,
                static_cast<int>(ObjectType::kExec));
        fclose(s);
        return error;
    }
    if (header.machine != Machine::k68k) {
        fprintf(
                s,
                "machine (0x%02x) is not supported, "
                "only Motorola 68k (0x%02x) machine is supported",
                header_raw.machine,
                static_cast<int>(Machine::k68k));
        fclose(s);
        return error;
    }
    if (header.phentsize != kProgramHeaderSize) {
        fprintf(
                s,
                "phentsize is invalid: expected (%zu), got (%zu)",
                kProgramHeaderSize,
                size_t(header.phentsize));
        fclose(s);
        return error;
    }
    if (d.size < header.phoff + header.phentsize * header.phnum) {
        fprintf(
                s,
                "data size (%zu) is lower than program header table end offset (%zu): "
                "program header table could not fit",
                d.size,
                size_t(header.phoff + header.phentsize * header.phnum));
        fclose(s);
        return error;
    }
    bool has_segment_with_entry = false;
    for (size_t i = 0; i < header.phnum; i++) {
        const auto ph = ProgramHeader32::FromBytes(
                d.buffer + header.phoff + header.phentsize * i, header.ident.data_encoding);
        if (d.size < ph.offset + ph.filesz) {
            fprintf(
                    s,
                    "data size (%zu) is lower than pht[%zu] segment end offset (%zu): "
                    "segment could not fit",
                    d.size,
                    i,
                    size_t(ph.offset + ph.filesz));
            fclose(s);
            return error;
        }
        const bool is_code = (ph.flags & (kPHFlagX | kPHFlagW | kPHFlagR)) == (kPHFlagX | kPHFlagR);
        if (ParsePHType(ph.type) == PHType::kLoad && is_code && ph.vaddr != 0) {
            fprintf(
                    s,
                    "pht[%zu] segment is a code, but it's vaddr (0x%08x) is not zero: "
                    "non-zero base address is not supported",
                    i,
                    ph.vaddr);
            fclose(s);
            return error;
        }
        const bool contains_entry = header.entry >= ph.vaddr && header.entry < ph.vaddr + ph.memsz;
        if (ParsePHType(ph.type) == PHType::kLoad && is_code && contains_entry) {
            has_segment_with_entry = true;
        }
    }
    if (!has_segment_with_entry) {
        fprintf(s, "no code segments containing entry point (0x%08x) found", header.entry);
        fclose(s);
        return error;
    }
    fclose(s);
    free(error);
    return nullptr;
}

ELF::Image::Image(DataBuffer&& data)
    : _data(static_cast<DataBuffer&&>(data))
    , _error(ValidateELF(_data.View()))
    , _h(_error ? ELF::Header32{} : ELF::Header32::FromBytes(_data.View().buffer))
    , _pht(_error
            ? ELF::ProgramHeader32Table{}
            : ELF::ProgramHeader32Table::FromBytes(
                _data.View(_h.phoff, _h.phnum * kProgramHeaderSize), _h.ident.data_encoding))
{}

ELF::Image::~Image()
{
    if (_error) {
        free(_error);
    }
    if (_pht.headers) {
        delete [] _pht.headers;
    }
}
