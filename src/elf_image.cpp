/* SPDX-License-Identifier: Unlicense
 */

#include "elf_image.h"

#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstring>

#ifdef __GNUC__
#define _PRINTF(strindex, first) __attribute__((format(printf, strindex, first)))
#else
#define _PRINTF(strindex, first)
#endif


ELF::ProgramHeader32Table ELF::ProgramHeader32Table::FromView(
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

static char *ValidateSectionHeader(
        const DataView& d,
        ELF::SectionHeader32 sh,
        size_t shstrndx,
        const char *shname)
{
    if (sh.offset >= d.size) {
        return Error(
                "Section header %zu (%s) offset is too big to fit into the file: "
                "expected (<%zu), got (%zu)",
                shstrndx,
                shname,
                d.size,
                size_t(sh.offset));
    }
    if (sh.size >= d.size - sh.offset) {
        return Error(
                "Section header %zu (%s) is too big to fit into the file: "
                "expected (<%zu), got (%zu)",
                shstrndx,
                shname,
                d.size - sh.offset,
                size_t(sh.size));
    }
    if (sh.entsize) {
        if (sh.entsize > sh.size) {
            return Error(
                    "Section header %zu (%s) entry size is too big to fit into "
                    "the table: expected (<%zu), got (%zu)",
                    shstrndx,
                    shname,
                    size_t(sh.size),
                    size_t(sh.entsize));
        }
        size_t const remainder = sh.size % sh.entsize;
        if (remainder) {
            return Error(
                    "Section header %zu (%s) size is not multiple of entsize: "
                    "expected (%zu %% %zu == 0), got (%zu)",
                    shstrndx,
                    shname,
                    size_t(sh.size),
                    size_t(sh.entsize),
                    remainder);
        }
    }
    return nullptr;
}

static char *ValidateELF(const DataView& d)
{
    using namespace ELF;
    if (d.size < kHeaderSize) {
        return Error(
                "data size (%zu) is lower than minimum ELF header size (%zu): "
                "ELF header could not fit",
                d.size,
                kHeaderSize);
    }
    const auto header_raw = Header32Raw::FromBytes(d.buffer);
    const auto header = Header32::FromBytes(d.buffer);
    if (!MagicIsValid(header.ident.magic)) {
        const uint8_t *m = header.ident.magic;
        return Error(
                "ELF Magic is invalid: expected [%02x %02x %02x %02x], got [%02x %02x %02x %02x]",
                0x7f, 'E', 'L', 'F',
                m[0], m[1], m[2], m[3]);
    }
    if (header.ident.version != Version::kCurrent) {
        return Error(
                "version (0x%02x) of ELF header.ident.version is not supported, "
                "only \"Current\" version (0x%02x) is supported",
                header_raw.ident.version,
                static_cast<int>(Version::kCurrent));
    }
    if (header.version != Version::kCurrent) {
        return Error(
                "version (0x%02x) of ELF header.version is not supported, "
                "only \"Current\" version (0x%02x) is supported",
                header_raw.version,
                static_cast<int>(Version::kCurrent));
    }
    if (header.type != ObjectType::kExec) {
        return Error(
                "object type (0x%02x) is not supported, "
                "only Exec (0x%02x) object type is supported",
                header_raw.type,
                static_cast<int>(ObjectType::kExec));
    }
    if (header.machine != Machine::k68k) {
        return Error(
                "machine (0x%02x) is not supported, "
                "only Motorola 68k (0x%02x) machine is supported",
                header_raw.machine,
                static_cast<int>(Machine::k68k));
    }
    if (header.ehsize > d.size) {
        return Error(
                "ELF header ehsize is too big to fit into the file: expected (<=%zu), got (%zu)",
                size_t(d.size),
                size_t(header.ehsize));
    }
    if (header.phentsize != kProgramHeaderSize) {
        return Error(
                "phentsize is invalid: expected (%zu), got (%zu)",
                kProgramHeaderSize,
                size_t(header.phentsize));
    }
    if (header.shentsize != kSectionHeaderSize) {
        return Error(
                "shentsize is invalid: expected (%zu), got (%zu)",
                kSectionHeaderSize,
                size_t(header.shentsize));
    }
    if (header.shoff < header.ehsize) {
        return Error(
                "shoff intersects with an ELF header: expected (>%zu), got (%zu)",
                size_t(header.ehsize),
                size_t(header.shoff));
    }
    if (header.shoff >= d.size) {
        return Error(
                "shoff is too big for a file size: expected (<%zu), got (%zu)",
                d.size,
                size_t(header.shoff));
    }
    if (header.shnum > (d.size - header.shoff) / header.shentsize) {
        return Error(
                "shnum is too big to fit shared headers table into the file: expected (<=%zu), got (%zu)",
                (d.size - header.shoff) / header.shentsize,
                size_t(header.shnum));
    }
    if (header.shstrndx > header.shnum) {
        return Error(
                "shstrndx exceeds shared headers table entries count: expected (<%zu), got (%zu)",
                size_t(header.shnum),
                size_t(header.shstrndx));
    }
    if (header.shstrndx) {
        const auto shstrtab = ELF::SectionHeader32::FromBytes(
            d.buffer + header.shoff + header.shstrndx * kSectionHeaderSize,
            header.ident.data_encoding);
        char *error = ValidateSectionHeader(d, shstrtab, header.shstrndx, ".shstrtab");
        if (error != nullptr) {
            return error;
        }
    }
    if (d.size < header.phoff + header.phentsize * header.phnum) {
        return Error(
                "data size (%zu) is lower than program header table end offset (%zu): "
                "program header table could not fit",
                d.size,
                size_t(header.phoff + header.phentsize * header.phnum));
    }
    bool has_segment_with_entry = false;
    for (size_t i = 0; i < header.phnum; i++) {
        const auto ph = ProgramHeader32::FromBytes(
                d.buffer + header.phoff + header.phentsize * i, header.ident.data_encoding);
        if (d.size < ph.offset + ph.filesz) {
            return Error(
                    "data size (%zu) is lower than pht[%zu] segment end offset (%zu): "
                    "segment could not fit",
                    d.size,
                    i,
                    size_t(ph.offset + ph.filesz));
        }
        const bool is_code = (ph.flags & (kPHFlagX | kPHFlagW | kPHFlagR)) == (kPHFlagX | kPHFlagR);
        if (ParsePHType(ph.type) == PHType::kLoad && is_code && ph.vaddr != 0) {
            return Error(
                    "pht[%zu] segment is a code, but it's vaddr (0x%08x) is not zero: "
                    "non-zero base address is not supported",
                    i,
                    ph.vaddr);
        }
        const bool contains_entry = header.entry >= ph.vaddr && header.entry < ph.vaddr + ph.memsz;
        if (ParsePHType(ph.type) == PHType::kLoad && is_code && contains_entry) {
            has_segment_with_entry = true;
        }
    }
    if (!has_segment_with_entry) {
        return Error("no code segments containing entry point (0x%08x) found", header.entry);
    }
    return nullptr;
}

ELF::Image::Image(DataBuffer&& data)
    : _data(static_cast<DataBuffer&&>(data))
    , _error(ValidateELF(_data.View()))
    , _h(_error ? ELF::Header32{} : ELF::Header32::FromBytes(_data.View().buffer))
    , _pht(_error
            ? ELF::ProgramHeader32Table{}
            : ELF::ProgramHeader32Table::FromView(
                _data.View(_h.phoff, _h.phnum * kProgramHeaderSize), _h.ident.data_encoding))
    , _shstrtab(_error
            ? ELF::SectionHeader32{}
            : ELF::SectionHeader32::FromBytes(
                _data.buffer + _h.shoff + _h.shstrndx * kSectionHeaderSize, _h.ident.data_encoding))
    , _symtab(GetSectionHeaderByName(".symtab"))
    , _strtab(GetSectionHeader(_symtab.link))
{}

ELF::SectionHeader32 ELF::Image::GetSectionHeaderByName(const char *name) const
{
    const uint32_t index = GetSectionHeaderIndexByName(name);
    if (index == 0) {
        return SectionHeader32{};
    }
    const size_t offset = _h.shoff + kSectionHeaderSize * index;
    return SectionHeader32::FromBytes(_data.buffer + offset, _h.ident.data_encoding);
}

uint32_t ELF::Image::GetSectionHeaderIndexByName(const char *name) const
{
    if (!IsValid()) {
        return 0;
    }
    if (name == nullptr) {
        return 0;
    }
    if (!_shstrtab.IsValid()) {
        return 0;
    }
    for (uint32_t index = 0; index < _h.shnum; index++) {
        const size_t offset = _h.shoff + kSectionHeaderSize * index;
        if (offset + kSectionHeaderSize > _data.buffer_size) {
            return 0;
        }
        const auto header = SectionHeader32::FromBytes(
                _data.buffer + offset, _h.ident.data_encoding);
        const char *name_in_elf = reinterpret_cast<const char *>(
                _data.buffer + _shstrtab.offset + header.name);
        if (0 == strcmp(name, name_in_elf)) {
            return index;
        }
    }
    return 0;
}

ELF::Image::~Image()
{
    if (_error) {
        free(_error);
    }
    if (_pht.headers) {
        delete [] _pht.headers;
    }
}
