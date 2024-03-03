#pragma once

/* SPDX-License-Identifier: Unlicense
 */

#include "elf_format.h"
#include "data_buffer.h"

#include <cstdlib>

namespace ELF {

struct ProgramHeader32Table {
    const ProgramHeader32 *headers{};
    size_t size{};
    static ProgramHeader32Table FromView(const DataView &, DataEncoding);
};

struct Segment {
    Segment *next{};
    const DataView view{};
};

class Image {
    const DataBuffer _data;
    char *const _error;
    const Header32 _h;
    const ProgramHeader32Table _pht;
    const SectionHeader32 _shstrtab, _symtab, _strtab;
public:
    explicit Image(DataBuffer&&);
    ~Image();
    constexpr bool IsValid() const { return _error == nullptr; }
    constexpr const DataBuffer &Data() const { return _data; };
    constexpr const DataView ProgramView() const
    {
        if (!IsValid()) {
            return DataView{};
        }
        for (size_t i = 0; i < _pht.size; i++) {
            const auto ph = _pht.headers[i];
            const bool is_code = (ph.flags & (kPHFlagX | kPHFlagW | kPHFlagR)) ==
                (kPHFlagX | kPHFlagR);
            const bool is_load = ParsePHType(ph.type) == PHType::kLoad;
            const bool contains_entry = _h.entry >= ph.vaddr && _h.entry < ph.vaddr + ph.memsz;
            if (is_load && is_code && ph.vaddr == 0 && contains_entry)
            {
                return _data.View(ph.offset, ph.filesz);
            }
        }
        return DataView{};
    };
    constexpr const char *Error() const { return _error; }
    ELF::SectionHeader32 GetSectionHeaderByName(const char *name) const;
    constexpr const ELF::SectionHeader32 GetSectionHeader(uint32_t index) const
    {
        if (index > _h.shnum) {
            return SectionHeader32{};
        }
        const size_t offset = _h.shoff + kSectionHeaderSize * index;
        if (offset + kSectionHeaderSize > _data.buffer_size) {
            return SectionHeader32{};
        }
        return SectionHeader32::FromBytes(
                _data.buffer + offset, _h.ident.data_encoding);
    }
    uint32_t GetSectionHeaderIndexByName(const char *name) const;
    constexpr ELF::Symbol32 GetSymbolByIndex(uint32_t index) const
    {
        if (!IsValid()) {
            return Symbol32{};
        }
        if (_symtab.entsize == 0 || index >= _symtab.size / _symtab.entsize) {
            return Symbol32{};
        }
        auto symbol = Symbol32::FromBytes(
                _data.buffer + _symtab.offset + _symtab.entsize * index,
                _h.ident.data_encoding);
        if (symbol.namendx < _strtab.size && _data.buffer[_strtab.offset + _strtab.size] == '\0') {
            symbol.name = reinterpret_cast<const char *>(
                    _data.buffer + _strtab.offset + symbol.namendx);
        }
        return symbol;
    }
};

}
