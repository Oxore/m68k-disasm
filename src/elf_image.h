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
    static ProgramHeader32Table FromBytes(const DataView &, DataEncoding);
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
};

}
