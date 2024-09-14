#pragma once

/* SPDX-License-Identifier: Unlicense
 */

#include "coff.h"

#include "data_buffer.h"

namespace COFF {

class Image {
    const DataBuffer _data;
    char *const _error;
    const COFF::FileHeader _file_header;
    bool _has_optional_header;
    const COFF::OptionalHeader _optional_header;
public:
    explicit Image(DataBuffer&&);
    ~Image();
    constexpr bool IsValid() const { return _error == nullptr; }
    constexpr const DataBuffer &Data() const { return _data; };
    constexpr const char *Error() const { return _error; }
    constexpr const COFF::FileHeader &FileHeader() const { return _file_header; }
    constexpr bool HasOptionalHeader() const { return _has_optional_header; }
    constexpr const COFF::OptionalHeader &OptionalHeader() const { return _optional_header; }
    constexpr const COFF::SectionHeader GetSectionHeader(unsigned index) const
    {
        if (index > _file_header.nsections) {
            return SectionHeader{};
        }
        const size_t offset = COFF::kFileHeaderSize + _file_header.optional_header_nbytes +
            COFF::kSectionHeaderSize * index;
        if (offset + kSectionHeaderSize > _data.buffer_size) {
            return SectionHeader{};
        }
        return SectionHeader::FromBytes(_data.buffer + offset);
    }
    constexpr DataView GetSectionDataView(const COFF::SectionHeader &header) const
    {
        return DataView{_data.buffer + header.section_offset, header.size};
    }
};

}
