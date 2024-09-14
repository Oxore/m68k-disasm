#pragma once

/* SPDX-License-Identifier: Unlicense
 *
 * Common Object File Format loader implementation.
 *
 * A section "11. COMMON OBJECT FILE FORMAT (COFF)" from the document named
 * "SYSTEM V/68 Release 3 Programmer's Guide" or "MU43715PG/D2" dated 12/01/87
 * was used for reference to implement this functionality.
 *
 * A "TI-89 / TI-92 Plus Sierra C Assembler Reference Manual, Beta Version"
 * dated "February 2, 2001" was used for reference to implement this
 * functionality.
 */

#include "common.h"

#include <cstdint>

namespace COFF {

constexpr size_t kFileHeaderSize = 20;
constexpr size_t kOptionalHeaderSize = 28;
constexpr size_t kSectionHeaderSize = 40;

/// Relocation information stripped from the file
constexpr uint16_t F_RELFG = 0x1;
/// File is executable (i.be. no unresolved external references)
constexpr uint16_t F_EXEC = 0x2;
/// Line numbers stripped from the file
constexpr uint16_t F_LNNO = 0x4;
/// Local symbols stripped from the file
constexpr uint16_t F_LSYMS = 0x8;
/// Global symbols stripped from the file
constexpr uint16_t F_GSYMS = 0x10;
/// Error in object file
constexpr uint16_t F_ERROR = 0x80;

struct FileHeader {
    uint16_t magic; ///< Magic number
    /// Number of section headers (equals to number of sections)
    uint16_t nsections;
    /// Time and date stamp indicating when the file was created, expressed as
    /// the number of elapsed seconds since 00:00:00 GMT, January 1, 1970
    int32_t timedate;
    /// File pointer containing the starting address of the symbol table
    uint32_t symtable_offset;
    uint32_t nsymbols; ///< Number of entries in the symbol table
    uint16_t optional_header_nbytes; ///< Number of bytes in the optional header
    uint16_t flags; ///< Flags (see F_* constexpr values)
    static constexpr inline auto FromBytes(const uint8_t *data)
    {
        const bool be = true;
        return FileHeader{
            /* .magic */ GetU16(data + 0, be),
            /* .nsections */ GetU16(data + 2, be),
            /* .timedate */ GetI32(data + 4, be),
            /* .symtable_offset */ GetU32(data + 8, be),
            /* .nsymbols */ GetU32(data + 12, be),
            /* .optional_header_nbytes */ GetU16(data + 16, be),
            /* .flags */ GetU16(data + 18, be),
        };
    }
    static constexpr uint16_t kMagicSierraM68k = 0x150;
};

struct OptionalHeader {
    uint16_t magic; ///< Magic number
    uint16_t version; ///< Version stamp
    uint32_t tsize; ///< Size of text in bytes
    uint32_t dsize; ///< Size of initialized data in bytes
    uint32_t bsize; ///< Size of uninitialized data in bytes
    uint32_t entry; ///< Program entry point
    uint32_t text_start; ///< Base address of text
    uint32_t data_start; ///< Base address of data
    static constexpr inline auto FromBytes(const uint8_t *data)
    {
        const bool be = true;
        return OptionalHeader{
            /* .magic */ GetU16(data + 0, be),
            /* .version */ GetU16(data + 2, be),
            /* .tsize */ GetU32(data + 4, be),
            /* .dsize */ GetU32(data + 8, be),
            /* .bsize */ GetU32(data + 12, be),
            /* .entry */ GetU32(data + 16, be),
            /* .text_start */ GetU32(data + 20, be),
            /* .data_start */ GetU32(data + 24, be),
        };
    }
};

enum class SectionType: uint32_t {
    /// Regular section (allocated, relocated, loaded)
    Regular = 0,
    /// Dummy section (not allocated, relocated, not loaded)
    Dummy = 0x1,
    /// Noload section (allocated, relocated, not loaded)
    NoLoad = 0x2,
    /// Grouped section (formed from input sections)
    Grouped = 0x4,
    /// Padding section (not allocated, not relocated, loaded)
    Padding = 0x8,
    /// Copy section (for a decision function used in updating fields; not
    /// allocated, not relocated, loaded, relocation and line number entries
    /// processed normally)
    Copy = 0x10,
    /// Section contains executable text
    Text = 0x20,
    /// Section contains initialized data
    Data = 0x40,
    /// Section contains only uninitialized data
    Bss = 0x80,
    /// Section contains ORG'd (absolute) data
    Org = 0x100,
    /// Comment section (not allocated, not relocated, not loaded)
    Info = 0x200,
    /// Overlay section (not allocated, relocated, not loaded)
    Overlay = 0x400,
    /// For .lib section (treated like STYP_INFO)
    Lib = 0x800,
};

struct SectionHeader {
    char name[8]; ///< 8-character null-padded section name
    uint32_t paddr; ///< Physical address of section
    uint32_t vaddr; ///< Virtual address of section
    uint32_t size; ///< Seciton size in bytes
    uint32_t section_offset; ///< File pointer to raw data
    uint32_t reloc_offset; ///< File pointer to relocation entries
    uint32_t lineno_offset; ///< File pointer to line number entries
    uint16_t nreloc; ///< Number of relocation entries
    uint16_t nlineno; ///< Number of line number entries
    uint32_t flags; ///< Flags (see STYP_* constexpr values)
    static constexpr inline auto FromBytes(const void *data)
    {
        const uint8_t *d = static_cast<const uint8_t *>(data);
        const char *c = static_cast<const char *>(data);
        const bool be = true;
        return SectionHeader{
            /* .name */ {
                c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7],
            },
            /* .paddr */ GetU32(d + 8, be),
            /* .vaddr */ GetU32(d + 12, be),
            /* .size */ GetU32(d + 16, be),
            /* .section_offset */ GetU32(d + 20, be),
            /* .reloc_offset */ GetU32(d + 24, be),
            /* .lineno_offset */ GetU32(d + 28, be),
            /* .nreloc */ GetU16(d + 32, be),
            /* .nlineno */ GetU16(d + 34, be),
            /* .flags */ GetU32(d + 36, be),
        };
    }
};

}
