#pragma once

/* SPDX-License-Identifier: Unlicense
 */

#include <cstddef>
#include <cstdint>

namespace ELF {

constexpr size_t kIdentSize = 16;
constexpr size_t kHeaderSize = kIdentSize + 36;
constexpr size_t kMagicSize = 4;
constexpr size_t kProgramHeaderSize = 32;

using Address = uint32_t;
using Offset = uint32_t;

enum class FileClass : uint8_t {
    kNone = 0,
    k32 = 1,
    k64 = 2,
    kUnknown,
};

enum class DataEncoding : uint8_t {
    kNone = 0,
    k2LSB = 1,
    kLE = k2LSB,
    k2MSB = 2,
    kBE = k2MSB,
    kUnknown,
};

enum class Version : uint8_t {
    kNone = 0,
    kCurrent = 1,
    kUnknown,
};

static constexpr inline auto ParseFileClass(const uint8_t file_class)
{
    switch (file_class) {
    case static_cast<uint8_t>(FileClass::kNone): return FileClass::kNone;
    case static_cast<uint8_t>(FileClass::k32): return FileClass::k32;
    case static_cast<uint8_t>(FileClass::k64): return FileClass::k64;
    }
    return FileClass::kUnknown;
}

static constexpr inline auto ParseDataEncoding(const uint8_t data_encoding)
{
    switch (data_encoding) {
    case static_cast<uint8_t>(DataEncoding::kNone): return DataEncoding::kNone;
    case static_cast<uint8_t>(DataEncoding::k2LSB): return DataEncoding::k2LSB;
    case static_cast<uint8_t>(DataEncoding::k2MSB): return DataEncoding::k2MSB;
    }
    return DataEncoding::kUnknown;
}

static constexpr inline auto ParseVersion(const uint8_t version)
{
    switch (version) {
    case static_cast<uint8_t>(Version::kNone): return Version::kNone;
    case static_cast<uint8_t>(Version::kCurrent): return Version::kCurrent;
    }
    return Version::kUnknown;
}

struct Ident32Raw {
    uint8_t magic[4];
    uint8_t file_class;
    uint8_t data_encoding;
    uint8_t version;
    uint8_t os_abi;
    uint8_t abi_version;
    uint8_t padding[7];
    static constexpr auto inline FromBytes(const uint8_t *data)
    {
        return Ident32Raw{
            { data[0], data[1], data[2], data[3] },
            data[4],
            data[5],
            data[6],
            data[7],
            data[8],
            { data[9], data[10], data[11], data[12], data[13], data[14], data[15], },
        };
    }
};

struct Ident32 {
    uint8_t magic[4];
    FileClass file_class;
    DataEncoding data_encoding;
    Version version;
    uint8_t os_abi;
    uint8_t abi_version;
    static constexpr inline auto FromBytes(const uint8_t *data)
    {
        return Ident32{
            { data[0], data[1], data[2], data[3] },
            ParseFileClass(data[4]),
            ParseDataEncoding(data[5]),
            ParseVersion(data[6]),
            data[7],
            data[8],
        };
    }
    static constexpr inline auto FromIdent32Raw(const Ident32Raw raw)
    {
        return Ident32{
            { raw.magic[0], raw.magic[1], raw.magic[2], raw.magic[3] },
            ParseFileClass(raw.file_class),
            ParseDataEncoding(raw.data_encoding),
            ParseVersion(raw.version),
            raw.os_abi,
            raw.abi_version,
        };
    }
};

enum class ObjectType : uint16_t {
    kNone = 0,
    kRel = 1,
    kExec = 2,
    kDyn = 3,
    kCore = 4,
    kUnknown = 0x7fff,
    kLoProc = 0xff00,
    kHiProc = 0xffff,
};

enum class Machine : uint16_t {
    kNone = 0,
    kM32 = 1,
    kSPARC = 2,
    k386 = 3,
    k68k = 4,
    k88k = 5,
    k860 = 7,
    kMIPS = 8,
    kUnknown,
};

static constexpr inline uint16_t ParseU16(const uint8_t *d, DataEncoding e)
{
    if (e == DataEncoding::k2MSB) {
        return uint16_t(d[0]) << 8 | d[1];
    }
    return uint16_t(d[1]) << 8 | d[0];
}

static constexpr inline uint32_t ParseU32(const uint8_t *d, DataEncoding e)
{
    if (e == DataEncoding::k2MSB) {
        return uint32_t(d[0]) << 24 | uint32_t(d[1]) << 16 | uint32_t(d[2]) << 8 | d[3];
    }
    return uint32_t(d[3]) << 24 | uint32_t(d[2]) << 16 | uint32_t(d[1]) << 8 | d[0];
}

static constexpr inline auto ParseObjectType(const uint16_t type)
{
    switch (type) {
    case static_cast<uint16_t>(ObjectType::kNone): return ObjectType::kNone;
    case static_cast<uint16_t>(ObjectType::kRel): return ObjectType::kRel;
    case static_cast<uint16_t>(ObjectType::kExec): return ObjectType::kExec;
    case static_cast<uint16_t>(ObjectType::kDyn): return ObjectType::kDyn;
    case static_cast<uint16_t>(ObjectType::kCore): return ObjectType::kCore;
    case static_cast<uint16_t>(ObjectType::kLoProc): return ObjectType::kLoProc;
    case static_cast<uint16_t>(ObjectType::kHiProc): return ObjectType::kHiProc;
    }
    return ObjectType::kUnknown;
}

static constexpr inline auto ParseMachine(const uint16_t machine)
{
    switch (machine) {
    case static_cast<uint16_t>(Machine::kNone): return Machine::kNone;
    case static_cast<uint16_t>(Machine::kM32): return Machine::kM32;
    case static_cast<uint16_t>(Machine::kSPARC): return Machine::kSPARC;
    case static_cast<uint16_t>(Machine::k386): return Machine::k386;
    case static_cast<uint16_t>(Machine::k68k): return Machine::k68k;
    case static_cast<uint16_t>(Machine::k88k): return Machine::k88k;
    case static_cast<uint16_t>(Machine::k860): return Machine::k860;
    case static_cast<uint16_t>(Machine::kMIPS): return Machine::kMIPS;
    }
    return Machine::kUnknown;
}

struct Header32Raw {
    Ident32Raw ident;
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    Address entry;
    Offset phoff;
    Offset shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
    static constexpr inline auto FromBytes(const uint8_t *data)
    {
        const auto ident = Ident32Raw::FromBytes(data);
        const DataEncoding e = ParseDataEncoding(ident.data_encoding);
        return Header32Raw{
            /* .ident */ ident,
            /* .type */ ParseU16(data + kIdentSize + 0, e),
            /* .machine */ ParseU16(data + kIdentSize + 2, e),
            /* .version */ ParseU32(data + kIdentSize + 4, e),
            /* .entry */ ParseU32(data + kIdentSize + 8, e),
            /* .phoff */ ParseU32(data + kIdentSize + 12, e),
            /* .shoff */ ParseU32(data + kIdentSize + 16, e),
            /* .flags */ ParseU32(data + kIdentSize + 20, e),
            /* .ehsize */ ParseU16(data + kIdentSize + 24, e),
            /* .phentsize */ ParseU16(data + kIdentSize + 26, e),
            /* .phnum */ ParseU16(data + kIdentSize + 28, e),
            /* .shentsize */ ParseU16(data + kIdentSize + 30, e),
            /* .shnum */ ParseU16(data + kIdentSize + 32, e),
            /* .shstrndx */ ParseU16(data + kIdentSize + 34, e),
        };
    }
};

struct Header32 {
    Ident32 ident;
    ObjectType type;
    Machine machine;
    Version version;
    Address entry;
    Offset phoff;
    Offset shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
    static constexpr inline auto FromBytes(const uint8_t *data)
    {
        const auto raw = Header32Raw::FromBytes(data);
        return Header32{
            Ident32::FromIdent32Raw(raw.ident),
            ParseObjectType(raw.type),
            ParseMachine(raw.machine),
            ParseVersion(raw.version),
            raw.entry,
            raw.phoff,
            raw.shoff,
            raw.flags,
            raw.ehsize,
            raw.phentsize,
            raw.phnum,
            raw.shentsize,
            raw.shnum,
            raw.shstrndx,
        };
    }
};

enum class PHType : uint32_t {
    kNull = 0,
    kLoad = 1,
    kDynamic = 2,
    kInterp = 3,
    kNote = 4,
    kSHLIB = 5,
    kProgramHeaderTable = 6,
    kLoProc = 0x70000000,
    kHiProc = 0x7fffffff,
    kUnknown,
};

static constexpr inline auto ParsePHType(const uint32_t type)
{
    switch (type) {
    case static_cast<uint32_t>(PHType::kNull): return PHType::kNull;
    case static_cast<uint32_t>(PHType::kLoad): return PHType::kLoad;
    case static_cast<uint32_t>(PHType::kDynamic): return PHType::kDynamic;
    case static_cast<uint32_t>(PHType::kInterp): return PHType::kInterp;
    case static_cast<uint32_t>(PHType::kNote): return PHType::kNote;
    case static_cast<uint32_t>(PHType::kSHLIB): return PHType::kSHLIB;
    case static_cast<uint32_t>(PHType::kProgramHeaderTable): return PHType::kProgramHeaderTable;
    case static_cast<uint32_t>(PHType::kLoProc): return PHType::kLoProc;
    case static_cast<uint32_t>(PHType::kHiProc): return PHType::kHiProc;
    }
    return PHType::kUnknown;
}

constexpr uint32_t kPHFlagX = 1 << 0;
constexpr uint32_t kPHFlagW = 1 << 1;
constexpr uint32_t kPHFlagR = 1 << 2;

struct ProgramHeader32 {
    uint32_t type;
    Offset offset;
    Address vaddr;
    Address paddr;
    uint32_t filesz;
    uint32_t memsz;
    uint32_t flags;
    uint32_t align;
    static constexpr inline auto FromBytes(const uint8_t *data, const DataEncoding e)
    {
        return ProgramHeader32{
            /* type */ ParseU32(data + 0, e),
            /* offset */ ParseU32(data + 4, e),
            /* vaddr */ ParseU32(data + 8, e),
            /* paddr */ ParseU32(data + 12, e),
            /* filesz */ ParseU32(data + 16, e),
            /* memsz */ ParseU32(data + 20, e),
            /* flags */ ParseU32(data + 24, e),
            /* align */ ParseU32(data + 28, e),
        };
    }
};

static constexpr inline bool MagicIsValid(const uint8_t *m)
{
    return m[0] == 0x7f && m[1] == 'E' && m[2] == 'L' && m[3] == 'F';
}

};
