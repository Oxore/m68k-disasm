#pragma once

/* SPDX-License-Identifier: Unlicense
 */

#include <cstddef>
#include <cstdint>

enum class BFDTarget {
    kAuto,
    kBinary,
    kELF,
};

enum class SplitPointType {
    kLabel = 0,
    kFunction,
};

enum class TargetAssembler {
    kGnuAs = 0,
    kSierraAsm68,
};

struct SplitParams {
    SplitPointType type{};
    size_t alignment{};
};

struct Settings {
    bool raw_data_comment{};
    bool raw_data_comment_all{};
    bool labels{};
    bool rel_labels{};
    bool abs_labels{};
    bool imm_labels{};
    bool short_ref_local_labels{};
    bool export_labels{};
    bool export_all_labels{};
    bool export_functions{};
    bool xrefs_to{};
    bool xrefs_from{};
    bool imm_hex{};
    bool follow_jumps{};
    bool walk{};
    bool symbols{};
    bool dot_size_spec{};
    BFDTarget bfd{};
    const char *indent{"\t"};
    const char *output_dir_path{};
    SplitParams split{};
    TargetAssembler target_asm{};
};

using RefKindMask = unsigned;

constexpr RefKindMask kRef1RelMask = (1 << 0); // For first argument
constexpr RefKindMask kRef1AbsMask = (1 << 1); // For first argument
constexpr RefKindMask kRef2RelMask = (1 << 2); // For second argument
constexpr RefKindMask kRef2AbsMask = (1 << 3); // For second argument
constexpr RefKindMask kRef1ReadMask = (1 << 4); // For first argument
constexpr RefKindMask kRef1WriteMask = (1 << 5); // For first argument
constexpr RefKindMask kRef2ReadMask = (1 << 6); // For second argument
constexpr RefKindMask kRef2WriteMask = (1 << 7); // For second argument
/// Indicates whether instruction is a call or just a branch, for any argument.
/// Calls are BSR and JSR, branches are DBcc, Bcc and JMP.
constexpr RefKindMask kRefCallMask = (1 << 8);
/// Hack flag for MOVEM with PC relative value when -frel-labels is set
constexpr RefKindMask kRefPcRelFix2Bytes = (1 << 9);
/// Register 1 may have immediate moving to address register which may be a
/// labeled location
constexpr RefKindMask kRef1ImmMask = (1 << 10);
/// Everything for first argument
constexpr RefKindMask kRef1Mask = kRef1RelMask | kRef1AbsMask | kRef1ReadMask | kRef1WriteMask | kRef1ImmMask;
/// Everything for Second argument
constexpr RefKindMask kRef2Mask = kRef2RelMask | kRef2AbsMask | kRef2ReadMask | kRef2WriteMask;
constexpr RefKindMask kRefRelMask = kRef1RelMask | kRef2RelMask;
constexpr RefKindMask kRefAbsMask = kRef1AbsMask | kRef2AbsMask;
constexpr RefKindMask kRef1DataMask = kRef1ReadMask | kRef1WriteMask; // For first argument
constexpr RefKindMask kRef2DataMask = kRef2ReadMask | kRef2WriteMask; // For second argument
constexpr RefKindMask kRefReadMask = kRef1ReadMask | kRef2ReadMask; // For any argument
constexpr RefKindMask kRefWriteMask = kRef1WriteMask | kRef2WriteMask; // For any argument
constexpr RefKindMask kRefDataMask = kRefReadMask | kRefWriteMask;
constexpr uint32_t kInstructionSizeStepBytes = 2;
constexpr uint32_t kRomSizeBytes = 4 * 1024 * 1024;
constexpr uint32_t kDisasmMapSizeElements = kRomSizeBytes / kInstructionSizeStepBytes;

static inline constexpr size_t Min(size_t a, size_t b) { return a < b ? a : b; }

static inline constexpr uint16_t GetU16BE(const void *buffer)
{
    const uint8_t *b = static_cast<const uint8_t *>(buffer);
    return (static_cast<uint16_t>(b[0]) << 8) | static_cast<uint16_t>(b[1]);
}

static inline constexpr uint16_t GetU16LE(const void *buffer)
{
    const uint8_t *b = static_cast<const uint8_t *>(buffer);
    return (static_cast<uint16_t>(b[1]) << 8) | static_cast<uint16_t>(b[0]);
}

static inline constexpr int16_t GetI16BE(const void *buffer)
{
    return GetU16BE(buffer);
}

static inline constexpr int16_t GetI16LE(const void *buffer)
{
    return GetU16LE(buffer);
}

static inline constexpr uint32_t GetU32BE(const void *buffer)
{
    const uint8_t *b = static_cast<const uint8_t *>(buffer);
    return (static_cast<uint32_t>(b[0]) << 24) |
        (static_cast<uint32_t>(b[1]) << 16) |
        (static_cast<uint32_t>(b[2]) << 8) |
        static_cast<uint32_t>(b[3]);
}

static inline constexpr uint32_t GetU32LE(const void *buffer)
{
    const uint8_t *b = static_cast<const uint8_t *>(buffer);
    return (static_cast<uint32_t>(b[3]) << 24) |
        (static_cast<uint32_t>(b[2]) << 16) |
        (static_cast<uint32_t>(b[1]) << 8) |
        static_cast<uint32_t>(b[0]);
}

static inline constexpr int32_t GetI32BE(const void *buffer)
{
    return GetU32BE(buffer);
}

static inline constexpr int32_t GetI32LE(const void *buffer)
{
    return GetU32LE(buffer);
}

static constexpr inline uint8_t GetU8(const void *d)
{
    return *static_cast<const uint8_t *>(d);
}

static constexpr inline uint8_t GetU8(const void *d, bool is_big_endian)
{
    return (void)is_big_endian, GetU8(d);
}

static constexpr inline int8_t GetI8(const void *d) { return GetU8(d); }

static constexpr inline int8_t GetI8(const void *d, bool is_big_endian)
{
    return (void)is_big_endian, GetI8(d);
}

static constexpr inline uint16_t GetU16(const void *d, bool is_big_endian)
{
    return is_big_endian ? GetU16BE(d) : GetU16LE(d);
}

static constexpr inline int16_t GetI16(const void *d, bool is_big_endian)
{
    return is_big_endian ? GetI16BE(d) : GetI16LE(d);
}

static constexpr inline uint32_t GetU32(const void *d, bool is_big_endian)
{
    return is_big_endian ? GetU32BE(d) : GetU32LE(d);
}

static constexpr inline int32_t GetI32(const void *d, bool is_big_endian)
{
    return is_big_endian ? GetI32BE(d) : GetI32LE(d);
}
