/* SPDX-License-Identifier: Unlicense
 */

#pragma once

struct Settings {
    bool marks{};
    bool rel_marks{};
    bool abs_marks{};
    bool xrefs_to{};
    bool xrefs_from{};
    bool raw_data_comment{};
};

using RefKindMask = unsigned;

constexpr RefKindMask kRef1RelMask = (1 << 0); // For first argument
constexpr RefKindMask kRef1AbsMask = (1 << 1); // For first argument
constexpr RefKindMask kRef2RelMask = (1 << 2); // For second argument
constexpr RefKindMask kRef2AbsMask = (1 << 3); // For second argument
/// Indicates whether instruction is a call or just a branch, for any argument.
/// Calls are BSR and JSR, branches are DBcc, Bcc and JMP.
constexpr RefKindMask kRefCallMask = (1 << 4);
constexpr RefKindMask kRefReadMask = (1 << 5); // For any argument
constexpr RefKindMask kRefWriteMask = (1 << 6); // For any argument
constexpr RefKindMask kRefRelMask = kRef1RelMask | kRef2RelMask;
constexpr RefKindMask kRefAbsMask = kRef1AbsMask | kRef2AbsMask;
constexpr RefKindMask kRef1Mask = kRef1RelMask | kRef1AbsMask; // For first argument
constexpr RefKindMask kRef2Mask = kRef2RelMask | kRef2AbsMask; // For second argument
constexpr RefKindMask kRefDataMask = kRefReadMask | kRefWriteMask;
constexpr size_t kInstructionSizeStepBytes = 2;
constexpr size_t kRomSizeBytes = 4 * 1024 * 1024;
constexpr size_t kDisasmMapSizeElements = kRomSizeBytes / kInstructionSizeStepBytes;

static inline constexpr size_t Min(size_t a, size_t b) { return a < b ? a : b; }

static inline constexpr uint16_t GetU16BE(uint8_t *buffer)
{
    return (static_cast<uint16_t>(buffer[0]) << 8) | static_cast<uint16_t>(buffer[1]);
}

static inline constexpr int16_t GetI16BE(uint8_t *buffer)
{
    return (static_cast<uint16_t>(buffer[0]) << 8) | static_cast<uint16_t>(buffer[1]);
}

static inline constexpr int32_t GetI32BE(uint8_t *buffer)
{
    return (static_cast<uint32_t>(buffer[0]) << 24) |
        (static_cast<uint32_t>(buffer[1]) << 16) |
        (static_cast<uint32_t>(buffer[2]) << 8) |
        static_cast<uint32_t>(buffer[3]);
}
