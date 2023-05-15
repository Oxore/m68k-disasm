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

constexpr unsigned kRelocRelMask = 1;
constexpr unsigned kRelocAbsMask = 2;
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
