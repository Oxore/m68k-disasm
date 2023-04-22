#pragma once

struct Settings {
};

constexpr size_t kInstructionSizeStepBytes = 2;
constexpr size_t kRomSizeBytes = 4 * 1024 * 1024;
constexpr size_t kDisasmMapSizeElements = kRomSizeBytes / kInstructionSizeStepBytes;

static inline size_t Min(size_t a, size_t b) { return a < b ? a : b; }

static inline uint16_t GetU16BE(uint8_t *buffer)
{
    return (static_cast<uint16_t>(buffer[0]) << 8) | static_cast<uint16_t>(buffer[1]);
}

static inline int16_t GetI16BE(uint8_t *buffer)
{
    return (static_cast<uint16_t>(buffer[0]) << 8) | static_cast<uint16_t>(buffer[1]);
}

static inline int32_t GetI32BE(uint8_t *buffer)
{
    return (static_cast<uint32_t>(buffer[0]) << 24) |
        (static_cast<uint32_t>(buffer[1]) << 16) |
        (static_cast<uint32_t>(buffer[2]) << 8) |
        static_cast<uint32_t>(buffer[3]);
}
