#pragma once

/* SPDX-License-Identifier: Unlicense
 */

#include "common.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>

struct DataView {
    const uint8_t *const buffer{};
    const size_t size{};
};

struct DataBuffer {
    DataBuffer(){};
    DataBuffer(const DataBuffer&) = delete;
    constexpr DataBuffer(DataBuffer&& other)
        : buffer(other.buffer)
        , buffer_size(other.buffer_size)
        , occupied_size(other.occupied_size)
    {
        other.occupied_size = 0;
        other.buffer_size = 0;
        other.buffer = nullptr;
    };
    static constexpr size_t kInitialSize = 4 * 1024;
    uint8_t *buffer{new uint8_t[kInitialSize]};
    size_t buffer_size{kInitialSize};
    size_t occupied_size{};
    void Expand(size_t new_size);
    constexpr auto View(size_t offset = 0, size_t size = SIZE_MAX) const
    {
        if (offset >= occupied_size) {
            return DataView{};
        }
        return DataView{buffer + offset, Min(occupied_size - offset, size)};
    };
    ~DataBuffer();
    static DataBuffer FromStream(FILE *stream);
};
