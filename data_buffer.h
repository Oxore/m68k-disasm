#pragma once

#include <cstddef>
#include <cstdint>

struct DataBuffer {
    static constexpr size_t kInitialSize = 4 * 1024;
    uint8_t *buffer{new uint8_t[kInitialSize]};
    size_t buffer_size{kInitialSize};
    size_t occupied_size{};
    void Expand(size_t new_size);
    ~DataBuffer();
};

