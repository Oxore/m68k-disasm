#include "data_buffer.h"

#include <cassert>
#include <cstring>

void DataBuffer::Expand(size_t new_size)
{
    if (new_size <= buffer_size) {
        return;
    }
    uint8_t *new_buffer{new uint8_t[new_size]};
    assert(new_buffer);
    memcpy(new_buffer, buffer, occupied_size);
    delete [] buffer;
    buffer = new_buffer;
    buffer_size = new_size;
}

DataBuffer::~DataBuffer()
{
    delete [] buffer;
    buffer = nullptr;
    buffer_size = 0;
    occupied_size = 0;
}
