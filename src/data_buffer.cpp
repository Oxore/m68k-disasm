/* SPDX-License-Identifier: Unlicense
 */

#include "data_buffer.h"

#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <cstring>

void DataBuffer::Expand(size_t new_size)
{
    assert(buffer);
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

DataBuffer DataBuffer::FromStream(FILE *stream)
{
    DataBuffer db{};
    assert(db.buffer && db.buffer_size >= db.kInitialSize);
    while (1) {
        const size_t read_size = db.buffer_size - db.occupied_size;
        const size_t fread_ret = fread(
                db.buffer + db.occupied_size, sizeof(*db.buffer), read_size, stream);
        db.occupied_size += fread_ret;
        if (fread_ret >= db.buffer_size) {
            assert(fread_ret == db.buffer_size);
            db.Expand(db.buffer_size * 2);
        } else {
            const int err = errno;
            if (feof(stream)) {
                break;
            } else if (ferror(stream)) {
                fprintf(
                        stderr,
                        "DataBuffer::FromStream: fread(%zu): "
                        "Error (%d): \"%s\"\n",
                        read_size,
                        err,
                        strerror(err));
            } else if (db.buffer_size == db.occupied_size) {
                db.Expand(db.buffer_size * 2);
            } else {
                assert(false);
            }
        }
    }
    return db;
}
