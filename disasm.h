#pragma once

#include "data_buffer.h"
#include "common.h"

#include <cstddef>
#include <cstdint>

enum class TracedNodeType {
    kInstruction,
    kData,
};

constexpr size_t kMnemonicBufferSize{10};
constexpr size_t kArgsBufferSize{50};

struct DisasmNode {
    TracedNodeType type{};
    uint32_t offset{};
    size_t size{kInstructionSizeStepBytes}; // Instruction size in bytes
    bool has_branch_addr{};
    uint32_t branch_addr{}; // Absolute address of where to branch to
    char mnemonic[kMnemonicBufferSize]{}; // Mnemonic of the instruction at the current offset
    char arguments[kArgsBufferSize]{}; // Formatted arguments of the instruction
    void Disasm(const DataBuffer &code);
};
