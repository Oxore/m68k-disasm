#pragma once

#include "data_buffer.h"
#include "common.h"

#include <cstddef>
#include <cstdint>

enum class TracedNodeType {
    kInstruction,
    kData,
};

constexpr size_t kRefsCountPerBuffer = 10;

constexpr size_t kMnemonicBufferSize = 8;
constexpr size_t kArgsBufferSize = 80;

enum class ReferenceType {
    kUnknown = 0,
    kBranch,
    kCall,
};

struct ReferenceRecord {
    ReferenceType type{};
    uint32_t address{};
};

struct ReferenceNode {
    ReferenceNode *next{};
    ReferenceRecord refs[kRefsCountPerBuffer];
    uint32_t refs_count{};
};

struct DisasmNode {
    const TracedNodeType type{};
    /// Absolute offset of the instruction (PC value basically)
    const uint32_t offset{};
    /// Instruction size in bytes
    size_t size{kInstructionSizeStepBytes};
    /// Indicates whether `branch_addr` should be interpreted
    bool has_branch_addr{};
    /// Absolute address of where to branch to
    uint32_t branch_addr{};
    /// Indicates whether instruction is a call (BSR, JSR) or just a branch
    /// (Bcc, JMP) if `has_branch_addr` is set
    bool is_call{};
    /// Mnemonic of the instruction at the current offset
    char mnemonic[kMnemonicBufferSize]{};
    /// Formatted arguments of the instruction;
    char arguments[kArgsBufferSize]{};
    /// Additional instruction specific info to put in a comment
    char additional[kArgsBufferSize]{};
    /// Additional instruction specific info to put in a comment
    ReferenceNode *ref_by{};
    ReferenceNode *last_ref_by{};
    void Disasm(const DataBuffer &code, const Settings&);
    void AddReferencedBy(uint32_t offset, ReferenceType);
    ~DisasmNode();
private:
};
