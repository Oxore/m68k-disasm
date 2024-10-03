#pragma once

/* SPDX-License-Identifier: Unlicense
 */

#include "elf_image.h"
#include "common.h"
#include "m68k.h"

#include <cstdint>
#include <cstddef>

enum class ReferenceType {
    kUnknown = 0,
    kCall,
    kBranch,
    kRead,
    kWrite,
};

struct ReferenceRecord {
    ReferenceType type{};
    uint32_t address{};
};

constexpr size_t kRefsCountPerBuffer = 10;

struct ReferenceNode {
    ReferenceNode *next{};
    ReferenceRecord refs[kRefsCountPerBuffer];
    uint32_t refs_count{};
};

enum class NodeType {
    kTracedInstruction,
    kRefInstruction,
    kData,
};

struct DisasmNode {
    const NodeType type{};
    /// Address of the instruction (PC value basically)
    const uint32_t address{};
    /// Instruction size in bytes
    size_t size{kInstructionSizeStepBytes};
    /// Indicates whether `ref_addr` should be interpreted and how
    RefKindMask ref_kinds{};
    /// Address of first argument reference
    uint32_t ref1_addr{};
    /// Address of second argument reference
    uint32_t ref2_addr{};
    ReferenceNode *ref_by{};
    ReferenceNode *last_ref_by{};
    Op op{};

    /*! Disassembles instruction with arguments
     * returns size of whole instruction with arguments in bytes
     */
    size_t Disasm(const DataView &code, const Settings &);
    size_t DisasmAsRaw(const DataView &code);
    void AddReferencedBy(uint32_t address, ReferenceType);
    ~DisasmNode();
};

static constexpr inline bool IsInstruction(NodeType t)
{
    return t == NodeType::kTracedInstruction || t == NodeType::kRefInstruction;
}

enum class SymbolType: int {
    kNone = 0,
    kFunction,
    kObject,
};

struct Symbol {
    uint32_t address{};
    SymbolType type{};
    const char *name{};
    size_t size{};
};

enum class DisasmMapType {
    kTraced,
    kRaw,
};

class DisasmMap {
    const DisasmMapType _type;
    DisasmNode *_map[kDisasmMapSizeElements]{};
    Symbol *_symtab{};
    size_t _symtab_size{};
    constexpr DisasmNode *findNodeByAddress(uint32_t address) const;
    constexpr size_t findFirstSymbolAtAddress(
            uint32_t address, bool return_last_considered=false) const;
    DisasmNode &insertNode(uint32_t address, NodeType);
    void insertSymbol(uint32_t address, ReferenceType ref_type);
    DisasmNode &insertReferencedBy(
            const uint32_t by_addr,
            const uint32_t ref_addr,
            const NodeType type,
            const ReferenceType ref_type);
    constexpr bool canBeAllocated(const DisasmNode& node) const;
    constexpr size_t symbolsCount() const { return _symtab_size / sizeof *_symtab; }
public:
    constexpr const Symbol *Symtab() const { return _symtab; }
    constexpr size_t SymbolsCount() const { return symbolsCount(); }
    constexpr const char *GetFirstSuitableSymbol(const DisasmNode &, bool is_call) const;
    constexpr bool HasSymbolsInRange(uint32_t at, size_t length) const;
    constexpr const DisasmNode *FindNodeByAddress(uint32_t address) const
    {
        return findNodeByAddress(address);
    };
    void InsertNode(uint32_t address, NodeType type);
    bool ApplySymbolsFromElf(const ELF::Image &);
    void Disasm(const DataView &code, const Settings &, size_t from=0, bool nested=false);
    DisasmMap(DisasmMapType type): _type(type) {}
    ~DisasmMap();
};

constexpr DisasmNode *DisasmMap::findNodeByAddress(uint32_t address) const
{
    if (address < kRomSizeBytes)
        return _map[address / kInstructionSizeStepBytes];
    return nullptr;
}

constexpr size_t DisasmMap::findFirstSymbolAtAddress(
        uint32_t address, bool return_last_considered) const
{
    if (_symtab == nullptr || symbolsCount() < 1) {
        return 0;
    }
    // A symbol at index 0 is a special null symbol and it must be skipped.
    size_t start = 1, len = symbolsCount() - start, middle = start, index = 0;
    while (1) {
        if (len == 0) {
            if (return_last_considered && index == 0) {
                index = start;
            }
            break;
        }
        middle = start + len / 2;
        if (_symtab[middle].address >= address) {
            if (_symtab[middle].address == address) {
                index = middle;
            }
            // Look at the span right before the middle one on the next step
            len = middle - start;
        } else {
            // Look at the span right after the middle one on the next step
            len -= middle + 1 - start;
            start = middle + 1;
        }
    }
    return index;
}

static constexpr bool IsWithinRange(uint32_t const value, uint32_t at, size_t length)
{
    return value >= at && value < at + length;
}

constexpr bool DisasmMap::HasSymbolsInRange(
        uint32_t const address, size_t const length) const
{
    size_t index = findFirstSymbolAtAddress(address, true);
    if (index == 0) {
        // The symtab is empty
        return false;
    }
    if (IsWithinRange(_symtab[index].address, address, length)) {
        // The symbol is found right at the address, which is unlikely
        return true;
    }
    if (_symtab[index].address < address) {
        // Maybe the next symbol falls into the range?
        if (index + 1 >= symbolsCount()) {
            // No more symbols after the index
            return false;
        }
        index++;
    } else {
        // Maybe the previous symbol falls into the range? (unlikely at all)
        if (index < 2) {
            // No more symbols before the index
            return false;
        }
        index--;
    }
    if (IsWithinRange(_symtab[index].address, address, length)) {
        return true;
    }
    return false;
}

constexpr bool DisasmMap::canBeAllocated(const DisasmNode& node) const
{
    const auto size = node.size / kInstructionSizeStepBytes;
    const auto *const node_real = findNodeByAddress(node.address);
    for (size_t i = 1; i < size; i++) {
        const auto *const ptr = _map[node.address / kInstructionSizeStepBytes + i];
        if (ptr != nullptr && ptr != node_real) {
            return false;
        }
    }
    return true;
}

static constexpr ReferenceType ReferenceTypeFromRefKindMask1(const RefKindMask ref_kinds)
{
    return (ref_kinds & kRefCallMask)
        ? ReferenceType::kCall
        : (ref_kinds & kRef1ReadMask)
            ? ReferenceType::kRead
            : (ref_kinds & kRef1WriteMask)
                ? ReferenceType::kWrite
                : ReferenceType::kBranch;
}

static constexpr ReferenceType ReferenceTypeFromRefKindMask2(const RefKindMask ref_kinds)
{
    // FIXME: AFAIK it is impossible for a call instruction to have second
    // argument. I can probably drop the first condition, but it needs testing
    return (ref_kinds & kRefCallMask)
        ? ReferenceType::kCall
        : (ref_kinds & kRef2ReadMask)
            ? ReferenceType::kRead
            : (ref_kinds & kRef2WriteMask)
                ? ReferenceType::kWrite
                : ReferenceType::kBranch;
}
