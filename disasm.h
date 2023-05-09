#pragma once

#include "data_buffer.h"
#include "common.h"

#include <cstddef>
#include <cstdint>

enum class OpCode: uint8_t {
    kNone = 0,
    kORI,
    kANDI,
    kSUBI,
    kADDI,
    kEORI,
    kCMPI,
    kBTST,
    kBCHG,
    kBCLR,
    kBSET,
    kMOVEP,
    kMOVEA,
    kMOVE,
    kNEGX,
    kCLR,
    kNEG,
    kNOT,
    kEXT,
    kNBCD,
    kSWAP,
    kPEA,
    kILLEGAL,
    kTAS,
    kTST,
    kTRAP,
    kLINK,
    kUNLK,
    kRESET,
    kNOP,
    kSTOP,
    kRTE,
    kRTS,
    kTRAPV,
    kRTR,
    kJSR,
    kJMP,
    kMOVEM,
    kLEA,
    kCHK,
    kADDQ,
    kSUBQ,
    kScc,
    kDBcc,
    kBcc,
    kMOVEQ,
    kDIVU,
    kDIVS,
    kSBCD,
    kOR,
    kSUB,
    kSUBX,
    kSUBA,
    kEOR,
    kCMPM,
    kCMP,
    kCMPA,
    kMULU,
    kMULS,
    kABCD,
    kEXG,
    kAND,
    kADD,
    kADDX,
    kADDA,
    kASR,
    kASL,
    kLSR,
    kLSL,
    kROXR,
    kROXL,
    kROR,
    kROL,
};

enum class Condition: uint8_t {
    kT,
    kBRA = kT,
    kF,
    kBSR = kF,
    kHI,
    kLS,
    kCC,
    kCS,
    kNE,
    kEQ,
    kVC,
    kVS,
    kPL,
    kMI,
    kGE,
    kLT,
    kGT,
    kLE,
};

enum class SizeSpec: uint8_t {
    kNone,
    kByte,
    kWord,
    kLong,
};

enum class ArgType: uint8_t {
    kNone,
    kDn, ///< Dn
    kAn, ///< An
    kAnAddr, ///< (An)
    kAnAddrIncr, ///< (An)+
    kAnAddrDecr, ///< -(An)
    kD16AnAddr, ///< (d16,An)
    kD8AnXiAddr, ///< (d8,An,Xi)
    kWord, ///< (xxx).W
    kLong, ///< (xxx).L
    kD16PCAddr, ///< (d16,PC)
    kD8PCXiAddr, ///< (d8,PC,Xn)
    kImmediate, ///< #imm
    kRegMask,
    kDisplacement, ///< BRA, BSR, Bcc, DBcc
    kCCR,
    kSR,
    kUSP,
};

enum class RegKind: uint8_t {
    kDn,
    kAn,
};

struct D8AnPCXiAddr {
    RegKind kind; ///< Kind of Xi reg, for kD8AnXiAddr and kD8PCXiAddr
    uint8_t an; ///< ID number of An reg, for kD8AnXiAddr only
    uint8_t xi; ///< ID number of Xi reg, for kD8AnXiAddr and kD8PCXiAddr
    int8_t d8; ///< Displacement, for kD8AnXiAddr and kD8PCXiAddr
};

struct D16AnPCAddr {
    uint8_t an; ///< ID number of An reg, for kD16AnAddr only
    int16_t d16; ///< Displacement, for D16AnAddr and kD16PCAddr
};

static_assert(sizeof(D8AnPCXiAddr) == sizeof(uint32_t), "");
static_assert(sizeof(D16AnPCAddr) == sizeof(uint32_t), "");

struct Arg {
    using Self = Arg;
    ArgType type{ArgType::kNone};
    union {
        int32_t lword{}; ///< kLong, kWord, kDisplacement
        uint16_t uword; ///< kRegMask
        uint8_t xn; ///< kDn, kAn, kAnAddr, kAnAddrIncr, kAnAddrDecr
        D16AnPCAddr d16_an; ///< kD16AnAddr
        D16AnPCAddr d16_pc; ///< kD16PCAddr
        D8AnPCXiAddr d8_an_xi; ///< kD8AnXiAddr
        D8AnPCXiAddr d8_pc_xi; ///< kD8PCXiAddr
    };
    static constexpr Self None() { return Arg{}; }
};

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
    ReferenceNode *ref_by{};
    ReferenceNode *last_ref_by{};
    OpCode opcode{OpCode::kNone}; ///< Should replace `mnemonic` field
    /// Size specifier, the suffix `b`, `w` or `l`
    SizeSpec size_spec{SizeSpec::kNone};
    Condition condition{Condition::kT}; ///< For Scc, Bcc and Dbcc
    Arg args[2]{}; ///< Should replace `arguments` field
    void Disasm(const DataBuffer &code, const Settings&);
    void AddReferencedBy(uint32_t offset, ReferenceType);
    ~DisasmNode();
private:
};
