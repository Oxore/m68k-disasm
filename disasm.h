/* SPDX-License-Identifier: Unlicense
 */

#pragma once

#include "data_buffer.h"
#include "common.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>

enum class OpSize: int {
    kByte = 0,
    kWord = 1,
    kLong = 2,
    kInvalid = 3,
    kNone = kInvalid,
    kShort, ///< Semantically is the same as kByte, pseudosize, used for Bcc
};

enum class OpCode: uint8_t {
    kNone,
    kRaw, ///< Emits ".short"
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
    kT = 0,
    kF = 1,
    kHI = 2,
    kLS = 3,
    kCC = 4,
    kCS = 5,
    kNE = 6,
    kEQ = 7,
    kVC = 8,
    kVS = 9,
    kPL = 10,
    kMI = 11,
    kGE = 12,
    kLT = 13,
    kGT = 14,
    kLE = 15,
};

enum class AddrMode: uint8_t {
    kInvalid = 0,
    kDn = 1,
    kAn = 2,
    kAnAddr = 3,
    kAnAddrIncr = 4,
    kAnAddrDecr = 5,
    kD16AnAddr = 6,
    kD8AnXiAddr = 7,
    kWord = 8,
    kLong = 9,
    kD16PCAddr = 10,
    kD8PCXiAddr = 11,
    kImmediate = 12,
};

enum class ArgType: uint8_t {
    kNone = 0,
    kDn = 1, ///< Dn
    kAn = 2, ///< An
    kAnAddr = 3, ///< (An)
    kAnAddrIncr = 4, ///< (An)+
    kAnAddrDecr = 5, ///< -(An)
    kD16AnAddr = 6, ///< (d16,An)
    kD8AnXiAddr = 7, ///< (d8,An,Xi)
    kWord = 8, ///< (xxx).W
    kLong = 9, ///< (xxx).L
    kD16PCAddr = 10, ///< (d16,PC)
    kD8PCXiAddr = 11, ///< (d8,PC,Xn)
    kImmediate = 12, ///< #imm
    kRegMask,
    kRegMaskPredecrement,
    kDisplacement, ///< For BRA, BSR, Bcc and DBcc
    kCCR,
    kSR,
    kUSP,
    kRaw, ///< Emits "0xXXXX" for ".short"
};

struct D8AnPCXiAddr {
    uint8_t an; ///< ID number of An reg, for kD8AnXiAddr only
    /*! ID number of Xi reg (3 lower bits), for kD8AnXiAddr and kD8PCXiAddr.
     * Bit 3 (mask 0x8) means 0 == Dn, 1 == An.
     * Bit 4 (mask 0x10) means 0 == Word, 1 == Long.
     */
    uint8_t xi;
    int8_t d8; ///< Displacement, for kD8AnXiAddr and kD8PCXiAddr
};

struct D16AnPCAddr {
    uint8_t an; ///< ID number of An reg, for kD16AnAddr only
    int16_t d16; ///< Displacement, for D16AnAddr and kD16PCAddr
};

static_assert(sizeof(D8AnPCXiAddr) <= sizeof(uint32_t), "");
static_assert(sizeof(D16AnPCAddr) <= sizeof(uint32_t), "");

struct Arg {
    union {
        ArgType type{ArgType::kNone};
        AddrMode mode;
    };
    union {
        int32_t lword{}; ///< kLong, kWord, kDisplacement, kImmediate
        uint16_t uword; ///< kRegMask, kRaw
        uint8_t xn; ///< kDn, kAn, kAnAddr, kAnAddrIncr, kAnAddrDecr
        D16AnPCAddr d16_an; ///< kD16AnAddr
        D16AnPCAddr d16_pc; ///< kD16PCAddr
        D8AnPCXiAddr d8_an_xi; ///< kD8AnXiAddr
        D8AnPCXiAddr d8_pc_xi; ///< kD8PCXiAddr
    };
    /// Size of the instruction extension: 0, 2 or 4 bytes
    constexpr size_t Size(const OpSize s) const
    {
        switch (mode) {
        case AddrMode::kInvalid:
        case AddrMode::kDn:
        case AddrMode::kAn:
        case AddrMode::kAnAddr:
        case AddrMode::kAnAddrIncr:
        case AddrMode::kAnAddrDecr:
            return 0;
        case AddrMode::kD16AnAddr:
        case AddrMode::kD8AnXiAddr:
        case AddrMode::kWord:
            return 2;
        case AddrMode::kLong:
            return 4;
        case AddrMode::kD16PCAddr:
        case AddrMode::kD8PCXiAddr:
            return 2;
        case AddrMode::kImmediate:
            // Byte and Word immediate are of 2 bytes length
            return s == OpSize::kLong ? 4 : 2;
        }
        return 0;
    }
    static constexpr auto AddrModeXn(const ArgType type, const uint8_t xn) {
        Arg a{type, 0};
        a.xn = xn;
        return a;
    }
    static constexpr auto Dn(const uint8_t xn) { return AddrModeXn(ArgType::kDn, xn); }
    static constexpr auto An(const uint8_t xn) { return AddrModeXn(ArgType::kAn, xn); }
    static constexpr auto AnAddr(const uint8_t xn) { return AddrModeXn(ArgType::kAnAddr, xn); }
    static constexpr auto AnAddrIncr(const uint8_t xn)
    {
        return AddrModeXn(ArgType::kAnAddrIncr, xn);
    }
    static constexpr auto AnAddrDecr(const uint8_t xn)
    {
        return AddrModeXn(ArgType::kAnAddrDecr, xn);
    }
    static constexpr auto D16AnAddr(const uint8_t xn, const int16_t d16)
    {
        Arg a{ArgType::kD16AnAddr, 0};
        a.d16_an = D16AnPCAddr{xn, d16};
        return a;
    }
    static constexpr auto D16PCAddr(const int16_t d16)
    {
        Arg a{ArgType::kD16PCAddr, 0};
        a.d16_pc = D16AnPCAddr{0, d16};
        return a;
    }
    static constexpr auto Word(const int16_t w)
    {
        Arg a{ArgType::kWord, 0};
        a.lword = w;
        return a;
    }
    static constexpr auto Long(const int32_t l)
    {
        Arg a{ArgType::kLong, 0};
        a.lword = l;
        return a;
    }
    static constexpr auto D8AnXiAddr(
            const uint8_t xn, const uint8_t xi, const OpSize s, const int8_t d8)
    {
        Arg a{ArgType::kD8AnXiAddr, 0};
        a.d8_an_xi = D8AnPCXiAddr{xn, uint8_t(xi | (s == OpSize::kLong ? 0x10u : 0u)), d8};
        return a;
    }
    static constexpr auto D8PCXiAddr(
            const uint8_t xn, const uint8_t xi, const OpSize s, const int8_t d8)
    {
        Arg a{ArgType::kD8PCXiAddr, 0};
        a.d8_pc_xi = D8AnPCXiAddr{xn, uint8_t(xi | (s == OpSize::kLong ? 0x10u : 0u)), d8};
        return a;
    }
    static constexpr auto Immediate(const int32_t value) {
        Arg a{ArgType::kImmediate, 0};
        a.lword = value;
        return a;
    }
    static constexpr auto RegMask(const uint16_t regmask) {
        Arg a{ArgType::kRegMask, 0};
        a.uword = regmask;
        return a;
    }
    static constexpr auto RegMaskPredecrement(const uint16_t regmask) {
        Arg a{ArgType::kRegMaskPredecrement, 0};
        a.uword = regmask;
        return a;
    }
    static constexpr auto Displacement(const int32_t displacement) {
        Arg a{ArgType::kDisplacement, 0};
        a.lword = displacement;
        return a;
    }
    static constexpr auto CCR() { return Arg{ArgType::kCCR, 0}; }
    static constexpr auto SR() { return Arg{ArgType::kSR, 0}; }
    static constexpr auto USP() { return Arg{ArgType::kUSP, 0}; }
    static constexpr auto Raw(const uint16_t instr) {
        Arg a{ArgType::kRaw, 0};
        a.uword = instr;
        return a;
    }
    int SNPrint(
            char *buf,
            size_t bufsz,
            unsigned ref_kinds = 0,
            uint32_t self_addr = 0,
            uint32_t ref_addr = 0) const;
};

enum class TracedNodeType {
    kInstruction,
    kData,
};

constexpr size_t kRefsCountPerBuffer = 10;

constexpr size_t kMnemonicBufferSize = 10;
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

struct Op {
    OpCode opcode{OpCode::kNone}; ///< Identifies instruction (mnemonic)
    /// Size specifier, the suffix `b`, `w` or `l`
    OpSize size_spec{OpSize::kNone};
    Condition condition{Condition::kT}; ///< For Scc, Bcc and Dbcc
    Arg arg1{}; ///< First argument, optional
    Arg arg2{}; ///< Second argument, optional, cannot be set if arg1 is not set
    static constexpr auto Typical(
            const OpCode opcode = OpCode::kNone,
            const OpSize opsize = OpSize::kNone,
            const Arg arg1 = Arg{},
            const Arg arg2 = Arg{})
    {
        return Op{opcode, opsize, Condition::kT, arg1, arg2};
    }
    static constexpr auto Raw(const uint16_t instr)
    {
        return Op::Typical(OpCode::kRaw, OpSize::kNone, Arg::Raw(instr));
    }
    int FPrint(
            FILE *,
            unsigned ref_kinds = 0,
            uint32_t self_addr = 0,
            uint32_t ref_addr = 0) const;
};

struct DisasmNode {
    const TracedNodeType type{};
    /// Absolute offset of the instruction (PC value basically)
    const uint32_t offset{};
    /// Instruction size in bytes
    size_t size{kInstructionSizeStepBytes};
    /// Indicates whether `ref_addr` should be interpreted and how
    bool has_ref{};
    /// Absolute address of where to branch to
    uint32_t ref_addr{};
    /// Indicates whether instruction is a call (BSR, JSR) or just a branch
    /// (Bcc, JMP) if `has_branch_addr` is set
    bool is_call{};
    ReferenceNode *ref_by{};
    ReferenceNode *last_ref_by{};
    Op op{};

    /*! Disassembles instruction with arguments
     * returns size of whole instruction with arguments in bytes
     */
    size_t Disasm(const DataBuffer &code);
    size_t DisasmAsRaw(const DataBuffer &code);
    void AddReferencedBy(uint32_t offset, ReferenceType);
    ~DisasmNode();
};
