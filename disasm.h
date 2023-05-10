#pragma once

#include "data_buffer.h"
#include "common.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
// TODO remove this include from the header when AddrModeArg will get rid of SNPrint
#include <cassert>

enum class AddrMode: uint8_t {
    kInvalid = 0,
    kDn,
    kAn,
    kAnAddr,
    kAnAddrIncr,
    kAnAddrDecr,
    kD16AnAddr,
    kD8AnXiAddr,
    kWord,
    kLong,
    kD16PCAddr,
    kD8PCXiAddr,
    kImmediate,
};

enum class OpSize: int {
    kByte = 0,
    kWord = 1,
    kLong = 2,
    kInvalid = 3,
};

struct AddrModeArg {
    AddrMode mode{};
    uint8_t xn{}; /// Xn register number: 0..7
    char r{}; /// Xi register type specifier letter: either 'd' or 'a'
    uint8_t xi{}; /// Xi register number: 0..7
    OpSize s{}; /// Size spec letter of Xi or imm: either 'w' or 'l'
    int32_t value{}; /// Word, Long or Immediate
    /// Size of the extension: 0, 2 or 4 bytes
    constexpr size_t Size() const
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
            return s == OpSize::kLong ? 4 : 2;
        }
        return 0;
    }
    static constexpr AddrModeArg Dn(uint8_t xn)
    {
        return AddrModeArg{AddrMode::kDn, xn};
    }
    static constexpr AddrModeArg An(uint8_t xn)
    {
        return AddrModeArg{AddrMode::kAn, xn};
    }
    static constexpr AddrModeArg AnAddr(uint8_t xn)
    {
        return AddrModeArg{AddrMode::kAnAddr, xn};
    }
    static constexpr AddrModeArg AnAddrIncr(uint8_t xn)
    {
        return AddrModeArg{AddrMode::kAnAddrIncr, xn};
    }
    static constexpr AddrModeArg AnAddrDecr(uint8_t xn)
    {
        return AddrModeArg{AddrMode::kAnAddrDecr, xn};
    }
    static constexpr AddrModeArg D16AnAddr(uint8_t xn, int16_t d16)
    {
        return AddrModeArg{AddrMode::kD16AnAddr, xn, 0, 0, OpSize::kWord, d16};
    }
    static constexpr AddrModeArg D8AnXiAddr(
            uint8_t xn, char r, uint8_t xi, OpSize s, int8_t d8)
    {
        return AddrModeArg{AddrMode::kD8AnXiAddr, xn, r, xi, s, d8};
    }
    static constexpr AddrModeArg Word(int16_t w)
    {
        return AddrModeArg{AddrMode::kWord, 0, 0, 0, OpSize::kWord, w};
    }
    static constexpr AddrModeArg Long(int32_t l)
    {
        return AddrModeArg{AddrMode::kLong, 1, 0, 0, OpSize::kWord, l};
    }
    static constexpr AddrModeArg D16PCAddr(uint8_t xn, int16_t d16)
    {
        return AddrModeArg{AddrMode::kD16PCAddr, xn, 0, 0, OpSize::kWord, d16};
    }
    static constexpr AddrModeArg D8PCXiAddr(
            uint8_t xn, char r, uint8_t xi, OpSize s, int8_t d8)
    {
        return AddrModeArg{AddrMode::kD8PCXiAddr, xn, r, xi, s, d8};
    }
    static constexpr AddrModeArg Immediate(OpSize s, int32_t value)
    {
        return AddrModeArg{AddrMode::kImmediate, 4, 0, 0, s, value};
    }
    int SNPrint(char *const buf, const size_t bufsz) const
    {
        switch (mode) {
        case AddrMode::kInvalid:
            assert(false);
            break;
        case AddrMode::kDn:
            return snprintf(buf, bufsz, "%%d%d", xn);
        case AddrMode::kAn:
            return snprintf(buf, bufsz, "%%a%u", xn);
        case AddrMode::kAnAddr:
            return snprintf(buf, bufsz, "%%a%u@", xn);
        case AddrMode::kAnAddrIncr:
            return snprintf(buf, bufsz, "%%a%u@+", xn);
        case AddrMode::kAnAddrDecr:
            return snprintf(buf, bufsz, "%%a%u@-", xn);
        case AddrMode::kD16AnAddr:
            return snprintf(buf, bufsz, "%%a%u@(%d:w)", xn, value);
        case AddrMode::kD8AnXiAddr:
            return snprintf(buf, bufsz, "%%a%u@(%d,%%%c%d:%c)", xn, value, r, xi, (s == OpSize::kLong) ? 'l' : 'w');
        case AddrMode::kWord:
            return snprintf(buf, bufsz, "0x%x:w", value);
        case AddrMode::kLong:
            return snprintf(buf, bufsz, "0x%x:l", value);
        case AddrMode::kD16PCAddr:
            return snprintf(buf, bufsz, "%%pc@(%d:w)", value);
        case AddrMode::kD8PCXiAddr:
            return snprintf(buf, bufsz, "%%pc@(%d,%%%c%d:%c)", value, r, xi, (s == OpSize::kLong) ? 'l' : 'w');
        case AddrMode::kImmediate:
            return snprintf(buf, bufsz, "#%d", value);
        }
        assert(false);
        return -1;
    }
};

enum class OpCode: uint8_t {
    kNone,
    kRaw,
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
    kF,
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
    kShort,
    kWord,
    kLong,
};

enum class ArgType: uint8_t {
    kNone,
    kRaw,
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
    kRegMaskPredecrement,
    kDisplacement, ///< For BRA, BSR, Bcc and DBcc
    kCCR,
    kSR,
    kUSP,
};

enum class RegKind: uint8_t {
    kDnWord,
    kDnLong,
    kAnWord,
    kAnLong,
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
        int32_t lword{}; ///< kLong, kWord, kDisplacement, kImmediate
        uint16_t uword; ///< kRegMask, kRaw
        uint8_t xn; ///< kDn, kAn, kAnAddr, kAnAddrIncr, kAnAddrDecr
        D16AnPCAddr d16_an; ///< kD16AnAddr
        D16AnPCAddr d16_pc; ///< kD16PCAddr
        D8AnPCXiAddr d8_an_xi; ///< kD8AnXiAddr
        D8AnPCXiAddr d8_pc_xi; ///< kD8PCXiAddr
    };
    static constexpr Self Raw(const uint16_t instr) {
        Arg a{ArgType::kRaw, 0};
        a.uword = instr;
        return a;
    }
    static constexpr Self RegMask(const uint16_t regmask) {
        Arg a{ArgType::kRegMask, 0};
        a.uword = regmask;
        return a;
    }
    static constexpr Self RegMaskPredecrement(const uint16_t regmask) {
        Arg a{ArgType::kRegMaskPredecrement, 0};
        a.uword = regmask;
        return a;
    }
    static constexpr Self Displacement(const int32_t displacement) {
        Arg a{ArgType::kDisplacement, 0};
        a.lword = displacement;
        return a;
    }
    static constexpr Self Immediate(int32_t value) {
        Arg a{ArgType::kImmediate, 0};
        a.lword = value;
        return a;
    }
    static constexpr Self CCR() { return Arg{ArgType::kCCR, 0}; }
    static constexpr Self SR() { return Arg{ArgType::kSR, 0}; }
    static constexpr Self USP() { return Arg{ArgType::kUSP, 0}; }
    static constexpr Self AddrModeXn(const ArgType type, const uint8_t xn) {
        Arg a{type, 0};
        a.xn = xn;
        return a;
    }
private:
    static constexpr Self addrModeD16AnAddr(const D16AnPCAddr d16_an) {
        Arg a{ArgType::kD16AnAddr, 0};
        a.d16_an = d16_an;
        return a;
    }
    static constexpr Self addrModeD16PCAddr(const D16AnPCAddr d16_pc) {
        Arg a{ArgType::kD16PCAddr, 0};
        a.d16_pc = d16_pc;
        return a;
    }
    static constexpr Self addrModeWord(const int16_t value) {
        Arg a{ArgType::kWord, 0};
        a.lword = value;
        return a;
    }
    static constexpr Self addrModeLong(const int32_t value) {
        Arg a{ArgType::kLong, 0};
        a.lword = value;
        return a;
    }
    static constexpr Self addrModeD8AnAddr(const D8AnPCXiAddr d8_an_xi) {
        Arg a{ArgType::kD8AnXiAddr, 0};
        a.d8_an_xi = d8_an_xi;
        return a;
    }
    static constexpr Self addrModeD8PCAddr(const D8AnPCXiAddr d8_pc_xi) {
        Arg a{ArgType::kD8PCXiAddr, 0};
        a.d8_pc_xi = d8_pc_xi;
        return a;
    }
    static constexpr Self addrModeImmediate(const int32_t value) {
        Arg a{ArgType::kImmediate, 0};
        a.lword = value;
        return a;
    }
    static constexpr RegKind regKindFromRegCharSizeChar(char r, OpSize s)
    {
        if (r == 'd' && s == OpSize::kWord) {
            return RegKind::kDnWord;
        } else if (r == 'd' && s == OpSize::kLong) {
            return RegKind::kDnLong;
        } else if (r == 'a' && s == OpSize::kWord) {
            return RegKind::kAnWord;
        } else if (r == 'a' && s == OpSize::kLong) {
            return RegKind::kAnLong;
        }
        return RegKind::kDnWord;
    }
public:
    static constexpr Self FromAddrModeArg(AddrModeArg arg) {
        switch (arg.mode) {
        case AddrMode::kInvalid:
            return Arg{};
        case AddrMode::kDn:
            return AddrModeXn(ArgType::kDn, arg.xn);
        case AddrMode::kAn:
            return AddrModeXn(ArgType::kAn, arg.xn);
        case AddrMode::kAnAddr:
            return AddrModeXn(ArgType::kAnAddr, arg.xn);
        case AddrMode::kAnAddrIncr:
            return AddrModeXn(ArgType::kAnAddrIncr, arg.xn);
        case AddrMode::kAnAddrDecr:
            return AddrModeXn(ArgType::kAnAddrDecr, arg.xn);
        case AddrMode::kD16AnAddr:
            return addrModeD16AnAddr(D16AnPCAddr{arg.xn, static_cast<int16_t>(arg.value)});
        case AddrMode::kD8AnXiAddr:
            return addrModeD8AnAddr(D8AnPCXiAddr{
                    regKindFromRegCharSizeChar(arg.r, arg.s),
                    arg.xn,
                    arg.xi,
                    static_cast<int8_t>(arg.value),
                    });
        case AddrMode::kWord:
            return addrModeWord(arg.value);
        case AddrMode::kLong:
            return addrModeLong(arg.value);
        case AddrMode::kD16PCAddr:
            return addrModeD16PCAddr(D16AnPCAddr{0, static_cast<int16_t>(arg.value)});
        case AddrMode::kD8PCXiAddr:
            return addrModeD8PCAddr(D8AnPCXiAddr{
                    regKindFromRegCharSizeChar(arg.r, arg.s),
                    0,
                    arg.xi,
                    static_cast<int8_t>(arg.value),
                    });
        case AddrMode::kImmediate:
            return addrModeImmediate(arg.value);
        }
        return Arg{};
    }
    int SNPrint(char *buf, size_t bufsz, const Settings&) const;
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
    ReferenceNode *ref_by{};
    ReferenceNode *last_ref_by{};
    OpCode opcode{OpCode::kNone}; ///< Should replace `mnemonic` field
    /// Size specifier, the suffix `b`, `w` or `l`
    SizeSpec size_spec{SizeSpec::kNone};
    Condition condition{Condition::kT}; ///< For Scc, Bcc and Dbcc
    Arg arg1{}, arg2{}; ///< Should replace `arguments` field

    /*! Disassembles instruction with arguments
     * returns size of whole instruction with arguments in bytes
     */
    size_t Disasm(const DataBuffer &code);
    int FPrint(FILE*, const Settings&) const;
    void AddReferencedBy(uint32_t offset, ReferenceType);
    ~DisasmNode();
private:
};
