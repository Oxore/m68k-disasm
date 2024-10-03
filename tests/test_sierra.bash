#!/usr/bin/env bash
#
# SPDX-License-Identifier: Unlicense
#
# Tests against examples known to be translated by Sierra ASM68 without any
# problem.

DISASM="../cmake-build/m68k-disasm --sierra-asm68 -fimm-hex -ffollow-jumps"
TEST_DIR=/tmp/m68k-disasm-tests

set -e
CRED="\033[31m"
CGREEN="\033[32m"
CRST="\033[39m"

rm -rf ${TEST_DIR}
mkdir -p ${TEST_DIR}

run_test() {
  local test_name=$1
  local test_name_sanitized=${test_name//[^a-zA-Z0-9_\-]/-}
  local data=$2
  local file_orig_bin=${TEST_DIR}/${test_name_sanitized}.orig.bin
  local file_orig_asm=${TEST_DIR}/${test_name_sanitized}.orig.asm
  local file_asm=${TEST_DIR}/${test_name_sanitized}.asm
  echo -ne "Test \"${test_name}\"... "
  echo -ne "${data}" >"${file_orig_bin}"
  echo -e "\t${test_name}" >"${file_orig_asm}"
  # When testing cases with .short literals it sometimes it emits multiple
  # lines. Here these additional lines are added to the reference asm file.
  shift 2
  for line in "$@"; do
    echo -e "\t${line}" >>"${file_orig_asm}"
  done
  ${DISASM} -o ${file_asm} ${file_orig_bin}
  if ! cmp "${file_orig_asm}" "${file_asm}" >/dev/null 2>&1; then
    echo -e "${CRED}FAIL${CRST}: expected and output listings do not match"
    diff --color=always -u "${file_orig_asm}" "${file_asm}"
  elif [[ ! "${test_name}" =~ ".short" ]] && grep ".short" ${file_asm} >/dev/null 2>&1; then
    echo -e "${CRED}FAIL${CRST}: .short emitted"
    cat ${file_asm}
  else
    echo -e "${CGREEN}OK${CRST}"
    #cat ${file_asm}
  fi
}

# bxxx cmpm
#
run_test "cmpm.b (a0)+,(a0)+" "\xb1\x08"
run_test "cmpm.w (a0)+,(a0)+" "\xb1\x48"
run_test "cmpm.l (a0)+,(a0)+" "\xb1\x88"

# bxxx eor
#
run_test "eor.b d2,d1" "\xb5\x01"
run_test "eor.b d2,(a1)" "\xb5\x11"
run_test "eor.b d2,(a1)+" "\xb5\x19"
run_test "eor.w d2,-(a1)" "\xb5\x61"
run_test "eor.l d2,0xffff0000.l" "\xb5\xb9\xff\xff\x00\x00"

# bxxx cmp
#
run_test "cmp.b d1,d2" "\xb4\x01"
# Seemingly cmp.b a1,d2, but "byte operations on address registers are illegal",
# hence it has to be a literal data.
run_test ".short 0xb409" "\xb4\x09"
run_test "cmp.w a1,d2" "\xb4\x49"
run_test "cmp.b (a1),d2" "\xb4\x11"
run_test "cmp.b (a1)+,d2" "\xb4\x19"
run_test "cmp.b -(a1),d2" "\xb4\x21"
# It turns out the pc-relative addressing mode differs from GNU AS when
# displacement is set as literal number.
run_test "cmp.l .+5(pc,a0.w),d0" "\xb0\xbb\x80\x03"
run_test "cmp.l .+5(pc,a0.l),d0" "\xb0\xbb\x88\x03"
run_test "cmp.l .+3(pc,a0.l),d0" "\xb0\xbb\x88\x01"
run_test "cmp.l .+1(pc,a0.l),d0" "\xb0\xbb\x88\xff"
run_test "cmp.l .(pc,a0.l),d0" "\xb0\xbb\x88\xfe"
run_test "cmp.l .-1(pc,a0.l),d0" "\xb0\xbb\x88\xfd"
run_test "cmp.l .-3(pc,a0.l),d0" "\xb0\xbb\x88\xfb"
run_test "cmp.l .-5(pc,a0.l),d0" "\xb0\xbb\x88\xf9"
run_test "cmp.w 0xffff88ff.w,d0" "\xb0\x78\x88\xff"
# Sierra would emit CMPI for "cmp #imm,Xn", so we disassemble it as short
run_test ".short 0xb6bc, 0x44d1, 0xe6e9" "\xb6\xbc\x44\xd1\xe6\xe9"

# bxxx cmpa
#
run_test "cmpa.w d1,a2" "\xb4\xc1"
run_test "cmpa.l a2,a5" "\xbb\xca"
run_test "cmpa.w (a2)+,a5" "\xba\xda"
run_test "cmpa.l 0x80000000.l,a5" "\xbb\xf9\x80\x00\x00\x00"
run_test "cmpa.w #0x100,a5" "\xba\xfc\x01\x00"
run_test "cmpa.l #0x80000000,a5" "\xbb\xfc\x80\x00\x00\x00"

# cxxx divu divs
#
run_test "divu.w d6,d1" "\x82\xc6"
run_test "divs.w (a6),d1" "\x83\xd6"
run_test "divu.w (a6)+,d1" "\x82\xde"
run_test "divs.w -(a6),d1" "\x83\xe6"
run_test "divu.w -24576(a6),d1" "\x82\xee\xa0\x00"
run_test "divs.w -16(a6,d6.l),d1" "\x83\xf6\x68\xf0"
run_test "divu.w 0x3000.w,d1" "\x82\xf8\x30\x00"
run_test "divs.w 0x80000000.l,d1" "\x83\xf9\x80\x00\x00\x00"
run_test "divu.w .+1(pc),d1" "\x82\xfa\xff\xff"
run_test "divs.w .+1(pc,a1.w),d1" "\x83\xfb\x90\xff"
run_test "divu.w #0x3000,d1" "\x82\xfc\x30\x00"

# cxxx mulu muls
#
run_test "mulu.w d6,d1" "\xc2\xc6"
run_test "muls.w (a6),d1" "\xc3\xd6"
run_test "mulu.w (a6)+,d1" "\xc2\xde"
run_test "muls.w -(a6),d1" "\xc3\xe6"
run_test "mulu.w -24576(a6),d1" "\xc2\xee\xa0\x00"
run_test "muls.w -16(a6,d6.l),d1" "\xc3\xf6\x68\xf0"
run_test "mulu.w 0x3000.w,d1" "\xc2\xf8\x30\x00"
run_test "muls.w 0x80000000.l,d1" "\xc3\xf9\x80\x00\x00\x00"
run_test "mulu.w .+1(pc),d1" "\xc2\xfa\xff\xff"
run_test "muls.w .+1(pc,a1.w),d1" "\xc3\xfb\x90\xff"
run_test "mulu.w #0x3000,d1" "\xc2\xfc\x30\x00"

# cxxx exg
#
run_test "exg.l d6,d1" "\xcd\x41"
run_test "exg.l d6,a1" "\xcd\x89"
run_test "exg.l a6,a1" "\xcd\x49"

# cxxx and
#
run_test "and.b d1,d2" "\xc4\x01"
# Short because direct address register access mode is forbidden for and.b
run_test ".short 0xc409" "\xc4\x09"
# Short because direct address register access mode is forbidden for and.w
run_test ".short 0xc449" "\xc4\x49"
run_test "and.b (a1),d2" "\xc4\x11"
run_test "and.b (a1)+,d2" "\xc4\x19"
run_test "and.w -(a1),d2" "\xc4\x61"
run_test "and.l .+9(pc,a4.l),d0" "\xc0\xbb\xc8\x07"
# Sierra would emit ANDI for "and #imm,Xn", so we disassemble it as short
run_test ".short 0xc6bc, 0x44d1, 0xe6e9" "\xc6\xbc\x44\xd1\xe6\xe9"

# cxxx abcd
#
run_test "abcd.b d1,d0" "\xc1\x01"
run_test "abcd.b -(a1),-(a0)" "\xc1\x09"

# 8xxx sbcd
#
run_test "sbcd.b d1,d0" "\x81\x01"
run_test "sbcd.b -(a1),-(a0)" "\x81\x09"

# 8xxx or
#
run_test "or.b d1,d2" "\x84\x01"
# Short because direct address register access mode is forbidden for or.b
run_test ".short 0x8409" "\x84\x09"
# Short because direct address register access mode is forbidden for or.w
run_test ".short 0x8449" "\x84\x49"
run_test "or.b (a1),d2" "\x84\x11"
run_test "or.b (a1)+,d2" "\x84\x19"
run_test "or.w -(a1),d2" "\x84\x61"
run_test "or.l .+9(pc,a0.l),d0" "\x80\xbb\x88\x07"
# Sierra would emit ORI for "or #imm,Xn", so we disassemble it as short
run_test ".short 0x86bc, 0x44d1, 0xe6e9" "\x86\xbc\x44\xd1\xe6\xe9"
# swapped register direction seems to be impossible to get legally
run_test ".short 0x8142" "\x81\x42"

# 48xx nbcd swap pea
#
run_test "swap.w d7" "\x48\x47"
run_test "swap.w d2" "\x48\x42"
run_test "pea.l (a0)" "\x48\x50"
run_test "pea.l -32768(a0)" "\x48\x68\x80\x00"
run_test "pea.l -2(a7,a1.w)" "\x48\x77\x90\xfe"
run_test "pea.l .+32769(pc)" "\x48\x7a\x7f\xff"
run_test "pea.l .(pc,d6.l)" "\x48\x7b\x68\xfe"
run_test "nbcd.b d3" "\x48\x03"
run_test "nbcd.b (a4)" "\x48\x14"
run_test "nbcd.b (a4)+" "\x48\x1c"
run_test "nbcd.b -(a5)" "\x48\x25"
run_test "nbcd.b -32768(a0)" "\x48\x28\x80\x00"
run_test "nbcd.b -2(a7,a1.w)" "\x48\x37\x90\xfe"

# 48xx ext
#
run_test "ext.w d7" "\x48\x87"
run_test "ext.l d4" "\x48\xc4"

# exxx asl, asr, lsl, lsr, roxl, roxr, rol, ror
#
run_test "asr.b d1,d2" "\xe2\x22"
run_test "asr.b #0x1,d2" "\xe2\x02"
run_test "asr.b #0x8,d2" "\xe0\x02"
run_test "asl.b #0x7,d2" "\xef\x02"
run_test "asr.w d1,d2" "\xe2\x62"
run_test "asr.l d1,d2" "\xe2\xa2"
run_test "asl.w #0x6,d3" "\xed\x43"
run_test "asl.l #0x5,d3" "\xeb\x83"
run_test "asr.w (a0)" "\xe0\xd0"
run_test "lsr.w (a0)+" "\xe2\xd8"
run_test "roxr.w -(a0)" "\xe4\xe0"
run_test "ror.w 256(a7)" "\xe6\xef\x01\x00"
# Found on random tests for GNU, just let it be here too
run_test "lsr.b d1,d4" "\xe2\x2c"

# 9xxx subx
#
run_test "subx.b d0,d0" "\x91\x00"
run_test "subx.w d7,d1" "\x93\x47"
run_test "subx.l d6,d2" "\x95\x86"
run_test "subx.b -(a0),-(a0)" "\x91\x08"
run_test "subx.w -(a7),-(a1)" "\x93\x4f"
run_test "subx.l -(a6),-(a2)" "\x95\x8e"

# 9xxx suba
#
run_test "suba.w d1,a2" "\x94\xc1"
run_test "suba.l a2,a5" "\x9b\xca"
run_test "suba.w (a2)+,a5" "\x9a\xda"
run_test "suba.w #0x100,a5" "\x9a\xfc\x01\x00"
run_test "suba.l #0x80000000,a5" "\x9b\xfc\x80\x00\x00\x00"

# 9xxx sub
#
run_test "sub.b d1,d2" "\x94\x01"
# Raw instead of  "sub.b a1,d2", because "byte operations on address registers
# are illegal" in Sierra
run_test ".short 0x9409" "\x94\x09"
run_test "sub.w a1,d2" "\x94\x49"
run_test "sub.b (a1),d2" "\x94\x11"
run_test "sub.b (a1)+,d2" "\x94\x19"
run_test "sub.b -(a1),d2" "\x94\x21"
# Sierra would emit SUBI for "sub #imm,Xn", so we disassemble it as short
run_test ".short 0x96bc, 0x44d1, 0xe6e9" "\x96\xbc\x44\xd1\xe6\xe9"

# dxxx addx
#
run_test "addx.b d0,d0" "\xd1\x00"
run_test "addx.w d7,d1" "\xd3\x47"
run_test "addx.l d6,d2" "\xd5\x86"
run_test "addx.b -(a0),-(a0)" "\xd1\x08"
run_test "addx.w -(a7),-(a1)" "\xd3\x4f"
run_test "addx.l -(a6),-(a2)" "\xd5\x8e"

# dxxx adda
#
run_test "adda.w d1,a2" "\xd4\xc1"
run_test "adda.l a2,a5" "\xdb\xca"
run_test "adda.w (a2)+,a5" "\xda\xda"
run_test "adda.w #0x100,a5" "\xda\xfc\x01\x00"
run_test "adda.l #0x80000000,a5" "\xdb\xfc\x80\x00\x00\x00"

# dxxx add
#
run_test "add.b d1,d2" "\xd4\x01"
# Short because "byte operations on address registers are illegal"
# Otherwise it could be "add.b a1,d2"
run_test ".short 0xd409" "\xd4\x09"
run_test "add.w a1,d2" "\xd4\x49"
run_test "add.b (a1),d2" "\xd4\x11"
run_test "add.b (a1)+,d2" "\xd4\x19"
run_test "add.b -(a1),d2" "\xd4\x21"
run_test "add.l .+1(pc,a0.l),d0" "\xd0\xbb\x88\xff"
# Sierra would emit addi.l for "add.l #0x44d1e6e9,d6", so we disassemble it as
# short
run_test ".short 0xd6bc, 0x44d1, 0xe6e9" "\xd6\xbc\x44\xd1\xe6\xe9"

# 4xxx chk.w
#
run_test "chk.w d2,d3" "\x47\x82"
run_test "chk.w (a0),d0" "\x41\x90"
run_test "chk.w (a3)+,d3" "\x47\x9b"
run_test "chk.w -32768(a1),d3" "\x47\xa9\x80\x00"
run_test "chk.w 127(a2,a2.l),d3" "\x47\xb2\xa8\x7f"

# 4xxx lea.l
#
run_test "lea.l (a0),a0" "\x41\xd0"
run_test "lea.l -32768(a1),a3" "\x47\xe9\x80\x00"
run_test "lea.l 127(a2,a2.l),a3" "\x47\xf2\xa8\x7f"
run_test "lea.l .+32769(pc),a3" "\x47\xfa\x7f\xff"
run_test "lea.l .-126(pc,a2.l),a3" "\x47\xfb\xa8\x80"

# 0xxx movep
#
run_test "movep.w 160(a3),d0" "\x01\x0b\x00\xa0"
run_test "movep.l 160(a2),d1" "\x03\x4a\x00\xa0"
run_test "movep.w d2,160(a1)" "\x05\x89\x00\xa0"
run_test "movep.l d3,160(a0)" "\x07\xc8\x00\xa0"

# 0xxx bitwise ops
#
run_test "btst.l #0x6,d7" "\x08\x07\x00\x06"
run_test "btst.b #0x6,(a7)" "\x08\x17\x00\x06"
run_test "btst.b #0x6,0xff000000.l" "\x08\x39\x00\x06\xff\x00\x00\x00"
run_test "btst.b d1,0xff000000.l" "\x03\x39\xff\x00\x00\x00"
run_test "bchg.b d2,0xff000000.l" "\x05\x79\xff\x00\x00\x00"
# Sierra emits a couple of warnings here, but nevertheless produces the same
# expected machine code as GNU AS. The warnings are:
# "warning: argument is out of range: immediate data"
# "warning: argument is out of range: bit number (applied modulo 8)"
run_test "bchg.b #0x79,-11406(a6)" "\x08\x6e\x00\x79\xd3\x72"
run_test "bclr.b d3,0xff000000.l" "\x07\xb9\xff\x00\x00\x00"
run_test "bset.b d4,0xff000000.l" "\x09\xf9\xff\x00\x00\x00"
# This is basically "btst.b #0x1021,0xff000000.l". Sierra says:
# warning: argument is out of range: immediate data
# warning: argument is out of range: bit number (applied modulo 8)
run_test ".short 0x0839, 0x1021, 0xff00, 0x0000" "\x08\x39\x10\x21\xff\x00\x00\x00"

# 0xxx immediate ops
#
run_test "ori.b #0x0,d0" "\x00\x00\x00\x00"
run_test "ori.b #0x0,ccr" "\x00\x3c\x00\x00"
run_test "ori.b #0x1,ccr" "\x00\x3c\x00\x01"
run_test "ori.b #0x7f,ccr" "\x00\x3c\x00\x7f"
run_test "ori.b #0xffffff80,ccr" "\x00\x3c\x00\x80"
run_test "ori.b #0xffffffff,ccr" "\x00\x3c\x00\xff"
# Sierra says "warning: argument is out of range: immediate data" when you try
# use something greater that 0xff with "ori.b #imm,ccr". Negative values are
# also take up only a lower byte, high byte is always zero from Sierra output.
run_test ".short 0x003c, 0x0100" "\x00\x3c\x01\x00"
run_test ".short 0x003c, 0xff80" "\x00\x3c\xff\x80"
run_test ".short 0x003c, 0xffff" "\x00\x3c\xff\xff"
run_test "ori.w #0x0,sr" "\x00\x7c\x00\x00"
run_test "ori.w #0xa,sr" "\x00\x7c\x00\x0a"
run_test "ori.w #0xffffffff,sr" "\x00\x7c\xff\xff"
run_test "ori.w #0xffffff80,sr" "\x00\x7c\xff\x80"
run_test "andi.w #0xa,sr" "\x02\x7c\x00\x0a"
run_test "eori.w #0xa,sr" "\x0a\x7c\x00\x0a"
run_test "andi.b #0xa,ccr" "\x02\x3c\x00\x0a"
run_test "eori.b #0xa,ccr" "\x0a\x3c\x00\x0a"
run_test "ori.b #0xa,d7" "\x00\x07\x00\x0a"
run_test "ori.w #0xa,d5" "\x00\x45\x00\x0a"
run_test "ori.l #0xa,d3" "\x00\x83\x00\x00\x00\x0a"
run_test "ori.b #0xffffff80,d7" "\x00\x07\x00\x80"
# Same here for "ori.w" with "warning: argument is out of range: immediate data"
run_test ".short 0x0007, 0xff80" "\x00\x07\xff\x80"
run_test "ori.w #0xffffff80,d5" "\x00\x45\xff\x80"
run_test "ori.l #0xff800000,d3" "\x00\x83\xff\x80\x00\x00"
run_test "addi.w #0x0,(a2)+" "\x06\x5a\x00\x00"
run_test "addi.w #0x0,-(a2)" "\x06\x62\x00\x00"
run_test "subi.w #0x0,(a2)+" "\x04\x5a\x00\x00"
run_test "subi.w #0x0,-(a2)" "\x04\x62\x00\x00"
# SUBI does not support An (direct address reg) addressing mode.
run_test ".short 0x044a" "\x04\x4a\x00\x12" \
         ".short 0x0012"
# ANDI does not support An (direct address reg) addressing mode.
run_test ".short 0x064a" "\x06\x4a\x00\x12" \
         ".short 0x0012"
# Small (less then or equal to 8) nonzero positive immediate values cause Sierra
# to produce SUBQ instead of SUBI and ADDQ instead of ADDI.
#
# This is "addi.w #0x4,(a2)+"
run_test ".short 0x065a, 0x0004" "\x06\x5a\x00\x04"
# This is "addi.w #0x3,-(a2)"
run_test ".short 0x0662, 0x0003" "\x06\x62\x00\x03"
# This is "addi.w #0x5,(a2)"
run_test ".short 0x0652, 0x0005" "\x06\x52\x00\x05"
# This is "addi.w #0x6,d2"
run_test ".short 0x0642, 0x0006" "\x06\x42\x00\x06"
# This is "subi.w #0x4,(a2)+"
run_test ".short 0x045a, 0x0004" "\x04\x5a\x00\x04"
# This is "subi.w #0x3,-(a2)"
run_test ".short 0x0462, 0x0003" "\x04\x62\x00\x03"
# This is "subi.w #0x5,(a2)"
run_test ".short 0x0452, 0x0005" "\x04\x52\x00\x05"
# This is "subi.w #0x6,d2"
run_test ".short 0x0442, 0x0006" "\x04\x42\x00\x06"
run_test "cmpi.b #0x20,(a2)" "\x0c\x12\x00\x20"
run_test "cmpi.w #0x30,(a2)" "\x0c\x52\x00\x30"
run_test "cmpi.l #0x40,(a2)" "\x0c\x92\x00\x00\x00\x40"
# When given "cmpi.b #0x0,.(pc)" or "cmpi.b #0x0,.(pc,d4)" Sierra says:
# "illegal addressing mode: pc-relative indirect"
run_test ".short 0x0c3a, 0x0000, 0xfffe" "\x0c\x3a\x00\x00\xff\xfe"
run_test ".short 0x0c3a, 0x0000, 0x40fe" "\x0c\x3a\x00\x00\x40\xfe"
# From random tests: cmpi.? with invalid opsize 0b11
run_test ".short 0x0ce4" "\x0c\xe4\xff\xff" \
         ".short 0xffff"

# 4axx
#
run_test "tas.b d2" "\x4a\xc2"
run_test "tst.b d2" "\x4a\x02"
run_test "tst.w d2" "\x4a\x42"
run_test "tst.l d2" "\x4a\x82"
# When given "tst.l .(pc)" or "tst.l .(pc,d4)" Sierra says:
# "illegal addressing mode: pc-relative indirect"
run_test ".short 0x4aba, 0xfffe" "\x4a\xba\xff\xfe"
run_test ".short 0x4aba, 0x40fe" "\x4a\xba\x40\xfe"

# For "tas .+1(pc)" Sierra says: "illegal addressing mode: pc-relative indirect"
run_test ".short 0x4afa" "\x4a\xfa\xff\xff" \
         ".short 0xffff"
# For "tas.b .+1(pc,a0.l)" Sierra says:
# "illegal addressing mode: pc-relative indirect"
run_test ".short 0x4afb" "\x4a\xfb\x88\xff" \
         ".short 0x88ff"

# 4xxx
#
run_test "negx.b d4" "\x40\x04"
run_test "clr.b d5" "\x42\x05"
run_test "neg.b d6" "\x44\x06"
run_test "not.b d7" "\x46\x07"
run_test "negx.w d4" "\x40\x44"
run_test "clr.w d5" "\x42\x45"
run_test "neg.w d6" "\x44\x46"
run_test "not.w d7" "\x46\x47"
run_test "negx.l d4" "\x40\x84"
run_test "clr.l d5" "\x42\x85"
run_test "neg.l d6" "\x44\x86"
run_test "not.l d7" "\x46\x87"

# 4e4x
#
run_test "trap #0x0" "\x4e\x40"
run_test "trap #0x8" "\x4e\x48"
run_test "trap #0xf" "\x4e\x4f"

# 4e5x
#
run_test "link.w a2,#0x100" "\x4e\x52\x01\x00"
run_test "link.w a2,#0xffffffff" "\x4e\x52\xff\xff"
run_test "link.w a2,#0xffff8000" "\x4e\x52\x80\x00"
run_test "unlk a2" "\x4e\x5a"

# 4e6x
#
run_test "move.l a2,usp" "\x4e\x62"
run_test "move.l usp,a7" "\x4e\x6f"

# 4xxx
#
run_test "move.w sr,d1" "\x40\xc1"
run_test "move.w d3,sr" "\x46\xc3"
# For some reason move to CCR is word only instruction, but CCR is byte sized
# register.
run_test "move.w d2,ccr" "\x44\xc2"

# 70xx / 72xx/ 74xx / 76xx / 78xx / 7axx / 7cxx / 7exx
#
run_test "moveq.l #0x0,d0" "\x70\x00"
run_test "moveq.l #0x1,d2" "\x74\x01"
run_test "moveq.l #0x7f,d7" "\x7e\x7f"
run_test "moveq.l #0xffffffff,d5" "\x7a\xff"
run_test "moveq.l #0xffffff80,d1" "\x72\x80"

# 1xxx [xxxx [xxxx]]
#
run_test "move.b d1,d0" "\x10\x01"
# For "move.b a1,d0" Sierra says:
# "byte operations on address registers are illegal"
run_test ".short 0x1009" "\x10\x09"
run_test "move.b (a1),d0" "\x10\x11"
run_test "move.b (a1)+,d0" "\x10\x19"
run_test "move.b -(a1),d0" "\x10\x21"
run_test "move.b -789(a1),d0" "\x10\x29\xfc\xeb"
run_test "move.b 112(a1,a1.l),d0" "\x10\x31\x98\x70"
run_test "move.b 0xffff9870.w,d0" "\x10\x38\x98\x70"
run_test "move.b 0x30303070.l,d0" "\x10\x39\x30\x30\x30\x70"
run_test "move.b .-787(pc),d0" "\x10\x3a\xfc\xeb"
run_test "move.b .+114(pc,a2.l),d0" "\x10\x3b\xa8\x70"
run_test "move.b #0xffffffff,d0" "\x10\x3c\x00\xff"
# For "move.b #0x7fff,d0" Sierra says:
# "warning: argument is out of range: immediate data"
# And then places zeros in the high byte, instead of the "7f" part. So it is
# impossible to get this sequence from a legal instruction.
run_test ".short 0x103c, 0x7fff" "\x10\x3c\x7f\xff"

# 3xxx [xxxx [xxxx]]
#
run_test "move.w d2,d7" "\x3e\x02"
run_test "move.w a2,d7" "\x3e\x0a"
run_test "move.w (a2),d7" "\x3e\x12"
run_test "move.w (a2)+,d0" "\x30\x1a"
run_test "move.w -(a2),d0" "\x30\x22"
run_test "move.w 16383(a2),d0" "\x30\x2a\x3f\xff"
run_test "move.w -128(a2,a1.w),d0" "\x30\x32\x90\x80"
run_test "move.w 0xffff9080.w,d0" "\x30\x38\x90\x80"
run_test "move.w 0xaaaaaaaa.l,d0" "\x30\x39\xaa\xaa\xaa\xaa"
run_test "move.w .+16385(pc),d0" "\x30\x3a\x3f\xff"
run_test "move.w .-126(pc,a2.w),d0" "\x30\x3b\xa0\x80"
run_test "move.w #0xffffa5a5,d0" "\x30\x3c\xa5\xa5"
run_test "movea.w d1,a0" "\x30\x41"
run_test "movea.w #0xffffa890,a0" "\x30\x7c\xa8\x90"

# 2xxx [xxxx [xxxx]]
#
run_test "move.l d5,d2" "\x24\x05"
run_test "move.l a5,d2" "\x24\x0d"
run_test "move.l (a5),d2" "\x24\x15"
run_test "move.l (a5)+,d2" "\x24\x1d"
run_test "move.l -(a5),d2" "\x24\x25"
run_test "move.l 30752(a5),d2" "\x24\x2d\x78\x20"
run_test "move.l -112(a5,a1.l),d2" "\x24\x35\x98\x90"
run_test "move.l 0x7890.w,d2" "\x24\x38\x78\x90"
run_test "move.l 0x7890.l,d2" "\x24\x39\x00\x00\x78\x90"
run_test "move.l .+30754(pc),d2" "\x24\x3a\x78\x20"
run_test "move.l .-110(pc,a2.l),d2" "\x24\x3b\xa8\x90"
run_test "move.l #0xa8900000,d2" "\x24\x3c\xa8\x90\x00\x00"
run_test "movea.l d1,a0" "\x20\x41"
run_test "movea.l #0xa8900000,a0" "\x20\x7c\xa8\x90\x00\x00"
# Sierra interprets "move.l 0(a2),14024(a5)" as "move.l (a2),14024(a5)" and
# won't produce displacement in "(d16,An)" situation if it is zero.
run_test ".short 0x2b6a, 0x0000, 0x36c8" "\x2b\x6a\x00\x00\x36\xc8"
run_test ".short 0x2b6a, 0x36c8, 0x0000" "\x2b\x6a\x36\xc8\x00\x00"
exit

# From random tests of GNU, so let it be here too
#
run_test "move.l .-14(pc,a0.l),(a3)+" "\x26\xfb\x88\xf0\x4e\x71" \
         "nop"

# 4890 xxx
#
run_test "movem.w d0,(a0)" "\x48\x90\x00\x01"
run_test "movem.w d0-d1/a0-a1,(a0)" "\x48\x90\x03\x03"
run_test "movem.l d0-d1/d3-d4/d6-d7/a1-a2/a4-a5/a7,(a0)" "\x48\xd0\xb6\xdb"
run_test "movem.w d0/d2/d4/d6/a0/a2/a4/a6,(a0)" "\x48\x90\x55\x55"
run_test "movem.l d1/d3/d5/d7/a1/a3/a5/a7,(a0)" "\x48\xd0\xaa\xaa"
run_test "movem.l d0-d7/a0-a7,(a0)" "\x48\xd0\xff\xff"
run_test "movem.w d0-d7/a0-a7,-(a0)" "\x48\xa0\xff\xff"
run_test "movem.l d0-d7/a0-a7,12317(a0)" "\x48\xe8\xff\xff\x30\x1d"
run_test "movem.w d0-d7/a0-a7,10(a7,d4.l)" "\x48\xb7\xff\xff\x48\x0a"
run_test "movem.l d0-d7/a0-a7,0xffff8010.w" "\x48\xf8\xff\xff\x80\x10"
run_test "movem.w d0-d7/a0-a7,0x7ff0.l" "\x48\xb9\xff\xff\x00\x00\x7f\xf0"
run_test "movem.w (a0),d0-d7/a0-a7" "\x4c\x90\xff\xff"
run_test "movem.l (a0)+,d0-d7/a0-a7" "\x4c\xd8\xff\xff"
run_test "movem.w 12317(a0),d0-d7/a0-a7" "\x4c\xa8\xff\xff\x30\x1d"
run_test "movem.l 10(a7,d4.l),d0-d7/a0-a7" "\x4c\xf7\xff\xff\x48\x0a"
run_test "movem.w 0xffff8010.w,d0-d7/a0-a7" "\x4c\xb8\xff\xff\x80\x10"
run_test "movem.l 0x7ff0.l,d0-d7/a0-a7" "\x4c\xf9\xff\xff\x00\x00\x7f\xf0"
fi
run_test "movem.w .-13978(pc),d2/d4/d7/a0-a2/a5-a6" "\x4c\xba\x67\x94\xc9\x62"

# From random tests of GNU, so let it be here too
# "movem.w ???,(a2)" trucated
run_test ".short 0x4892" "\x48\x92"

# 5x38 / 5x78 / 5xb8 (xxx).W
#
run_test "addq.b #0x8,0x73.w" "\x50\x38\x00\x73"
run_test "addq.l #0x4,0xffff8014.w" "\x58\xb8\x80\x14"

# 5x39 / 5x79 / 5xb9 (xxx).L
#
run_test "addq.w #0x5,0x18fc0000.l" "\x5a\x79\x18\xfc\x00\x00"
run_test "addq.l #0x1,0xf1000001.l" "\x52\xb9\xf1\x00\x00\x01"

# 5x30..5x37 / 5x70..5x77 / 5xb0..5xb7, (d16, An, Xi), Brief Extension Word
#
run_test "addq.b #0x8,115(a7,d0.w)" "\x50\x37\x00\x73"
run_test "addq.w #0x5,-4(a2,d1.l)" "\x5a\x72\x18\xfc"
run_test "addq.l #0x1,-127(a3,a3.w)" "\x52\xb3\xb0\x81"

# 5x28..5x2f / 5x68..5x6f / 5xa8..5xaf, (d16, An), Displacement Word
#
run_test "addq.b #0x8,128(a7)" "\x50\x2f\x00\x80"
run_test "addq.w #0x5,-772(a2)" "\x5a\x6a\xfc\xfc"
run_test "addq.l #0x1,-1(a3)" "\x52\xab\xff\xff"

# 5x20..5x27 / 5x60..5x67 / 5xa0..5xa7, -(An)
#
run_test "addq.b #0x8,-(a7)" "\x50\x27"
run_test "addq.w #0x5,-(a2)" "\x5a\x62"
run_test "addq.l #0x1,-(a3)" "\x52\xa3"

# 5x18..5x1f / 5x58..5x5f / 5x98..5x9f, (An)+
#
run_test "addq.b #0x8,(a7)+" "\x50\x1f"
run_test "addq.w #0x5,(a2)+" "\x5a\x5a"
run_test "addq.l #0x1,(a5)+" "\x52\x9d"

# 5x10..5x17 / 5x50..5x57 / 5x90..5x97, (An)
#
run_test "addq.b #0x8,(a7)" "\x50\x17"
run_test "addq.w #0x5,(a2)" "\x5a\x52"
run_test "addq.l #0x1,(a3)" "\x52\x93"

# 5x08..5x0f / 5x48..5x4f / 5x88..5x8f, An
#
# NOTE: addq.b with An does not exits
run_test "addq.w #0x6,a7" "\x5c\x4f"
run_test "addq.l #0x1,a5" "\x52\x8d"

# 5x00..5x07 / 5x40..5x47 / 5x80..5x87, Dn
#
run_test "addq.b #0x8,d7" "\x50\x07"
run_test "addq.w #0x5,d2" "\x5a\x42"
run_test "addq.l #0x1,d3" "\x52\x83"

# 50f9 xxxx
#
run_test "sf.b 0x74.l" "\x51\xf9\x00\x00\x00\x74"
run_test "sf.b 0xc0febabe.l" "\x51\xf9\xc0\xfe\xba\xbe"

# 50f8 xxxx
#
run_test "sf.b 0x66.w" "\x51\xf8\x00\x66"
run_test "sf.b 0xffff80c4.w" "\x51\xf8\x80\xc4"

# 51f0 xxxx
#
run_test "sf.b 4(a4,a3.w)" "\x51\xf4\xb0\x04"
run_test "sf.b -14(a3,d6.w)" "\x51\xf3\x60\xf2"

# 5fe8 xxxx
#
run_test "sle.b 160(a0)" "\x5f\xe8\x00\xa0"
run_test "sle.b -7166(a0)" "\x5f\xe8\xe4\x02"

# 5ee1
#
run_test "sgt.b -(a1)" "\x5e\xe1"

# 56df
#
run_test "sne.b (a7)+" "\x56\xdf"

# 5dd3
#
run_test "slt.b (a3)" "\x5d\xd3"

# 57cx
#
run_test "seq.b d1" "\x57\xc1"

# 50cf xxxx
#
run_test "dbt.w d7,.-2" "\x50\xcf\xff\xfc"
run_test "dbt.w d7,.+266" "\x50\xcf\x01\x08"
run_test "dbt.w d7,.+2" "\x50\xcf\x00\x00"
# When given "dbt.w d7,.+3" Sierra says:
# "branch to/from odd address: destination address is odd"
run_test ".short 0x50cf, 0x0001" "\x50\xcf\x00\x01"

# 50c9 7ffe
#
# From random tests
run_test "dbt.w d1,.+32768" "\x50\xc9\x7f\xfe"

# 60xx
#
run_test "bra.s .-2" "\x60\xfc"
run_test "bra.s ." "\x60\xfe"
run_test "bra.s .+10" "\x60\x08"
# When given "bra.s .+2" Sierra says:
# "short branch to next instruction is illegal"
run_test ".short 0x6000" "\x60\x00"
# When given "bra.s .+3" Sierra says:
# "branch to/from odd address: destination address is odd"
run_test ".short 0x6001" "\x60\x01"

# 60xx (xxxx)
#
run_test "bra.w .-2000" "\x60\x00\xf8\x2e"
run_test "bra.w .+1000" "\x60\x00\x03\xe6"
# When given "bra.w .+2" Sierra says:
# "short branch to next instruction is illegal"
run_test ".short 0x6000, 0x0000" "\x60\x00\x00\x00"
# When given "bra.w .+3" Sierra says:
# "branch to/from odd address: destination address is odd"
run_test ".short 0x6000, 0x0001" "\x60\x00\x00\x01"

# 61xx (xxxx)
#
run_test "bsr.s .-118" "\x61\x88"
run_test "bsr.w .+1000" "\x61\x00\x03\xe6"

# 6xxx
#
run_test "bhi.s .+12" "\x62\x0a"
run_test "bls.s .+12" "\x63\x0a"
run_test "bcc.s .+12" "\x64\x0a"
run_test "bcs.s .+12" "\x65\x0a"
run_test "bne.s .+12" "\x66\x0a"
run_test "beq.s .+12" "\x67\x0a"
run_test "bvc.s .+12" "\x68\x0a"
run_test "bvs.s .+12" "\x69\x0a"
run_test "bpl.s .+12" "\x6a\x0a"
run_test "bmi.s .+12" "\x6b\x0a"
run_test "bge.s .+12" "\x6c\x0a"
run_test "blt.s .+12" "\x6d\x0a"
run_test "bgt.s .+12" "\x6e\x0a"
run_test "ble.s .+12" "\x6f\x0a"

# 4afc
#
# reset
#
run_test "illegal" "\x4a\xfc"

# 4e70
#
# reset
run_test "reset" "\x4e\x70"

# 4e71
#
# nop
run_test "nop" "\x4e\x71"

# 4e72 xxxx
#
run_test "stop #0x8" "\x4e\x72\x00\x08"
run_test "stop #0xffffffff" "\x4e\x72\xff\xff"

# 4e73
#
# rte
run_test "rte" "\x4e\x73"

# 4e75
#
# rts
run_test "rts" "\x4e\x75"

# 4e76
#
# trapv
run_test "trapv" "\x4e\x76"

# 4e77
#
# rtr
run_test "rtr" "\x4e\x77"

# 4e90..4e97
#
run_test "jsr (a1)" "\x4e\x91"

# (4ea8..4eaf) xxxx
#
run_test "jsr 0(a0)" "\x4e\xa8\x00\x00"
run_test "jsr 10(a1)" "\x4e\xa9\x00\x0a"
run_test "jsr -32753(a2)" "\x4e\xaa\x80\x0f"

# (4eb0..4eb7) xxxx
#
run_test "jsr 15(a1,d0.w)" "\x4e\xb1\x00\x0f"
run_test "jsr -16(a0,d0.w)" "\x4e\xb0\x00\xf0"
run_test "jsr 0(a0,d0.w)" "\x4e\xb0\x00\x00"
run_test "jsr 10(a0,a0.w)" "\x4e\xb0\x80\x0a"
run_test "jsr 12(a0,d0.l)" "\x4e\xb0\x08\x0c"
run_test "jsr -80(a0,d0.l)" "\x4e\xb0\x08\xb0"
run_test "jsr 15(a0,d1.w)" "\x4e\xb0\x10\x0f"
run_test "jsr 17(a2,a1.w)" "\x4e\xb2\x90\x11"

# 4eb8 xxxx Word displacement
#
run_test "jsr 0x0.w" "\x4e\xb8\x00\x00"
run_test "jsr 0x1f.w" "\x4e\xb8\x00\x1f"
run_test "jsr 0xffff8a0c.w" "\x4e\xb8\x8a\x0c"

# 4eb9 xxxx Long displacement
#
run_test "jsr 0x0.l" "\x4e\xb9\x00\x00\x00\x00"
run_test "jsr 0x10bb431f.l" "\x4e\xb9\x10\xbb\x43\x1f"
run_test "jsr 0x80ccd98a.l" "\x4e\xb9\x80\xcc\xd9\x8a"

# 4eba xxxx
#
run_test "jsr .+2(pc)" "\x4e\xba\x00\x00"
run_test "jsr .+33(pc)" "\x4e\xba\x00\x1f"
run_test "jsr .-30194(pc)" "\x4e\xba\x8a\x0c"

# 4ebb xxxx
#
run_test "jsr .-14(pc,d0.w)" "\x4e\xbb\x00\xf0"
run_test "jsr .+2(pc,d0.w)" "\x4e\xbb\x00\x00"
run_test "jsr .+12(pc,a0.w)" "\x4e\xbb\x80\x0a"
run_test "jsr .+14(pc,d0.l)" "\x4e\xbb\x08\x0c"
run_test "jsr .-78(pc,d0.l)" "\x4e\xbb\x08\xb0"

run_test "jsr .+17(pc,d1.w)" "\x4e\xbb\x10\x0f"
run_test "jsr .+19(pc,a1.w)" "\x4e\xbb\x90\x11"
