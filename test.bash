#!/usr/bin/env bash
#
# SPDX-License-Identifier: Unlicense
#
# Tests against m68k-none-elf-as.

AS=m68k-none-elf-as
OBJCOPY=m68k-none-elf-objcopy
LD="m68k-none-elf-ld -Ttest.ld"
DISASM="./cmake-build/m68k-disasm -fabs-marks -frel-marks -fmarks"
TEST_DIR=/tmp/m68k-disasm-tests

set -e
CRED="\033[31m"
CGREEN="\033[32m"
CRST="\033[39m"

rm -rf ${TEST_DIR}
mkdir -p ${TEST_DIR}

run_test_expect_short() {
  local test_name=$1
  local test_name_sanitized=${test_name//[^a-zA-Z0-9_\-]/-}
  local data=$2
  local file_orig_bin=${TEST_DIR}/${test_name_sanitized}.orig.bin
  local file_asm=${TEST_DIR}/${test_name_sanitized}.S
  local file_as_o=${TEST_DIR}/${test_name_sanitized}.as.o
  local file_as_elf=${TEST_DIR}/${test_name_sanitized}.as.elf
  local file_as_bin=${TEST_DIR}/${test_name_sanitized}.as.bin
  echo -ne "Test expect .short \"${test_name}\"... "
  echo -ne "${data}" >${file_orig_bin}
  ${DISASM} -o ${file_asm} ${file_orig_bin}
  ${AS} -m68000 -o ${file_as_o} ${file_asm}
  ${LD} -o ${file_as_elf} ${file_as_o}
  ${OBJCOPY} ${file_as_elf} -O binary ${file_as_bin}
  if ! grep ".short" ${file_asm} >/dev/null 2>&1; then
    echo -e "${CRED}FAIL${CRST}: NOT .short emitted, but .short EXPECTED"
    cat ${file_asm}
  elif ! cmp ${file_orig_bin} ${file_as_bin} >/dev/null 2>&1; then
    echo -e "${CRED}FAIL${CRST}: output and input binaries do not match"
    cat ${file_asm}
    echo ${file_orig_bin}
    hexdump -Cv ${file_orig_bin} | head -n1
    echo ${file_as_bin}
    hexdump -Cv ${file_as_bin} | head -n1
  else
    echo -e "${CGREEN}OK${CRST}"
    #cat ${file_asm}
  fi
}

run_test_simple() {
  local test_name=$1
  local test_name_sanitized=${test_name//[^a-zA-Z0-9_\-]/-}
  local data=$2
  local file_orig_bin=${TEST_DIR}/${test_name_sanitized}.orig.bin
  local file_asm=${TEST_DIR}/${test_name_sanitized}.S
  local file_as_o=${TEST_DIR}/${test_name_sanitized}.as.o
  local file_as_elf=${TEST_DIR}/${test_name_sanitized}.as.elf
  local file_as_bin=${TEST_DIR}/${test_name_sanitized}.as.bin
  echo -ne "Test \"${test_name}\"... "
  echo -ne "${data}" >${file_orig_bin}
  ${DISASM} -o ${file_asm} ${file_orig_bin}
  ${AS} -m68000 -o ${file_as_o} ${file_asm}
  ${LD} -o ${file_as_elf} ${file_as_o}
  ${OBJCOPY} ${file_as_elf} -O binary ${file_as_bin}
  if ! cmp ${file_orig_bin} ${file_as_bin} >/dev/null 2>&1; then
    echo -e "${CRED}FAIL${CRST}: output and input binaries do not match"
    cat ${file_asm}
    echo ${file_orig_bin}
    hexdump -Cv ${file_orig_bin} | head -n1
    echo ${file_as_bin}
    hexdump -Cv ${file_as_bin} | head -n1
  elif grep ".short" ${file_asm} >/dev/null 2>&1; then
    echo -e "${CRED}FAIL${CRST}: .short emitted"
    cat ${file_asm}
  else
    echo -e "${CGREEN}OK${CRST}"
    #cat ${file_asm}
  fi
}

run_test_iterative() {
  local test_name=$1
  local prefix=$2
  local offset=$3
  local count=$4
  local step=$5
  local suffix=$6
  for i in $(seq 0 $(( step )) $(( count*step-1 )) ); do
    local value=$(printf "%02x" $(( offset+i )))
    run_test_simple "${test_name}:${value}" "${prefix}\x${value}${suffix}"
  done
}

# 48xx ext
#
run_test_simple "extw %d7" "\x48\x87"
run_test_simple "extl %d4" "\x48\xc4"

# exxx asl, asr, lsl, lsr, roxl, roxr, rol, ror
#
run_test_simple "asrb Dn, Dn" "\xe2\x22"
run_test_simple "asrb #1, Dn" "\xe2\x02"
run_test_simple "asrb #8, Dn" "\xe0\x02"
run_test_simple "aslb #7, Dn" "\xef\x02"
run_test_simple "asrw Dn, Dn" "\xe2\x62"
run_test_simple "asrl Dn, Dn" "\xe2\xa2"
run_test_simple "aslw #6, Dn" "\xed\x43"
run_test_simple "asll #5, Dn" "\xeb\x83"
run_test_simple "asrw (An)" "\xe0\xd0"
run_test_simple "lsrw (An)+" "\xe2\xd8"
run_test_simple "roxrw -(An)" "\xe4\xe0"
run_test_simple "rorw (d16,An)" "\xe6\xef\x01\x00"
# Found on random tests
run_test_simple "lsrb D1,D4" "\xe2\x2c"

# 9xxx subx
#
run_test_simple "subxb Dn, Dn" "\x91\x00"
run_test_simple "subxw Dn, Dn" "\x93\x47"
run_test_simple "subxl Dn, Dn" "\x95\x86"
run_test_simple "subxb -(An), -(An)" "\x91\x08"
run_test_simple "subxw -(An), -(An)" "\x93\x4f"
run_test_simple "subxl -(An), -(An)" "\x95\x8e"

# 9xxx suba
#
run_test_simple "subaw Dn, An" "\x94\xc1"
run_test_simple "subal An, An" "\x9b\xca"
run_test_simple "subaw (An)+, An" "\x9a\xda"
run_test_simple "subaw #imm, An" "\x9a\xfc\x01\x00"
run_test_simple "subal #imm, An" "\x9b\xfc\x80\x00\x00\x00"

# 9xxx sub
#
run_test_simple "subb Dn, Dn" "\x94\x01"
run_test_expect_short "subb An, Dn" "\x94\x09"
run_test_simple "subw An, Dn" "\x94\x49"
run_test_simple "subb (An), Dn" "\x94\x11"
run_test_simple "subb (An)+, Dn" "\x94\x19"
run_test_simple "subb -(An), Dn" "\x94\x21"
# GNU AS would emit SUBQ for "sub #imm,Xn", so we diassemble it as short
run_test_expect_short "subl #imm, D6" "\x96\xbc\x44\xd1\xe6\xe9"

# dxxx addx
#
run_test_simple "addxb Dn, Dn" "\xd1\x00"
run_test_simple "addxw Dn, Dn" "\xd3\x47"
run_test_simple "addxl Dn, Dn" "\xd5\x86"
run_test_simple "addxb -(An), -(An)" "\xd1\x08"
run_test_simple "addxw -(An), -(An)" "\xd3\x4f"
run_test_simple "addxl -(An), -(An)" "\xd5\x8e"

# dxxx adda
#
run_test_simple "addaw Dn, An" "\xd4\xc1"
run_test_simple "addal An, An" "\xdb\xca"
run_test_simple "addaw (An)+, An" "\xda\xda"
run_test_simple "addaw #imm, An" "\xda\xfc\x01\x00"
run_test_simple "addal #imm, An" "\xdb\xfc\x80\x00\x00\x00"

# dxxx add
#
run_test_simple "addb Dn, Dn" "\xd4\x01"
run_test_expect_short "addb An, Dn" "\xd4\x09"
run_test_simple "addw An, Dn" "\xd4\x49"
run_test_simple "addb (An), Dn" "\xd4\x11"
run_test_simple "addb (An)+, Dn" "\xd4\x19"
run_test_simple "addb -(An), Dn" "\xd4\x21"
# GNU AS would emit ADDI for "add #imm,Xn", so we diassemble it as short
run_test_expect_short "addl #imm, D6" "\xd6\xbc\x44\xd1\xe6\xe9"

# 4xxx chkw
#
run_test_simple "chkw Dn" "\x47\x82"
run_test_simple "chkw (An)" "\x41\x90"
run_test_simple "chkw (An)+" "\x47\x9b"
run_test_simple "chkw (d16,An)" "\x47\xa9\x80\x00"
run_test_simple "chkw (d8,An,Xi)" "\x47\xb2\xa8\x7f"

# 4xxx leal
#
run_test_simple "leal (An)" "\x41\xd0"
run_test_simple "leal (d16,An)" "\x47\xe9\x80\x00"
run_test_simple "leal (d8,An,Xi)" "\x47\xf2\xa8\x7f"
run_test_simple "leal (d16,PC)" "\x47\xfa\x7f\xff"
run_test_simple "leal (d8,PC,Xi)" "\x47\xfb\xa8\x80"

# 0xxx movep
#
run_test_simple "movepw Dn to (An)" "\x01\x0b\x00\xa0"
run_test_simple "movepl Dn to (An)" "\x03\x4a\x00\xa0"
run_test_simple "movepw (An) to Dn" "\x05\x89\x00\xa0"
run_test_simple "movepl (An) to Dn" "\x07\xc8\x00\xa0"

# 0xxx bitwise ops
#
run_test_simple "btstl immediate in Dn" "\x08\x07\x00\x06"
run_test_simple "btstb immediate in (An)" "\x08\x17\x00\x06"
run_test_simple "btstb immediate in (xxx).L" "\x08\x39\x00\x06\xff\x00\x00\x00"
run_test_simple "btstb Dn in (xxx).L" "\x03\x39\xff\x00\x00\x00"
run_test_simple "bchgb Dn in (xxx).L" "\x05\x79\xff\x00\x00\x00"
run_test_simple "bclrb Dn in (xxx).L" "\x07\xb9\xff\x00\x00\x00"
run_test_simple "bsetb Dn in (xxx).L" "\x09\xf9\xff\x00\x00\x00"
run_test_expect_short "btstb large immediate in (xxx).L" "\x08\x39\x10\x21\xff\x00\x00\x00"

# 0xxx immediate ops
#
run_test_simple "orib zero to CCR" "\x00\x3c\x00\x00"
run_test_simple "orib positive to CCR" "\x00\x3c\x00\x01"
run_test_simple "orib positive to CCR" "\x00\x3c\x00\x7f"
run_test_expect_short "orib #imm (too much for orib) to CCR" "\x00\x3c\x01\x00"
run_test_simple "orib negative to CCR" "\x00\x3c\xff\x80"
run_test_simple "orib negative to CCR" "\x00\x3c\xff\xff"
run_test_simple "oriw zero to SR" "\x00\x7c\x00\x00"
run_test_simple "oriw positive to SR" "\x00\x7c\x00\x0a"
run_test_simple "andiw positive to SR" "\x02\x7c\x00\x0a"
run_test_simple "eoriw positive to SR" "\x0a\x7c\x00\x0a"
run_test_simple "andib positive to CCR" "\x02\x3c\x00\x0a"
run_test_simple "eorib positive to CCR" "\x0a\x3c\x00\x0a"
run_test_simple "orib positive to Dn" "\x00\x07\x00\x0a"
run_test_simple "oriw positive to Dn" "\x00\x45\x00\x0a"
run_test_simple "oril positive to Dn" "\x00\x83\x00\x00\x00\x0a"
run_test_simple "andib negative to Dn" "\x00\x07\xff\x80"
run_test_simple "andiw negative to Dn" "\x00\x45\xff\x80"
run_test_simple "andil negative to Dn" "\x00\x83\xff\x80\x00\x00"
run_test_simple "addiw zero to (An)+" "\x06\x5a\x00\x00"
run_test_simple "subiw zero from -(An)" "\x06\x62\x00\x00"
run_test_simple "cmpib zero to (An)" "\x0c\x12\x00\x20"
run_test_simple "cmpiw zero to (An)" "\x0c\x52\x00\x30"
run_test_simple "cmpil zero to (An)" "\x0c\x92\x00\x00\x00\x40"
# From random tests
run_test_expect_short "cmpil with invalid opsize" "\x0c\xe4\x26\xa3"

# 4axx
#
run_test_simple "tas Dn" "\x4a\xc2"
run_test_simple "tstb Dn" "\x4a\x02"
run_test_simple "tstw Dn" "\x4a\x42"
run_test_simple "tstl Dn" "\x4a\x82"
run_test_expect_short "tas (d16,PC)" "\x4a\xfa\xff\xff"
run_test_expect_short "tas (d8,PC,Xi)" "\x4a\xfb\x00\x00"

# 4xxx
#
run_test_simple "negxb Dn" "\x40\x04"
run_test_simple "clrb Dn" "\x42\x05"
run_test_simple "negb Dn" "\x44\x06"
run_test_simple "notb Dn" "\x46\x07"
run_test_simple "negxw Dn" "\x40\x44"
run_test_simple "clrw Dn" "\x42\x45"
run_test_simple "negw Dn" "\x44\x46"
run_test_simple "notw Dn" "\x46\x47"
run_test_simple "negxl Dn" "\x40\x84"
run_test_simple "clrl Dn" "\x42\x85"
run_test_simple "negl Dn" "\x44\x86"
run_test_simple "notl Dn" "\x46\x87"

# 4e4x
#
run_test_simple "trap 0" "\x4e\x40"
run_test_simple "trap 8" "\x4e\x48"
run_test_simple "trap 15" "\x4e\x4f"

# 4e5x
#
run_test_simple "linkw positive" "\x4e\x52\x01\x00"
run_test_simple "linkw negative" "\x4e\x52\xff\xff"
run_test_simple "linkw negative" "\x4e\x52\x80\x00"
run_test_simple "unlk" "\x4e\x5a"

# 4e6x
#
run_test_simple "move to USP" "\x4e\x62"
run_test_simple "move from USP" "\x4e\x6f"

# 4xxx
#
run_test_simple "move from SR" "\x40\xc1"
run_test_simple "move to CCR" "\x44\xc2"
run_test_simple "move to SR" "\x46\xc3"

# 70xx / 72xx/ 74xx / 76xx / 78xx / 7axx / 7cxx / 7exx
#
run_test_simple "moveq #0 to D0" "\x70\x00"
run_test_simple "moveq #1 to D2" "\x74\x01"
run_test_simple "moveq #127 to D7" "\x7e\x7f"
run_test_simple "moveq #-1 to D5" "\x7a\xff"
run_test_simple "moveq #-128 to D1" "\x72\x80"

# From random tests
# 
run_test_simple "movel %pc@(-16,%a0:l),%a3@+ with nop" "\x26\xfb\x88\xf0\x4e\x71"

# 1xxx [xxxx [xxxx]]
#
run_test_simple "moveb Dn to Dn" "\x10\x01"
run_test_simple "moveb (An) to Dn" "\x10\x11"
run_test_simple "moveb (An)+ to Dn" "\x10\x19"
run_test_simple "moveb -(An) to Dn" "\x10\x21"
run_test_simple "moveb (d16,An) to Dn" "\x10\x29\xfc\xeb"
run_test_simple "moveb (d8,An,Xi) to Dn" "\x10\x31\x98\x70"
run_test_simple "moveb (xxx).W to Dn" "\x10\x38\x98\x70"
run_test_simple "moveb (xxx).L to Dn" "\x10\x39\x30\x30\x30\x70"
run_test_simple "moveb (d16,PC) to Dn" "\x10\x3a\xfc\xeb"
run_test_simple "moveb (d8,PC,Xi) to Dn" "\x10\x3b\xa8\x70"
run_test_simple "moveb #imm to Dn" "\x10\x3c\xff\xff"

# 3xxx [xxxx [xxxx]]
#
run_test_simple "movew Dn to Dn" "\x3e\x02"
run_test_simple "movew An to Dn" "\x3e\x0a"
run_test_simple "movew (An) to Dn" "\x3e\x12"
run_test_simple "movew (An)+ to Dn" "\x30\x1a"
run_test_simple "movew -(An) to Dn" "\x30\x22"
run_test_simple "movew (d16,An) to Dn" "\x30\x2a\x3f\xff"
run_test_simple "movew (d8,An,Xi) to Dn" "\x30\x32\x90\x80"
run_test_simple "movew (xxx).W to Dn" "\x30\x38\x90\x80"
run_test_simple "movew (xxx).L to Dn" "\x30\x39\xaa\xaa\xaa\xaa"
run_test_simple "movew (d16,PC) to Dn" "\x30\x3a\x3f\xff"
run_test_simple "movew (d8,PC,Xi) to Dn" "\x30\x3b\xa0\x80"
run_test_simple "movew #imm to Dn" "\x30\x3c\xa5\xa5"
run_test_simple "moveaw Dn" "\x30\x41"
run_test_simple "moveaw #imm" "\x30\x7c\xa8\x90"

# 2xxx [xxxx [xxxx]]
#
run_test_simple "movel Dn to Dn" "\x24\x05"
run_test_simple "movel An to Dn" "\x24\x0d"
run_test_simple "movel (An) to Dn" "\x24\x15"
run_test_simple "movel (An)+ to Dn" "\x24\x1d"
run_test_simple "movel -(An) to Dn" "\x24\x25"
run_test_simple "movel (d16,An) to Dn" "\x24\x2d\x78\x20"
run_test_simple "movel (d8,An,Xi) to Dn" "\x24\x35\x98\x90"
run_test_simple "movel (xxx).W to Dn" "\x24\x38\x78\x90"
run_test_simple "movel (xxx).L to Dn" "\x24\x39\x00\x00\x78\x90"
run_test_simple "movel (d16,PC) to Dn" "\x24\x3a\x78\x20"
run_test_simple "movel (d8,PC,Xi) to Dn" "\x24\x3b\xa8\x90"
run_test_simple "movel #imm to Dn" "\x24\x3c\xa8\x90\x00\x00"
run_test_simple "moveal Dn" "\x20\x41"
run_test_simple "moveal #imm" "\x20\x7c\xa8\x90\x00\x00"

# 4890 xxx
#
run_test_simple "movemw single register to (An)" "\x48\x90\x00\x01"
run_test_simple "movemw d0-d1,a0-a1 to (An)" "\x48\x90\x03\x03"
run_test_simple "moveml 6 spans to (An)" "\x48\xd0\xb6\xdb"
run_test_simple "movemw 8 non-neighboring regs to (An)" "\x48\x90\x55\x55"
run_test_simple "moveml other 8 non-neighboring regs to (An)" "\x48\xd0\xaa\xaa"
run_test_simple "moveml all registers to (An)" "\x48\xd0\xff\xff"
run_test_simple "movemw all registers to -(An)" "\x48\xa0\xff\xff"
run_test_simple "moveml all registers to (d16,An)" "\x48\xe8\xff\xff\x30\x1d"
run_test_simple "movemw all registers to (d8,An,Xi)" "\x48\xb7\xff\xff\x48\x0a"
run_test_simple "moveml all registers to (xxx).W" "\x48\xf8\xff\xff\x80\x10"
run_test_simple "movemw all registers to (xxx).L" "\x48\xb9\xff\xff\x00\x00\x7f\xf0"
run_test_simple "movemw (An) to all registers " "\x4c\x90\xff\xff"
run_test_simple "moveml (An)+ to all registers" "\x4c\xd8\xff\xff"
run_test_simple "movemw (d16,An) to all registers" "\x4c\xa8\xff\xff\x30\x1d"
run_test_simple "moveml (d8,An,Xi) to all registers" "\x4c\xf7\xff\xff\x48\x0a"
run_test_simple "movemw (xxx).W to all registers" "\x4c\xb8\xff\xff\x80\x10"
run_test_simple "moveml (xxx).L to all registers" "\x4c\xf9\xff\xff\x00\x00\x7f\xf0"

# From random tests
#
run_test_expect_short "movem truncated" "\x48\x92"

# 5x38 / 5x78 / 5xb8 (xxx).W
#
run_test_simple "addqb #8,offset:w" "\x50\x38\x00\x73"
run_test_simple "addql #4,offset:w" "\x58\xb8\x80\x14"

# 5x39 / 5x79 / 5xb9 (xxx).L
#
run_test_simple "addqw #5,offset:l" "\x5a\x79\x18\xfc\x00\x00"
run_test_simple "addql #1,offset:l" "\x52\xb9\xf1\x00\x00\x01"

# 5x30..5x37 / 5x70..5x77 / 5xb0..5xb7, (d16, An, Xi), Brief Extension Word
#
run_test_simple "addqb #8,a7(positive,d0:w)" "\x50\x37\x00\x73"
run_test_simple "addqw #5,a2(negative,d1:l)" "\x5a\x72\x18\xfc"
run_test_simple "addql #1,a3(negative,a3:w)" "\x52\xb3\xb0\x81"

# 5x28..5x2f / 5x68..5x6f / 5xa8..5xaf, (d16, An), Displacement Word
#
run_test_simple "addqb #8,a7(positive)" "\x50\x2f\x00\x80"
run_test_simple "addqw #5,a2(negative)" "\x5a\x6a\xfc\xfc"
run_test_simple "addql #1,a3(negative)" "\x52\xab\xff\xff"

# 5x20..5x27 / 5x60..5x67 / 5xa0..5xa7, -(An)
#
run_test_simple "addqb #8,-(a7)" "\x50\x27"
run_test_simple "addqw #5,-(a2)" "\x5a\x62"
run_test_simple "addql #1,-(a3)" "\x52\xa3"

# 5x18..5x1f / 5x58..5x5f / 5x98..5x9f, (An)+
#
run_test_simple "addqb #8,(a7)+" "\x50\x1f"
run_test_simple "addqw #5,(a2)+" "\x5a\x5a"
run_test_simple "addql #1,(a3)+" "\x52\x9d"

# 5x10..5x17 / 5x50..5x57 / 5x90..5x97, (An)
#
run_test_simple "addqb #8,(a7)" "\x50\x17"
run_test_simple "addqw #5,(a2)" "\x5a\x52"
run_test_simple "addql #1,(a3)" "\x52\x93"

# 5x08..5x0f / 5x48..5x4f / 5x88..5x8f, An
#
# NOTE: addqb with An does not exits
run_test_simple "addqw #6,a7" "\x5c\x4f"
run_test_simple "addql #1,a5" "\x52\x8d"

# 5x00..5x07 / 5x40..5x47 / 5x80..5x87, Dn
#
run_test_simple "addqb #8,d7" "\x50\x07"
run_test_simple "addqw #5,d2" "\x5a\x42"
run_test_simple "addql #1,d3" "\x52\x83"

# 50f9 xxxx
#
run_test_simple "st d16:l positive" "\x51\xf9\x00\x00\x00\x74"
run_test_simple "st d16:l negative" "\x51\xf9\xc0\xfe\xba\xbe"

# 50f8 xxxx
#
run_test_simple "st d16:w positive" "\x51\xf8\x00\x66"
run_test_simple "st d16:w negative" "\x51\xf8\x80\xc4"

# 51f0 xxxx
#
run_test_simple "sf (d16:w,A4,D3) positive" "\x51\xf4\xb0\x04"
run_test_simple "sf (d16:w,A3,A6) negative" "\x51\xf3\x60\xf2"

# 5fe8 xxxx
#
run_test_simple "sle (d16,A0) positive" "\x5f\xe8\x00\xa0"
run_test_simple "sle (d16,A0) negative" "\x5f\xe8\xe4\x02"

# 5ee1
#
run_test_simple "sgt -(%a1)" "\x5e\xe1"

# 56df
#
run_test_simple "sne (%a7)+" "\x56\xdf"

# 5dd3
#
run_test_simple "slt (%a3)" "\x5d\xd3"

# 57cx
#
run_test_iterative "seq Xn" "\x57" 0xc0 8 1

# 50cf xxxx
#
run_test_simple "dbt negative displacement" "\x50\xcf\xff\xfc"
run_test_simple "dbt positive displacement" "\x50\xcf\x01\x08"

# 50c9 7ffe
#
# From random tests
run_test_simple "dbt %d1,.+32768" "\x50\xc9\x7f\xfe"

# 60xx
#
run_test_simple "bras negative displacement" "\x60\xfc"
run_test_simple "bras positive displacement" "\x60\x08"

# 60xx (xxxx)
#
run_test_simple "braw negative displacement" "\x60\x00\xf8\x2e"
run_test_simple "braw positive displacement" "\x60\x00\x03\xe6"
run_test_simple "braw zero displacement" "\x60\x00\x00\x00"

# 61xx (xxxx)
#
run_test_simple "bsrs negative displacement" "\x61\x88"
run_test_simple "bsrw positive displacement" "\x61\x00\x03\xe6"

# 6xxx
#
run_test_simple "bhis" "\x62\x0a"
run_test_simple "blss" "\x63\x0a"
run_test_simple "bccs" "\x64\x0a"
run_test_simple "bcss" "\x65\x0a"
run_test_simple "bnes" "\x66\x0a"
run_test_simple "beqs" "\x67\x0a"
run_test_simple "bvcs" "\x68\x0a"
run_test_simple "bvss" "\x69\x0a"
run_test_simple "bpls" "\x6a\x0a"
run_test_simple "bmis" "\x6b\x0a"
run_test_simple "bges" "\x6c\x0a"
run_test_simple "blts" "\x6d\x0a"
run_test_simple "bgts" "\x6e\x0a"
run_test_simple "bles" "\x6f\x0a"

# 4afc
#
# reset
#
run_test_simple "illegal" "\x4a\xfc"

# 4e70
#
# reset
run_test_simple "reset" "\x4e\x70"

# 4e71
#
# nop
run_test_simple "nop" "\x4e\x71"

# 4e72 xxxx
#
run_test_simple "stop #8:w" "\x4e\x72\x00\x08"
run_test_simple "stop #ffff:w" "\x4e\x72\xff\xff"

# 4e73
#
# rte
run_test_simple "rte" "\x4e\x73"

# 4e75
#
# rts
run_test_simple "rts" "\x4e\x75"

# 4e76
#
# trapv
run_test_simple "trapv" "\x4e\x76"

# 4e77
#
# rtr
run_test_simple "rtr" "\x4e\x77"

# 4e90..4e97
#
run_test_iterative "jsr M2 all An" "\x4e" 0x90 8 1 ""

# (4ea8..4eaf) xxxx
#
run_test_simple "jsr M5 zero value" "\x4e\xa8\x00\x00"
run_test_iterative "jsr M5 all An, positive" "\x4e" 0xa8 8 1 "\x00\x0a"
run_test_simple "jsr M5 A0 negative" "\x4e\xa8\x80\x0f"

# (4eb0..4eb7) xxxx
#
run_test_iterative "jsr M6 arbitrary An, positive" "\x4e" 0xb0 8 1 "\x00\x0f"
run_test_simple "jsr M6 A0 negative" "\x4e\xb0\x00\xf0"
run_test_simple "jsr M6 A0 zero" "\x4e\xb0\x00\x00"
run_test_simple "jsr M6 address register" "\x4e\xb0\x80\x0a"
run_test_simple "jsr M6 long displacement positive" "\x4e\xb0\x08\x0c"
run_test_simple "jsr M6 long displacement negative" "\x4e\xb0\x08\xb0"
run_test_iterative "jsr M6 arbitrary Xn2" "\x4e\xb0" 0x00 8 0x10 "\x0f"

# 4eb8 xxxx Word displacement
#
run_test_simple "jsr M7 Xn0 zero" "\x4e\xb8\x00\x00"
run_test_simple "jsr M7 Xn0 positive" "\x4e\xb8\x00\x1f"
run_test_simple "jsr M7 Xn0 negative" "\x4e\xb8\x8a\x0c"

# 4eb9 xxxx Long displacement
#
run_test_simple "jsr M7 X1 zero" "\x4e\xb9\x00\x00\x00\x00"
run_test_simple "jsr M7 X1 positive" "\x4e\xb9\x10\xbb\x43\x1f"
run_test_simple "jsr M7 X1 negative" "\x4e\xb9\x80\xcc\xd9\x8a"

# 4eba xxxx
#
run_test_simple "jsr M7 X2 zero value" "\x4e\xba\x00\x00"
run_test_simple "jsr M7 X2 positive value" "\x4e\xba\x00\x1f"
run_test_simple "jsr M7 X2 negative value" "\x4e\xba\x8a\x0c"

# 4ebb xxxx
#
run_test_simple "jsr M7 X3 negative" "\x4e\xbb\x00\xf0"
run_test_simple "jsr M7 X3 zero displacement" "\x4e\xbb\x00\x00"
run_test_simple "jsr M7 X3 An2=A0" "\x4e\xbb\x80\x0a"
run_test_simple "jsr M7 X3 long positive displacement" "\x4e\xbb\x08\x0c"
run_test_simple "jsr M7 X3 long negative displacement" "\x4e\xbb\x08\xb0"
run_test_iterative "jsr M7 X3 arbitrary Dn2" "\x4e\xbb" 0x00 8 0x10 "\x0f"
