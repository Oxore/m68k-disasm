#!/usr/bin/env bash
#
# SPDX-License-Identifier: Unlicense
#
# Tests against m68k-none-elf-as.

AS=m68k-none-elf-as
OBJCOPY=m68k-none-elf-objcopy
LD="m68k-none-elf-ld -Ttest.ld"
DISASM="../cmake-build/m68k-disasm -ffollow-jumps"
TEST_DIR=/tmp/m68k-disasm-tests-labels-referencing

set -e
CRED="\033[31m"
CGREEN="\033[32m"
CRST="\033[39m"

rm -rf ${TEST_DIR}
mkdir -p ${TEST_DIR}

run_test_r() {
  local test_name=$1
  local test_name_sanitized=${test_name//[^a-zA-Z0-9_\-]/-}
  local data=$2
  local args=$3
  local file_orig_bin=${TEST_DIR}/${test_name_sanitized}.orig.bin
  local file_asm=${TEST_DIR}/${test_name_sanitized}.S
  local file_as_o=${TEST_DIR}/${test_name_sanitized}.as.o
  local file_as_elf=${TEST_DIR}/${test_name_sanitized}.as.elf
  local file_as_bin=${TEST_DIR}/${test_name_sanitized}.as.bin
  echo -ne "Test \"${test_name}\"... "
  echo -ne "${data}" >${file_orig_bin}
  ${DISASM} $args -o ${file_asm} ${file_orig_bin}
  ${AS} -m68000 -o ${file_as_o} ${file_asm}
  ${LD} -o ${file_as_elf} ${file_as_o}
  ${OBJCOPY} ${file_as_elf} -O binary ${file_as_bin}
  if ! cmp ${file_orig_bin} ${file_as_bin}; then
    cat ${file_asm}
    echo -e "${CRED}FAIL${CRST}: output and input binaries do not match"
    hexdump -Cv ${file_orig_bin} >${file_orig_bin}.txt
    hexdump -Cv ${file_as_bin} >${file_as_bin}.txt
    echo ${file_orig_bin}
    echo ${file_as_bin}
    exit
  elif grep ".short" ${file_asm} >/dev/null 2>&1; then
    echo -e "${CRED}FAIL${CRST}: .short emitted"
    cat ${file_asm}
    exit
  fi
  local run_check=$4
  $run_check
  #echo && cat ${file_asm}
  echo -e "${CGREEN}OK${CRST}"
}

run_check_rdisp() {
  if grep -e "\s\.\([+-]\+\|\s\+\|$\)" ${file_asm} >/dev/null 2>&1; then
    echo -e "${CRED}FAIL${CRST}: raw displacement emitted"
    cat ${file_asm}
    exit
  fi
}

run_check_r() {
  if grep -e "[^0-9a-zA-Z_+][0-9]\+" ${file_asm} >/dev/null 2>&1; then
    echo -e "${CRED}FAIL${CRST}: raw number or displacement emitted"
    cat ${file_asm}
    exit
  fi
}

run_check_dummy() { :; }

run_test_rdisp() {
  run_test_r "$1" "$2" "-flabels -frel-labels" run_check_rdisp
}

run_test_rword() {
  run_test_r "$1" "$2" "-flabels -fabs-labels" run_check_r
}

run_test_rpcrel() {
  run_test_r "$1" "$2" "-flabels -frel-labels" run_check_r
}

run_test_rlocal() {
  run_test_r "$1" "$2" "-flabels -frel-labels -fabs-labels -fshort-ref-local-labels" run_check_dummy
}

run_test_rdisp "bras ." "\x60\xfe"
run_test_rdisp "bras .-2" "\x4e\x71\x60\xfc"
run_test_rdisp "bras .-1" "\x4e\x71\x60\xfd"
run_test_rdisp "braw .+2" "\x4e\x71\x60\x00\x00\x00"
run_test_rword "moveml 0x0:w,%d0" "\x4c\xf8\x00\x01\x00\x00"
run_test_rword "moveml 0x6:w,%a0" "\x4c\xf8\x01\x00\x00\x06\x4e\x71\x4e\x71"
run_test_rword "movemw 0x0:l,%a0" "\x4e\x71\x4e\x71\x4c\xb9\x01\x00\x00\x00\x00\x02"
run_test_rpcrel "movemw (0,PC),%a0" "\x4e\x71\x4e\x71\x4c\xba\x01\x00\x00\x00"
run_test_rpcrel "lea (0,PC)" "\x47\xfa\x00\x00"
run_test_rpcrel "jmp (0,PC)" "\x4e\xfa\x00\x00"
run_test_rword "peal 0x0:w" "\x48\x78\x00\x00"
run_test_rword "peal 0x0:l" "\x48\x79\x00\x00\x00\x00"
run_test_rpcrel "peal (0,PC)" "\x48\x7a\x00\x00"
run_test_rword "nbcd 0x0:w" "\x48\x38\x00\x00"
run_test_rword "nbcd 0x6:l with nop" "\x48\x39\x00\x00\x00\x06\x4e\x71"
run_test_rword "cmpl 0x4:w, D2 with nop" "\xb4\xb8\x00\x04\x4e\x71"
run_test_rword "cmpw 0x0:l, D2" "\xb4\x79\x00\x00\x00\x00"
run_test_rpcrel "cmpl (0,PC), D2" "\xb4\xba\x00\x00"
run_test_rpcrel "cmpl (-2,PC), D2" "\xb4\xba\xff\xfe"
run_test_rlocal "bras 1f; nop; 1: bras 1b" "\x60\x02\x4e\x71\x60\xfe"
run_test_rlocal "2: bras 1f; nop; 1: bras 2b" "\x60\x02\x4e\x71\x60\xfa"
