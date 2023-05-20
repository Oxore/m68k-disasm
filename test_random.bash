#!/usr/bin/env bash
#
# SPDX-License-Identifier: Unlicense
#
# Tests against m68k-none-elf-as.

AS=m68k-none-elf-as
OBJCOPY=m68k-none-elf-objcopy
LD="m68k-none-elf-ld -Ttest.ld"
DISASM="./cmake-build/m68k-disasm -fabs-marks -frel-marks -fmarks -frdc"
TEST_DIR=/tmp/m68k-disasm-random-tests

set -e
CRED="\033[31m"
CGREEN="\033[32m"
CRST="\033[39m"

rm -rf ${TEST_DIR}
mkdir -p ${TEST_DIR}

run_test_random() {
  local pass_number=$1
  local blocks_count=$2
  local test_name_sanitized=${pass_number//[^a-zA-Z0-9_\-]/-}
  local file_orig_bin=${TEST_DIR}/${test_name_sanitized}.orig.bin
  local file_asm=${TEST_DIR}/${test_name_sanitized}.S
  local file_as_o=${TEST_DIR}/${test_name_sanitized}.as.o
  local file_as_elf=${TEST_DIR}/${test_name_sanitized}.as.elf
  local file_as_bin=${TEST_DIR}/${test_name_sanitized}.as.bin
  echo -ne "Test random, pass ${pass_number}... "
  dd if=/dev/urandom of=${file_orig_bin} bs=1024 count=${blocks_count} >/dev/null 2>&1
  ${DISASM} -o ${file_asm} ${file_orig_bin}
  ${AS} -o ${file_as_o} ${file_asm}
  ${LD} -o ${file_as_elf} ${file_as_o}
  ${OBJCOPY} ${file_as_elf} -O binary ${file_as_bin}
  if ! cmp ${file_orig_bin} ${file_as_bin}; then
    echo -e "${CRED}FAIL${CRST}: output and input binaries do not match"
    hexdump -Cv ${file_orig_bin} >${file_orig_bin}.txt
    hexdump -Cv ${file_as_bin} >${file_as_bin}.txt
    echo ${file_orig_bin}
    echo ${file_as_bin}
    exit
  else
    echo -e "${CGREEN}OK${CRST}"
    rm ${file_orig_bin} ${file_asm} ${file_as_o} ${file_as_elf} ${file_as_bin}
  fi
}

for i in `seq 1 1000`; do
  run_test_random tiny$i 1
done

for i in `seq 1 10`; do
  run_test_random huge$i 1024
done
