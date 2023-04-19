#!/usr/bin/env bash
#
# SPDX-License-Identifier: Unlicense
#
# Tests against m68k-none-elf-as.

AS=m68k-none-elf-as
OBJCOPY=m68k-none-elf-objcopy
TEST_DIR=/tmp/m68k-disasm-tests
TRACE_FILE=${TEST_DIR}/trace.txt

set -e

rm -rf ${TEST_DIR}
mkdir -p ${TEST_DIR}
echo "0" >${TRACE_FILE}

run_test() {
  test_name=$1
  prefix=$2
  offset=$3
  count=$4
  suffix=$5
  file_orig_bin=${TEST_DIR}/${test_name}.orig.bin
  file_asm=${TEST_DIR}/${test_name}.S
  file_as_o=${TEST_DIR}/${test_name}.as.o
  file_as_bin=${TEST_DIR}/${test_name}.as.bin
  for i in $(seq 0 $(( count-1 )) ); do
    echo -ne "Test ${test_name}:$i... "
    value=$(printf "%02x\n" $(( offset+i )))
    echo -ne "${prefix}\x${value}${suffix}" >${file_orig_bin}
    ./cmake-build/m68k-disasm -t ${TRACE_FILE} -o ${file_asm} ${file_orig_bin}
    ${AS} -o ${file_as_o} ${file_asm}
    ${OBJCOPY} ${file_as_o} -O binary ${file_as_bin}
    if ! cmp ${file_orig_bin} ${file_as_bin}; then
      echo ""
      echo ${file_orig_bin}
      hexdump -Cv ${file_orig_bin} | head -n1
      echo ${file_as_bin}
      hexdump -Cv ${file_as_bin} | head -n1
      break;
    else
      echo "OK"
    fi
  done
}

jsr_m2() {
  # 4e90..4e97
  #
  run_test ${FUNCNAME} "\x4e" 0x90 8 ""
}

jsr_m6() {
  # (4ea8..4eaf) 0000
  #
  # XXX this test fails with suffix "\x00\x00", because GNU AS makes
  # optimization and inserts jsr M2/"(An)" (0x4e90) version instead. Hence the
  # disassembler must generate ".short" alternative in such cases. But it may be
  # irrelevant in practice if this variant simply does not exist in the wild.
  #
  # Positive value
  run_test ${FUNCNAME} "\x4e" 0xa8 8 "\x00\x0a"
  # Negative value
  run_test ${FUNCNAME} "\x4e" 0xa8 8 "\x80\x0f"
}

jsr_m2
jsr_m6
