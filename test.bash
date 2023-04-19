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
  step=$5
  suffix=$6
  file_orig_bin=${TEST_DIR}/${test_name}.orig.bin
  file_asm=${TEST_DIR}/${test_name}.S
  file_as_o=${TEST_DIR}/${test_name}.as.o
  file_as_bin=${TEST_DIR}/${test_name}.as.bin
  for i in $(seq 0 $(( step )) $(( count*step-1 )) ); do
    echo -ne "Test ${test_name}:$(( i / step ))... "
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
      cat ${file_asm}
    fi
  done
}

jsr_m2() {
  # 4e90..4e97
  #
  # All registers
  run_test ${FUNCNAME} "\x4e" 0x90 8 1 ""
}

jsr_m5() {
  # (4ea8..4eaf) xxxx
  #
  # XXX this test fails with suffix "\x00\x00", because GNU AS makes
  # optimization and inserts jsr M2/"(An)" (0x4e90) version instead. Hence the
  # disassembler must generate ".short" alternative in such cases. But it may be
  # irrelevant in practice if this variant simply does not exist in the wild.
  #
  # Positive value, all registers
  run_test ${FUNCNAME} "\x4e" 0xa8 8 1 "\x00\x0a"
  # Negative value
  run_test ${FUNCNAME} "\x4e" 0xa8 1 1 "\x80\x0f"
}

jsr_m6() {
  # (4eb0..4eb7) xxxx
  #
  # Positive value, Arbitrary Xn register
  run_test ${FUNCNAME} "\x4e" 0xb0 8 1 "\x00\x0f"
  # Negative value
  run_test ${FUNCNAME} "\x4e" 0xb0 1 1 "\x00\xf0"
  # Zero displacement
  run_test ${FUNCNAME} "\x4e" 0xb0 1 1 "\x00\x00"
  # Address register
  run_test ${FUNCNAME} "\x4e" 0xb0 1 1 "\x80\x0a"
  # Long displacement, positive
  run_test ${FUNCNAME} "\x4e" 0xb0 1 1 "\x08\x0c"
  # Long displacement, negative
  run_test ${FUNCNAME} "\x4e" 0xb0 1 1 "\x08\xb0"
  # Arbitrary Xn2
  run_test ${FUNCNAME} "\x4e\xb0" 0x00 8 0x10 "\x0f"
}

jsr_m2
jsr_m5
jsr_m6
