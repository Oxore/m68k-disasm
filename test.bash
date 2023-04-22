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

run_test_simple() {
  test_name=$1
  data=$2
  file_orig_bin=${TEST_DIR}/${test_name}.orig.bin
  file_asm=${TEST_DIR}/${test_name}.S
  file_as_o=${TEST_DIR}/${test_name}.as.o
  file_as_bin=${TEST_DIR}/${test_name}.as.bin
  echo -ne "Test ${test_name}... "
  echo -ne "${data}" >${file_orig_bin}
  ./cmake-build/m68k-disasm -t ${TRACE_FILE} -o ${file_asm} ${file_orig_bin}
  ${AS} -o ${file_as_o} ${file_asm}
  ${OBJCOPY} ${file_as_o} -O binary ${file_as_bin}
  if ! cmp ${file_orig_bin} ${file_as_bin} >/dev/null 2>&1; then
    echo "FAIL"
    cat ${file_asm}
    echo ${file_orig_bin}
    hexdump -Cv ${file_orig_bin} | head -n1
    echo ${file_as_bin}
    hexdump -Cv ${file_as_bin} | head -n1
  else
    echo "OK"
    #cat ${file_asm}
  fi
}

run_test_iterative() {
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
    value=$(printf "%02x\n" $(( offset+i )))
    run_test_simple $test_name "${prefix}\x${value}${suffix}"
  done
}

jsr_m2() {
  # 4e90..4e97
  #
  # All registers
  run_test_iterative ${FUNCNAME} "\x4e" 0x90 8 1 ""
}

jsr_m5() {
  # (4ea8..4eaf) xxxx
  #
  # Zero value
  run_test_simple ${FUNCNAME} "\x4e\xa8\x00\x00"
  # Positive value, all registers
  run_test_iterative ${FUNCNAME} "\x4e" 0xa8 8 1 "\x00\x0a"
  # Negative value
  run_test_simple ${FUNCNAME} "\x4e\xa8\x80\x0f"
}

jsr_m6() {
  # (4eb0..4eb7) xxxx
  #
  # Positive value, Arbitrary An register
  run_test_iterative ${FUNCNAME} "\x4e" 0xb0 8 1 "\x00\x0f"
  # Negative value
  run_test_simple ${FUNCNAME} "\x4e\xb0\x00\xf0"
  # Zero displacement
  run_test_simple ${FUNCNAME} "\x4e\xb0\x00\x00"
  # Address register
  run_test_simple ${FUNCNAME} "\x4e\xb0\x80\x0a"
  # Long displacement, positive
  run_test_simple ${FUNCNAME} "\x4e\xb0\x08\x0c"
  # Long displacement, negative
  run_test_simple ${FUNCNAME} "\x4e\xb0\x08\xb0"
  # Arbitrary Xn2
  run_test_iterative ${FUNCNAME} "\x4e\xb0" 0x00 8 0x10 "\x0f"
}

jsr_m7_xn0() {
  # 43b8 xxxx Word displacement
  #
  # Zero value
  run_test_simple ${FUNCNAME} "\x4e\xb8\x00\x00"
  # Positive value
  run_test_simple ${FUNCNAME} "\x4e\xb8\x00\x1f"
  # Negative value
  run_test_simple ${FUNCNAME} "\x4e\xb8\x8a\x0c"
}

jsr_m7_xn1() {
  # 43b9 xxxx Long displacement
  #
  # Zero value
  run_test_simple ${FUNCNAME} "\x4e\xb9\x00\x00\x00\x00"
  # Positive value
  run_test_simple ${FUNCNAME} "\x4e\xb9\x10\xbb\x43\x1f"
  # Negative value
  run_test_simple ${FUNCNAME} "\x4e\xb9\x80\xcc\xd9\x8a"
}

jsr_m7_xn2() {
  # 43ba xxxx
  #
  # Zero value
  run_test_simple ${FUNCNAME} "\x4e\xba\x00\x00"
  # Positive value
  run_test_simple ${FUNCNAME} "\x4e\xba\x00\x1f"
  # Negative value
  run_test_simple ${FUNCNAME} "\x4e\xba\x8a\x0c"
}

jsr_m7_xn3() {
  # 43bb xxxx
  #
  # Positive value, Arbitrary Xn register
  run_test_iterative ${FUNCNAME} "\x4e\xbb" 0x00 8 0x10 "\x1a"
  # Negative value
  run_test_simple ${FUNCNAME} "\x4e\xbb\x00\xf0"
  # Zero displacement
  run_test_simple ${FUNCNAME} "\x4e\xbb\x00\x00"
  # Address register
  run_test_simple ${FUNCNAME} "\x4e\xbb\x80\x0a"
  # Long displacement, positive
  run_test_simple ${FUNCNAME} "\x4e\xbb\x08\x0c"
  # Long displacement, negative
  run_test_simple ${FUNCNAME} "\x4e\xbb\x08\xb0"
  # Arbitrary Xn2
  run_test_iterative ${FUNCNAME} "\x4e\xbb" 0x00 8 0x10 "\x0f"
}

reset_nop_rte_rts_trapv_rtr() {
  # 4e7x
  #
  # reset / 4e70
  run_test_simple ${FUNCNAME} "\x4e\x70"
  # nop / 4e71
  run_test_simple ${FUNCNAME} "\x4e\x71"
  # rte / 4e73
  run_test_simple ${FUNCNAME} "\x4e\x73"
  # rts / 4e75
  run_test_simple ${FUNCNAME} "\x4e\x75"
  # trapv / 4e76
  run_test_simple ${FUNCNAME} "\x4e\x76"
  # rtr / 4e77
  run_test_simple ${FUNCNAME} "\x4e\x77"
}

jsr_m2
jsr_m5
jsr_m6
jsr_m7_xn0
jsr_m7_xn1
jsr_m7_xn2
jsr_m7_xn3
reset_nop_rte_rts_trapv_rtr
