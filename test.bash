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
  local test_name=$1
  local test_name_sanitized=${test_name//[^a-zA-Z0-9_\-]/-}
  local data=$2
  local file_orig_bin=${TEST_DIR}/${test_name_sanitized}.orig.bin
  local file_asm=${TEST_DIR}/${test_name_sanitized}.S
  local file_as_o=${TEST_DIR}/${test_name_sanitized}.as.o
  local file_as_bin=${TEST_DIR}/${test_name_sanitized}.as.bin
  echo -ne "Test \"${test_name}\"... "
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

# 4e70
#
# reset
run_test_simple "reset" "\x4e\x70"

# 4e71
#
# nop
run_test_simple "nop" "\x4e\x71"

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

# 43b8 xxxx Word displacement
#
run_test_simple "jsr M7 Xn0 zero" "\x4e\xb8\x00\x00"
run_test_simple "jsr M7 Xn0 positive" "\x4e\xb8\x00\x1f"
run_test_simple "jsr M7 Xn0 negative" "\x4e\xb8\x8a\x0c"

# 43b9 xxxx Long displacement
#
run_test_simple "jsr M7 X1 zero" "\x4e\xb9\x00\x00\x00\x00"
run_test_simple "jsr M7 X1 positive" "\x4e\xb9\x10\xbb\x43\x1f"
run_test_simple "jsr M7 X1 negative" "\x4e\xb9\x80\xcc\xd9\x8a"

# 43ba xxxx
#
run_test_simple "jsr M7 X2 zero value" "\x4e\xba\x00\x00"
run_test_simple "jsr M7 X2 positive value" "\x4e\xba\x00\x1f"
run_test_simple "jsr M7 X2 negative value" "\x4e\xba\x8a\x0c"

# 43bb xxxx
#
run_test_simple "jsr M7 X3 negative" "\x4e\xbb\x00\xf0"
run_test_simple "jsr M7 X3 zero displacement" "\x4e\xbb\x00\x00"
run_test_simple "jsr M7 X3 An2=A0" "\x4e\xbb\x80\x0a"
run_test_simple "jsr M7 X3 long positive displacement" "\x4e\xbb\x08\x0c"
run_test_simple "jsr M7 X3 long negative displacement" "\x4e\xbb\x08\xb0"
run_test_iterative "jsr M7 X3 arbitrary Dn2" "\x4e\xbb" 0x00 8 0x10 "\x0f"
