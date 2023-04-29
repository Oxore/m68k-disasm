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
TRACE_FILE=${TEST_DIR}/trace.txt

set -e
CRED="\033[31m"
CGREEN="\033[32m"
CRST="\033[39m"

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
  local file_as_elf=${TEST_DIR}/${test_name_sanitized}.as.elf
  local file_as_bin=${TEST_DIR}/${test_name_sanitized}.as.bin
  echo -ne "Test \"${test_name}\"... "
  echo -ne "${data}" >${file_orig_bin}
  ${DISASM} -t ${TRACE_FILE} -o ${file_asm} ${file_orig_bin}
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
