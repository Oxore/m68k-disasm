#!/usr/bin/env bash
#
# SPDX-License-Identifier: Unlicense
#
# Tests against reference text for -ffollow-jumps and -fwalk features

TEST_DIR=/tmp/m68k-disasm-follow-jumps-walk-tests
DISASM="./cmake-build/m68k-disasm -flabels -frel-labels -fabs-labels"

set -e
CRED="\033[31m"
CGREEN="\033[32m"
CRST="\033[39m"

rm -rf ${TEST_DIR}
mkdir -p ${TEST_DIR}

OUTPUT_ASM="$TEST_DIR"/output.S
TRACE="$TEST_DIR"/trace.txt
REFERENCE="$TEST_DIR"/reference.S
REFERENCE_W="$TEST_DIR"/reference_w.S
REFERENCE_F="$TEST_DIR"/reference_f.S
REFERENCE_WF="$TEST_DIR"/reference_wf.S

run_test_inner() {
  local test_name=$1
  local disasm_args="$2"
  local input="$3"
  local reference="$4"
  echo -ne "Test \"${test_name}\" ($disasm_args)... "
  echo -ne "$input" | ${DISASM} --indent='  ' $disasm_args -t "$TRACE" -o "$OUTPUT_ASM" -
  if ! diff --ignore-trailing-space "$reference" "$OUTPUT_ASM" >/dev/null 2>&1; then
    echo -e "${CRED}FAIL${CRST}: output and reference text files do not match"
    diff --color=always --unified --ignore-trailing-space "$reference" "$OUTPUT_ASM" || true
  else
    echo -e "${CGREEN}OK${CRST}"
  fi
}

run_test() {
  local test_name=$1
  local input="$2"
  local reference="$3"
  local reference_w="$4"
  local reference_f="$5"
  local reference_wf="$6"
  run_test_inner "$test_name" "" "$input" "$reference"
  run_test_inner "$test_name" "-fwalk" "$input" "$reference_w"
  run_test_inner "$test_name" "-ffollow-jumps" "$input" "$reference_f"
  run_test_inner "$test_name" "-fwalk -ffollow-jumps" "$input" "$reference_wf"
}


echo -e "0" >"$TRACE"
cat >"$REFERENCE" << EOF
  nop
  .short 0x4e71
EOF
cat >"$REFERENCE_W" << EOF
  nop
  nop
EOF
# $REFERENCE_F is same as $REFERENCE
# $REFERENCE_WF is same as $REFERENCE_W
run_test "linear nops, trace @0" "\x4e\x71\x4e\x71" \
  "$REFERENCE" "$REFERENCE_W" "$REFERENCE" "$REFERENCE_W"


cat >"$REFERENCE" << EOF
  nop
  .short 0x6002
  .short 0x4e71
  .short 0x4e71
EOF
cat >"$REFERENCE_W" << EOF
  nop
  bras L00000006
  .short 0x4e71
L00000006:
  .short 0x4e71
EOF
# $REFERENCE_F is same as $REFERENCE
cat >"$REFERENCE_WF" << EOF
  nop
  bras L00000006
  .short 0x4e71
L00000006:
  nop
EOF
run_test "nop and unconditional branch, trace @0" "\x4e\x71\x60\x02\x4e\x71\x4e\x71" \
  "$REFERENCE" "$REFERENCE_W" "$REFERENCE" "$REFERENCE_WF"


cat >"$REFERENCE" << EOF
  nop
  .short 0x6602
  .short 0x4e71
  .short 0x4e71
EOF
cat >"$REFERENCE_W" << EOF
  nop
  bnes L00000006
  nop
L00000006:
  nop
EOF
# $REFERENCE_F is same as $REFERENCE
# $REFERENCE_WF is same as $REFERENCE_W
run_test "nop and conditional branch, trace @0" "\x4e\x71\x66\x02\x4e\x71\x4e\x71" \
  "$REFERENCE" "$REFERENCE_W" "$REFERENCE" "$REFERENCE_W"


cat >"$REFERENCE" << EOF
  bnes L00000004
  .short 0x4e71
L00000004:
  .short 0x4e71
EOF
cat >"$REFERENCE_W" << EOF
  bnes L00000004
  nop
L00000004:
  nop
EOF
cat >"$REFERENCE_F" << EOF
  bnes L00000004
  .short 0x4e71
L00000004:
  nop
EOF
# $REFERENCE_WF is same as $REFERENCE_W
run_test "conditional branch, trace @0" "\x66\x02\x4e\x71\x4e\x71" \
  "$REFERENCE" "$REFERENCE_W" "$REFERENCE_F" "$REFERENCE_W"


cat >"$REFERENCE" << EOF
  bras L00000004
  .short 0x4e71
L00000004:
  .short 0x4e71
EOF
# $REFERENCE_W is same as $REFERENCE
cat >"$REFERENCE_F" << EOF
  bras L00000004
  .short 0x4e71
L00000004:
  nop
EOF
# $REFERENCE_WF is same as $REFERENCE_F
run_test "unconditional branch, trace @0" "\x60\x02\x4e\x71\x4e\x71" \
  "$REFERENCE" "$REFERENCE" "$REFERENCE_F" "$REFERENCE_F"


echo -e "0\n2" >"$TRACE"
cat >"$REFERENCE" << EOF
L00000000:
  nop
  bnes L00000000
  .short 0x4e71
EOF
cat >"$REFERENCE_W" << EOF
L00000000:
  nop
  bnes L00000000
  nop
EOF
# $REFERENCE_F is same as $REFERENCE
# $REFERENCE_WF is same as $REFERENCE_W
run_test "nop and conditional branch backwards, trace @0, @2" "\x4e\x71\x66\xfc\x4e\x71" \
  "$REFERENCE" "$REFERENCE_W" "$REFERENCE" "$REFERENCE_W"


echo -e "2" >"$TRACE"
cat >"$REFERENCE" << EOF
L00000000:
  .short 0x4e71
  bnes L00000000
  .short 0x4e71
EOF
cat >"$REFERENCE_W" << EOF
L00000000:
  .short 0x4e71
  bnes L00000000
  nop
EOF
cat >"$REFERENCE_F" << EOF
L00000000:
  nop
  bnes L00000000
  .short 0x4e71
EOF
cat >"$REFERENCE_WF" << EOF
L00000000:
  nop
  bnes L00000000
  nop
EOF
run_test "nop and conditional branch backwards, trace @2" "\x4e\x71\x66\xfc\x4e\x71" \
  "$REFERENCE" "$REFERENCE_W" "$REFERENCE_F" "$REFERENCE_WF"

