# SPDX-License-Identifier: Unlicense

cmake_minimum_required(VERSION 3.16)
project(m68k-disasm)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_EXPORT_COMPILE_COMMANDS True)

set(common_debug_flags
    -fsanitize=address,undefined
    -fno-omit-frame-pointer
    -O1
    -g3
    # Uncomment to enable profiler
    # -pg
    )

add_executable(m68k-disasm
    src/main.cpp
    src/data_buffer.cpp
    src/disasm.cpp
    src/m68k.cpp
    src/elf_image.cpp
    )

target_compile_options(m68k-disasm PRIVATE
    $<$<CONFIG:Debug>:${common_debug_flags}>
    $<$<COMPILE_LANGUAGE:C>:-Wno-nested-anon-types>
    # Speed up compilation with -fno-exceptions and -fno-rtti
    $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>
    $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>
    $<$<COMPILE_LANGUAGE:CXX>:-Wold-style-cast>
    $<$<COMPILE_LANGUAGE:CXX>:-Wsuggest-override>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU>:-Wsuggest-final-types>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU>:-Wsuggest-final-methods>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU>:-fstrict-volatile-bitfields>
    $<$<COMPILE_LANG_AND_ID:C,GNU>:-fstrict-volatile-bitfields>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU>:-Wlogical-op>
    $<$<COMPILE_LANG_AND_ID:C,GNU>:-Wlogical-op>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU>:-ffile-prefix-map=${CMAKE_SOURCE_DIR}/=>
    $<$<COMPILE_LANG_AND_ID:C,GNU>:-ffile-prefix-map=${CMAKE_SOURCE_DIR}/=>
    -Wall
    -Wextra
    -pedantic
    -Wcast-align
    -Wshadow
    )

target_compile_definitions(m68k-disasm PRIVATE $<$<CONFIG:Debug>:_FORTIFY_SOURCE=2>)
target_link_options(m68k-disasm PRIVATE $<$<CONFIG:Debug>:${common_debug_flags}>)
target_include_directories(m68k-disasm PRIVATE . lib)
