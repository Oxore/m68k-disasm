# SPDX-License-Identifier: Unlicense

cmake_minimum_required(VERSION 3.16)
project(m68k-disasm)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_EXPORT_COMPILE_COMMANDS True)
set(common_flags)
set(common_debug_flags "-fsanitize=address -fno-omit-frame-pointer -O1")
# Uncomment to enalbe profiler
#set(common_debug_flags "${common_debug_flags} -pg")
set(common_compile_flags "-Wall -Wextra -pedantic")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${common_compile_flags} ${common_flags}")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${common_debug_flags}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${common_compile_flags} ${common_flags}")
# Speed up compilation with -fno-exceptions and -fno-rtti
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions -fno-rtti -Wno-nested-anon-types")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${common_debug_flags}")
set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} ${common_flags}")
set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} ${common_debug_flags}")

set(m68kdisasm_sources
    main.cpp
    data_buffer.cpp
    disasm.cpp
    elf_image.cpp
    )

add_executable(m68k-disasm ${m68kdisasm_sources})

include_directories(
    .
    lib
    )
