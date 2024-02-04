# SPDX-License-Identifier: Unlicense

WARNFLAGS = -Wall -Wextra -pedantic -Wlogical-op
OPTFLAGS = -O2
ARCHFLAGS =
INCLUDES = lib
_CFLAGS = $(CFLAGS) $(WARNFLAGS) $(addprefix -I,$(INCLUDES)) $(ARCHFLAGS) $(OPTFLAGS) -pipe -g
_CXXFLAGS = $(CXXFLAGS) $(WARNFLAGS) $(addprefix -I,$(INCLUDES)) $(ARCHFLAGS) $(OPTFLAGS) -pipe -g
LDSCRIPTS =
_LDFLAGS = $(LDFLAGS) $(OPTFLAGS) $(addprefix -T,$(LDSCRIPTS))

OBJECTS=main.o \
	data_buffer.o \
	elf_image.o \
	disasm.o

.PHONY: all
all: m68k-disasm

m68k-disasm: $(OBJECTS) $(LDSCRIPTS) Makefile
	sh -c "time $(CXX) -o $@ $(_LDFLAGS) $(OBJECTS)"

$(OBJECTS): Makefile

%.o: src/%.c Makefile
	sh -c "time $(CC) $(_CFLAGS) -c -o $@ $<"

%.o: src/%.cpp Makefile
	sh -c "time $(CXX) $(_CXXFLAGS) -c -o $@ $<"

clean:
	rm -rfv m68k-disasm $(OBJECTS)
