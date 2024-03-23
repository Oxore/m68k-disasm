#pragma once

/* SPDX-License-Identifier: Unlicense
 */

#include "disasm.h"

#include <cstdio>

namespace Gnu {
void EmitSymbolMetadata(FILE *, const char *indent, const Symbol &);
void EmitSymbolSize(FILE *, const char *indent, const char *sym_name);
}
