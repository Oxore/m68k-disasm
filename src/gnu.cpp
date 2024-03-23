/* SPDX-License-Identifier: Unlicense
 */

#include "gnu.h"

using namespace Gnu;

static constexpr const char *SymbolTypeToElfTypeString(SymbolType t)
{
    switch (t) {
        case SymbolType::kNone: return nullptr;
        case SymbolType::kFunction: return "function";
        case SymbolType::kObject: return "object";
    }
    return nullptr;
}

void Gnu::EmitSymbolMetadata(FILE *out, const char *indent, const Symbol &symbol)
{
    const char *const type = SymbolTypeToElfTypeString(symbol.type);
    if (type) {
        fprintf(out, "%s.type\t%s, @%s\n", indent, symbol.name, type);
    }
}

void Gnu::EmitSymbolSize(FILE *out, const char *indent, const char *sym_name)
{
    fprintf(out, "%s.size\t%s,.-%s\n", indent, sym_name, sym_name);
}
