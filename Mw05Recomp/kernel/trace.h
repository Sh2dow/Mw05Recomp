#pragma once

#include <cpu/ppc_context.h>

// Returns true if kernel import tracing is enabled via env var.
bool KernelTraceEnabled();

// Logs a single kernel import call if tracing is enabled.
// Captures thread id and a few PPC argument registers for quick inspection.
void KernelTraceImport(const char* import_name, PPCContext& ctx);

// Diagnostic: dump recent imports captured in a small ring buffer
void KernelTraceDumpRecent(int maxCount = 16);
