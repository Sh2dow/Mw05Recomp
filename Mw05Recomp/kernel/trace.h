#pragma once

#include <cpu/ppc_context.h>

// Returns true if kernel import tracing is enabled via env var.
bool KernelTraceEnabled();

// Logs a single kernel import call if tracing is enabled.
// Captures thread id and a few PPC argument registers for quick inspection.
void KernelTraceImport(const char* import_name, PPCContext& ctx);

// Diagnostic: dump recent imports captured in a small ring buffer
void KernelTraceDumpRecent(int maxCount = 16);

// Bridge for host-side GPU calls: mark the current guest ctx for logging.
// Call KernelTraceHostBegin(ctx) before invoking a host GPU op from a PPC bridge
// and KernelTraceHostEnd() after it returns. Then, inside the host op, call
// KernelTraceHostOp("HOST.<Name>") to record the event with LR and args.
void KernelTraceHostBegin(PPCContext& ctx);
void KernelTraceHostEnd();
void KernelTraceHostOp(const char* name);
void KernelTraceHostOpF(const char* fmt, ...);
