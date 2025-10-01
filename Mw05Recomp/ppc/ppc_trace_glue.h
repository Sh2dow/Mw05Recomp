#pragma once

#ifndef MW05_TRACE_GLUE_INCLUDED
#define MW05_TRACE_GLUE_INCLUDED

#include "ppc/ppc_context.h"
#include <kernel/trace.h>

// Override PPC store macros to route through watched big-endian stores for tracing.
// This is force-included for Mw05RecompLib so it applies to all generated PPC TUs.
// We only override 32/64-bit stores which cover PM4/RB writes and common fences.
#ifdef PPC_STORE_U32
#undef PPC_STORE_U32
#endif
#define PPC_STORE_U32(ea, v) StoreBE32_Watched(base, (ea), (uint32_t)(v))

#ifdef PPC_STORE_U64
#undef PPC_STORE_U64
#endif
#define PPC_STORE_U64(ea, v) StoreBE64_Watched(base, (ea), (uint64_t)(v))

// Override PPC_LOAD_U32 to intercept flag reads (for MW05_UNBLOCK_MAIN workaround)
#ifdef PPC_LOAD_U32
#undef PPC_LOAD_U32
#endif
#define PPC_LOAD_U32(ea) LoadBE32_Watched(base, (ea))

#endif // MW05_TRACE_GLUE_INCLUDED
