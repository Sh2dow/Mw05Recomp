#include "trace.h"

#include <cpu/guest_thread.h>
#include <os/logger.h>
#include <cctype>
#include <cstdlib>
#include <atomic>

static std::atomic<int> g_traceEnabled{-1}; // -1 = unknown, 0 = no, 1 = yes

static bool ReadEnvBool(const char* name)
{
    const char* v = std::getenv(name);
    if (!v) return false;
    // Enable unless explicit 0
    if (v[0] == '0' && v[1] == '\0') return false;
    // Treat common falsy strings as disabled
    auto eq_ci = [](const char* a, const char* b){
        for (; *a && *b; ++a, ++b) if (std::tolower(*a) != std::tolower(*b)) return false; 
        return *a == 0 && *b == 0; };
    if (eq_ci(v, "false") || eq_ci(v, "off") || eq_ci(v, "no")) return false;
    return true;
}

bool KernelTraceEnabled()
{
    int s = g_traceEnabled.load(std::memory_order_relaxed);
    if (s < 0)
    {
        s = ReadEnvBool("MW05_TRACE_KERNEL") ? 1 : 0;
        g_traceEnabled.store(s, std::memory_order_relaxed);
    }
    return s != 0;
}

void KernelTraceImport(const char* import_name, PPCContext& ctx)
{
    if (!KernelTraceEnabled()) return;
    const uint32_t tid = GuestThread::GetCurrentThreadId();
    LOGFN("[TRACE] import={} tid={:08X} r3={:08X} r4={:08X} r5={:08X} r6={:08X}",
          import_name ? import_name : "<null>",
          tid,
          ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32);
}

