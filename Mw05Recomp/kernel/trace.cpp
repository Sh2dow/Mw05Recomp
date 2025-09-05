#include "trace.h"

#include <cpu/guest_thread.h>
#include <os/logger.h>
#include <cctype>
#include <cstdlib>
#include <atomic>

static std::atomic<int> g_traceEnabled{-1}; // -1 = unknown, 0 = no, 1 = yes
struct TraceEntry {
    char name[48];
    uint32_t tid;
    uint32_t r3, r4, r5, r6;
};
static TraceEntry g_ring[64];
static std::atomic<uint32_t> g_ringIndex{0};

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
    const uint32_t tid = GuestThread::GetCurrentThreadId();
    // Always store to ring buffer for post-mortem diagnostics
    uint32_t idx = g_ringIndex.fetch_add(1, std::memory_order_relaxed);
    TraceEntry& e = g_ring[idx % (uint32_t)std::size(g_ring)];
    const char* name = import_name ? import_name : "<null>";
    std::snprintf(e.name, sizeof(e.name), "%s", name);
    e.tid = tid;
    e.r3 = ctx.r3.u32; e.r4 = ctx.r4.u32; e.r5 = ctx.r5.u32; e.r6 = ctx.r6.u32;

    if (!KernelTraceEnabled()) return;
    LOGFN("[TRACE] import={} tid={:08X} r3={:08X} r4={:08X} r5={:08X} r6={:08X}", name, tid, e.r3, e.r4, e.r5, e.r6);
}

void KernelTraceDumpRecent(int maxCount)
{
    const uint32_t end = g_ringIndex.load(std::memory_order_relaxed);
    const uint32_t count = std::min<uint32_t>(maxCount, (uint32_t)std::size(g_ring));
    const uint32_t start = (end >= count) ? end - count : 0;
    for (uint32_t i = start; i < end; ++i)
    {
        const TraceEntry& e = g_ring[i % (uint32_t)std::size(g_ring)];
        if (e.name[0] == '\0') continue;
        LOGFN("[TRACE][recent] import={} tid={:08X} r3={:08X} r4={:08X} r5={:08X} r6={:08X}", e.name, e.tid, e.r3, e.r4, e.r5, e.r6);
    }
}
