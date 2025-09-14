#include "trace.h"

#include <cpu/guest_thread.h>
#include <os/logger.h>
#include <cctype>
#include <cstdlib>
#include <atomic>
#include <fstream>
#include <mutex>
#ifdef _WIN32
#include <windows.h>
#endif

static std::atomic<int> g_traceEnabled{-1}; // -1 = unknown, 0 = no, 1 = yes
struct TraceEntry {
    char name[48];
    uint32_t tid;
    uint32_t r3, r4, r5, r6;
    uint32_t lr;
};
static TraceEntry g_ring[64];
static std::atomic<uint32_t> g_ringIndex{0};
static thread_local PPCContext* g_hostCtx = nullptr; // guest ctx active during a host GPU call
static std::mutex g_hostFileMutex;
static const char* GetHostTracePath()
{
    static const char* path = nullptr;
    if (!path)
    {
        const char* envp = std::getenv("MW05_HOST_TRACE_FILE");
        path = envp && envp[0] ? envp : "mw05_host_trace.log";
    }
    return path;
}

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

static inline void SafeCopyName(char* dst, size_t dst_cap, const char* src)
{
    if (!dst || dst_cap == 0) return;
#ifdef _WIN32
    __try {
        if (!src) {
            std::snprintf(dst, dst_cap, "%s", "<null>");
            return;
        }
        // Copy up to dst_cap-1, byte-by-byte, stopping at NUL.
        size_t i = 0;
        for (; i + 1 < dst_cap; ++i) {
            char c = src[i];
            dst[i] = c;
            if (c == '\0') break;
        }
        if (i + 1 >= dst_cap) dst[dst_cap - 1] = '\0';
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        std::snprintf(dst, dst_cap, "%s", "<bad-name>");
    }
#else
    std::snprintf(dst, dst_cap, "%s", src ? src : "<null>");
#endif
}

void KernelTraceImport(const char* import_name, PPCContext& ctx)
{
    const uint32_t tid = GuestThread::GetCurrentThreadId();
    // Always store to ring buffer for post-mortem diagnostics
    uint32_t idx = g_ringIndex.fetch_add(1, std::memory_order_relaxed);
    TraceEntry& e = g_ring[idx % (uint32_t)std::size(g_ring)];
    SafeCopyName(e.name, sizeof(e.name), import_name);
    e.tid = tid;
    e.r3 = ctx.r3.u32; e.r4 = ctx.r4.u32; e.r5 = ctx.r5.u32; e.r6 = ctx.r6.u32;
    e.lr = (uint32_t)ctx.lr;

    if (!KernelTraceEnabled()) return;
    LOGFN("[TRACE] import={} tid={:08X} lr=0x{:08X} r3={:08X} r4={:08X} r5={:08X} r6={:08X}", e.name, tid, e.lr, e.r3, e.r4, e.r5, e.r6);

    // Always mirror to a simple local file to decouple from logger config.
    try {
        std::lock_guard<std::mutex> lk(g_hostFileMutex);
        std::ofstream out(GetHostTracePath(), std::ios::app);
        if (out)
        {
            out << "[HOST] import=" << e.name
                << " tid=" << std::hex << tid
                << " lr=0x" << std::uppercase << std::hex << e.lr
                << " r3=0x" << std::uppercase << std::hex << e.r3
                << " r4=0x" << std::uppercase << std::hex << e.r4
                << " r5=0x" << std::uppercase << std::hex << e.r5
                << " r6=0x" << std::uppercase << std::hex << e.r6
                << "\n";
        }
    } catch (...) {
        // best-effort
    }
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
        LOGFN("[TRACE][recent] import={} tid={:08X} lr=0x{:08X} r3={:08X} r4={:08X} r5={:08X} r6={:08X}", e.name, e.tid, e.lr, e.r3, e.r4, e.r5, e.r6);
    }
}

void KernelTraceHostBegin(PPCContext& ctx)
{
    g_hostCtx = &ctx;
}

void KernelTraceHostEnd()
{
    g_hostCtx = nullptr;
}

void KernelTraceHostOp(const char* name)
{
    // Always log host GPU ops to file to aid mapping, independent of MW05_TRACE_KERNEL.
    // These entries are low volume and essential for wiring MW05 wrappers.
    uint32_t tid = GuestThread::GetCurrentThreadId();
    uint32_t idx = g_ringIndex.fetch_add(1, std::memory_order_relaxed);
    TraceEntry& e = g_ring[idx % (uint32_t)std::size(g_ring)];
    SafeCopyName(e.name, sizeof(e.name), name);
    e.tid = tid;
    PPCContext* c = g_hostCtx ? g_hostCtx : GetPPCContext();
    if (c)
    {
        e.r3 = c->r3.u32;
        e.r4 = c->r4.u32;
        e.r5 = c->r5.u32;
        e.r6 = c->r6.u32;
        e.lr = (uint32_t)c->lr;
    }
    else { e.r3 = e.r4 = e.r5 = e.r6 = e.lr = 0; }

    // Mirror to logger
    LOGFN("[TRACE] import={} tid={:08X} lr=0x{:08X} r3={:08X} r4={:08X} r5={:08X} r6={:08X}", e.name, tid, e.lr, e.r3, e.r4, e.r5, e.r6);

    // Also append to host trace file like KernelTraceImport
    try {
        std::lock_guard<std::mutex> lk(g_hostFileMutex);
        std::ofstream out(GetHostTracePath(), std::ios::app);
        if (out)
        {
            out << "[HOST] import=" << e.name
                << " tid=" << std::hex << tid
                << " lr=0x" << std::uppercase << std::hex << e.lr
                << " r3=0x" << std::uppercase << std::hex << e.r3
                << " r4=0x" << std::uppercase << std::hex << e.r4
                << " r5=0x" << std::uppercase << std::hex << e.r5
                << " r6=0x" << std::uppercase << std::hex << e.r6
                << "\n";
        }
    } catch (...) {
        // best-effort
    }
}

extern "C" void MwTraceIndirectMiss(unsigned int addr)
{
    // Always log to file via os::logger; mirror to stderr if MW_VERBOSE
    LOGFN_WARNING("[ppc][indirect-miss] target=0x{:08X}", addr);
#if _WIN32
    if (SDL_GetHintBoolean("MW_VERBOSE", SDL_FALSE)) {
        fprintf(stderr, "[ppc][indirect-miss] target=0x%08X\n", addr);
    }
#endif
}
