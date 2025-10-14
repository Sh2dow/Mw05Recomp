#pragma once
#include <atomic>
#include <cstring>
#include <cstdlib>
#include <chrono>

#include <cpu/ppc_context.h>
#include "memory.h"

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

extern std::atomic<uint32_t> g_watchEA;

// Accessors exposed by kernel/imports.cpp
extern "C" uint32_t Mw05GetRingBaseEA();
extern "C" uint32_t Mw05GetRingSizeBytes();
extern "C" uint32_t Mw05GetSysBufBaseEA();
extern "C" uint32_t Mw05GetSysBufSizeBytes();

// Loader/streaming sentinel bridge (implemented in cpu/mw05_streaming_bridge.cpp)
extern "C" bool Mw05HandleSchedulerSentinel(uint8_t* base, uint32_t slotEA, uint64_t lr);

// Optional: watched EA→EA memcpy wrapper (used only if your code does memcpy base+dstEA <- base+srcEA)
inline void* Memcpy_Watched_GG(uint8_t* base, uint32_t dstEA, uint32_t srcEA, size_t len) {
    const uint32_t watch = g_watchEA.load(std::memory_order_relaxed);
    if (watch && dstEA <= watch && watch < dstEA + len) {
        if (auto* c = GetPPCContext()) {
            KernelTraceHostOpF("HOST.watch.memcpyGG dst=%08X len=%zu hit=%08X lr=%08llX",
                               dstEA, len, watch, (unsigned long long)c->lr);
        } else {
            KernelTraceHostOpF("HOST.watch.memcpyGG dst=%08X len=%zu hit=%08X lr=0",
                               dstEA, len, watch);
        }
    }
    return std::memcpy(base + dstEA, base + srcEA, len);
}



// tweak if your consumer LR differs:
static inline bool IsConsumerLR(uint64_t lr) { return lr == 0x82813514ull; }

static inline bool Overlaps(uint32_t ea, size_t n, uint32_t watch) {
    const uint64_t a0 = ea, a1 = uint64_t(ea) + (n ? (n - 1) : 0);
    const uint64_t w0 = watch, w1 = uint64_t(watch) + 3; // watched 32-bit slot
    return !(a1 < w0 || a0 > w1);
}

// Forward declaration for PM4 parser hook
void PM4_OnRingBufferWriteAddr(uint32_t writeAddr, size_t writeSize);

// RB write tracer (env-gated)
static inline void TraceRbWrite(uint32_t ea, size_t n) {
    const uint32_t base = Mw05GetRingBaseEA();
    const uint32_t size = Mw05GetRingSizeBytes();
    if (!base || !size) return;

    const uint64_t a0 = ea, a1 = uint64_t(ea) + (n ? (n - 1) : 0);
    const uint64_t b0 = base, b1 = uint64_t(base) + (size - 1);

    // Check if write overlaps ring buffer
    if (!(a1 < b0 || a0 > b1)) {
        // Notify PM4 parser of ring buffer write
        PM4_OnRingBufferWriteAddr(ea, n);

        // Optional verbose tracing
        static const bool s_trace = [](){
            if (const char* v = std::getenv("MW05_TRACE_RB_WRITES"))
                return !(v[0]=='0' && v[1]=='\0');
            return false;
        }();
        if (s_trace) {
            PPCContext* c = GetPPCContext();
            const unsigned long long lr = c ? (unsigned long long)c->lr : 0ull;
            KernelTraceHostOpF("HOST.RB.write ea=%08X..%08X n=%zu lr=%08llX", ea, (uint32_t)a1, n, lr);
        }
    }
}

inline void StoreBE8_Watched(uint8_t* /*base*/, uint32_t ea, uint8_t v8)
{
    static bool banner8 = (KernelTraceHostOp("HOST.watch.store8 override ACTIVE"), true);
    (void)banner8;

    PPCContext* c = GetPPCContext();
    const unsigned long long lr = c ? (unsigned long long)c->lr : 0ull;

    KernelTraceHostOpF("HOST.Store8BE_W.called ea=%08X val=%02X", ea, v8);

    if (uint32_t watch = g_watchEA.load(std::memory_order_relaxed)) {
        if (Overlaps(ea, 1, watch)) {
            KernelTraceHostOpF("HOST.watch.hit8 ea=%08X val=%02X lr=%08llX", ea, v8, lr);
        }
    }

    // Optional: log if a store hits the System Command Buffer region (first hit only)
    static const bool s_sysbuf_watch = [](){
        if (const char* v = std::getenv("MW05_PM4_SYSBUF_WATCH")) return !(v[0]=='0' && v[1]=='\0');
        return false;
    }();
    if (s_sysbuf_watch) {
        const uint32_t base_ea = Mw05GetSysBufBaseEA();
        const uint32_t size_ea = Mw05GetSysBufSizeBytes();
        if (base_ea && ea >= base_ea && ea < base_ea + size_ea) {
            static bool s_logged_once8 = false;
            if (!s_logged_once8) {
                KernelTraceHostOpF("HOST.PM4.SysBufWrite.hit ea=%08X bytes=%u lr=%08llX", ea, 1u, lr);
                s_logged_once8 = true;
            }
        }
    }

    TraceRbWrite(ea, 1);

    if (uint8_t* p = (uint8_t*)g_memory.Translate(ea)) {
        p[0] = v8; // endianness irrelevant for a single byte
    }
}

static inline void BE_Store32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16); p[2] = uint8_t(v >> 8); p[3] = uint8_t(v);
}

inline void StoreBE32_Watched(uint8_t* base, uint32_t ea, uint32_t v) {
    static bool banner = (KernelTraceHostOp("HOST.watch.store override ACTIVE"), true);
    (void)banner;

    const uint32_t watch = g_watchEA.load(std::memory_order_relaxed);
    if (watch && ea == watch) {
        if (auto* c = GetPPCContext())
            KernelTraceHostOpF("HOST.watch.hit ea=%08X val=%08X lr=%08llX", ea, v,
                               (unsigned long long)c->lr);
        else
            KernelTraceHostOpF("HOST.watch.hit ea=%08X val=%08X lr=0", ea, v);
    }

    // Watch for vtable pointer writes (0x82065268 is the expected vtable address)
    // Also watch for ANY writes to addresses ending in +196 (0xC4) which is where vtable pointers are stored
    if (v == 0x82065268 || (ea & 0xFFF) == 0xC4) {
        static int vtable_write_count = 0;
        if (vtable_write_count++ < 20) {
            if (auto* c = GetPPCContext()) {
                KernelTraceHostOpF("HOST.vtable.write ea=%08X val=%08X lr=%08llX r31=%08X r29=%08X",
                                  ea, v, (unsigned long long)c->lr, c->r31.u32, c->r29.u32);
            } else {
                KernelTraceHostOpF("HOST.vtable.write ea=%08X val=%08X lr=0", ea, v);
            }
            fflush(stderr);
        }
    }

    // Optional: log if a store hits the System Command Buffer region (first hit only)
    static const bool s_sysbuf_watch = [](){
        if (const char* v = std::getenv("MW05_PM4_SYSBUF_WATCH")) return !(v[0]=='0' && v[1]=='\0');
        return false;
    }();
    if (s_sysbuf_watch) {
        const uint32_t base_ea = Mw05GetSysBufBaseEA();
        const uint32_t size_ea = Mw05GetSysBufSizeBytes();
        if (base_ea && ea >= base_ea && ea < base_ea + size_ea) {
            static bool s_logged_once32 = false;
            if (!s_logged_once32) {
                if (auto* c = GetPPCContext())
                    KernelTraceHostOpF("HOST.PM4.SysBufWrite.hit ea=%08X bytes=%u lr=%08llX", ea, 4u, (unsigned long long)c->lr);
                else
                    KernelTraceHostOpF("HOST.PM4.SysBufWrite.hit ea=%08X bytes=%u lr=0", ea, 4u);
                s_logged_once32 = true;
            }
        }
    }

    // Prevent main thread flag at 0x82A2CF40 from being reset to 0
    // This works in conjunction with LoadBE32_Watched forcing reads to return 1
    const uint32_t FLAG_EA = 0x82A2CF40;
    if (ea == FLAG_EA) {
        static bool block_reset_enabled = []() {
            const char* env = std::getenv("MW05_UNBLOCK_MAIN");
            return env && *env && *env != '0';
        }();

        if (block_reset_enabled && v == 0) {
            // Optional grace period: allow clearing after N ms (env MW05_ALLOW_FLAG_CLEAR_AFTER_MS)
            static int allow_after_ms = [](){
                if (const char* s = std::getenv("MW05_ALLOW_FLAG_CLEAR_AFTER_MS")) {
                    int n = std::atoi(s); return n > 0 ? n : -1;
                }
                return -1; // disabled by default
            }();
            static auto t0 = std::chrono::steady_clock::now();
            const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();

            const bool allow_now = (allow_after_ms >= 0) && (elapsed_ms >= allow_after_ms);
            if (!allow_now) {
                // Block the reset - log it and skip the write
                static int block_count = 0;
                if (block_count++ < 10) {
                    if (auto* c = GetPPCContext()) {
                        KernelTraceHostOpF("HOST.StoreBE32_Watched BLOCKING reset of flag ea=%08X val=%08X lr=%08llX",
                                          ea, v, (unsigned long long)c->lr);
                    } else {
                        KernelTraceHostOpF("HOST.StoreBE32_Watched BLOCKING reset of flag ea=%08X val=%08X lr=0", ea, v);
                    }
                }
                return; // Skip the write
            } else {
                KernelTraceHostOpF("HOST.StoreBE32_Watched ALLOWING reset of flag after %lld ms", (long long)elapsed_ms);
            }
        }
    }

    if (v == 0x0A000000u || v == 0x0000000Au) {
        if (auto* c = GetPPCContext()) {
            const unsigned long long lr = (unsigned long long)c->lr;
            KernelTraceHostOpF("HOST.watch.any val=0A000000 ea=%08X lr=%08llX", ea, lr);
            if (Mw05HandleSchedulerSentinel(base, ea, lr)) {
                return;
            }
        } else {
            KernelTraceHostOpF("HOST.watch.any val=0A000000 ea=%08X lr=0", ea);
            if (Mw05HandleSchedulerSentinel(base, ea, 0)) {
                return;
            }

        }
    }

    // CRITICAL: Detect GPU MMIO writes (MW05 uses direct register writes instead of PM4 ring buffer!)
    // Xbox 360 GPU registers are mapped at physical address 0xC0000000+
    // The game writes to these addresses using stwbrx instructions
    static const bool s_trace_mmio = [](){
        if (const char* v = std::getenv("MW05_TRACE_MMIO")) return !(v[0]=='0' && v[1]=='\0');
        return true; // Enable by default to discover GPU writes
    }();

    // Check if this is a GPU MMIO write (physical address 0xC0000000+)
    // In guest virtual memory, this might be mapped to a different range
    // Common Xbox 360 MMIO ranges: 0xC0000000-0xC0010000 (GPU registers)
    if (s_trace_mmio && (ea >= 0xC0000000u && ea < 0xC0010000u)) {
        static int mmio_log_count = 0;
        if (mmio_log_count++ < 100) {  // Log first 100 MMIO writes
            if (auto* c = GetPPCContext()) {
                KernelTraceHostOpF("HOST.GPU.MMIO.write ea=%08X val=%08X lr=%08llX",
                                  ea, v, (unsigned long long)c->lr);
            } else {
                KernelTraceHostOpF("HOST.GPU.MMIO.write ea=%08X val=%08X lr=0", ea, v);
            }
        }

        // TODO: Implement GPU register write handling
        // - Detect draw initiator register writes
        // - Translate to host draw calls
        // - Handle state registers (viewport, scissor, render targets)

        // For now, just log and skip the write (MMIO addresses are not in guest memory)
        return;
    }

    // Trace potential ring-buffer write (32-bit stores are the common PM4 path)
    TraceRbWrite(ea, 4);

    if (auto* p = (uint8_t*)g_memory.Translate(ea)) {
        p[0] = uint8_t(v >> 24);
        p[1] = uint8_t(v >> 16);
        p[2] = uint8_t(v >>  8);
        p[3] = uint8_t(v >>  0);
    }
}

// 64-bit big-endian watched store
inline void StoreBE64_Watched(uint8_t* base, uint32_t ea, uint64_t v64)
{
    static bool banner64 = (KernelTraceHostOp("HOST.watch.store64 override ACTIVE"), true);
    (void)banner64;

    PPCContext* c = GetPPCContext();
    const unsigned long long lr = c ? (unsigned long long)c->lr : 0ull;

    KernelTraceHostOpF("HOST.Store64BE_W.called ea=%08X val=%016llX", ea, v64);

    if (uint32_t watch = g_watchEA.load(std::memory_order_relaxed)) {
        if (Overlaps(ea, 8, watch)) {
            KernelTraceHostOpF("HOST.watch.hit64 ea=%08X val=%016llX lr=%08llX", ea, v64, lr);
        }
    }

    // Optional: log if a store hits the System Command Buffer region (first hit only)
    static const bool s_sysbuf_watch = [](){
        if (const char* v = std::getenv("MW05_PM4_SYSBUF_WATCH")) return !(v[0]=='0' && v[1]=='\0');
        return false;
    }();
    if (s_sysbuf_watch) {
        const uint32_t base_ea = Mw05GetSysBufBaseEA();
        const uint32_t size_ea = Mw05GetSysBufSizeBytes();
        if (base_ea && ea >= base_ea && ea < base_ea + size_ea) {
            static bool s_logged_once64 = false;
            if (!s_logged_once64) {
                KernelTraceHostOpF("HOST.PM4.SysBufWrite.hit ea=%08X bytes=%u lr=%08llX", ea, 8u, lr);
                s_logged_once64 = true;
            }
        }
    }

    bool handled = false;
    auto try_handle = [&](uint32_t slotEA) {
        // When forcing presentation for bring-up, avoid touching the loader/streaming
        // bridge to minimize interference with early guest init. This can be
        // re-enabled explicitly via MW05_STREAM_BRIDGE and MW05_VBLANK_CB once stable.
        const char* fp = std::getenv("MW05_FORCE_PRESENT");
        if (fp && !(fp[0]=='0' && fp[1]=='\0')) {
            return; // skip sentinel handling under MW05_FORCE_PRESENT
        }
        if (!handled && Mw05HandleSchedulerSentinel(base, slotEA, lr)) {
            handled = true;
        }
    };

    const uint32_t hi = (uint32_t)(v64 >> 32);
    const uint32_t lo = (uint32_t)(v64 & 0xFFFFFFFFu);
    if (hi == 0x0A000000u || hi == 0x0000000Au) {
        KernelTraceHostOpF("HOST.watch.any64 ea=%08X val=%016llX lr=%08llX", ea, v64, lr);
        try_handle(ea);
    }
    if (!handled && (lo == 0x0A000000u || lo == 0x0000000Au)) {
        KernelTraceHostOpF("HOST.watch.any64 ea=%08X val=%016llX lr=%08llX", ea, v64, lr);
        try_handle(ea + 4);
    }
    if (handled) {
        return;
    }

    TraceRbWrite(ea, 8);

    if (uint8_t* p = (uint8_t*)g_memory.Translate(ea)) {
        p[0] = uint8_t(v64 >> 56);
        p[1] = uint8_t(v64 >> 48);
        p[2] = uint8_t(v64 >> 40);
        p[3] = uint8_t(v64 >> 32);
        p[4] = uint8_t(v64 >> 24);
        p[5] = uint8_t(v64 >> 16);
        p[6] = uint8_t(v64 >>  8);
        p[7] = uint8_t(v64 >>  0);
    }
}

inline void StoreBE128_Watched(uint8_t* base, uint32_t ea, uint64_t hi, uint64_t lo)
{
    static bool banner128 = (KernelTraceHostOp("HOST.watch.store128 override ACTIVE"), true);
    (void)banner128;

    PPCContext* c = GetPPCContext();
    const unsigned long long lr = c ? (unsigned long long)c->lr : 0ull;

    KernelTraceHostOpF("HOST.Store128BE_W.called ea=%08X val=%016llX%016llX", ea, hi, lo);

    if (uint32_t watch = g_watchEA.load(std::memory_order_relaxed)) {
        if (Overlaps(ea, 16, watch)) {
            KernelTraceHostOpF("HOST.watch.hit128 ea=%08X val=%016llX%016llX lr=%08llX", ea, hi, lo, lr);
        }
    }

    uint8_t be[16] = {
        uint8_t(hi >> 56), uint8_t(hi >> 48), uint8_t(hi >> 40), uint8_t(hi >> 32),
        uint8_t(hi >> 24), uint8_t(hi >> 16), uint8_t(hi >>  8), uint8_t(hi >>  0),
        uint8_t(lo >> 56), uint8_t(lo >> 48), uint8_t(lo >> 40), uint8_t(lo >> 32),
        uint8_t(lo >> 24), uint8_t(lo >> 16), uint8_t(lo >>  8), uint8_t(lo >>  0),
    };
    for (int i = 0; i <= 12; ++i) {
        if (be[i+0]==0x0A && be[i+1]==0x00 && be[i+2]==0x00 && be[i+3]==0x00) {
            KernelTraceHostOpF("HOST.watch.any128 ea=%08X off=%d lr=%08llX", ea, i, lr);
            if (Mw05HandleSchedulerSentinel(base, ea + static_cast<uint32_t>(i), lr)) {
                return;
            }
            break;
        }
    }

    TraceRbWrite(ea, 16);

    if (uint8_t* p = (uint8_t*)g_memory.Translate(ea)) {
        for (int i = 0; i < 16; ++i) p[i] = be[i];
    }
}

inline void StoreBE128_Watched_P(uint8_t* base, uint32_t ea, const void* src16)
{
    static bool banner128p = (KernelTraceHostOp("HOST.watch.store128(ptr) override ACTIVE"), true);
    (void)banner128p;

    PPCContext* c = GetPPCContext();
    const unsigned long long lr = c ? (unsigned long long)c->lr : 0ull;

    const uint8_t* s = reinterpret_cast<const uint8_t*>(src16);
    KernelTraceHostOpF("HOST.Store128BE_W.ptr.called ea=%08X src=%p", ea, src16);

    if (uint32_t watch = g_watchEA.load(std::memory_order_relaxed)) {
        if (Overlaps(ea, 16, watch)) {
            KernelTraceHostOpF("HOST.watch.hit128 ea=%08X lr=%08llX", ea, lr);
        }
    }

    for (int i = 0; i <= 12; ++i) {
        if (s[i+0]==0x0A && s[i+1]==0x00 && s[i+2]==0x00 && s[i+3]==0x00) {
            KernelTraceHostOpF("HOST.watch.any128 ea=%08X off=%d lr=%08llX", ea, i, lr);
            if (Mw05HandleSchedulerSentinel(base, ea + static_cast<uint32_t>(i), lr)) {
                return;
            }
            break;
        }
    }

    TraceRbWrite(ea, 16);

    if (uint8_t* p = (uint8_t*)g_memory.Translate(ea)) {
        for (int i = 0; i < 16; ++i) p[i] = s[i];
    }
}

// If your generator uses: PPC_STORE_U128(ea, srcPtr)
// #ifdef PPC_STORE_U128
// #  undef PPC_STORE_U128
// #endif
// #define PPC_STORE_U128(ea, srcPtr) StoreBE128_Watched_P(base, (ea), (srcPtr))

#ifdef PPC_STORE_U8
#  undef PPC_STORE_U8
#endif
#define PPC_STORE_U8(ea, v) StoreBE8_Watched(base, (ea), (v))

// funnel every generated store through us
#ifdef PPC_STORE_U32
#  undef PPC_STORE_U32
#endif
#define PPC_STORE_U32(ea, v) StoreBE32_Watched(base, (ea), (v))

// Funnel all generated 64-bit stores through us (mirrors the 32-bit macro hook)
#ifdef PPC_STORE_U64
#  undef PPC_STORE_U64
#endif
#define PPC_STORE_U64(ea, v) StoreBE64_Watched(base, (ea), (v))

#ifdef PPC_STORE_U128
#  undef PPC_STORE_U128
#endif
// Expecting recompiler form: PPC_STORE_U128(ea, hi, lo)
#define PPC_STORE_U128(ea, hi, lo) StoreBE128_Watched(base, (ea), (hi), (lo))

// Override PPC_LOAD_U32 to intercept the flag read at dword_82A2CF40
// This is a workaround to force the main thread to see the flag as 1
inline uint32_t LoadBE32_Watched(uint8_t* base, uint32_t ea) {
    // Check if this is the flag address that the main thread is waiting on
    const uint32_t FLAG_EA = 0x82A2CF40;
    if (ea == FLAG_EA) {
        // Check if MW05_UNBLOCK_MAIN is enabled
        static bool unblock_enabled = []() {
            const char* env = std::getenv("MW05_UNBLOCK_MAIN");
            return env && *env && *env != '0';
        }();

        if (unblock_enabled) {
            // Force return 1 to unblock the main thread
            static int log_count = 0;
            if (log_count++ < 10) {
                KernelTraceHostOpF("HOST.LoadBE32_Watched FORCING flag ea=%08X to 1", ea);
            }
            return 1;
        }
    }

    // Normal load with byte swap
    // ea is a guest address (e.g., 0x82813090)
    // The default PPC_LOAD_U32 macro does: base + ea
    // So we just replicate that behavior here
    return __builtin_bswap32(*(volatile uint32_t*)(base + ea));
}

#ifdef PPC_LOAD_U32
#  undef PPC_LOAD_U32
#endif
#define PPC_LOAD_U32(ea) LoadBE32_Watched(base, (ea))
