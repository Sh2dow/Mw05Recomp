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
#ifndef PPC_CONFIG_SKIP_LR
            KernelTraceHostOpF("HOST.watch.memcpyGG dst=%08X len=%zu hit=%08X lr=%08llX",
                               dstEA, len, watch, (unsigned long long)c->lr);
#else
            KernelTraceHostOpF("HOST.watch.memcpyGG dst=%08X len=%zu hit=%08X lr=N/A",
                               dstEA, len, watch);
#endif
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
#ifndef PPC_CONFIG_SKIP_LR
            PPCContext* c = GetPPCContext();
            const unsigned long long lr = c ? (unsigned long long)c->lr : 0ull;
            KernelTraceHostOpF("HOST.RB.write ea=%08X..%08X n=%zu lr=%08llX", ea, (uint32_t)a1, n, lr);
#else
            KernelTraceHostOpF("HOST.RB.write ea=%08X..%08X n=%zu lr=N/A", ea, (uint32_t)a1, n);
#endif
        }
    }
}

inline void StoreBE8_Watched(uint8_t* /*base*/, uint32_t ea, uint8_t v8)
{
    // CRITICAL FIX: Prevent infinite recursion during static initialization
    static bool banner8_logged = false;
    if (!banner8_logged) {
        banner8_logged = true;
        KernelTraceHostOp("HOST.watch.store8 override ACTIVE");
    }

#ifndef PPC_CONFIG_SKIP_LR
    PPCContext* c = GetPPCContext();
    const unsigned long long lr = c ? (unsigned long long)c->lr : 0ull;
#else
    const unsigned long long lr = 0ull;
#endif

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

static inline void BE_Store16(uint8_t* p, uint16_t v) {
    p[0] = uint8_t(v >> 8); p[1] = uint8_t(v);
}

static inline void BE_Store32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16); p[2] = uint8_t(v >> 8); p[3] = uint8_t(v);
}

inline void StoreBE16_Watched(uint8_t* base, uint32_t ea, uint16_t v) {
    // CRITICAL FIX: Prevent infinite recursion during static initialization
    static bool banner16_logged = false;
    if (!banner16_logged) {
        banner16_logged = true;
        KernelTraceHostOp("HOST.watch.store16 override ACTIVE");
    }

#ifndef PPC_CONFIG_SKIP_LR
    PPCContext* c = GetPPCContext();
    const unsigned long long lr = c ? (unsigned long long)c->lr : 0ull;
#else
    const unsigned long long lr = 0ull;
#endif

    KernelTraceHostOpF("HOST.Store16BE_W.called ea=%08X val=%04X", ea, v);

    if (uint32_t watch = g_watchEA.load(std::memory_order_relaxed)) {
        if (Overlaps(ea, 2, watch)) {
            KernelTraceHostOpF("HOST.watch.hit16 ea=%08X val=%04X lr=%08llX", ea, v, lr);
        }
    }

    // CRITICAL FIX: BLOCK ALL writes from game's buggy memset function (lr=0x825A7DC8)
    // The game's memset function is being called with corrupted parameters (size=0xFFE8001C = 4GB)
    // which causes it to write zeros across the entire heap, corrupting o1heap's free list.
    // The corruption happens at addresses like 0x001A0340 (656 KB into the heap).
    //
    // We BLOCK ALL writes from lr=0x825A7DC8 regardless of address, since this function
    // is clearly buggy and should not be writing to memory at all.
    // We ALLOW all other writes (including o1heap's own internal operations) to proceed normally.
#ifndef PPC_CONFIG_SKIP_LR
    if (auto* c = GetPPCContext()) {
        uint32_t lr = c->lr;

        // BLOCK ALL writes from the game's buggy memset function (lr=0x825A7DC8)
        if (lr == 0x825A7DC8) {
            static int block_count = 0;
            block_count++;

            // Log first 10 blocked writes, then log every 10 millionth write to reduce spam
            if (block_count <= 10 || (block_count % 10000000) == 0) {
                fprintf(stderr, "[HEAP-PROTECT] BLOCKED Store16 from buggy memset! (count=%d)\n", block_count);
                fprintf(stderr, "[HEAP-PROTECT]   ea=0x%08X val=0x%04X lr=0x%08X\n", ea, v, lr);
                fprintf(stderr, "[HEAP-PROTECT]   r3=0x%08X r4=0x%08X r5=0x%08X\n",
                        c->r3.u32, c->r4.u32, c->r5.u32);
#ifndef PPC_CONFIG_NON_VOLATILE_AS_LOCAL
                fprintf(stderr, "[HEAP-PROTECT]   r31=0x%08X r30=0x%08X r29=0x%08X\n",
                        c->r31.u32, c->r30.u32, c->r29.u32);
#endif
                fflush(stderr);
            }

            // CRITICAL: Return WITHOUT writing to prevent heap corruption!
            return;
        }
    }
#endif

    TraceRbWrite(ea, 2);

    if (uint8_t* p = (uint8_t*)g_memory.Translate(ea)) {
        BE_Store16(p, v);
    }
}

inline void StoreBE32_Watched(uint8_t* base, uint32_t ea, uint32_t v) {
    // CRITICAL FIX: Prevent infinite recursion during static initialization
    static bool banner_logged = false;
    if (!banner_logged) {
        banner_logged = true;
        // CRITICAL FIX: KernelTraceHostOp hangs in natural path! Skip it.
        // KernelTraceHostOp("HOST.watch.store override ACTIVE");
    }

    // CRITICAL FIX: BLOCK ALL writes from game's buggy memset function (lr=0x825A7DC8)
    // The game's memset function is being called with corrupted parameters (size=0xFFE8001C = 4GB)
    // which causes it to write zeros across the entire heap, corrupting o1heap's free list.
    // The corruption happens at addresses like 0x001A0340 (656 KB into the heap).
    //
    // We BLOCK ALL writes from lr=0x825A7DC8 regardless of address, since this function
    // is clearly buggy and should not be writing to memory at all.
    // We ALLOW all other writes (including o1heap's own internal operations) to proceed normally.
#ifndef PPC_CONFIG_SKIP_LR
    if (auto* c = GetPPCContext()) {
        uint32_t lr = c->lr;

        // BLOCK ALL writes from the game's buggy memset function (lr=0x825A7DC8)
        if (lr == 0x825A7DC8) {
            static int block_count = 0;
            block_count++;

            // Log first 10 blocked writes, then log every 10 millionth write to reduce spam
            if (block_count <= 10 || (block_count % 10000000) == 0) {
                fprintf(stderr, "[HEAP-PROTECT] BLOCKED Store32 from buggy memset! (count=%d)\n", block_count);
                fprintf(stderr, "[HEAP-PROTECT]   ea=0x%08X val=0x%08X lr=0x%08X\n", ea, v, lr);
                fprintf(stderr, "[HEAP-PROTECT]   r3=0x%08X r4=0x%08X r5=0x%08X\n",
                        c->r3.u32, c->r4.u32, c->r5.u32);
#ifndef PPC_CONFIG_NON_VOLATILE_AS_LOCAL
                fprintf(stderr, "[HEAP-PROTECT]   r31=0x%08X r30=0x%08X r29=0x%08X\n",
                        c->r31.u32, c->r30.u32, c->r29.u32);
#endif
                fflush(stderr);
            }

            // CRITICAL: Return WITHOUT writing to prevent heap corruption!
            return;
        }
    }
#endif // PPC_CONFIG_SKIP_LR

    // CRITICAL DEBUG: Watch for stores to callback parameter structure at 0x82A2B318
    // The structure is 32 bytes (0x82A2B318 to 0x82A2B338)
    // Field at offset +0x10 (0x82A2B328) is the work_func pointer (should be 0x82441E58)
    if (ea >= 0x82A2B318 && ea < 0x82A2B338) {
#ifndef PPC_CONFIG_SKIP_LR
        if (auto* c = GetPPCContext()) {
            uint32_t lr = c->lr;
            fprintf(stderr, "[CALLBACK_PARAM_WATCH] Store32 to callback param structure: ea=%08X val=%08X lr=%08X\n", ea, v, lr);
            fprintf(stderr, "[CALLBACK_PARAM_WATCH]   Offset from base: +0x%X (%d bytes)\n", ea - 0x82A2B318, ea - 0x82A2B318);
            if (ea == 0x82A2B328) {  // work_func field at offset +0x10
                fprintf(stderr, "[CALLBACK_PARAM_WATCH]   *** WORK_FUNC FIELD WRITE: val=%08X (expected 0x82441E58) ***\n", v);
            }
            fflush(stderr);
        }
#endif
    }

    // Log all stores from sub_82849DE8 function (worker thread initialization)
    // This function is at 0x82849DE8-0x82849F78, so lr should be in range 0x82849DE8-0x82849F7C
#ifndef PPC_CONFIG_SKIP_LR
    if (auto* c = GetPPCContext()) {
        uint32_t lr = c->lr;
        if (lr >= 0x82849DE8 && lr <= 0x82849F7C) {
#ifndef PPC_CONFIG_NON_VOLATILE_AS_LOCAL
            KernelTraceHostOpF("HOST.Store32.sub_82849DE8 ea=%08X val=%08X lr=%08X r30=%08X r31=%08X",
                               ea, v, lr, c->r30.u32, c->r31.u32);
#else
            KernelTraceHostOpF("HOST.Store32.sub_82849DE8 ea=%08X val=%08X lr=%08X",
                               ea, v, lr);
#endif
        }
        // Also log stores from sub_8284D168 (the function that calls sub_82849DE8)
        if (lr >= 0x8284D168 && lr <= 0x8284D218) {
#ifndef PPC_CONFIG_NON_VOLATILE_AS_LOCAL
            KernelTraceHostOpF("HOST.Store32.sub_8284D168 ea=%08X val=%08X lr=%08X r29=%08X r30=%08X r31=%08X",
                               ea, v, lr, c->r29.u32, c->r30.u32, c->r31.u32);
#else
            KernelTraceHostOpF("HOST.Store32.sub_8284D168 ea=%08X val=%08X lr=%08X",
                               ea, v, lr);
#endif
        }
        // Also log stores from sub_82548A08 (calls sub_8284D168)
        if (lr >= 0x82548A08 && lr <= 0x82548AC0) {
#ifndef PPC_CONFIG_NON_VOLATILE_AS_LOCAL
            KernelTraceHostOpF("HOST.Store32.sub_82548A08 ea=%08X val=%08X lr=%08X r28=%08X r29=%08X r30=%08X r31=%08X",
                               ea, v, lr, c->r28.u32, c->r29.u32, c->r30.u32, c->r31.u32);
#else
            KernelTraceHostOpF("HOST.Store32.sub_82548A08 ea=%08X val=%08X lr=%08X",
                               ea, v, lr);
#endif
        }
        // Also log stores from sub_8284D218 (calls sub_8284D168)
        if (lr >= 0x8284D218 && lr <= 0x8284D268) {
#ifndef PPC_CONFIG_NON_VOLATILE_AS_LOCAL
            KernelTraceHostOpF("HOST.Store32.sub_8284D218 ea=%08X val=%08X lr=%08X r29=%08X r30=%08X r31=%08X",
                               ea, v, lr, c->r29.u32, c->r30.u32, c->r31.u32);
#else
            KernelTraceHostOpF("HOST.Store32.sub_8284D218 ea=%08X val=%08X lr=%08X",
                               ea, v, lr);
#endif
        }
    }
#endif // PPC_CONFIG_SKIP_LR

    const uint32_t watch = g_watchEA.load(std::memory_order_relaxed);
    if (watch && ea == watch) {
#ifndef PPC_CONFIG_SKIP_LR
        if (auto* c = GetPPCContext())
            KernelTraceHostOpF("HOST.watch.hit ea=%08X val=%08X lr=%08llX", ea, v,
                               (unsigned long long)c->lr);
        else
#endif
            KernelTraceHostOpF("HOST.watch.hit ea=%08X val=%08X lr=0", ea, v);
    }

    // Watch for vtable pointer writes (0x82065268 is the expected vtable address)
    // Also watch for ANY writes to addresses ending in +196 (0xC4) which is where vtable pointers are stored
    if (v == 0x82065268 || (ea & 0xFFF) == 0xC4) {
        static int vtable_write_count = 0;
        if (vtable_write_count++ < 20) {
#if !defined(PPC_CONFIG_SKIP_LR) && !defined(PPC_CONFIG_NON_VOLATILE_AS_LOCAL)
            if (auto* c = GetPPCContext()) {
                KernelTraceHostOpF("HOST.vtable.write ea=%08X val=%08X lr=%08llX r31=%08X r29=%08X",
                                  ea, v, (unsigned long long)c->lr, c->r31.u32, c->r29.u32);
            } else
#endif
            {
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
#ifndef PPC_CONFIG_SKIP_LR
                if (auto* c = GetPPCContext())
                    KernelTraceHostOpF("HOST.PM4.SysBufWrite.hit ea=%08X bytes=%u lr=%08llX", ea, 4u, (unsigned long long)c->lr);
                else
#endif
                    KernelTraceHostOpF("HOST.PM4.SysBufWrite.hit ea=%08X bytes=%u lr=0", ea, 4u);
                s_logged_once32 = true;
            }
        }
    }

    // WATCHPOINT: Log writes to callback parameter structure at 0x82A2B318
    // This structure is critical for worker thread initialization
    // We need to find what naturally initializes it (especially work_func at +0x10)
    if (ea >= 0x82A2B318 && ea < 0x82A2B338) {  // Structure is 32 bytes (0x20)
#ifndef PPC_CONFIG_SKIP_LR
        if (auto* c = GetPPCContext()) {
            uint32_t offset = ea - 0x82A2B318;
            const char* field_name = "unknown";
            if (offset == 0x00) field_name = "field_00";
            else if (offset == 0x04) field_name = "field_04";
            else if (offset == 0x08) field_name = "state";
            else if (offset == 0x0C) field_name = "result";
            else if (offset == 0x10) field_name = "work_func (CRITICAL!)";
            else if (offset == 0x14) field_name = "work_param";
            else if (offset == 0x18) field_name = "field_18";
            else if (offset == 0x1C) field_name = "flag";

            KernelTraceHostOpF("HOST.WATCHPOINT.0x82A2B318 WRITE: offset=+0x%02X (%s) val=0x%08X lr=%08llX",
                              offset, field_name, v, (unsigned long long)c->lr);
        }
#endif
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
#ifndef PPC_CONFIG_SKIP_LR
                    if (auto* c = GetPPCContext()) {
                        KernelTraceHostOpF("HOST.StoreBE32_Watched BLOCKING reset of flag ea=%08X val=%08X lr=%08llX",
                                          ea, v, (unsigned long long)c->lr);
                    } else
#endif
                    {
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
#ifndef PPC_CONFIG_SKIP_LR
        if (auto* c = GetPPCContext()) {
            const unsigned long long lr = (unsigned long long)c->lr;
            KernelTraceHostOpF("HOST.watch.any val=0A000000 ea=%08X lr=%08llX", ea, lr);
            if (Mw05HandleSchedulerSentinel(base, ea, lr)) {
                return;
            }
        } else
#endif
        {
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
#ifndef PPC_CONFIG_SKIP_LR
            if (auto* c = GetPPCContext()) {
                KernelTraceHostOpF("HOST.GPU.MMIO.write ea=%08X val=%08X lr=%08llX",
                                  ea, v, (unsigned long long)c->lr);
            } else
#endif
            {
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

// 64-bit big-endian watched load (for debugging)
inline uint64_t LoadBE64_Watched(uint8_t* base, uint32_t ea)
{
    // Memory barrier to ensure we see the latest stores from other threads
    std::atomic_thread_fence(std::memory_order_seq_cst);

    // Load the value using BOTH methods to compare
    uint64_t value_translate = 0;
    uint64_t value_base = 0;
    uint8_t* ptr_translate = nullptr;
    uint8_t* ptr_base = base + ea;

    if (auto* p = (uint8_t*)g_memory.Translate(ea)) {
        ptr_translate = p;
        value_translate = (uint64_t(p[0]) << 56) | (uint64_t(p[1]) << 48) |
                          (uint64_t(p[2]) << 40) | (uint64_t(p[3]) << 32) |
                          (uint64_t(p[4]) << 24) | (uint64_t(p[5]) << 16) |
                          (uint64_t(p[6]) <<  8) | (uint64_t(p[7]) <<  0);
    }

    // Also load using base + ea
    value_base = (uint64_t(ptr_base[0]) << 56) | (uint64_t(ptr_base[1]) << 48) |
                 (uint64_t(ptr_base[2]) << 40) | (uint64_t(ptr_base[3]) << 32) |
                 (uint64_t(ptr_base[4]) << 24) | (uint64_t(ptr_base[5]) << 16) |
                 (uint64_t(ptr_base[6]) <<  8) | (uint64_t(ptr_base[7]) <<  0);

    // Log if this is qword_828F1F98 (the worker thread flag)
    if (ea == 0x828F1F98u) {
#ifndef PPC_CONFIG_SKIP_LR
        PPCContext* c = GetPPCContext();
        const unsigned long long lr = c ? (unsigned long long)c->lr : 0ull;
#else
        const unsigned long long lr = 0ull;
#endif
        // Check if pointers are the same
        bool ptrs_same = (ptr_translate == ptr_base);
        // Read raw bytes from both pointers
        uint64_t raw_translate = ptr_translate ? *(uint64_t*)ptr_translate : 0;
        uint64_t raw_base = *(uint64_t*)ptr_base;
        KernelTraceHostOpF("HOST.LoadBE64_W.qword_828F1F98 val_t=%016llX val_b=%016llX raw_t=%016llX raw_b=%016llX ptrs_same=%d lr=%08llX",
                          (unsigned long long)value_translate, (unsigned long long)value_base,
                          (unsigned long long)raw_translate, (unsigned long long)raw_base,
                          ptrs_same ? 1 : 0, lr);
    }

    return value_base;  // Use base + ea like the rest of the code
}

// 64-bit big-endian watched store
inline void StoreBE64_Watched(uint8_t* base, uint32_t ea, uint64_t v64)
{
    // CRITICAL FIX: Prevent infinite recursion during static initialization
    // The old code had: static bool banner64 = (KernelTraceHostOp(...), true);
    // This caused infinite recursion because KernelTraceHostOp could trigger
    // another memory store, which would call StoreBE64_Watched again before
    // the static initialization completed.
    // Solution: Use a simple static bool without calling any functions during initialization
    static bool banner64_logged = false;
    if (!banner64_logged) {
        banner64_logged = true;
        // Log banner AFTER setting the flag to prevent recursion
        KernelTraceHostOp("HOST.watch.store64 override ACTIVE");
    }

#ifndef PPC_CONFIG_SKIP_LR
    PPCContext* c = GetPPCContext();
    const unsigned long long lr = c ? (unsigned long long)c->lr : 0ull;
#else
    const unsigned long long lr = 0ull;
    PPCContext* c = nullptr;
#endif

    // CRITICAL FIX: BLOCK ALL writes from game's buggy memset function (lr=0x825A7DC8)
    // The game's memset function is being called with corrupted parameters (size=0xFFE8001C = 4GB)
    // which causes it to write zeros across the entire heap, corrupting o1heap's free list.
    // The corruption happens at addresses like 0x001A0340 (656 KB into the heap).
    //
    // We BLOCK ALL writes from lr=0x825A7DC8 regardless of address, since this function
    // is clearly buggy and should not be writing to memory at all.
    // We ALLOW all other writes (including o1heap's own internal operations) to proceed normally.

    // BLOCK ALL writes from the game's buggy memset function (lr=0x825A7DC8)
    if (lr == 0x825A7DC8) {
        static int block_count = 0;
        block_count++;

        // Log first 10 blocked writes, then log every 10 millionth write to reduce spam
        if (block_count <= 10 || (block_count % 10000000) == 0) {
            fprintf(stderr, "[HEAP-PROTECT] BLOCKED Store64 from buggy memset! (count=%d)\n", block_count);
            fprintf(stderr, "[HEAP-PROTECT]   ea=0x%08X val=0x%016llX lr=0x%08llX\n", ea, v64, lr);
            if (c) {
                fprintf(stderr, "[HEAP-PROTECT]   r3=0x%08X r4=0x%08X r5=0x%08X\n",
                        c->r3.u32, c->r4.u32, c->r5.u32);
#ifndef PPC_CONFIG_NON_VOLATILE_AS_LOCAL
                fprintf(stderr, "[HEAP-PROTECT]   r31=0x%08X r30=0x%08X r29=0x%08X\n",
                        c->r31.u32, c->r30.u32, c->r29.u32);
#endif
            }
            fflush(stderr);
        }

        // CRITICAL: Return WITHOUT writing to prevent heap corruption!
        return;
    }

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
        if (ea == 0x828F1F98) {
            KernelTraceHostOpF("HOST.Store64.828F1F98.SKIPPED handled=true lr=%08llX", lr);
        }
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

        // Memory barrier to ensure store is visible to other threads
        std::atomic_thread_fence(std::memory_order_seq_cst);

        if (ea == 0x828F1F98) {
            KernelTraceHostOpF("HOST.Store64.828F1F98.WRITTEN ptr=%p val=%016llX lr=%08llX", p, v64, lr);
        }
    } else {
        if (ea == 0x828F1F98) {
            KernelTraceHostOpF("HOST.Store64.828F1F98.NULL_PTR ea=%08X lr=%08llX", ea, lr);
        }
    }
}

inline void StoreBE128_Watched(uint8_t* base, uint32_t ea, uint64_t hi, uint64_t lo)
{
    // CRITICAL FIX: Prevent infinite recursion during static initialization
    static bool banner128_logged = false;
    if (!banner128_logged) {
        banner128_logged = true;
        KernelTraceHostOp("HOST.watch.store128 override ACTIVE");
    }

#ifndef PPC_CONFIG_SKIP_LR
    PPCContext* c = GetPPCContext();
    const unsigned long long lr = c ? (unsigned long long)c->lr : 0ull;
#else
    const unsigned long long lr = 0ull;
#endif

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
    // CRITICAL FIX: Prevent infinite recursion during static initialization
    static bool banner128p_logged = false;
    if (!banner128p_logged) {
        banner128p_logged = true;
        KernelTraceHostOp("HOST.watch.store128(ptr) override ACTIVE");
    }

#ifndef PPC_CONFIG_SKIP_LR
    PPCContext* c = GetPPCContext();
    const unsigned long long lr = c ? (unsigned long long)c->lr : 0ull;
#else
    const unsigned long long lr = 0ull;
#endif

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

// CRITICAL FIX: Intercept 16-bit stores to prevent heap corruption
// The game's memset function uses 16-bit stores that were bypassing protection
#ifdef PPC_STORE_U16
#  undef PPC_STORE_U16
#endif
#define PPC_STORE_U16(ea, v) StoreBE16_Watched(base, (ea), (v))

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
        // DISABLED: Workaround no longer needed after fixing byte-swapping in VBlank handler
        // The flag is now correctly written in big-endian format and read correctly
        static bool unblock_enabled = []() {
            const char* env = std::getenv("MW05_UNBLOCK_MAIN");
            if (env && *env && *env != '0') return true;  // Allow enabling via env var
            return false;  // Disabled by default (byte-swapping is fixed)
        }();

        if (unblock_enabled) {
            // Force return 1 to unblock the main thread (only if env var is set)
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

    // CRITICAL: Memory fence to ensure we see the latest writes from other threads
    // Without this, the CPU cache may return stale values
    std::atomic_thread_fence(std::memory_order_acquire);

    return __builtin_bswap32(*(volatile uint32_t*)(base + ea));
}

#ifdef PPC_LOAD_U32
#  undef PPC_LOAD_U32
#endif
#define PPC_LOAD_U32(ea) LoadBE32_Watched(base, (ea))
