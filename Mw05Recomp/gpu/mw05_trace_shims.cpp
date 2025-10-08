// MW05 dynamic discovery shims for frequently used engine helpers.
extern void PM4_ScanLinear(uint32_t addr, uint32_t bytes);

// They log the caller (LR) and common arg regs, then tail-call the original.

#include <cpu/ppc_context.h>
#include <kernel/trace.h>
#include <ppc/ppc_context.h>

#include <kernel/memory.h>
#include <atomic>

// Forward declarations for GPU writeback access functions
extern "C" uint32_t GetRbWriteBackPtr();
extern "C" uint32_t GetVdSystemCommandBufferGpuIdAddr();
extern "C" uint32_t GetRbLen();

// Forward declarations for diagnostic draw testing
struct GuestDevice;  // Forward declaration
extern "C" void Mw05HostDraw(uint32_t primitiveType, uint32_t startVertex, uint32_t primitiveCount);
extern "C" void Mw05DebugKickClear();
extern "C" GuestDevice* Mw05GetGuestDevicePtr();

// Forward declaration for Video::Present()
namespace Video { void Present(); }
#include <cstdlib>
#include <atomic>

static inline bool TitleStateTraceOn() {
    if (const char* v = std::getenv("MW05_TITLE_STATE_TRACE")) return !(v[0]=='0' && v[1]=='\0');
    return false;
}

// Helper to check if a guest offset is valid
static inline bool GuestOffsetInRange(uint32_t off, size_t bytes = 1) {
    if (off == 0) return false;
    if (off < 4096) return false; // guard page
    return (size_t)off + bytes <= PPC_MEMORY_SIZE;
}

static inline void DumpEAWindow(const char* tag, uint32_t ea) {
    if (!TitleStateTraceOn() || !ea) return;
    if (uint8_t* p = (uint8_t*)g_memory.Translate(ea)) {
        uint32_t w0 = *(uint32_t*)(p + 0);
        uint32_t w1 = *(uint32_t*)(p + 4);
        uint32_t w2 = *(uint32_t*)(p + 8);
        uint32_t w3 = *(uint32_t*)(p + 12);
    #if defined(_MSC_VER)
        w0 = _byteswap_ulong(w0); w1 = _byteswap_ulong(w1); w2 = _byteswap_ulong(w2); w3 = _byteswap_ulong(w3);
    #else
        w0 = __builtin_bswap32(w0); w1 = __builtin_bswap32(w1); w2 = __builtin_bswap32(w2); w3 = __builtin_bswap32(w3);
    #endif
        KernelTraceHostOpF("HOST.TitleState.%s ea=%08X w0=%08X w1=%08X w2=%08X w3=%08X", tag, ea, w0, w1, w2, w3);
    }
}

// Small helpers to read guest memory as big-endian safely for diagnostics
static inline uint32_t ReadBE32(uint32_t ea) {
    if (!ea) return 0u;
    if (auto* p = reinterpret_cast<const uint32_t*>(g_memory.Translate(ea))) {
    #if defined(_MSC_VER)
        return _byteswap_ulong(*p);
    #else
        return __builtin_bswap32(*p);
    #endif
    }
    return 0u;
}

// Write helpers mirroring ReadBE32
static inline void WriteBE32(uint32_t ea, uint32_t value) {
    if (!ea) return;
    if (auto* p = reinterpret_cast<uint32_t*>(g_memory.Translate(ea))) {
    #if defined(_MSC_VER)
        *p = _byteswap_ulong(value);
    #else
        *p = __builtin_bswap32(value);
    #endif
    }
}
static inline void WriteBE8(uint32_t ea, uint8_t value) {
    if (!ea) return;
    if (auto* p = reinterpret_cast<uint8_t*>(g_memory.Translate(ea))) {
        *p = value;
    }
}


static inline void DumpSchedState(const char* tag, uint32_t baseEA) {
    if (!TitleStateTraceOn() || !baseEA) return;
    // Best-effort peek at a few plausible fields (head/tail/flags) near the control block
    const uint32_t qhead = ReadBE32(baseEA + 0x10);
    const uint32_t qtail = ReadBE32(baseEA + 0x14);
    const uint32_t flags = ReadBE32(baseEA + 0x1C);
    KernelTraceHostOpF("HOST.Sched.%s base=%08X qhead=%08X qtail=%08X flags=%08X",
                       tag, baseEA, qhead, qtail, flags);
}

// Track all unique scheduler contexts we've seen
static std::atomic<uint32_t> g_schedulerContexts[8] = {};
static std::atomic<uint32_t> g_schedulerContextCount{0};

static inline void RegisterSchedulerContext(uint32_t baseEA) {
    if (!baseEA) return;

    // Check if already registered
    uint32_t count = g_schedulerContextCount.load(std::memory_order_acquire);
    for (uint32_t i = 0; i < count; ++i) {
        if (g_schedulerContexts[i].load(std::memory_order_relaxed) == baseEA) {
            return; // Already registered
        }
    }

    // Add new context (if space available)
    if (count < 8) {
        g_schedulerContexts[count].store(baseEA, std::memory_order_relaxed);
        g_schedulerContextCount.fetch_add(1, std::memory_order_release);
        if (TitleStateTraceOn()) {
            KernelTraceHostOpF("HOST.RegisterSchedulerContext base=%08X count=%d", baseEA, count + 1);
        }
    }
}

// Process commands in the MW05 scheduler queue
static inline void ProcessMW05Queue(uint32_t baseEA) {
    if (!baseEA) return;

    uint32_t qhead = ReadBE32(baseEA + 0x10);
    uint32_t qtail = ReadBE32(baseEA + 0x14);

    // If queue is empty, nothing to do
    if (qtail == 0 || qhead == qtail) return;

    // CRITICAL FIX: If qhead is 0, MW05 hasn't initialized it yet.
    // The queue actually starts at the syscmd buffer (typically 0x00140400).
    // We can infer the queue start from qtail by masking to the buffer base.
    if (qhead == 0 && qtail != 0) {
        // Assume queue starts at a 1KB-aligned address before qtail
        // Typical syscmd buffer is at 0x00140400
        qhead = qtail & 0xFFFF0000;  // Get base (e.g., 0x00140000)
        if (qhead < qtail) {
            qhead += 0x400;  // Add typical offset (0x400)
        }

        if (TitleStateTraceOn()) {
            KernelTraceHostOpF("HOST.ProcessQueue.infer_qhead base=%08X qtail=%08X inferred_qhead=%08X",
                               baseEA, qtail, qhead);
        }
    }

    // Sanity check: qhead should be less than qtail
    if (qhead >= qtail) return;

    uint32_t bytes_to_process = qtail - qhead;

    // Trace that we're processing the queue
    if (TitleStateTraceOn()) {
        KernelTraceHostOpF("HOST.ProcessQueue base=%08X qhead=%08X qtail=%08X bytes=%d",
                           baseEA, qhead, qtail, (int32_t)bytes_to_process);
    }

    // Limit processing to avoid excessive work in one frame
    if (bytes_to_process > 0x10000) {
        bytes_to_process = 0x10000;
        if (TitleStateTraceOn()) {
            KernelTraceHostOpF("HOST.ProcessQueue.limit bytes to %d", (int32_t)bytes_to_process);
        }
    }

    // Scan the PM4 commands in the queue
    // This will parse and execute the commands
    PM4_ScanLinear(qhead, bytes_to_process);

    // Advance qhead to mark commands as consumed
    uint32_t new_qhead = qhead + bytes_to_process;
    WriteBE32(baseEA + 0x10, new_qhead);

    // CRITICAL: Set the ready bit at +0x1C to signal MW05 that commands have been processed
    // This is what MW05 is waiting for - without this, the game will stall!
    uint32_t ready = ReadBE32(baseEA + 0x1C);
    if ((ready & 0x1u) == 0) {
        WriteBE32(baseEA + 0x1C, ready | 0x1u);
        if (TitleStateTraceOn()) {
            KernelTraceHostOpF("HOST.ProcessQueue.ready_flag %08X->%08X", ready, ready | 0x1u);
        }
    }

    // CRITICAL: Update GPU writeback pointers to signal command completion
    // MW05 polls these addresses waiting for the GPU to make progress!
    // This is the Xbox 360's "tail pointer write-back" mechanism.

    // 1. Update ring buffer read pointer writeback
    uint32_t rb_wb = GetRbWriteBackPtr();
    if (rb_wb) {
        if (auto* rptr = reinterpret_cast<uint32_t*>(g_memory.Translate(rb_wb))) {
            // Advance the read pointer using proper ring buffer wrapping logic
            uint32_t old_rptr = *rptr;
            uint32_t len_log2 = GetRbLen() & 31u;
            uint32_t mask = len_log2 ? ((1u << len_log2) - 1u) : 0xFFFFu;

            // Advance by the number of bytes we processed
            uint32_t next = (old_rptr + bytes_to_process) & mask;
            // Avoid writing 0, use 0x20 instead (matches imports.cpp pattern)
            uint32_t write_val = next ? next : 0x20u;

            *rptr = write_val;
            if (TitleStateTraceOn() && old_rptr != write_val) {
                KernelTraceHostOpF("HOST.ProcessQueue.rb_writeback %08X: %08X->%08X (bytes=%d mask=%08X)",
                                   rb_wb, old_rptr, write_val, (int32_t)bytes_to_process, mask);
            }
        }
    }

    // 2. Update GPU identifier writeback (increment to show progress)
    uint32_t gpu_id_ea = GetVdSystemCommandBufferGpuIdAddr();
    if (gpu_id_ea) {
        if (auto* gpu_id = reinterpret_cast<uint32_t*>(g_memory.Translate(gpu_id_ea))) {
            uint32_t old_id = *gpu_id;
            *gpu_id = old_id + 1;  // Increment to signal GPU progress
            if (TitleStateTraceOn()) {
                KernelTraceHostOpF("HOST.ProcessQueue.gpu_id_writeback %08X: %08X->%08X",
                                   gpu_id_ea, old_id, old_id + 1);
            }
        }
    }

    if (TitleStateTraceOn()) {
        KernelTraceHostOpF("HOST.ProcessQueue.done new_qhead=%08X consumed=%d ready=%08X",
                           new_qhead, (int32_t)bytes_to_process, ReadBE32(baseEA + 0x1C));
    }

    // DIAGNOSTIC: Emit a test draw call to verify the rendering pipeline works
    // This is a temporary test to see if draw commands can reach the renderer
    static std::atomic<uint32_t> s_diagDrawCount{0};
    uint32_t drawNum = s_diagDrawCount.fetch_add(1, std::memory_order_relaxed);
    if (drawNum < 10) {  // Only emit first 10 diagnostic draws to avoid spam
        // Check if device is initialized
        auto* dev = Mw05GetGuestDevicePtr();
        if (TitleStateTraceOn()) {
            KernelTraceHostOpF("HOST.ProcessQueue.DIAG_DRAW num=%d device=%p primitiveType=3 startVertex=0 primitiveCount=1",
                               drawNum, dev);
        }
        if (dev) {
            // Emit a simple triangle draw (primitiveType=3 is D3DPT_TRIANGLELIST)
            // This should trigger the rendering pipeline if it's working
            Mw05HostDraw(3, 0, 1);
        } else {
            if (TitleStateTraceOn()) {
                KernelTraceHostOpF("HOST.ProcessQueue.DIAG_DRAW.skip num=%d reason=device_not_initialized", drawNum);
            }
        }
    }
}

// Extern "C" wrapper to allow calling from imports.cpp
extern "C" void Mw05ProcessSchedulerQueue(uint32_t baseEA) {
    ProcessMW05Queue(baseEA);
}

// Track last-seen scheduler/context pointer to optionally nudge present-wrapper once
static std::atomic<uint32_t> s_lastSchedR3{0};
static std::atomic<bool> s_schedR3Logged{false};
static std::atomic<uint32_t> s_schedR3Seen{0};
extern "C" uint32_t Mw05Trace_SchedR3SeenCount() { return s_schedR3Seen.load(std::memory_order_acquire); }

static inline void MaybeLogSchedCapture(uint32_t r3) {
    if (r3 >= 0x1000 && r3 < PPC_MEMORY_SIZE) {
        if (!s_schedR3Logged.exchange(true, std::memory_order_acq_rel)) {
            KernelTraceHostOpF("HOST.SchedR3.Captured r3=%08X", r3);
        }
    }
}
extern "C" uint32_t Mw05Trace_LastSchedR3() { return s_lastSchedR3.load(std::memory_order_acquire); }
extern "C" void Mw05Trace_SeedSchedR3_NoLog(uint32_t r3) {
    if (r3 >= 0x1000 && r3 < PPC_MEMORY_SIZE) {
        s_lastSchedR3.store(r3, std::memory_order_release);
        s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel);
    }
}

extern "C" void Mw05Trace_ConsiderSchedR3(uint32_t r3) {
    if (r3 >= 0x1000 && r3 < PPC_MEMORY_SIZE) {
        MaybeLogSchedCapture(r3);
        s_lastSchedR3.store(r3, std::memory_order_release);
        s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel);
    }
}


extern "C" {
    // Forward decls of the recompiled originals
    void __imp__sub_82595FC8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825972B0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A54F0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A6DF0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A65A8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825986F8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825987E0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825988B0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A7A40(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A7DE8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A7E60(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A7EA0(PPCContext& ctx, uint8_t* base);


    void __imp__sub_82599010(PPCContext& ctx, uint8_t* base);
    // MW05 micro-IB interpreter
    void Mw05InterpretMicroIB(uint32_t ib_addr, uint32_t ib_size);

    void __imp__sub_82599208(PPCContext& ctx, uint8_t* base);
    void __imp__sub_82599338(PPCContext& ctx, uint8_t* base);
    void __imp__sub_82596E40(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825968B0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_82597650(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825976D8(PPCContext& ctx, uint8_t* base);


    void __imp__sub_825A7208(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A74B8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A7F10(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A7F88(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A8040(PPCContext& ctx, uint8_t* base);
    // New: functions near LRs observed in HOST.Store64BE_W traces
    void __imp__sub_8262F248(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8262F2A0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8262F330(PPCContext& ctx, uint8_t* base);
    void __imp__sub_823BC638(PPCContext& ctx, uint8_t* base);
    void __imp__sub_82812E20(PPCContext& ctx, uint8_t* base);
    void __imp__sub_82596978(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825979A8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_82595FC8(PPCContext& ctx, uint8_t* base);

    void __imp__sub_825A97B8(PPCContext& ctx, uint8_t* base);

    void __imp__sub_82441CF0(PPCContext& ctx, uint8_t* base);

    void __imp__sub_82598A20(PPCContext& ctx, uint8_t* base);

}

#define SHIM(name) \
    void MW05Shim_##name(PPCContext& ctx, uint8_t* base) { \
        KernelTraceHostOpF(#name ".lr=%08llX r3=%08X r4=%08X r5=%08X", \
                           (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32); \
        __imp__##name(ctx, base); \
    }

// Default log-and-forward shims
SHIM(sub_82599010)
SHIM(sub_82599208)
SHIM(sub_82599338)
SHIM(sub_825A7208)
SHIM(sub_825A74B8)

// Forward decls of local shim helpers used before their definitions (C++ linkage)
struct PPCContext;
void MW05Shim_sub_825972B0(PPCContext& ctx, uint8_t* base);
void MW05Shim_sub_82597650(PPCContext& ctx, uint8_t* base);
void MW05Shim_sub_825976D8(PPCContext& ctx, uint8_t* base);
void MW05Shim_sub_825968B0(PPCContext& ctx, uint8_t* base);
void MW05Shim_sub_82596E40(PPCContext& ctx, uint8_t* base);


SHIM(sub_825A7F10)
SHIM(sub_825A7F88)
SHIM(sub_825A8040)

// Candidate MW05 render/viewport/draw-adjacent helpers to log-and-forward
SHIM(sub_825986F8)
SHIM(sub_825987E0)
SHIM(sub_825988B0)
SHIM(sub_825A7A40)
SHIM(sub_825A7DE8)
SHIM(sub_825A7E60)
SHIM(sub_825A7EA0)

// Scheduler/notify-adjacent shims (log, dump key pointers, and forward)
void MW05Shim_sub_8262F248(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_8262F248.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    DumpEAWindow("8262F248.r3", ctx.r3.u32);
    DumpEAWindow("8262F248.r4", ctx.r4.u32);
    DumpEAWindow("8262F248.r5", ctx.r5.u32);
    __imp__sub_8262F248(ctx, base);
}
void MW05Shim_sub_8262F2A0(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_8262F2A0.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    auto looks_ptr = [](uint32_t ea){ return ea >= 0x1000 && ea < PPC_MEMORY_SIZE; };
    uint32_t seed = ctx.r3.u32;
    if (!looks_ptr(seed) && looks_ptr(ctx.r5.u32)) seed = ctx.r5.u32; // MW05: loop passes ctx in r5
    if (looks_ptr(seed)) { MaybeLogSchedCapture(seed); s_lastSchedR3.store(seed, std::memory_order_release); s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel); }
    DumpEAWindow("8262F2A0.r3", ctx.r3.u32);
    DumpEAWindow("8262F2A0.r4", ctx.r4.u32);
    DumpEAWindow("8262F2A0.r5", ctx.r5.u32);
    DumpSchedState("8262F2A0", seed);

    static const bool s_loop_try_pm4_pre = [](){ if (const char* v = std::getenv("MW05_LOOP_TRY_PM4_PRE")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    static const bool s_loop_try_pm4 = [](){ if (const char* v = std::getenv("MW05_LOOP_TRY_PM4")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    static const bool s_loop_try_pm4_deep = [](){ if (const char* v = std::getenv("MW05_LOOP_TRY_PM4_DEEP")) return !(v[0]=='0' && v[1]=='\0'); return false; }();

    if (s_loop_try_pm4_pre && looks_ptr(seed)) {
        uint32_t saved_r3 = ctx.r3.u32;
        ctx.r3.u32 = seed;
        KernelTraceHostOpF("HOST.sub_8262F2A0.pre.try_825972B0 r3=%08X (seed)", ctx.r3.u32);
        MW05Shim_sub_825972B0(ctx, base);
        if (s_loop_try_pm4_deep) {
            KernelTraceHostOpF("HOST.sub_8262F2A0.pre.try_deep r3=%08X", ctx.r3.u32);
            MW05Shim_sub_82597650(ctx, base);
            MW05Shim_sub_825976D8(ctx, base);
            // Additional allocator/callback prep + gating clear
            MW05Shim_sub_825968B0(ctx, base);
            MW05Shim_sub_82596E40(ctx, base);
        }
        ctx.r3.u32 = saved_r3;
    }

    __imp__sub_8262F2A0(ctx, base);

    if (s_loop_try_pm4 && looks_ptr(seed)) {
        uint32_t saved_r3 = ctx.r3.u32;
        ctx.r3.u32 = seed;
        KernelTraceHostOpF("HOST.sub_8262F2A0.post.try_825972B0 r3=%08X (seed)", ctx.r3.u32);
        MW05Shim_sub_825972B0(ctx, base);
        if (s_loop_try_pm4_deep) {
            KernelTraceHostOpF("HOST.sub_8262F2A0.post.try_deep r3=%08X", ctx.r3.u32);
            MW05Shim_sub_82597650(ctx, base);
            MW05Shim_sub_825976D8(ctx, base);
            // Additional allocator/callback prep + gating clear
            MW05Shim_sub_825968B0(ctx, base);
            MW05Shim_sub_82596E40(ctx, base);
        }
        ctx.r3.u32 = saved_r3;
    }
}
void MW05Shim_sub_8262F330(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_8262F330.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    if (ctx.r3.u32 >= 0x1000 && ctx.r3.u32 < PPC_MEMORY_SIZE) { MaybeLogSchedCapture(ctx.r3.u32); s_lastSchedR3.store(ctx.r3.u32, std::memory_order_release); s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel); }
    DumpEAWindow("8262F330.r3", ctx.r3.u32);
    DumpEAWindow("8262F330.r4", ctx.r4.u32);
    DumpEAWindow("8262F330.r5", ctx.r5.u32);
    DumpSchedState("8262F330", ctx.r3.u32);
    __imp__sub_8262F330(ctx, base);
}
void MW05Shim_sub_823BC638(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_823BC638.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    DumpEAWindow("823BC638.r3", ctx.r3.u32);
    DumpEAWindow("823BC638.r4", ctx.r4.u32);
    DumpEAWindow("823BC638.r5", ctx.r5.u32);
    __imp__sub_823BC638(ctx, base);
}
void MW05Shim_sub_82812E20(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_82812E20.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    if (ctx.r3.u32 >= 0x1000 && ctx.r3.u32 < PPC_MEMORY_SIZE) { MaybeLogSchedCapture(ctx.r3.u32); s_lastSchedR3.store(ctx.r3.u32, std::memory_order_release); s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel); }
    DumpEAWindow("82812E20.r3", ctx.r3.u32);
    DumpEAWindow("82812E20.r4", ctx.r4.u32);
    DumpEAWindow("82812E20.r5", ctx.r5.u32);
    DumpSchedState("82812E20", ctx.r3.u32);
    __imp__sub_82812E20(ctx, base);
}

void MW05Shim_sub_82596978(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_82596978.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    DumpEAWindow("82596978.r3", ctx.r3.u32);
    DumpEAWindow("82596978.r4", ctx.r4.u32);
    __imp__sub_82596978(ctx, base);
}

void MW05Shim_sub_825979A8(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_825979A8.lr=%08llX r3=%08X r4=%08X r5=%08X",
                       (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);

    auto looks_ptr = [](uint32_t ea) {
        return ea >= 0x1000 && ea < PPC_MEMORY_SIZE;
    };

    // Opt-in: swap params at ISR entry so scheduler/context lands in r3.
    static const bool s_swap_entry = [](){
        if (const char* v = std::getenv("MW05_VD_ISR_SWAP_AT_ENTRY")) return !(v[0]=='0' && v[1]=='\0');
        // Default off unless explicitly enabled by runner/diag
        return false;
    }();
    if (s_swap_entry) {
        const bool r3_ok = looks_ptr(ctx.r3.u32);
        const bool r4_ok = looks_ptr(ctx.r4.u32);
        if (!r3_ok && r4_ok) {
            KernelTraceHostOp("HOST.sub_825979A8.swap@entry r3<->r4");
        #if defined(_MSC_VER)
            std::swap(ctx.r3.u32, ctx.r4.u32);
        #else
            uint32_t tmp = ctx.r3.u32; ctx.r3.u32 = ctx.r4.u32; ctx.r4.u32 = tmp;
        #endif
        }
    }

    // Optional: force r3 from last-seen scheduler or env if r3 is null/unusable.
    static const bool s_force_r3 = [](){
        if (const char* v = std::getenv("MW05_VD_ISR_FORCE_R3")) return !(v[0]=='0' && v[1]=='\0');
        return false;
    }();
    if (s_force_r3) {
        uint32_t seed = 0;
        if (const char* v = std::getenv("MW05_SCHED_R3_EA")) {
            // Accept both hex (0x...) and decimal
            seed = static_cast<uint32_t>(std::strtoul(v, nullptr, 0));
        }
        if (!seed) {
            seed = s_lastSchedR3.load(std::memory_order_acquire);
        }
        if (looks_ptr(seed) && !looks_ptr(ctx.r3.u32)) {
            KernelTraceHostOpF("HOST.sub_825979A8.force r3=%08X", seed);
            ctx.r3.u32 = seed;
        }
    }

    // Record scheduler/context sighting so host gates can proceed
    Mw05Trace_ConsiderSchedR3(ctx.r3.u32);

    DumpEAWindow("825979A8.r3", ctx.r3.u32);
    DumpEAWindow("825979A8.r4", ctx.r4.u32);
    DumpSchedState("825979A8", ctx.r3.u32);

    // Register this scheduler context
    RegisterSchedulerContext(ctx.r3.u32);

    // CRITICAL: Process any pending commands in ALL MW05 scheduler queues
    // MW05 uses multiple scheduler contexts, so we need to process all of them
    uint32_t count = g_schedulerContextCount.load(std::memory_order_acquire);
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t schedEA = g_schedulerContexts[i].load(std::memory_order_relaxed);
        if (schedEA) {
            ProcessMW05Queue(schedEA);
        }
    }

    // Just call the original guest ISR - no present function workaround
    // The present function hangs when called from within the vblank ISR
    __imp__sub_825979A8(ctx, base);
}


void MW05Shim_sub_825A97B8(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_825A97B8.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    DumpEAWindow("825A97B8.r3", ctx.r3.u32);
    __imp__sub_825A97B8(ctx, base);
}

// Shim for sub_82880FA0 - logs calls to the function that calls sub_82885A70
void MW05Shim_sub_82880FA0(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_82880FA0.lr=%08llX r3=%08X r4=%08X r5=%08X",
                       (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    extern void sub_82880FA0(PPCContext& ctx, uint8_t* base);
    sub_82880FA0(ctx, base);
    KernelTraceHostOpF("sub_82880FA0.ret r3=%08X", ctx.r3.u32);
}

// Shim for sub_82885A70 - logs the condition check for thread creation
void MW05Shim_sub_82885A70(PPCContext& ctx, uint8_t* base) {
    // Log the input structure to understand what's being checked
    uint32_t r25 = ctx.r3.u32;  // r25 = r3 (first parameter)
    uint32_t r30_ptr = 0;
    uint32_t check_value = 0xFFFFFFFF;

    if (r25 >= 0x0A000000 && r25 < 0x90000000) {
        r30_ptr = ReadBE32(r25 + 0);  // r30 = *(r25 + 0)
        if (r30_ptr != 0 && r30_ptr >= 0x0A000000 && r30_ptr < 0x90000000) {
            check_value = ReadBE32(r30_ptr + 0);  // value at *(r30 + 0) that will be copied to *(r31 + 8)
        }
    }

    KernelTraceHostOpF("sub_82885A70.lr=%08llX r3=%08X r4=%08X r30_ptr=%08X check_value=%08X",
                       (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, r30_ptr, check_value);
    extern void sub_82885A70(PPCContext& ctx, uint8_t* base);
    sub_82885A70(ctx, base);
    KernelTraceHostOpF("sub_82885A70.ret r3=%08X", ctx.r3.u32);
}



// Host allocator callback to be installed into scheduler if game leaves it null
// Contract: return r3 = pointer to writable PM4 space (we use System Command Buffer payload)
void MW05HostAllocCb(PPCContext& ctx, uint8_t* base) {
    const uint32_t sys_base    = 0x00140400u;
    const uint32_t sys_payload = sys_base + 0x10u;
    const uint32_t sys_end     = sys_base + 0x10000u;

    // Treat r3 (or r4 if non-zero) as scheduler EA
    uint32_t sched = ctx.r3.u32 ? ctx.r3.u32 : ctx.r4.u32;
    if (!(sched >= 0x1000 && sched + 14024 < PPC_MEMORY_SIZE)) {
        // Fallback: just return the payload start
        KernelTraceHostOpF("HOST.MW05HostAllocCb.fallback.ret r3=%08X", sys_payload);
        ctx.r3.u32 = sys_payload;
        return;
    }

    // Ensure allocator fields are initialized
    uint32_t cur = ReadBE32(sched + 14012);
    uint32_t end = ReadBE32(sched + 14020);
    if (cur == 0 || end == 0) {
        WriteBE32(sched + 14012, sys_payload);
        WriteBE32(sched + 14016, sys_payload);
        WriteBE32(sched + 14020, sys_end);
        cur = sys_payload;
        end = sys_end;
    }

    // Size heuristic: use r5 (count), assume dwords if small; fall back to 16 dwords
    uint32_t count = ctx.r5.u32;
    if (count == 0 || count > 0x10000u) count = 16; // safety bound
    uint32_t bytes = count * 4u;

    uint32_t ret = cur;
    uint32_t next = cur + bytes;
    if (next > end) {
        // Clamp and wrap to start of payload to avoid overflow
        ret = sys_payload;
        next = sys_payload + bytes;
    }

    // Publish tail and current write pointer
    WriteBE32(sched + 0x14, next);      // qtail (best-effort)
    WriteBE32(sched + 14012, next);     // current write ptr

    KernelTraceHostOpF("HOST.MW05HostAllocCb.alloc ret=%08X bytes=%u next=%08X lr=%08llX r5=%u", ret, (unsigned)bytes, next, (unsigned long long)ctx.lr, (unsigned)ctx.r5.u32);
    ctx.r3.u32 = ret;
}


// Add shims for research helpers used by MW05 during rendering.
// Specialize 82595FC8/825972B0 to dump more state
// CRITICAL FIX: sub_82595FC8 is called from the present function and appears to hang
// This function checks buffer space and calls sub_825972B0 (PM4 builder) and sub_82596978
// For now, stub it to just return the current buffer pointer (r3 = [r31+0])
void MW05Shim_sub_82595FC8(PPCContext& ctx, uint8_t* base) {
    static int call_count = 0;
    call_count++;
    if (call_count <= 10) {
        KernelTraceHostOpF("sub_82595FC8.STUB count=%d r3=%08X r4=%08X", call_count, ctx.r3.u32, ctx.r4.u32);
    }

    // Capture scheduler context
    if (ctx.r3.u32 >= 0x1000 && ctx.r3.u32 < PPC_MEMORY_SIZE) {
        MaybeLogSchedCapture(ctx.r3.u32);
        s_lastSchedR3.store(ctx.r3.u32, std::memory_order_release);
        s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel);
    }

    // Return the current buffer pointer from [r31+0]
    uint32_t r31 = ctx.r3.u32;
    if (r31 >= 0x1000 && r31 < PPC_MEMORY_SIZE - 4) {
        uint32_t* ptr = reinterpret_cast<uint32_t*>(g_memory.Translate(r31));
        if (ptr) {
            ctx.r3.u32 = be<uint32_t>(*ptr);
            if (call_count <= 10) {
                KernelTraceHostOpF("sub_82595FC8.STUB.ret r3=%08X", ctx.r3.u32);
            }
            return;
        }
    }

    // Fallback: return 0
    ctx.r3.u32 = 0;
    if (call_count <= 10) {
        KernelTraceHostOpF("sub_82595FC8.STUB.ret r3=00000000 (fallback)");
    }
}

void MW05Shim_sub_825972B0(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_825972B0.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    uint32_t pre_r3 = ctx.r3.u32;

    if (ctx.r3.u32 >= 0x1000 && ctx.r3.u32 < PPC_MEMORY_SIZE) {
        MaybeLogSchedCapture(ctx.r3.u32);
        s_lastSchedR3.store(ctx.r3.u32, std::memory_order_release);
        s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel);
    }
    uint32_t v13520b = ReadBE32(ctx.r3.u32 + 13520);
    uint8_t v10432b = (uint8_t)(ReadBE32(ctx.r3.u32 + 10432) & 0xFF);
    KernelTraceHostOpF("HOST.825972B0.pre 13520=%08X 10432=%02X", v13520b, (unsigned)v10432b);

    // Seed syscmd payload pointer if missing (game expects this for PM4 emission)
    if (v13520b == 0) {
        const uint32_t sys_payload = 0x00140410u; // system command buffer payload start
        WriteBE32(ctx.r3.u32 + 13520, sys_payload);
        KernelTraceHostOpF("HOST.825972B0.seed 13520=%08X", sys_payload);
        v13520b = sys_payload;
    }

    // If allocator callback is null, install our host callback so builder can proceed
    uint32_t fp_ea = ReadBE32(ctx.r3.u32 + 13620);
    uint32_t cbctx = ReadBE32(ctx.r3.u32 + 13624);
    if (fp_ea == 0) {
        WriteBE32(ctx.r3.u32 + 13620, 0x82FF1000u);
        WriteBE32(ctx.r3.u32 + 13624, ctx.r3.u32);
        KernelTraceHostOpF("HOST.825972B0.install_alloc_cb fp=%08X ctx=%08X", 0x82FF1000u, ctx.r3.u32);
    }

    // Conservative ready-bit nudge: set bit0 at +0x1C if not set yet
    {
        uint32_t ready = ReadBE32(ctx.r3.u32 + 0x1C);
        if ((ready & 0x1u) == 0) {
            WriteBE32(ctx.r3.u32 + 0x1C, ready | 0x1u);
            KernelTraceHostOpF("HOST.825972B0.ready_flag %08X->%08X", ready, ready | 0x1u);
        }
    }
    // Clear gating bits and seed allocator like pre-build helpers do
    // Some XEX variants require clearing forbid bits at +10432 (low8), e.g., 0x84
    {
        uint32_t f10432 = ReadBE32(ctx.r3.u32 + 10432);
        uint8_t b10433 = (uint8_t)(f10432 & 0xFF);
        uint8_t nb = (uint8_t)(b10433 & ~0x84u);
        if (nb != b10433) {
            uint32_t nw = (f10432 & 0xFFFFFF00u) | nb;
            WriteBE32(ctx.r3.u32 + 10432, nw);
            KernelTraceHostOpF("HOST.825972B0.flags10433 %02X->%02X", (unsigned)b10433, (unsigned)nb);
        }
        // Seed allocator state if missing: write_ptr/rear_ptr/end_ptr
        uint32_t a_wptr = ReadBE32(ctx.r3.u32 + 14012);
        uint32_t a_rend = ReadBE32(ctx.r3.u32 + 14016);
        uint32_t a_end  = ReadBE32(ctx.r3.u32 + 14020);
        if (a_wptr == 0 || a_end == 0) {
            const uint32_t sysbufBase = 0x00140400u;
            const uint32_t sysbufSize = 0x00010000u; // 64 KB
            WriteBE32(ctx.r3.u32 + 14012, sysbufBase + 0x10u);
            WriteBE32(ctx.r3.u32 + 14016, sysbufBase + sysbufSize);
            WriteBE32(ctx.r3.u32 + 14020, sysbufBase + sysbufSize);
            KernelTraceHostOpF("HOST.825972B0.seed alloc w=%08X re=%08X end=%08X", sysbufBase+0x10, sysbufBase+sysbufSize, sysbufBase+sysbufSize);
        }
    }


    // Keep dumps minimal; avoid heavy structure mutation here (XEX variant sensitive)
    DumpEAWindow("825972B0.r3", ctx.r3.u32);
    DumpSchedState("825972B0", ctx.r3.u32);
    __imp__sub_825972B0(ctx, base);

    // Optional post-call dump of syscmd payload region to catch freshly written PM4
    static const bool s_dump_after_builder = [](){ if (const char* v = std::getenv("MW05_PM4_DUMP_AFTER_BUILDER")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    if (s_dump_after_builder) {
        uint32_t post_sys = ReadBE32(pre_r3 + 13520);
        if ((post_sys & 0xFFFF0000u) == 0x00140000u) {
            DumpEAWindow("825972B0.post.sys", post_sys);
        }
        DumpSchedState("825972B0.post", pre_r3);
    }
    // Opportunistic scan of the just-built syscmd payload to surface MW05 wrapper and nested PM4
    static const bool s_scan_after_builder = [](){ if (const char* v = std::getenv("MW05_PM4_SCAN_AFTER_BUILDER")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    if (s_scan_after_builder) {
        uint32_t post_sys = ReadBE32(pre_r3 + 13520);
        if ((post_sys & 0xFFFF0000u) == 0x00140000u) {
            uint32_t be_hdr = ReadBE32(post_sys);
        #if defined(_MSC_VER)
            uint32_t hdr_le = _byteswap_ulong(be_hdr);
        #else
            uint32_t hdr_le = __builtin_bswap32(be_hdr);
        #endif
            uint32_t hdr_be = be_hdr; // handle case where value is already LE in dumps
            auto decode_and_scan = [&](uint32_t hdr){
                uint32_t type = (hdr >> 30) & 0x3u;
                uint32_t opc  = (hdr >> 8)  & 0x7Fu;
                uint32_t cnt  = (hdr >> 16) & 0x3FFFu;
                if (type == 3u && opc == 0x04u) {
                    uint32_t bytes = (cnt + 1u) * 4u;
                    // Optionally force-call the MW05 micro-IB interpreter on the syscmd payload
                    static const bool s_force_micro = [](){ if (const char* v = std::getenv("MW05_FORCE_MICROIB")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
                    if (s_force_micro) {
                        uint32_t payload_ea = post_sys + 0x10u;
                        uint32_t payload_bytes = bytes > 0x10u ? (bytes - 0x10u) : 0u;
                            // Expand interpreter scan window to improve discovery
                            payload_bytes = 0x400u;
                        KernelTraceHostOpF("HOST.PM4.MW05.ForceMicroIB.call2 ea=%08X size=%u", payload_ea, payload_bytes);
                        Mw05InterpretMicroIB(payload_ea, payload_bytes);
                    }

                    KernelTraceHostOpF("HOST.PM4.ScanAfterBuilder ea=%08X bytes=%u", post_sys, bytes);
                    PM4_ScanLinear(post_sys, bytes);
                    return true;
                }
                return false;
            };
            if (!decode_and_scan(hdr_le)) {
                (void)decode_and_scan(hdr_be);
            }
        }
    }

}
extern "C" uint32_t VdGetSystemCommandBuffer(void* outCmdBufPtr, void* outValue);



extern "C" void Mw05TryBuilderKickNoForward(uint32_t schedEA) {
    auto looks_ptr = [](uint32_t ea) { return ea >= 0x1000 && ea < PPC_MEMORY_SIZE; };
    if (!looks_ptr(schedEA)) return;
    KernelTraceHostOpF("HOST.BuilderKick.no_fwd2 r3=%08X", schedEA);
    // Debug probe of scheduler block before seeding
    KernelTraceHostOpF("HOST.BuilderKick.probe @%08X 13520=%08X 13620=%08X 13624=%08X 10432=%08X 14012=%08X 14016=%08X 14020=%08X 001C=%08X",
        schedEA,
        ReadBE32(schedEA + 13520), ReadBE32(schedEA + 13620), ReadBE32(schedEA + 13624), ReadBE32(schedEA + 10432),
        ReadBE32(schedEA + 14012), ReadBE32(schedEA + 14016), ReadBE32(schedEA + 14020), ReadBE32(schedEA + 0x1C));

    // Seed syscmd payload pointer if missing (game expects this for PM4 emission)
    uint32_t v13520b = ReadBE32(schedEA + 13520);
    if (v13520b == 0) {
        uint32_t sys_base = VdGetSystemCommandBuffer(nullptr, nullptr);
        const uint32_t sys_payload = sys_base ? (sys_base + 0x10u) : 0u;
        if (sys_payload) {
            WriteBE32(schedEA + 13520, sys_payload);
            KernelTraceHostOpF("HOST.BuilderKick.seed 13520=%08X", sys_payload);
            v13520b = sys_payload;
        }
    }
    // If allocator callback is null, install our host callback so builder can proceed
    uint32_t fp_ea = ReadBE32(schedEA + 13620);
    uint32_t cbctx = ReadBE32(schedEA + 13624);
    if (fp_ea == 0) {
        WriteBE32(schedEA + 13620, 0x82FF1000u);
        WriteBE32(schedEA + 13624, schedEA);
        KernelTraceHostOpF("HOST.BuilderKick.install_alloc_cb fp=%08X ctx=%08X", 0x82FF1000u, schedEA);
    }
    // Clear gating bits similar to builder shim and seed allocator window
    {
        uint32_t f10432 = ReadBE32(schedEA + 10432);
        uint8_t b10433 = (uint8_t)(f10432 & 0xFF);
        uint8_t nb = (uint8_t)(b10433 & ~0x84u);
        if (nb != b10433) {
            uint32_t nw = (f10432 & 0xFFFFFF00u) | nb;
            WriteBE32(schedEA + 10432, nw);
            KernelTraceHostOpF("HOST.BuilderKick.flags10433 %02X->%02X", (unsigned)b10433, (unsigned)nb);
        }
        // Seed allocator state if missing: write_ptr/rear_ptr/end_ptr
        uint32_t a_wptr = ReadBE32(schedEA + 14012);
        uint32_t a_rear = ReadBE32(schedEA + 14016);
        uint32_t a_end  = ReadBE32(schedEA + 14020);
        if (a_wptr == 0 || a_rear == 0 || a_end == 0) {
            uint32_t sysbufBase = VdGetSystemCommandBuffer(nullptr, nullptr);
            const uint32_t sysbufSize = 64u * 1024u;
            if (sysbufBase) {
                WriteBE32(schedEA + 14012, sysbufBase + 0x10u);
                WriteBE32(schedEA + 14016, sysbufBase + sysbufSize);
                WriteBE32(schedEA + 14020, sysbufBase + sysbufSize);
                KernelTraceHostOpF("HOST.BuilderKick.seed alloc w=%08X re=%08X end=%08X", sysbufBase+0x10, sysbufBase+sysbufSize, sysbufBase+sysbufSize);
            }
        }
        // Conservative ready-bit nudge: set bit0 at +0x1C if not set yet
        uint32_t ready = ReadBE32(schedEA + 0x1C);
        if ((ready & 0x1u) == 0) {
            WriteBE32(schedEA + 0x1C, ready | 0x1u);
            KernelTraceHostOpF("HOST.BuilderKick.ready_flag %08X->%08X", ready, ready | 0x1u);
        }
    }
    KernelTraceHostOpF("HOST.BuilderKick.will_forward r3=%08X", schedEA);

    // Forward-call the actual PM4 builder now that state is seeded (optional, gated)
    static const bool s_try_builder_with_seh = [](){
        if (const char* v = std::getenv("MW05_TRY_BUILDER_WITH_SEH")) return !(v[0]=='0' && v[1]=='\0');
        return false;
    }();
    static bool s_tried_once = false;
    if (s_try_builder_with_seh && !s_tried_once && looks_ptr(schedEA)) {
        s_tried_once = true;
        PPCContext ctx{};
        if (auto* cur = GetPPCContext()) ctx = *cur; // preserve TOC/r13 etc.
        ctx.r3.u32 = schedEA;
        uint8_t* base = g_memory.base;
        KernelTraceHostOpF("HOST.BuilderKick.forward r3=%08X", ctx.r3.u32);
    #if defined(_MSC_VER)
        __try {
            MW05Shim_sub_825972B0(ctx, base);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            KernelTraceHostOpF("HOST.BuilderKick.forward.EXCEPTION code=%08X", (unsigned)GetExceptionCode());
        }
    #else
        try {
            MW05Shim_sub_825972B0(ctx, base);
        } catch (...) {
            KernelTraceHostOpF("HOST.BuilderKick.forward.EXCEPTION cpp");
        }
    #endif
    }

    // Optional scan of the syscmd payload to surface MW05 wrapper and nested PM4
    KernelTraceHostOpF("HOST.BuilderKick.end r3=%08X", schedEA);

    uint32_t post_sys = ReadBE32(schedEA + 13520);
    if ((post_sys & 0xFFFF0000u) == 0x00140000u) {
        uint32_t be_hdr = ReadBE32(post_sys);
    #if defined(_MSC_VER)
        uint32_t hdr_le = _byteswap_ulong(be_hdr);
    #else
        uint32_t hdr_le = __builtin_bswap32(be_hdr);
    #endif
        uint32_t type = (hdr_le >> 30) & 0x3u;
        uint32_t opc  = (hdr_le >> 8)  & 0x7Fu;
        uint32_t cnt  = (hdr_le >> 16) & 0x3FFFu;
        if (type == 3u && opc == 0x04u) {
            uint32_t bytes = (cnt + 1u) * 4u;
            KernelTraceHostOpF("HOST.PM4.ScanAfterKick ea=%08X bytes=%u", post_sys, bytes);
            static const bool s_force_micro = [](){ if (const char* v = std::getenv("MW05_FORCE_MICROIB")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
            if (s_force_micro) {
                uint32_t payload_ea = post_sys + 0x10u;
                uint32_t payload_bytes = bytes > 0x10u ? (bytes - 0x10u) : 0u;
                if (payload_bytes >= 8u && payload_bytes <= 0x10000u) {
                    KernelTraceHostOpF("HOST.PM4.MW05.ForceMicroIB.call2 ea=%08X size=%u", payload_ea, payload_bytes);
                    Mw05InterpretMicroIB(payload_ea, payload_bytes);
                }
            }
            PM4_ScanLinear(post_sys, bytes);
        }
    }
}


// Declare the original recompiled function
PPC_FUNC_IMPL(__imp__sub_825968B0);

// Full replacement for sub_825968B0 to avoid NULL function pointer calls
PPC_FUNC(sub_825968B0) {
    // Forward to the shim implementation
    MW05Shim_sub_825968B0(ctx, base);
}

void MW05Shim_sub_825968B0(PPCContext& ctx, uint8_t* base) {
    fprintf(stderr, "[SHIM-ENTRY] sub_825968B0 lr=%08llX r3=%08X\n", (unsigned long long)ctx.lr, ctx.r3.u32);
    fflush(stderr);
    KernelTraceHostOpF("sub_825968B0.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);

    // Check if fake_alloc is enabled first
    static const bool s_fake_alloc = [](){
        const char* v = std::getenv("MW05_FAKE_ALLOC_SYSBUF");
        bool result = (v && v[0] && !(v[0]=='0' && v[1]=='\0'));
        fprintf(stderr, "[SHIM-INIT] MW05_FAKE_ALLOC_SYSBUF=%s result=%d\n", v ? v : "(null)", result);
        fflush(stderr);
        return result;
    }();

    // Check if r3 is valid before accessing memory
    // If invalid, try to seed from environment variable or last known scheduler context
    if (ctx.r3.u32 < 0x1000 || ctx.r3.u32 >= PPC_MEMORY_SIZE) {
        KernelTraceHostOpF("HOST.825968B0.invalid_r3 r3=%08X - attempting to seed", ctx.r3.u32);

        // Try environment variable first
        if (const char* seed = std::getenv("MW05_SCHED_R3_EA")) {
            uint32_t env_r3 = (uint32_t)std::strtoul(seed, nullptr, 0);
            if (env_r3 >= 0x1000 && env_r3 < PPC_MEMORY_SIZE) {
                ctx.r3.u32 = env_r3;
                KernelTraceHostOpF("HOST.825968B0.seeded_from_env r3=%08X", ctx.r3.u32);
            }
        }

        // If still invalid, try last known scheduler context
        if (ctx.r3.u32 < 0x1000 || ctx.r3.u32 >= PPC_MEMORY_SIZE) {
            uint32_t last_sched = s_lastSchedR3.load(std::memory_order_acquire);
            if (last_sched >= 0x1000 && last_sched < PPC_MEMORY_SIZE) {
                ctx.r3.u32 = last_sched;
                KernelTraceHostOpF("HOST.825968B0.seeded_from_last r3=%08X", ctx.r3.u32);
            }
        }

        // If still invalid and fake_alloc is enabled, return fake allocation
        if (ctx.r3.u32 < 0x1000 || ctx.r3.u32 >= PPC_MEMORY_SIZE) {
            if (s_fake_alloc) {
                // Return a fake allocation from the system command buffer
                const uint32_t sys_base    = 0x00140400u;
                const uint32_t sys_payload = sys_base + 0x10u;
                KernelTraceHostOpF("HOST.825968B0.fake_alloc_no_ctx ret=%08X", sys_payload);
                ctx.r3.u32 = sys_payload;
                return;
            }
            // Otherwise return NULL
            KernelTraceHostOpF("HOST.825968B0.still_invalid r3=%08X - returning NULL", ctx.r3.u32);
            ctx.r3.u32 = 0;
            return;
        }
    }

    if (ctx.r3.u32 >= 0x1000 && ctx.r3.u32 < PPC_MEMORY_SIZE) { MaybeLogSchedCapture(ctx.r3.u32); s_lastSchedR3.store(ctx.r3.u32, std::memory_order_release); s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel); }
    uint32_t fp_ea = ReadBE32(ctx.r3.u32 + 13620);
    uint32_t cbctx = ReadBE32(ctx.r3.u32 + 13624);
    KernelTraceHostOpF("HOST.825968B0.cb fp=%08X ctx=%08X", fp_ea, cbctx);
    uint32_t f10432w = ReadBE32(ctx.r3.u32 + 10432);
    uint8_t b10433 = (uint8_t)(f10432w & 0xFF);
    KernelTraceHostOpF("HOST.825968B0.flags10433=%02X", (unsigned)b10433);
    // If the allocator callback is NULL or invalid, optionally fake an allocation into the System Command Buffer payload
    KernelTraceHostOpF("HOST.825968B0.fake_alloc=%d", s_fake_alloc);
    // Check if function pointer is NULL or outside valid PPC range
    bool fp_invalid = (fp_ea == 0 || fp_ea < 0x82000000 || fp_ea >= 0x82CD0000);
    if (s_fake_alloc) {
        // CRITICAL: Always skip calling the original function when fake_alloc is enabled
        // The original function will try to call through fp_ea, which might be NULL or invalid
        if (fp_invalid) {
            // Known default guest EA for syscmd buffer base from our bridge: 0x00140400
            // Return a pointer just past the 16-byte header we seed (payload begins at +0x10)
            const uint32_t sys_base    = 0x00140400u;
            const uint32_t sys_payload = sys_base + 0x10u;
            const uint32_t sys_end     = sys_base + 0x10000u; // 64 KiB
            // Seed basic allocator state so subsequent code can advance pointers
            WriteBE32(ctx.r3.u32 + 14012, sys_payload); // current write ptr
            WriteBE32(ctx.r3.u32 + 14016, sys_payload); // running end ptr


            WriteBE32(ctx.r3.u32 + 14020, sys_end);     // buffer end
            // Clear forbid bit (top bit of 10433) if set, to avoid early exits
            uint32_t f10432w2 = ReadBE32(ctx.r3.u32 + 10432);
            uint8_t b10433_2 = (uint8_t)(f10432w2 & 0xFF);
            if (b10433_2 & 0x80) {
                WriteBE8(ctx.r3.u32 + 10433, (uint8_t)(b10433_2 & ~0x80));
            }
            KernelTraceHostOpF("HOST.825968B0.fake ret=%08X (fp_ea=%08X was invalid)", sys_payload, fp_ea);
            ctx.r3.u32 = sys_payload;
            return;
        } else {
            // fp_ea is valid, but we still don't want to call the original function
            // because it might call through fp_ea which could cause issues
            // Instead, return a fake allocation
            const uint32_t sys_base    = 0x00140400u;
            const uint32_t sys_payload = sys_base + 0x10u;
            KernelTraceHostOpF("HOST.825968B0.fake ret=%08X (fp_ea=%08X was valid but skipped)", sys_payload, fp_ea);
            ctx.r3.u32 = sys_payload;
            return;
        }
    }
    __imp__sub_825968B0(ctx, base);
    KernelTraceHostOpF("HOST.825968B0.ret r3=%08X", ctx.r3.u32);
}

void MW05Shim_sub_82596E40(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_82596E40.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    if (ctx.r3.u32 >= 0x1000 && ctx.r3.u32 < PPC_MEMORY_SIZE) { MaybeLogSchedCapture(ctx.r3.u32); s_lastSchedR3.store(ctx.r3.u32, std::memory_order_release); s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel); }
    uint32_t v13520c = ReadBE32(ctx.r3.u32 + 13520);
    uint8_t v10432c = (uint8_t)(ReadBE32(ctx.r3.u32 + 10432) & 0xFF);
    KernelTraceHostOpF("HOST.82596E40.pre 13520=%08X 10432=%02X", v13520c, (unsigned)v10432c);
    __imp__sub_82596E40(ctx, base);
}
void MW05Shim_sub_82597650(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_82597650.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    uint32_t pre_r3 = ctx.r3.u32;

    if (ctx.r3.u32 >= 0x1000 && ctx.r3.u32 < PPC_MEMORY_SIZE) {
        MaybeLogSchedCapture(ctx.r3.u32);
        s_lastSchedR3.store(ctx.r3.u32, std::memory_order_release);
        s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel);
        // Clear forbid bits like in 825972B0 shim
        uint32_t f10432 = ReadBE32(ctx.r3.u32 + 10432);
        uint8_t b10433 = (uint8_t)(f10432 & 0xFF);
        uint8_t nb = (uint8_t)(b10433 & ~0x84u);
        if (nb != b10433) {
            uint32_t nw = (f10432 & 0xFFFFFF00u) | nb;
            WriteBE32(ctx.r3.u32 + 10432, nw);
            KernelTraceHostOpF("HOST.82597650.flags10433 %02X->%02X", (unsigned)b10433, (unsigned)nb);
        }
        // Seed allocator state if missing
        uint32_t a_wptr = ReadBE32(ctx.r3.u32 + 14012);
        uint32_t a_rend = ReadBE32(ctx.r3.u32 + 14016);
        uint32_t a_end  = ReadBE32(ctx.r3.u32 + 14020);

        if (a_wptr == 0 || a_end == 0) {
            uint32_t sysbufBase = 0x00140400u;
            uint32_t sysbufSize = 0x00010000u; // 64 KB
            WriteBE32(ctx.r3.u32 + 14012, sysbufBase + 0x10u);
            WriteBE32(ctx.r3.u32 + 14016, sysbufBase + sysbufSize);
            WriteBE32(ctx.r3.u32 + 14020, sysbufBase + sysbufSize);
            KernelTraceHostOpF("HOST.82597650.seed alloc w=%08X re=%08X end=%08X", sysbufBase+0x10, sysbufBase+sysbufSize, sysbufBase+sysbufSize);
        }
        DumpSchedState("82597650.pre", ctx.r3.u32);
    }
    __imp__sub_82597650(ctx, base);
    // Optional post-call dump of syscmd payload region (same guard as 825972B0)
    static const bool s_dump_after_builder = [](){ if (const char* v = std::getenv("MW05_PM4_DUMP_AFTER_BUILDER")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    if (s_dump_after_builder) {
        uint32_t post_sys = ReadBE32(pre_r3 + 13520);
        if ((post_sys & 0xFFFF0000u) == 0x00140000u) {
            DumpEAWindow("82597650.post.sys", post_sys);
        }
        DumpSchedState("82597650.post", pre_r3);
    }
    // Opportunistic scan of syscmd payload (same guard as 825972B0)
    static const bool s_scan_after_builder_650 = [](){ if (const char* v = std::getenv("MW05_PM4_SCAN_AFTER_BUILDER")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    if (s_scan_after_builder_650) {
        uint32_t post_sys = ReadBE32(pre_r3 + 13520);
        if ((post_sys & 0xFFFF0000u) == 0x00140000u) {
            uint32_t be_hdr = ReadBE32(post_sys);
        #if defined(_MSC_VER)
            uint32_t hdr_le = _byteswap_ulong(be_hdr);
        #else
            uint32_t hdr_le = __builtin_bswap32(be_hdr);
        #endif
            uint32_t hdr_be = be_hdr;
            auto decode_and_scan = [&](uint32_t hdr){
                uint32_t type = (hdr >> 30) & 0x3u;
                uint32_t opc  = (hdr >> 8)  & 0x7Fu;
                uint32_t cnt  = (hdr >> 16) & 0x3FFFu;
                if (type == 3u && opc == 0x04u) {
                    uint32_t bytes = (cnt + 1u) * 4u;
                    extern void PM4_ScanLinear(uint32_t addr, uint32_t bytes);
                    KernelTraceHostOpF("HOST.PM4.ScanAfterBuilder ea=%08X bytes=%u", post_sys, bytes);
                    // Optionally force-call the MW05 micro-IB interpreter on the syscmd payload
                    static const bool s_force_micro = [](){ if (const char* v = std::getenv("MW05_FORCE_MICROIB")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
                    if (s_force_micro) {
                        uint32_t payload_ea = post_sys + 0x10u;
                        uint32_t payload_bytes = bytes > 0x10u ? (bytes - 0x10u) : 0u;
                        // Expand interpreter scan window to improve discovery
                        payload_bytes = 0x2000u;
                        KernelTraceHostOpF("HOST.PM4.MW05.ForceMicroIB.call2 ea=%08X size=%u", payload_ea, payload_bytes);
                        Mw05InterpretMicroIB(payload_ea, payload_bytes);
                    }
                    PM4_ScanLinear(post_sys, bytes);
                    return true;
                }
                return false;
            };
            if (!decode_and_scan(hdr_le)) {
                (void)decode_and_scan(hdr_be);
            }
        }
    }


}

void MW05Shim_sub_825976D8(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_825976D8.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    uint32_t pre_r3 = ctx.r3.u32;

    if (ctx.r3.u32 >= 0x1000 && ctx.r3.u32 < PPC_MEMORY_SIZE) {
        MaybeLogSchedCapture(ctx.r3.u32);
        s_lastSchedR3.store(ctx.r3.u32, std::memory_order_release);
        s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel);
        uint32_t f10432 = ReadBE32(ctx.r3.u32 + 10432);
        uint8_t b10433 = (uint8_t)(f10432 & 0xFF);
        uint8_t nb = (uint8_t)(b10433 & ~0x84u);
        if (nb != b10433) {
            uint32_t nw = (f10432 & 0xFFFFFF00u) | nb;
            WriteBE32(ctx.r3.u32 + 10432, nw);
            KernelTraceHostOpF("HOST.825976D8.flags10433 %02X->%02X", (unsigned)b10433, (unsigned)nb);

        }
        // Ensure allocator fields look valid
        uint32_t a_wptr = ReadBE32(ctx.r3.u32 + 14012);
        if (a_wptr == 0) {

            uint32_t sysbufBase = 0x00140400u;
            WriteBE32(ctx.r3.u32 + 14012, sysbufBase + 0x10u);
            WriteBE32(ctx.r3.u32 + 14016, sysbufBase + 0x00010000u);
            WriteBE32(ctx.r3.u32 + 14020, sysbufBase + 0x00010000u);
            KernelTraceHostOpF("HOST.825976D8.seed alloc w=%08X", sysbufBase+0x10);
        }
        DumpSchedState("825976D8.pre", ctx.r3.u32);
    }
    __imp__sub_825976D8(ctx, base);
    // Optional post-call dump of syscmd payload region (same guard)
    static const bool s_dump_after_builder = [](){ if (const char* v = std::getenv("MW05_PM4_DUMP_AFTER_BUILDER")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    if (s_dump_after_builder) {
        uint32_t post_sys = ReadBE32(pre_r3 + 13520);
        if ((post_sys & 0xFFFF0000u) == 0x00140000u) {
            DumpEAWindow("825976D8.post.sys", post_sys);
        }
        DumpSchedState("825976D8.post", pre_r3);
    }

}

void MW05Shim_sub_825A54F0(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_825A54F0.lr=%08llX r3=%08X r4=%08X r5=%08X",
                       (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    // Ensure r3 looks like a pointer; if not, seed from last-sched
    if (!(ctx.r3.u32 >= 0x1000 && ctx.r3.u32 < PPC_MEMORY_SIZE)) {
        uint32_t seed = s_lastSchedR3.load(std::memory_order_acquire);

        if (seed >= 0x1000 && seed < PPC_MEMORY_SIZE) {
            KernelTraceHostOpF("HOST.sub_825A54F0.force r3=%08X", seed);
            ctx.r3.u32 = seed;
        }
    }
    // Record scheduler sighting
    Mw05Trace_ConsiderSchedR3(ctx.r3.u32);
    // Nudge a plausible scheduler-flag bit if it appears unset to unlock PM4 path
    // Heuristic: flags at +0x1C, set bit0 if zero
    uint32_t flags_ea = ctx.r3.u32 + 0x1C;
    if (flags_ea >= 0x1000 && flags_ea + 4 <= PPC_MEMORY_SIZE) {

        if (auto* pf = reinterpret_cast<uint32_t*>(g_memory.Translate(flags_ea))) {
        #if defined(_MSC_VER)
            uint32_t le = _byteswap_ulong(*pf);
        #else
            uint32_t le = __builtin_bswap32(*pf);
        #endif
            if ((le & 0x1u) == 0u) {
                uint32_t nle = le | 0x1u;
            #if defined(_MSC_VER)
                *pf = _byteswap_ulong(nle);
            #else
                *pf = __builtin_bswap32(nle);
            #endif
                KernelTraceHostOpF("HOST.sub_825A54F0.flags.bump ea=%08X %08X->%08X", flags_ea, le, nle);
            }
        }
    }
    DumpEAWindow("825A54F0.r3.pre", ctx.r3.u32);
    DumpEAWindow("825A54F0.r3+40.pre", ctx.r3.u32 ? ctx.r3.u32 + 0x40 : 0);
    DumpSchedState("825A54F0.pre", ctx.r3.u32);
    __imp__sub_825A54F0(ctx, base);
    DumpEAWindow("825A54F0.r3.post", ctx.r3.u32);
    DumpEAWindow("825A54F0.r3+40.post", ctx.r3.u32 ? ctx.r3.u32 + 0x40 : 0);
    DumpSchedState("825A54F0.post", ctx.r3.u32);
    // Optionally attempt a PM4 build pass right after inner present-manager, within same guest context
    static const bool s_try_pm4_after_inner = [](){ if (const char* v = std::getenv("MW05_INNER_TRY_PM4")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    static const bool s_try_pm4_deep = [](){ if (const char* v = std::getenv("MW05_INNER_TRY_PM4_DEEP")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    if (s_try_pm4_after_inner) {
        uint32_t saved_r3 = ctx.r3.u32;
        // Force r3 to the last known scheduler context before calling the builder
        uint32_t seed = s_lastSchedR3.load(std::memory_order_acquire);
        if (seed >= 0x1000 && seed < PPC_MEMORY_SIZE) {
            ctx.r3.u32 = seed;
        }
        KernelTraceHostOpF("HOST.sub_825A54F0.post.try_825972B0 r3=%08X", ctx.r3.u32);
        // Call the PM4 builder through our shim so gating clears and fake alloc run
        MW05Shim_sub_825972B0(ctx, base);
        if (s_try_pm4_deep) {
            KernelTraceHostOpF("HOST.sub_825A54F0.post.try_deep r3=%08X", ctx.r3.u32);
            // Route through our deep shims to keep gating clears and allocator seeding
            MW05Shim_sub_82597650(ctx, base);
            MW05Shim_sub_825976D8(ctx, base);
            // Additional allocator/callback prep + gating clear
            MW05Shim_sub_825968B0(ctx, base);
            MW05Shim_sub_82596E40(ctx, base);
        }
        ctx.r3.u32 = saved_r3;
    }
}

// Main loop caller shim observed in logs (lr=82441D4C around TitleState calls)
void MW05Shim_sub_82441CF0(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_82441CF0.lr=%08llX r3=%08X r4=%08X r5=%08X",
                       (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    // Heuristic: r5 looks like a small control block observed at TitleState; capture as scheduler seed
    Mw05Trace_ConsiderSchedR3(ctx.r5.u32);
    DumpEAWindow("82441CF0.r5", ctx.r5.u32);
    DumpSchedState("82441CF0", ctx.r5.u32);

    static const bool s_loop_try_pm4_pre = [](){ if (const char* v = std::getenv("MW05_LOOP_TRY_PM4_PRE")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    static const bool s_loop_try_pm4 = [](){ if (const char* v = std::getenv("MW05_LOOP_TRY_PM4")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    static const bool s_loop_try_pm4_deep = [](){ if (const char* v = std::getenv("MW05_LOOP_TRY_PM4_DEEP")) return !(v[0]=='0' && v[1]=='\0'); return false; }();

    if (s_loop_try_pm4_pre && ctx.r5.u32 >= 0x1000 && ctx.r5.u32 < PPC_MEMORY_SIZE) {
        uint32_t saved_r3 = ctx.r3.u32;
        ctx.r3.u32 = ctx.r5.u32;
        KernelTraceHostOpF("HOST.sub_82441CF0.pre.try_825972B0 r3=%08X (from r5)", ctx.r3.u32);
        MW05Shim_sub_825972B0(ctx, base);
        if (s_loop_try_pm4_deep) {
            KernelTraceHostOpF("HOST.sub_82441CF0.pre.try_deep r3=%08X", ctx.r3.u32);
            MW05Shim_sub_82597650(ctx, base);
            MW05Shim_sub_825976D8(ctx, base);
            // Additional allocator/callback prep + gating clear
            MW05Shim_sub_825968B0(ctx, base);
            MW05Shim_sub_82596E40(ctx, base);
        }
        ctx.r3.u32 = saved_r3;
    }

    __imp__sub_82441CF0(ctx, base);

    if (s_loop_try_pm4 && ctx.r5.u32 >= 0x1000 && ctx.r5.u32 < PPC_MEMORY_SIZE) {
        uint32_t saved_r3 = ctx.r3.u32;
        ctx.r3.u32 = ctx.r5.u32;
        KernelTraceHostOpF("HOST.sub_82441CF0.post.try_825972B0 r3=%08X (from r5)", ctx.r3.u32);
        MW05Shim_sub_825972B0(ctx, base);
        if (s_loop_try_pm4_deep) {
            KernelTraceHostOpF("HOST.sub_82441CF0.post.try_deep r3=%08X", ctx.r3.u32);
            MW05Shim_sub_82597650(ctx, base);
            MW05Shim_sub_825976D8(ctx, base);
            // Additional allocator/callback prep + gating clear
            MW05Shim_sub_825968B0(ctx, base);
            MW05Shim_sub_82596E40(ctx, base);
        }
        ctx.r3.u32 = saved_r3;
    }
}


// Present wrapper shim: log + dump scheduler block, then forward
// CRITICAL FIX: The present function hangs after calling VdSwap
// Stub it completely - don't call the guest function at all
// Forward declaration for VdSwap (C++ linkage, not extern "C")
void VdSwap(uint32_t, uint32_t, uint32_t);

void MW05Shim_sub_82598A20(PPCContext& ctx, uint8_t* base) {
    static int call_count = 0;
    call_count++;
    if (call_count <= 10) {
        KernelTraceHostOpF("sub_82598A20.STUB count=%d r3=%08X r4=%08X r5=%08X",
                          call_count, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    }

    // Record scheduler/context state
    Mw05Trace_ConsiderSchedR3(ctx.r3.u32);

    // Call VdSwap to signal frame completion to the guest
    // This allows the guest rendering loop to continue
    VdSwap(0, 0, 0);

    if (call_count <= 10) {
        KernelTraceHostOpF("sub_82598A20.STUB.ret count=%d", call_count);
    }
}

SHIM(sub_825A6DF0)
SHIM(sub_825A65A8)
