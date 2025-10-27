// MW05 dynamic discovery shims for frequently used engine helpers.
extern void PM4_ScanLinear(uint32_t addr, uint32_t bytes);

// They log the caller (LR) and common arg regs, then tail-call the original.

#include <cpu/ppc_context.h>
#include <kernel/trace.h>
#include <ppc/ppc_context.h>

#include <kernel/memory.h>
#include <kernel/heap.h>
#include <atomic>

// Type definitions for kernel functions
#ifndef NTSTATUS
  using NTSTATUS = long;
  #define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
  #ifndef STATUS_USER_APC
    #define STATUS_USER_APC ((NTSTATUS)0x000000C0L)
  #endif
  #define STATUS_ALERTED ((NTSTATUS)0x00000101L)
#endif
#ifndef BOOLEAN
  using BOOLEAN = unsigned char;
#endif
#ifndef _KPROCESSOR_MODE_DEFINED
  using KPROCESSOR_MODE = unsigned char;
  #define _KPROCESSOR_MODE_DEFINED
#endif

// Forward declarations for diagnostic draw testing
struct GuestDevice;  // Forward declaration


// Forward declarations for GPU writeback access functions
extern "C"
{
    // Forward declaration for KeDelayExecutionThread
    NTSTATUS KeDelayExecutionThread(KPROCESSOR_MODE Mode, BOOLEAN Alertable, PLARGE_INTEGER IntervalGuest);
    
    uint32_t GetRbWriteBackPtr();
    uint32_t GetVdSystemCommandBufferGpuIdAddr();
    uint32_t GetRbLen();

    void Mw05HostDraw(uint32_t primitiveType, uint32_t startVertex, uint32_t primitiveCount);
    void Mw05DebugKickClear();
    GuestDevice* Mw05GetGuestDevicePtr();
}

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


static inline void WriteBE16(uint32_t ea, uint16_t value) {
    if (!ea) return;
    if (auto* p = reinterpret_cast<uint16_t*>(g_memory.Translate(ea))) {
    #if defined(_MSC_VER)
        *p = _byteswap_ushort(value);
    #else
        *p = __builtin_bswap16(value);
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
        // DEBUG: Always log scheduler context registration (first 10 times)
        static std::atomic<int> s_reg_log_count{0};
        if (s_reg_log_count.fetch_add(1, std::memory_order_relaxed) < 10) {
            fprintf(stderr, "[SCHED-REG] RegisterSchedulerContext base=%08X count=%d\n", baseEA, count + 1);
            fflush(stderr);
        }
    }
}

// Process commands in the MW05 scheduler queue
static inline void ProcessMW05Queue(uint32_t baseEA) {
    if (!baseEA) return;

    uint32_t qhead = ReadBE32(baseEA + 0x10);
    uint32_t qtail = ReadBE32(baseEA + 0x14);

    // DEBUG: Check VBlank callback function pointer
    // According to decompiled sub_825979A8, the VBlank callback is at a2[3899]
    // where a2 is the context pointer (baseEA)
    // Offset: 3899 * 4 = 15596 = 0x3CEC
    uint32_t vblank_cb_ptr = ReadBE32(baseEA + 0x3CEC);

    static std::atomic<int> s_queue_log_count{0};
    static std::atomic<uint32_t> s_last_vblank_cb{0};
    int log_count = s_queue_log_count.fetch_add(1, std::memory_order_relaxed);
    uint32_t last_cb = s_last_vblank_cb.load(std::memory_order_relaxed);

    if (log_count < 20 || vblank_cb_ptr != last_cb) {
        fprintf(stderr, "[QUEUE-DEBUG] ProcessMW05Queue #%d: base=%08X qhead=%08X qtail=%08X vblank_cb=%08X\n",
                log_count, baseEA, qhead, qtail, vblank_cb_ptr);

        if (vblank_cb_ptr == 0) {
            fprintf(stderr, "[QUEUE-DEBUG]   VBlank callback NOT SET (a2[3899]=0) - game won't process queue!\n");
        } else {
            fprintf(stderr, "[QUEUE-DEBUG]   VBlank callback SET to 0x%08X\n", vblank_cb_ptr);
        }

        s_last_vblank_cb.store(vblank_cb_ptr, std::memory_order_relaxed);
        fflush(stderr);
    }

    // If queue is empty, nothing to do
    if (qtail == 0 || qhead == qtail) {
        if (log_count < 20) {
            fprintf(stderr, "[QUEUE-DEBUG] Queue empty or not initialized (qtail=%08X qhead=%08X)\n", qtail, qhead);
            fflush(stderr);
        }
        return;
    }

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

// Track last-seen scheduler/context pointer to optionally nudge present-wrapper once
static std::atomic<uint32_t> s_lastSchedR3{0};
static std::atomic<bool> s_schedR3Logged{false};
static std::atomic<uint32_t> s_schedR3Seen{0};

static inline void MaybeLogSchedCapture(uint32_t r3) {
    if (r3 >= 0x1000 && r3 < PPC_MEMORY_SIZE) {
        if (!s_schedR3Logged.exchange(true, std::memory_order_acq_rel)) {
            KernelTraceHostOpF("HOST.SchedR3.Captured r3=%08X", r3);
        }
    }
}

extern "C" 
{
    uint32_t VdGetSystemCommandBuffer(void* outCmdBufPtr, void* outValue);

    void Mw05ProcessSchedulerQueue(uint32_t baseEA) {
        ProcessMW05Queue(baseEA);
    }

    uint32_t Mw05Trace_SchedR3SeenCount() { return s_schedR3Seen.load(std::memory_order_acquire); }
    uint32_t Mw05Trace_LastSchedR3() { return s_lastSchedR3.load(std::memory_order_acquire); }
    
    void Mw05Trace_SeedSchedR3_NoLog(uint32_t r3) 
    {
        if (r3 >= 0x1000 && r3 < PPC_MEMORY_SIZE) 
        {
            s_lastSchedR3.store(r3, std::memory_order_release);
            s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel);
        }
    }

    void Mw05Trace_ConsiderSchedR3(uint32_t r3) 
    {
        if (r3 >= 0x1000 && r3 < PPC_MEMORY_SIZE) 
        {
            MaybeLogSchedCapture(r3);
            s_lastSchedR3.store(r3, std::memory_order_release);
            s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel);
        }
    }

    // Forward decls of the recompiled originals
    void __imp__sub_82595FC8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825972B0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A54F0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825986F8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825987E0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825988B0(PPCContext& ctx, uint8_t* base);
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

    void __imp__sub_825A97B8(PPCContext& ctx, uint8_t* base);

    void __imp__sub_82441CF0(PPCContext& ctx, uint8_t* base);

    // NOTE: sub_8262D998 wrapper is now in mw05_trace_threads.cpp (lines 699-731)
    // It saves/restores qword_828F1F98 to prevent corruption
    // NOTE: sub_82630378 wrapper is also in mw05_trace_threads.cpp - wait function wrapper
    // NOTE: sub_82598A20 wrapper is in mw05_trace_shims.cpp - rendering function that calls VdSwap
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
// sub_825A74B8 has a custom implementation with SEH exception handling below (line 473)

// Forward declarations removed - all functions now use PPC_FUNC_IMPL pattern


SHIM(sub_825A7F10)
SHIM(sub_825A7F88)
SHIM(sub_825A8040)

// Candidate MW05 render/viewport/draw-adjacent helpers to log-and-forward
SHIM(sub_825986F8)
SHIM(sub_825987E0)
SHIM(sub_825988B0)

// Shim for sub_825A7A40 - viewport/aspect ratio calculation function
// CRITICAL FIX: This function has a divide-by-zero bug when viewport dimensions are invalid
// The game sometimes passes all-zero viewport dimensions, causing crash at 0x825A7AEC (divwu r30, r9, r10)
// We add a safety check to prevent the crash
// Convert MW05Shim_sub_825A7A40 to PPC_FUNC_IMPL pattern
PPC_FUNC_IMPL(__imp__sub_825A7A40);
PPC_FUNC(sub_825A7A40) {
    // Read parameters
    uint32_t r6 = ctx.r6.u32;  // input viewport struct pointer
    uint32_t r7 = ctx.r7.u32;  // output viewport struct pointer

    // Read input viewport dimensions
    uint32_t* input = reinterpret_cast<uint32_t*>(g_memory.Translate(r6));
    if (!input) {
        // Invalid pointer - just return
        return;
    }

    // Read viewport bounds (big-endian)
    uint32_t v16 = ReadBE32(r6 + 0);   // x_min
    uint32_t v17 = ReadBE32(r6 + 4);   // y_min
    uint32_t v18 = ReadBE32(r6 + 8);   // x_max
    uint32_t v19 = ReadBE32(r6 + 12);  // y_max

    // Calculate width and height
    uint32_t width = v18 - v16;
    uint32_t height = v19 - v17;

    // CRITICAL FIX: Check for divide-by-zero condition
    static std::atomic<uint64_t> s_invalidCount{0};
    if (width == 0 || height == 0) {
        uint64_t count = s_invalidCount.fetch_add(1);

        // Log first 5 invalid calls with full details
        if (count < 5) {
            fprintf(stderr, "[sub_825A7A40] INVALID VIEWPORT #%llu: input bounds [%u,%u,%u,%u] -> size (%u x %u)\n",
                    count, v16, v17, v18, v19, width, height);
            fprintf(stderr, "[sub_825A7A40]   r6=%08X r7=%08X lr=%08llX\n", r6, r7, ctx.lr);
            fflush(stderr);
        }

        // Invalid viewport dimensions - use default 1280x720
        // Set default viewport: 0,0 to 1280,720
        WriteBE32(r7 + 0, 0);      // x_min = 0
        WriteBE32(r7 + 4, 0);      // y_min = 0
        WriteBE32(r7 + 8, 1280);   // x_max = 1280
        WriteBE32(r7 + 12, 720);   // y_max = 720
        WriteBE32(r7 + 16, ReadBE32(r6 + 16));  // copy field 4
        WriteBE32(r7 + 20, ReadBE32(r6 + 20));  // copy field 5
        return;
    }

    // Valid dimensions - call original function
    SetPPCContext(ctx);

    __imp__sub_825A7A40(ctx, base);
}

// CRITICAL FIX: sub_825A7B78 (scaler command buffer / viewport setup function)
// This function calls RtlFillMemoryUlong with corrupted parameters due to a recompiler bug.
// The recompiled code passes:
//   r3 = destination - 4 (wrong offset)
//   r4 = garbage address instead of pattern
//   r5 = 0xFFE8001C (4GB as unsigned, -1.5MB as signed) instead of 800 bytes
//
// This causes an infinite loop where the heap protection blocks billions of writes,
// consuming 100% CPU and preventing the game from progressing to the rendering stage.
//
// Solution: Completely skip this function. It's a scaler command buffer initialization
// function that's not critical for basic rendering. The game can work without it.
PPC_FUNC_IMPL(__imp__sub_825A7B78);
PPC_FUNC(sub_825A7B78) {
    // CRITICAL: Return immediately to avoid the buggy RtlFillMemoryUlong call
    // This function is called during video initialization but is not essential.
    // Skipping it allows the game to progress past the infinite loop.

    // Log once to confirm the shim is being used
    static std::atomic<bool> s_logged{false};
    if (!s_logged.exchange(true, std::memory_order_relaxed)) {
        KernelTraceHostOpF("HOST.sub_825A7B78.SKIPPED to avoid buggy RtlFillMemoryUlong infinite loop");
        KernelTraceHostOpF("HOST.sub_825A7B78.This function initializes scaler command buffer - not critical for rendering");
    }

    // Return success (r3 = 0)
    ctx.r3.u32 = 0;

    // DO NOT call __imp__sub_825A7B78 - it contains the buggy code!
}

// Convert MW05Shim_sub_825A74B8 to PPC_FUNC_IMPL pattern
PPC_FUNC_IMPL(__imp__sub_825A74B8);
PPC_FUNC(sub_825A74B8) {
    // sub_825A74B8 is another viewport-related function
    KernelTraceHostOpF("HOST.sub_825A74B8.enter r3=%08X r4=%08X r5=%08X",
                       ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);

    // Call the original function with SEH exception handling for divide-by-zero
    __try {
        SetPPCContext(ctx);

        __imp__sub_825A74B8(ctx, base);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KernelTraceHostOpF("HOST.sub_825A74B8.exception caught code=%08X", GetExceptionCode());
        // Return safely
        ctx.r3.u32 = 0;
    }
}

SHIM(sub_825A7DE8)
SHIM(sub_825A7E60)

// CRITICAL FIX: The game doesn't call VdQueryVideoMode, so viewport data is never initialized
// We need to initialize the viewport structure at r3 + 0x364C (offset 13900) which is passed via r6
PPC_FUNC_IMPL(__imp__sub_825A7EA0);
PPC_FUNC(sub_825A7EA0) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    uint32_t r3 = ctx.r3.u32;  // a1 - object pointer
    uint32_t r4 = ctx.r4.u32;  // a2 - width parameter
    uint32_t r5 = ctx.r5.u32;  // a3 - height parameter
    uint32_t r6 = ctx.r6.u32;  // a4 - viewport bounds pointer (set by caller)

    // Log first few calls to understand what's happening
    if (count < 5) {
        fprintf(stderr, "[sub_825A7EA0] CALL #%llu: r3=%08X r4=%u r5=%u r6=%08X lr=%08llX\n",
                count, r3, r4, r5, r6, ctx.lr);
        fflush(stderr);

        // Check if r6 points to valid memory
        if (GuestOffsetInRange(r6, 24)) {
            uint8_t* r6_ptr = (uint8_t*)g_memory.Translate(r6);
            uint32_t v0 = ReadBE32((uintptr_t)(r6_ptr + 0));
            uint32_t v1 = ReadBE32((uintptr_t)(r6_ptr + 4));
            uint32_t v2 = ReadBE32((uintptr_t)(r6_ptr + 8));
            uint32_t v3 = ReadBE32((uintptr_t)(r6_ptr + 12));
            fprintf(stderr, "[sub_825A7EA0]   r6 points to: [%u,%u,%u,%u]\n", v0, v1, v2, v3);
            fflush(stderr);
        } else {
            fprintf(stderr, "[sub_825A7EA0]   r6 is INVALID!\n");
            fflush(stderr);
        }
    }

    // CRITICAL FIX: Initialize viewport data at r6 if it's all zeros
    // The game doesn't call VdQueryVideoMode, so the viewport structure is never initialized
    if (r4 == 0 && r5 == 0 && GuestOffsetInRange(r6, 24)) {
        uint8_t* r6_ptr = (uint8_t*)g_memory.Translate(r6);
        uint32_t v0 = ReadBE32((uintptr_t)(r6_ptr + 0));
        uint32_t v1 = ReadBE32((uintptr_t)(r6_ptr + 4));
        uint32_t v2 = ReadBE32((uintptr_t)(r6_ptr + 8));
        uint32_t v3 = ReadBE32((uintptr_t)(r6_ptr + 12));

        // Check if viewport is uninitialized (all zeros)
        if (v0 == 0 && v1 == 0 && v2 == 0 && v3 == 0) {
            fprintf(stderr, "[sub_825A7EA0] FORCE-INIT: Viewport at r6=%08X is zero, initializing to [0,0,1280,720]\n", r6);
            fflush(stderr);

            // Initialize viewport bounds: [x_min=0, y_min=0, x_max=1280, y_max=720]
            WriteBE32((uintptr_t)(r6_ptr + 0), 0);      // x_min
            WriteBE32((uintptr_t)(r6_ptr + 4), 0);      // y_min
            WriteBE32((uintptr_t)(r6_ptr + 8), 1280);   // x_max
            WriteBE32((uintptr_t)(r6_ptr + 12), 720);   // y_max

            fprintf(stderr, "[sub_825A7EA0] FORCE-INIT: Viewport initialized successfully\n");
            fflush(stderr);
        }
    }

    // Call the original recompiled function
    __imp__sub_825A7EA0(ctx, base);
}

// Scheduler/notify-adjacent shims (log, dump key pointers, and forward)
// Convert MW05Shim_sub_8262F248 to PPC_FUNC_IMPL pattern
PPC_FUNC_IMPL(__imp__sub_8262F248);
PPC_FUNC(sub_8262F248) {
    KernelTraceHostOpF("sub_8262F248.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    DumpEAWindow("8262F248.r3", ctx.r3.u32);
    DumpEAWindow("8262F248.r4", ctx.r4.u32);
    DumpEAWindow("8262F248.r5", ctx.r5.u32);
    SetPPCContext(ctx);

    __imp__sub_8262F248(ctx, base);
}

PPC_FUNC_IMPL(__imp__sub_8262F2A0);
PPC_FUNC(sub_8262F2A0)
{
    // RECOMPILER BUG FIX: This function has a bug in the auto-generated code
    // The sleep loop doesn't exit when Alertable=FALSE because the recompiler
    // generates incorrect code for the loop condition check.
    //
    // Original assembly (correct):
    //   .text:8262F2EC    clrlwi    r31, r29, 24    # r31 = r29 & 0xFF (extract Alertable)
    //   .text:8262F2F0 loc_8262F2F0:                 # Loop start
    //   .text:8262F2FC    bl        KeDelayExecutionThread
    //   .text:8262F300    cmplwi    cr6, r31, 0     # Compare r31 (Alertable) with 0
    //   .text:8262F304    beq       cr6, loc_8262F310  # If r31==0, EXIT LOOP
    //   .text:8262F308    cmpwi     cr6, r3, 0x101  # Compare return with STATUS_ALERTED
    //   .text:8262F30C    beq       cr6, loc_8262F2F0  # If return==STATUS_ALERTED, loop back
    //
    // IDA decompilation (correct):
    //   v10 = a2;  // v10 = Alertable
    //   do
    //     v11 = KeDelayExecutionThread(UserMode, a2, v9);
    //   while ( v10 && v11 == 257 );  // Loop while Alertable AND return == STATUS_ALERTED
    //
    // The auto-generated code has a bug that prevents the loop from exiting.
    // This replacement implements the correct logic.

    KernelTraceHostOpF("sub_8262F2A0.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);

    // Extract parameters
    int32_t timeout_ms = static_cast<int32_t>(ctx.r3.s32);

    // CRITICAL FIX (2025-10-27): Restore alertable parameter to allow APC delivery
    // The game uses async file I/O with APC callbacks. Forcing alertable=FALSE breaks
    // APC delivery, causing the game to hang waiting for file loads to complete.
    // The original fix (forcing alertable=FALSE) was to prevent stuck threads, but it
    // broke file I/O. The real solution is to properly implement APC delivery in alertable waits.
    BOOLEAN alertable = static_cast<BOOLEAN>(ctx.r4.u32 & 0xFF);  // RESTORED - was forced to FALSE

    // Prepare interval structure on stack
    int64_t interval_value;
    PLARGE_INTEGER interval_ptr;

    if (timeout_ms == -1)
    {
        // Infinite timeout
        interval_value = static_cast<int64_t>(0x8000000000000000ULL);
        interval_ptr = reinterpret_cast<PLARGE_INTEGER>(&interval_value);
    }
    else
    {
        // Convert milliseconds to 100ns units (negative = relative)
        interval_value = static_cast<int64_t>(timeout_ms) * -10000LL;
        interval_ptr = reinterpret_cast<PLARGE_INTEGER>(&interval_value);
    }

    // Sleep loop (FIXED VERSION)
    NTSTATUS result;
    do
    {
        result = KeDelayExecutionThread(static_cast<KPROCESSOR_MODE>(1), alertable, interval_ptr);  // WaitMode=1 (UserMode)
    }
    while (alertable && result == 0x101);  // Loop while Alertable AND return == STATUS_ALERTED (257)

    // Return value logic
    if (result == 0xC0)  // STATUS_USER_APC (192)
    {
        ctx.r3.u32 = 0xC0;
    }
    else
    {
        ctx.r3.u32 = 0;
    }

    // Debug logging (only log first few calls to avoid spam)
    static std::atomic<int> call_count{0};
    int count = call_count.fetch_add(1, std::memory_order_relaxed);
    if (count < 10)
    {
        fprintf(stderr, "[SLEEP-FIX] sub_8262F2A0: timeout_ms=%d alertable=%u result=0x%X return=0x%X\n",
                timeout_ms, static_cast<unsigned>(alertable), static_cast<unsigned>(result), ctx.r3.u32);
        fflush(stderr);
    }
}
// Convert MW05Shim_sub_823BC638 to PPC_FUNC_IMPL pattern
PPC_FUNC_IMPL(__imp__sub_823BC638);
PPC_FUNC(sub_823BC638) {
    KernelTraceHostOpF("sub_823BC638.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    DumpEAWindow("823BC638.r3", ctx.r3.u32);
    DumpEAWindow("823BC638.r4", ctx.r4.u32);
    DumpEAWindow("823BC638.r5", ctx.r5.u32);
    SetPPCContext(ctx);

    __imp__sub_823BC638(ctx, base);
}
// Convert MW05Shim_sub_82812E20 to PPC_FUNC_IMPL pattern
PPC_FUNC_IMPL(__imp__sub_82812E20);
PPC_FUNC(sub_82812E20) {
    KernelTraceHostOpF("sub_82812E20.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    if (ctx.r3.u32 >= 0x1000 && ctx.r3.u32 < PPC_MEMORY_SIZE) { MaybeLogSchedCapture(ctx.r3.u32); s_lastSchedR3.store(ctx.r3.u32, std::memory_order_release); s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel); }
    DumpEAWindow("82812E20.r3", ctx.r3.u32);
    DumpEAWindow("82812E20.r4", ctx.r4.u32);
    DumpEAWindow("82812E20.r5", ctx.r5.u32);
    DumpSchedState("82812E20", ctx.r3.u32);
    SetPPCContext(ctx);

    __imp__sub_82812E20(ctx, base);
}

// Convert MW05Shim_sub_82596978 to PPC_FUNC_IMPL pattern
PPC_FUNC_IMPL(__imp__sub_82596978);
PPC_FUNC(sub_82596978) {
    KernelTraceHostOpF("sub_82596978.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    DumpEAWindow("82596978.r3", ctx.r3.u32);
    DumpEAWindow("82596978.r4", ctx.r4.u32);
    SetPPCContext(ctx);

    __imp__sub_82596978(ctx, base);
}

// Convert MW05Shim_sub_825979A8 to PPC_FUNC_IMPL pattern
PPC_FUNC_IMPL(__imp__sub_825979A8);
PPC_FUNC(sub_825979A8) {
    // DEBUG: Log first 10 calls to see if callback is being invoked
    static std::atomic<int> s_gfx_call_count{0};
    int gfx_count = s_gfx_call_count.fetch_add(1, std::memory_order_relaxed);
    if (gfx_count < 10) {
        fprintf(stderr, "[GFX-CB] Call #%d: source=%u ctx=%08X\n", gfx_count, ctx.r3.u32, ctx.r4.u32);
        fflush(stderr);
    }

    static const bool s_trace_gfx_callback = [](){
        if (const char* v = std::getenv("MW05_TRACE_GFX_CALLBACK")) return !(v[0]=='0' && v[1]=='\0');
        return false;
    }();

    if (s_trace_gfx_callback) {
        KernelTraceHostOpF("sub_825979A8.lr=%08llX r3=%08X r4=%08X r5=%08X",
                           (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    }

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
            if (s_trace_gfx_callback) {
                KernelTraceHostOp("HOST.sub_825979A8.swap@entry r3<->r4");
            }
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
            if (s_trace_gfx_callback) {
                KernelTraceHostOpF("HOST.sub_825979A8.force r3=%08X", seed);
            }
            ctx.r3.u32 = seed;
        }
    }

    // Record scheduler/context sighting so host gates can proceed
    Mw05Trace_ConsiderSchedR3(ctx.r4.u32);

    // PERFORMANCE FIX: Disable expensive debug dumps (called 36,000+ times per 5 minutes!)
    // Only dump on first few calls for debugging
    static std::atomic<int> s_dump_count{0};
    if (s_dump_count.fetch_add(1, std::memory_order_relaxed) < 5) {
        DumpEAWindow("825979A8.r3", ctx.r3.u32);
        DumpEAWindow("825979A8.r4", ctx.r4.u32);
        DumpSchedState("825979A8", ctx.r4.u32);
    }

    // Track the present function pointer at a2[3899] (offset 0x3CEC)
    // This pointer is checked by the graphics callback to decide whether to call the present function
    // If it's NULL, the callback skips the present function call
    //
    // CRITICAL FIX: The memory system stores values in LITTLE-ENDIAN format!
    // PPC_STORE_U32 byte-swaps before writing, so the bytes in memory are little-endian.
    // We must read the value directly WITHOUT byte-swapping to get the correct value!
    static uint32_t s_last_present_fp = 0xFFFFFFFF;
    static uint32_t s_present_fp_check_count = 0;
    const uint32_t ctx_ea = ctx.r4.u32;
    const uint32_t present_fp_ea = ctx_ea ? (ctx_ea + 0x3CECu) : 0u;
    const uint32_t source = ctx.r3.u32;
    if (present_fp_ea && source == 0) {  // Only check on source=0 (VBlank)
        // Read the function pointer directly (memory is in little-endian format)
        uint32_t present_fp = 0;
        if (auto* p = reinterpret_cast<const uint32_t*>(g_memory.Translate(present_fp_ea))) {
            present_fp = *p;  // Read little-endian value directly (no byte-swap!)
        }

        // Log the function pointer value on every source=0 call (first 20 calls)
        if (s_present_fp_check_count < 20) {
            fprintf(stderr, "[GFX-CB-FP-CHECK] source=0 call #%u: present_fp=%08X (ctx=%08X addr=%08X)\n",
                    s_present_fp_check_count, present_fp, ctx_ea, present_fp_ea);
            fflush(stderr);
        }
        s_present_fp_check_count++;

        // Log when the function pointer changes
        if (present_fp != s_last_present_fp) {
            fprintf(stderr, "[GFX-CB-FP] Present function pointer at ctx+0x3CEC changed: was=%08X now=%08X (ctx=%08X addr=%08X)\n",
                    s_last_present_fp, present_fp, ctx_ea, present_fp_ea);
            fflush(stderr);
            s_last_present_fp = present_fp;
        }

        // CRITICAL FIX: The game sets the present function pointer, but we need to check if it's valid
        // The present function should be at 0x82598A20 (from investigation)
        // If the game set a different address, log it and optionally override it
        static const bool s_set_present_cb = [](){ if (const char* v = std::getenv("MW05_SET_PRESENT_CB")) return !(v[0]=='0' && v[1]=='\0'); return true; }();
        const uint32_t kPresentFuncEA = 0x82598A20u;  // Known-good present function address

        if (s_set_present_cb) {
            // CRITICAL FIX: The game writes the present function pointer in the WRONG format!
            // The game writes 0x82598A20 to memory (little-endian bytes: 20 8A 59 82),
            // but the GUEST callback reads it with PPC_LOAD_U32 (which byte-swaps),
            // so it gets __builtin_bswap32(0x82598A20) = 0x208A5982 (WRONG!)
            //
            // We need to write 0x208A5982 to memory (little-endian bytes: 82 59 8A 20),
            // so that PPC_LOAD_U32 reads: __builtin_bswap32(0x208A5982) = 0x82598A20 (CORRECT!)
            //
            // So we ALWAYS overwrite the value with the byte-swapped version.
            if (auto* p = reinterpret_cast<uint32_t*>(g_memory.Translate(present_fp_ea))) {
                *p = __builtin_bswap32(kPresentFuncEA);  // Write byte-swapped value
            }

            if (present_fp == 0u) {
                fprintf(stderr, "[GFX-CB-FP] Forced present function pointer (was NULL): ptr@%08X=%08X (stored as %08X)\n",
                        present_fp_ea, kPresentFuncEA, __builtin_bswap32(kPresentFuncEA));
                fflush(stderr);
            } else if (present_fp != __builtin_bswap32(kPresentFuncEA)) {
                // Game set a different value - log it and override it
                fprintf(stderr, "[GFX-CB-FP] Game set present function pointer to %08X (expected %08X) - OVERRIDING to %08X\n",
                        present_fp, __builtin_bswap32(kPresentFuncEA), __builtin_bswap32(kPresentFuncEA));
                fflush(stderr);
            }
        }
    }

    // Register this scheduler context (r4 holds context/scheduler base)
    RegisterSchedulerContext(ctx.r4.u32);

    // CRITICAL: Process any pending commands in ALL MW05 scheduler queues
    // MW05 uses multiple scheduler contexts, so we need to process all of them
    uint32_t count = g_schedulerContextCount.load(std::memory_order_acquire);
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t schedEA = g_schedulerContexts[i].load(std::memory_order_relaxed);
        if (schedEA) {
            ProcessMW05Queue(schedEA);
        }
    }

    // Force expected entry state: r30 must be zero for the source==0/1 paths to run
    // If non-zero, the guest ISR takes an early path and skips the present scheduler logic.
    ctx.r30.u32 = 0;

    // The ISR's source==0 path uses r31 as the base pointer to the "inner" structure.
    // IMPORTANT: The field at ctx+0x2894 is stored using PPC_STORE_U32, which already byte-swaps
    // to big-endian format in memory. When we read it here, we need to read it WITHOUT byte-swapping
    // because the value in memory is already in the correct (little-endian) format for the host.
    if (looks_ptr(ctx.r4.u32)) {
        uint32_t inner_raw = 0;
        if (auto* p = reinterpret_cast<const uint32_t*>(g_memory.Translate(ctx.r4.u32 + 0x2894))) {
            inner_raw = *p; // NO byte-swap - PPC_STORE_U32 already did it
        }
        if (looks_ptr(inner_raw)) {
            ctx.r31.u32 = inner_raw;
        }
    }

    // Just call the original guest ISR - no present function workaround
    // The present function hangs when called from within the vblank ISR
    // DISABLED: This debug logging was causing massive performance issues (called thousands of times per second)
    // fprintf(stderr, "[GFX-SHIM] 825979A8 entry r3(source)=%u r4(ctx)=%08X r30=%08X r31=%08X\n", ctx.r3.u32, ctx.r4.u32, ctx.r30.u32, ctx.r31.u32);

    // DISABLED: CRITICAL DEBUG logging - was slowing down rendering
    // if (ctx.r31.u32 != 0 && ctx.r31.u32 >= 0x1000 && ctx.r31.u32 < 0x90000000) {
    //     uint32_t r10_value = 0;
    //     if (auto* p = reinterpret_cast<const be<uint32_t>*>(g_memory.Translate(ctx.r31.u32 + 10388))) {
    //         r10_value = p->get();
    //         fprintf(stderr, "[GFX-SHIM-DEBUG] r31+10388 (will be r10) = 0x%08X\n", r10_value);
    //         ...
    //     }
    // }
    // fflush(stderr);

    SetPPCContext(ctx);

    // CRITICAL DEBUG: Log what the GUEST callback will see when it reads the flag and present function pointer
    // This helps us understand why the callback isn't calling the present function
    static uint32_t s_guest_debug_count = 0;
    if (source == 0 && s_guest_debug_count < 20) {
        // Read the flag at 0x7FC86544 (same way the GUEST code does with PPC_LOAD_U32)
        const uint32_t flag_ea = 0x7FC86544;
        uint32_t flag_value_guest = 0;
        if (auto* p = reinterpret_cast<const uint32_t*>(g_memory.Translate(flag_ea))) {
            flag_value_guest = __builtin_bswap32(*p);  // PPC_LOAD_U32 byte-swaps
        }

        // Read the present function pointer at ctx+15596 (same way the GUEST code does with PPC_LOAD_U32)
        const uint32_t present_fp_ea_guest = ctx_ea + 15596;
        uint32_t present_fp_guest = 0;
        if (auto* p = reinterpret_cast<const uint32_t*>(g_memory.Translate(present_fp_ea_guest))) {
            present_fp_guest = __builtin_bswap32(*p);  // PPC_LOAD_U32 byte-swaps
        }

        fprintf(stderr, "[GFX-CB-GUEST] VBlank call #%u: source=%u ctx=%08X flag=%08X (bit0=%u) present_fp=%08X\n",
                s_guest_debug_count, source, ctx_ea, flag_value_guest, (flag_value_guest & 1), present_fp_guest);
        fflush(stderr);
        s_guest_debug_count++;
    }

    __imp__sub_825979A8(ctx, base);
}


// Convert MW05Shim_sub_825A97B8 to PPC_FUNC_IMPL pattern
PPC_FUNC_IMPL(__imp__sub_825A97B8);
PPC_FUNC(sub_825A97B8) {
    KernelTraceHostOpF("sub_825A97B8.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    DumpEAWindow("825A97B8.r3", ctx.r3.u32);
    SetPPCContext(ctx);

    __imp__sub_825A97B8(ctx, base);
}

// Shim for sub_82880FA0 - logs calls to the function that calls sub_82885A70
// Convert MW05Shim_sub_82880FA0 to PPC_FUNC_IMPL pattern
PPC_FUNC_IMPL(__imp__sub_82880FA0);
PPC_FUNC(sub_82880FA0) {
    KernelTraceHostOpF("sub_82880FA0.lr=%08llX r3=%08X r4=%08X r5=%08X",
                       (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    extern void sub_82880FA0(PPCContext& ctx, uint8_t* base);
    __imp__sub_82880FA0(ctx, base);
    KernelTraceHostOpF("sub_82880FA0.ret r3=%08X", ctx.r3.u32);
}

// Shim for sub_82885A70 - logs the condition check for thread creation
// Convert MW05Shim_sub_82885A70 to PPC_FUNC_IMPL pattern
PPC_FUNC_IMPL(__imp__sub_82885A70);
PPC_FUNC(sub_82885A70) {
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
    __imp__sub_82885A70(ctx, base);
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
// CRITICAL FIX: sub_82595FC8 is a BUFFER ALLOCATION function, not an array access!
// It checks if there's enough space in the PM4 command buffer and returns a pointer.
// The previous implementation was WRONG - it was treating it as array access.
// Now we call the original recompiled function to get the correct behavior.
// Convert MW05Shim_sub_82595FC8 to PPC_FUNC_IMPL pattern
PPC_FUNC_IMPL(__imp__sub_82595FC8);
PPC_FUNC(sub_82595FC8) {
    static int call_count = 0;
    call_count++;

    uint32_t baseAddr = ctx.r3.u32;
    uint32_t index = ctx.r4.u32;

    // Capture scheduler context
    if (baseAddr >= 0x1000 && baseAddr < PPC_MEMORY_SIZE) {
        MaybeLogSchedCapture(baseAddr);
        s_lastSchedR3.store(baseAddr, std::memory_order_release);
        s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel);
    }

    // Call the original recompiled function to get the correct buffer pointer
    SetPPCContext(ctx);

    __imp__sub_82595FC8(ctx, base);

    // Log the result
    if (call_count <= 10) {
        KernelTraceHostOpF("sub_82595FC8 count=%d base=%08X index=%08X ret=%08X",
                          call_count, baseAddr, index, ctx.r3.u32);
    }
}

// Convert MW05Shim_sub_825972B0 to PPC_FUNC_IMPL pattern
PPC_FUNC_IMPL(__imp__sub_825972B0);
PPC_FUNC(sub_825972B0) {
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
    SetPPCContext(ctx);

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
            __imp__sub_825972B0(ctx, base);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            KernelTraceHostOpF("HOST.BuilderKick.forward.EXCEPTION code=%08X", (unsigned)GetExceptionCode());
        }
    #else
        try {
            __imp__sub_825972B0(ctx, base);
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

// ---- Present function trace shim -------------------------------------------------
// Convert MW05Shim_sub_82598A20 to PPC_FUNC_IMPL pattern
PPC_FUNC_IMPL(__imp__sub_82598A20);
PPC_FUNC(sub_82598A20) {
    // Call count tracking
    static std::atomic<uint64_t> s_call_count{0};
    const uint64_t count = s_call_count.fetch_add(1);

    // Identify the caller based on link register (lr)
    const char* caller_name = "UNKNOWN";
    switch ((uint32_t)ctx.lr) {
        case 0x82439B00: caller_name = "sub_82439AF0"; break;  // Simple wrapper
        case 0x82458B6C: caller_name = "sub_82458B20"; break;  // Setup function
        case 0x82599138: caller_name = "sub_82599010"; break;  // Complex setup
        case 0x825AA9FC: caller_name = "sub_825AA970"; break;  // Thread #8 worker loop
        case 0x82597AB4: caller_name = "sub_82597A00"; break;  // VBlank callback path
    }

    // Lightweight entry trace. Keep stderr + trace consistent with other shims.
    if (count < 20 || (count % 100) == 0) {
        fprintf(stderr, "[PRESENT-CB] sub_82598A20 called! count=%llu caller=%s r3=%08X r4=%08X r5=%08X lr=%08X\n",
                count, caller_name, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, (uint32_t)ctx.lr);
        fflush(stderr);
    }

    KernelTraceHostOpF("sub_82598A20.PRESENT enter count=%llu caller=%s lr=%08llX r3=%08X r4=%08X r5=%08X r31=%08X",
                       count, caller_name, (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r31.u32);

    // Optional stub mode to force progress: call VdSwap directly and return.
    static const bool s_present_stub = [](){
        if (const char* v = std::getenv("MW05_PRESENT_STUB")) return !(v[0]=='0' && v[1]=='\0');
        return false; // default OFF: trace and forward to guest present
    }();
    if (s_present_stub) {
        static int stub_count = 0;
        if (stub_count < 8) KernelTraceHostOpF("sub_82598A20.STUB calling VdSwap() (count=%d)", stub_count);
        ++stub_count;
        extern void VdSwap(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
        VdSwap(0, 0, 0, 0, 0, 0, 0, 0);
        return;
    }

    // Probe likely gating fields observed in research notes (context anchored at r31)
    auto looks_ptr = [](uint32_t ea){ return ea >= 0x1000 && ea < PPC_MEMORY_SIZE; };
    if (looks_ptr(ctx.r31.u32)) {
        uint32_t v5030 = ReadBE32(ctx.r31.u32 + 0x5030);
        uint32_t v5034 = ReadBE32(ctx.r31.u32 + 0x5034);
        uint32_t v5038 = ReadBE32(ctx.r31.u32 + 0x5038);
        int32_t diff = (int32_t)(v5034 - v5030);
        KernelTraceHostOpF("sub_82598A20.PRESENT gates +5030=%08X +5034=%08X +5038=%08X diff=%d",
                           v5030, v5034, v5038, diff);
    }

    // Correlate with system command buffer availability
    if (looks_ptr(ctx.r3.u32)) {
        DumpSchedState("82598A20.pre", ctx.r3.u32);
        uint32_t sysPtr = ReadBE32(ctx.r3.u32 + 13520);
        KernelTraceHostOpF("sub_82598A20.PRESENT pre.syscmd ptr13520=%08X", sysPtr);
    }

    // CRITICAL: Track the function pointer gate at r31+0x3CEC
    // This pointer controls whether the rendering function is called
    // If it's NULL, the caller skips the call (see 0x82597A8C-0x82597A90)
    if (looks_ptr(ctx.r31.u32)) {
        uint32_t func_ptr_addr = ctx.r31.u32 + 0x3CEC;  // r31 + 15596
        uint32_t func_ptr = ReadBE32(func_ptr_addr);
        static uint32_t s_last_func_ptr = 0xFFFFFFFF;
        if (func_ptr != s_last_func_ptr) {
            fprintf(stderr, "[PRESENT-GATE] Function pointer at r31+0x3CEC changed: was=%08X now=%08X (r31=%08X addr=%08X)\n",
                    s_last_func_ptr, func_ptr, ctx.r31.u32, func_ptr_addr);
            fflush(stderr);
            KernelTraceHostOpF("sub_82598A20.PRESENT.GATE r31=%08X addr=%08X was=%08X now=%08X",
                               ctx.r31.u32, func_ptr_addr, s_last_func_ptr, func_ptr);
            s_last_func_ptr = func_ptr;
        }
    }

    // Track the global flag at 0x7FC86544 that gates VBlank callback execution
    // This flag is checked in the VBlank callback (sub_825979A8) at line 55:
    // else if ( !a1 && (MEMORY[0x7FC86544] & 1) != 0 )
    // If bit 0 is cleared, the VBlank callback won't call the rendering function
    //
    // CRITICAL FIX: Read the flag directly WITHOUT byte-swapping!
    // The memory system stores values in little-endian format (PPC_STORE_U32 byte-swaps before writing).
    static uint32_t s_last_flag_value = 0xFFFFFFFF;
    if (looks_ptr(0x7FC86544)) {
        uint32_t flag_value = 0;
        if (auto* p = reinterpret_cast<const uint32_t*>(g_memory.Translate(0x7FC86544))) {
            flag_value = *p;  // Read little-endian value directly (no byte-swap!)
        }
        if (flag_value != s_last_flag_value) {
            fprintf(stderr, "[PRESENT-FLAG] Global flag at 0x7FC86544 changed: was=%08X now=%08X (bit0=%d)\n",
                    s_last_flag_value, flag_value, (flag_value & 1));
            fflush(stderr);
            KernelTraceHostOpF("sub_82598A20.PRESENT.FLAG addr=7FC86544 was=%08X now=%08X bit0=%d",
                               s_last_flag_value, flag_value, (flag_value & 1));
            s_last_flag_value = flag_value;
        }
    }

    // Track the countdown field at r4+0x3CF8 (offset 15608 = a2[3902])
    // This field is decremented on each VBlank callback (sub_825979A8 line 59-68)
    // When it reaches 0, the function pointer at a2[2597]+4 is cleared to 0
    // This is likely why the rendering function stops being called after 7 times
    if (looks_ptr(ctx.r4.u32)) {
        uint32_t countdown_addr = ctx.r4.u32 + 0x3CF8;  // r4 + 15608
        uint32_t countdown = ReadBE32(countdown_addr);
        static uint32_t s_last_countdown = 0xFFFFFFFF;
        if (countdown != s_last_countdown) {
            fprintf(stderr, "[PRESENT-COUNTDOWN] Countdown at r4+0x3CF8 changed: was=%08X now=%08X (r4=%08X addr=%08X)\n",
                    s_last_countdown, countdown, ctx.r4.u32, countdown_addr);
            fflush(stderr);
            KernelTraceHostOpF("sub_82598A20.PRESENT.COUNTDOWN r4=%08X addr=%08X was=%08X now=%08X",
                               ctx.r4.u32, countdown_addr, s_last_countdown, countdown);
            s_last_countdown = countdown;
        }
    }

    // CRITICAL DEBUG: Check VdSwap function pointer before calling present
    // The game calls VdSwap through a function pointer at 0x828AA03C (type=1 thunk)
    // Let's check what's at that address AND the type=0 thunk
    static bool s_vdswap_ptr_logged = false;
    if (!s_vdswap_ptr_logged && count < 5) {
        uint32_t vdswap_type1_addr = 0x828AA03C;  // Type=1 thunk address
        uint32_t vdswap_type0_addr = 0x82000A1C;  // Type=0 thunk address

        if (auto* p1 = reinterpret_cast<const uint32_t*>(g_memory.Translate(vdswap_type1_addr))) {
            uint32_t vdswap_type1_value = __builtin_bswap32(*p1);  // Read big-endian
            fprintf(stderr, "[VDSWAP-PTR-DEBUG] Type=1 thunk at 0x%08X = 0x%08X (raw bytes: %02X %02X %02X %02X)\n",
                    vdswap_type1_addr, vdswap_type1_value,
                    ((const uint8_t*)p1)[0], ((const uint8_t*)p1)[1],
                    ((const uint8_t*)p1)[2], ((const uint8_t*)p1)[3]);
            fflush(stderr);
        }

        if (auto* p0 = reinterpret_cast<const uint32_t*>(g_memory.Translate(vdswap_type0_addr))) {
            uint32_t vdswap_type0_value = __builtin_bswap32(*p0);  // Read big-endian
            fprintf(stderr, "[VDSWAP-PTR-DEBUG] Type=0 thunk at 0x%08X = 0x%08X (raw bytes: %02X %02X %02X %02X)\n",
                    vdswap_type0_addr, vdswap_type0_value,
                    ((const uint8_t*)p0)[0], ((const uint8_t*)p0)[1],
                    ((const uint8_t*)p0)[2], ((const uint8_t*)p0)[3]);
            fflush(stderr);
        }

        if (count >= 4) s_vdswap_ptr_logged = true;
    }

    // Forward to original present implementation
    SetPPCContext(ctx);

    __imp__sub_82598A20(ctx, base);

    // Post-call breadcrumbs
    KernelTraceHostOpF("sub_82598A20.PRESENT ret r3=%08X", ctx.r3.u32);
    if (looks_ptr(ctx.r3.u32)) {
        uint32_t post_sys = ReadBE32(ctx.r3.u32 + 13520);
        KernelTraceHostOpF("sub_82598A20.PRESENT post.syscmd ptr13520=%08X", post_sys);
        DumpSchedState("82598A20.post", ctx.r3.u32);
    }
}

// NOTE: sub_825968B0 override moved to ppc_manual_overrides_symbols.cpp
PPC_FUNC_IMPL(__imp__sub_8214B490);

// Full replacement for sub_8214B490 to check parameter validity
// This function initializes a structure and accesses fields in the second parameter
// Crash happens when r4 (a2) is NULL or invalid
PPC_FUNC(sub_8214B490) {
    uint32_t r3 = ctx.r3.u32;  // result structure pointer
    uint32_t r4 = ctx.r4.u32;  // a2 structure pointer

    // Check if r3 is valid (result structure)
    if (r3 < 0x1000 || r3 >= PPC_MEMORY_SIZE) {
        KernelTraceHostOpF("HOST.8214B490.invalid_r3 r3=%08X r4=%08X - returning", r3, r4);
        return;
    }

    // Check if r4 is valid (a2 structure)
    // The function accesses r4+24, r4+28, r4+36
    if (r4 != 0 && (r4 < 0x1000 || r4 >= PPC_MEMORY_SIZE || r4 + 36 >= PPC_MEMORY_SIZE)) {
        KernelTraceHostOpF("HOST.8214B490.invalid_r4 r3=%08X r4=%08X - skipping memory access", r3, r4);
        // Initialize the result structure with zeros (safe default)
        WriteBE32(r3 + 0, 0);
        WriteBE32(r3 + 4, r4);  // Store the pointer even if invalid
        WriteBE32(r3 + 8, 0);
        WriteBE32(r3 + 12, 0);
        WriteBE16(r3 + 16, 0);
        WriteBE16(r3 + 18, 0);
        return;
    }

    // Parameters are valid, call the original function
    SetPPCContext(ctx);

    __imp__sub_8214B490(ctx, base);
}

// Convert MW05Shim_sub_82596E40 to PPC_FUNC_IMPL pattern
PPC_FUNC_IMPL(__imp__sub_82596E40);
PPC_FUNC(sub_82596E40) {
    KernelTraceHostOpF("sub_82596E40.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    if (ctx.r3.u32 >= 0x1000 && ctx.r3.u32 < PPC_MEMORY_SIZE) { MaybeLogSchedCapture(ctx.r3.u32); s_lastSchedR3.store(ctx.r3.u32, std::memory_order_release); s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel); }
    uint32_t v13520c = ReadBE32(ctx.r3.u32 + 13520);
    uint8_t v10432c = (uint8_t)(ReadBE32(ctx.r3.u32 + 10432) & 0xFF);
    KernelTraceHostOpF("HOST.82596E40.pre 13520=%08X 10432=%02X", v13520c, (unsigned)v10432c);
    SetPPCContext(ctx);

    __imp__sub_82596E40(ctx, base);
}
// Convert MW05Shim_sub_82597650 to PPC_FUNC_IMPL pattern
PPC_FUNC_IMPL(__imp__sub_82597650);
PPC_FUNC(sub_82597650) {
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
    SetPPCContext(ctx);

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

// Convert MW05Shim_sub_825976D8 to PPC_FUNC_IMPL pattern
PPC_FUNC_IMPL(__imp__sub_825976D8);
PPC_FUNC(sub_825976D8) {
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
    SetPPCContext(ctx);

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

// Convert MW05Shim_sub_825A54F0 to PPC_FUNC_IMPL pattern
PPC_FUNC_IMPL(__imp__sub_825A54F0);
PPC_FUNC(sub_825A54F0) {
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
    SetPPCContext(ctx);

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
        __imp__sub_825972B0(ctx, base);
        if (s_try_pm4_deep) {
            KernelTraceHostOpF("HOST.sub_825A54F0.post.try_deep r3=%08X", ctx.r3.u32);
            // Route through our deep shims to keep gating clears and allocator seeding
            __imp__sub_82597650(ctx, base);
            __imp__sub_825976D8(ctx, base);
            // Additional allocator/callback prep + gating clear
            __imp__sub_825968B0(ctx, base);
            __imp__sub_82596E40(ctx, base);
        }
        ctx.r3.u32 = saved_r3;
    }
}

// Main loop caller shim observed in logs (lr=82441D4C around TitleState calls)
// Convert MW05Shim_sub_82441CF0 to PPC_FUNC_IMPL pattern
PPC_FUNC_IMPL(__imp__sub_82441CF0);
PPC_FUNC(sub_82441CF0) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    // Log the sleep-skip flag value at 0x82A1FF40
    // The main loop checks this address: if it's non-zero, it skips sleep and calls frame update
    if (count < 10) {
        uint32_t sleepSkipFlag = PPC_LOAD_U32(0x82A1FF40);
        KernelTraceHostOpF("sub_82441CF0.entry lr=%08llX count=%llu sleepSkipFlag@0x82A1FF40=%08X r3=%08X r4=%08X r5=%08X",
                          (unsigned long long)ctx.lr, count, sleepSkipFlag, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    } else if ((count % 1000) == 0) {
        // Log occasionally to track progress
        uint32_t sleepSkipFlag = PPC_LOAD_U32(0x82A1FF40);
        KernelTraceHostOpF("sub_82441CF0.periodic lr=%08llX count=%llu sleepSkipFlag@0x82A1FF40=%08X",
                          (unsigned long long)ctx.lr, count, sleepSkipFlag);
    }

    // DISABLED: We now set the flag in sub_8262DE60 wrapper instead
    // This was setting it to the wrong value (2 instead of 0)
    // Keeping this code here for reference but commented out
    /*
    static const bool s_force_sleep_flag = [](){
        if (const char* v = std::getenv("MW05_FORCE_SLEEP_FLAG"))
            return !(v[0]=='0' && v[1]=='\0');
        return true;  // Enable by default!
    }();

    if (s_force_sleep_flag) {
        PPC_STORE_U32(0x82A1FF40, 0);  // Force to 0 to make sleep check call sleep
        if (count < 10) {
            KernelTraceHostOpF("sub_82441CF0.forced_sleep_flag_to_0 count=%llu", count);
        }
    }
    */

    // Heuristic: r5 looks like a small control block observed at TitleState; capture as scheduler seed
    Mw05Trace_ConsiderSchedR3(ctx.r5.u32);
    if (count < 10) {
        DumpEAWindow("82441CF0.r5", ctx.r5.u32);
        DumpSchedState("82441CF0", ctx.r5.u32);
    }

    static const bool s_loop_try_pm4_pre = [](){ if (const char* v = std::getenv("MW05_LOOP_TRY_PM4_PRE")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    static const bool s_loop_try_pm4 = [](){ if (const char* v = std::getenv("MW05_LOOP_TRY_PM4")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    static const bool s_loop_try_pm4_deep = [](){ if (const char* v = std::getenv("MW05_LOOP_TRY_PM4_DEEP")) return !(v[0]=='0' && v[1]=='\0'); return false; }();

    if (s_loop_try_pm4_pre && ctx.r5.u32 >= 0x1000 && ctx.r5.u32 < PPC_MEMORY_SIZE) {
        uint32_t saved_r3 = ctx.r3.u32;
        ctx.r3.u32 = ctx.r5.u32;
        KernelTraceHostOpF("HOST.sub_82441CF0.pre.try_825972B0 r3=%08X (from r5)", ctx.r3.u32);
        __imp__sub_825972B0(ctx, base);
        if (s_loop_try_pm4_deep) {
            KernelTraceHostOpF("HOST.sub_82441CF0.pre.try_deep r3=%08X", ctx.r3.u32);
            __imp__sub_82597650(ctx, base);
            __imp__sub_825976D8(ctx, base);
            // Additional allocator/callback prep + gating clear
            __imp__sub_825968B0(ctx, base);
            __imp__sub_82596E40(ctx, base);
        }
        ctx.r3.u32 = saved_r3;
    }

    __imp__sub_82441CF0(ctx, base);

    if (s_loop_try_pm4 && ctx.r5.u32 >= 0x1000 && ctx.r5.u32 < PPC_MEMORY_SIZE) {
        uint32_t saved_r3 = ctx.r3.u32;
        ctx.r3.u32 = ctx.r5.u32;
        KernelTraceHostOpF("HOST.sub_82441CF0.post.try_825972B0 r3=%08X (from r5)", ctx.r3.u32);
        __imp__sub_825972B0(ctx, base);
        if (s_loop_try_pm4_deep) {
            KernelTraceHostOpF("HOST.sub_82441CF0.post.try_deep r3=%08X", ctx.r3.u32);
            __imp__sub_82597650(ctx, base);
            __imp__sub_825976D8(ctx, base);
            // Additional allocator/callback prep + gating clear
            __imp__sub_825968B0(ctx, base);
            __imp__sub_82596E40(ctx, base);
        }
        ctx.r3.u32 = saved_r3;
    }
}
