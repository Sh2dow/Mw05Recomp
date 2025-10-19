// Trace MW05 thread entries and optionally kick minimal video init.

#include <cpu/ppc_context.h>
#include <kernel/trace.h>
#include <kernel/memory.h>
#include <kernel/heap.h>
#include "xbox.h"
#include "guest_thread.h"
#include <cstdlib>
#include <atomic>
#include <chrono>
#include <thread>
#include <kernel/trace.h>

extern std::atomic<uint32_t> g_watchEA;

PPC_FUNC_IMPL(__imp__sub_82442080);
PPC_FUNC(sub_82442080)
{
    fprintf(stderr, "[INIT-TRACE] sub_82442080 ENTER\n"); fflush(stderr);
    SetPPCContext(ctx);
    __imp__sub_82442080(ctx, base);
    fprintf(stderr, "[INIT-TRACE] sub_82442080 RETURN\n"); fflush(stderr);
}

PPC_FUNC_IMPL(__imp__sub_824411E0);
PPC_FUNC(sub_824411E0) 
{
    fprintf(stderr, "[INIT-TRACE] sub_824411E0 ENTER\n"); fflush(stderr);
    SetPPCContext(ctx);
    __imp__sub_824411E0(ctx, base);
    fprintf(stderr, "[INIT-TRACE] sub_824411E0 RETURN\n"); fflush(stderr);
}

// Wrapper for sub_8262D9D0 - sleep function called from main loop
// This is called when the sleep-skip flag at 0x82A1FF40 is ZERO
PPC_FUNC_IMPL(__imp__sub_8262D9D0);
PPC_FUNC(sub_8262D9D0) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    // Log every call - this should be called if the sleep-skip flag is ZERO
    KernelTraceHostOpF("HOST.sub_8262D9D0.called lr=%08llX count=%llu r3=%08X",
                      ctx.lr, count, ctx.r3.u32);

    // Call the original
    __imp__sub_8262D9D0(ctx, base);
}

extern "C" {
    uint32_t Mw05PeekSchedulerBlockEA();
	void Mw05RegisterVdInterruptEvent(uint32_t eventEA, bool manualReset);
    void Mw05ForceVdInitOnce();
    void Mw05LogIsrIfRegisteredOnce();
    uint32_t Mw05GetGraphicsContextAddress();  // Get heap-allocated graphics context address

    // Minimal host-side kick (idempotent) to initialize system command buffer.
    // Host Vd helper forward-decl (defined in kernel/imports.cpp)
    uint32_t VdGetSystemCommandBuffer(be<uint32_t>* outCmdBufPtr, be<uint32_t>* outValue);
    // Host Vd helpers we can invoke to seed minimal video state
    void VdInitializeEngines();
    void VdInitializeRingBuffer(uint32_t base, uint32_t len_log2);
    void VdEnableRingBufferRPtrWriteBack(uint32_t base);
    void VdSetSystemCommandBufferGpuIdentifierAddress(uint32_t addr);

    // Trace key initialization functions to find where sub_823AF590 is blocking
    // void __imp__sub_8215D598(PPCContext& ctx, uint8_t* base);
    // void __imp__sub_8262D010(PPCContext& ctx, uint8_t* base);
    // void __imp__sub_8215E510(PPCContext& ctx, uint8_t* base);
    // void __imp__sub_8245FBD0(PPCContext& ctx, uint8_t* base);
    // void __imp__sub_823BCBF0(PPCContext& ctx, uint8_t* base);
    // void __imp__sub_82812F10(PPCContext& ctx, uint8_t* base);

}


static inline bool KickVideoInitEnabled() {
    const char* env = std::getenv("MW05_KICK_VIDEO");
    return env && *env && *env != '0';
}

static inline bool ForceVdInitEnabled() {
	const char* env = std::getenv("MW05_FORCE_VD_INIT");
	return env && *env && *env != '0';
}

static inline bool UnblockMainThreadEnabled() {
	const char* env = std::getenv("MW05_UNBLOCK_MAIN");
	return env && *env && *env != '0';
}

// Background thread that continuously sets the flag to unblock the main thread.
// The main thread at sub_82441CF0 waits for dword_82A2CF40 to become non-zero,
// then clears it at the end of each iteration. This thread keeps setting it.
static std::atomic<bool> g_unblockThreadRunning{false};
static std::thread g_unblockThread;

static void UnblockThreadFunc() {
	const uint32_t flag_ea = 0x82A2CF40;
	fprintf(stderr, "[UNBLOCK-DEBUG] UnblockThread started, flag_ea=%08X\n", flag_ea);
	fflush(stderr);
	KernelTraceHostOpF("HOST.UnblockThread.start flag_ea=%08X", flag_ea);

	// Set the VD callback render thread creation flag
	// Address: 0x7FE86544 (from lis r11,32712; lwz r11,25924(r11) in sub_825979A8)
	const uint32_t vd_flag_ea = 0x7FE86544;
	uint32_t* vd_flag_ptr = static_cast<uint32_t*>(g_memory.Translate(vd_flag_ea));
	if (vd_flag_ptr) {
		*vd_flag_ptr = 1;  // Enable render thread creation
		fprintf(stderr, "[UNBLOCK-DEBUG] Set VD render flag at %08X to 1\n", vd_flag_ea);
		fflush(stderr);
		KernelTraceHostOpF("HOST.UnblockThread.set_vd_flag addr=%08X value=1", vd_flag_ea);
	}

	// Check the VD callback function pointer that creates the render thread
	// Graphics context is heap-allocated (following Xenia's approach)
	// r10 = *(gfx_ctx + 10388)
	// r30 = *(r10 + 16) - this is the function pointer
	const uint32_t gfx_ctx_ea = Mw05GetGraphicsContextAddress();
	if (gfx_ctx_ea == 0) {
		fprintf(stderr, "[UNBLOCK-DEBUG] Graphics context not yet allocated\n");
		fflush(stderr);
		return;
	}
	uint32_t* gfx_ctx_ptr = static_cast<uint32_t*>(g_memory.Translate(gfx_ctx_ea + 10388));
	if (gfx_ctx_ptr) {
		uint32_t r10_value = __builtin_bswap32(*gfx_ctx_ptr);  // Big-endian
		fprintf(stderr, "[UNBLOCK-DEBUG] GFX context (heap=0x%08X) +10388 = %08X\n", gfx_ctx_ea, r10_value);
		fflush(stderr);

		if (r10_value != 0) {
			uint32_t* func_ptr_ptr = static_cast<uint32_t*>(g_memory.Translate(r10_value + 16));
			if (func_ptr_ptr) {
				uint32_t func_ptr = __builtin_bswap32(*func_ptr_ptr);  // Big-endian
				fprintf(stderr, "[UNBLOCK-DEBUG] VD callback function pointer at %08X+16 = %08X\n", r10_value, func_ptr);
				fflush(stderr);
			}
		}
	}

	// Throttle logging: env-configurable interval (ms) and max lines
	auto read_env_u32 = [](const char* name, uint32_t defv) -> uint32_t {
		if (const char* v = std::getenv(name)) {
			char* end = nullptr;
			unsigned long val = std::strtoul(v, &end, 10);
			if (end && end != v) return (uint32_t)val;
		}
		return defv;
	};
	const uint32_t log_ms  = read_env_u32("MW05_UNBLOCK_LOG_MS", 500);  // Log every 500ms
	const uint32_t log_max = read_env_u32("MW05_UNBLOCK_LOG_MAX", 10);  // Max 10 logs

	int iteration = 0;
	uint32_t logged = 0;
	auto last = std::chrono::steady_clock::now();
	while (g_unblockThreadRunning.load(std::memory_order_acquire)) {
		uint32_t* flag_ptr = static_cast<uint32_t*>(g_memory.Translate(flag_ea));
		if (flag_ptr) {
			// Read current value
			uint32_t current = __builtin_bswap32(*flag_ptr);

			// Set the flag to 1 (big-endian) using volatile write
			// Note: We can't use std::atomic here because the pointer might not be properly aligned
			volatile uint32_t* vol_ptr = flag_ptr;
			*vol_ptr = __builtin_bswap32(1);

			// Log only if enough time passed and we haven't exceeded max lines
			if (logged < log_max) {
				auto now = std::chrono::steady_clock::now();
				uint64_t elapsed = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(now - last).count();
				if (elapsed >= log_ms) {
					uint32_t readback = __builtin_bswap32(*vol_ptr);
					fprintf(stderr, "[UNBLOCK-DEBUG] UnblockThread iter=%d current=%u readback=%u\n", iteration, current, readback);
					fflush(stderr);
					KernelTraceHostOpF("HOST.UnblockThread.set iter=%d current=%u readback=%u", iteration, current, readback);
					last = now;
					logged++;
				}
			}
			iteration++;
		}
		// NO SLEEP - keep the flag set continuously
	}

	fprintf(stderr, "[UNBLOCK-DEBUG] UnblockThread exiting, iterations=%d\n", iteration);
	fflush(stderr);
	KernelTraceHostOpF("HOST.UnblockThread.exit iterations=%d", iteration);
}

// String formatting function that main thread gets stuck in
extern "C" void __imp__sub_8262DD80(PPCContext& ctx, uint8_t* base);

// CRT initialization function that calls sub_8262DD80 in a loop
extern "C" void __imp__sub_8262DE60(PPCContext& ctx, uint8_t* base);

// REAL FIX: Call sub_82442080 directly to set the unblock flag
// This is what should happen naturally, but the initialization chain is broken
extern "C" void UnblockMainThreadEarly() {
	fprintf(stderr, "[UNBLOCK-DEBUG] UnblockMainThreadEarly called, enabled=%d\n", UnblockMainThreadEnabled());
	fflush(stderr);

	if(!UnblockMainThreadEnabled()) return;

	const uint32_t flag_ea = 0x82A2CF40;
	uint32_t* flag_ptr = static_cast<uint32_t*>(g_memory.Translate(flag_ea));
	if(!flag_ptr) {
		fprintf(stderr, "[UNBLOCK-DEBUG] FAILED to translate ea=%08X\n", flag_ea);
		fflush(stderr);
		KernelTraceHostOpF("HOST.UnblockMainThreadEarly FAILED: could not translate ea=%08X", flag_ea);
		return;
	}

	// REAL FIX: Call sub_82442080 directly instead of just setting the flag
	// This function does the proper initialization and sets the flag
	fprintf(stderr, "[UNBLOCK-DEBUG] Calling sub_82442080 to set unblock flag\n");
	fflush(stderr);
	KernelTraceHostOp("HOST.UnblockMainThreadEarly calling sub_82442080");

	PPCContext ctx{};
	if (auto* cur = GetPPCContext()) {
		ctx = *cur;
	} else {
		// Initialize a minimal context if none exists
		ctx.r1.u32 = 0x7FEA0000; // Stack pointer
		ctx.r3.u32 = 0;
		ctx.r4.u32 = 0;
	}
	uint8_t* base = g_memory.base;
	__imp__sub_82442080(ctx, base);

	fprintf(stderr, "[UNBLOCK-DEBUG] sub_82442080 returned, checking flag\n");
	fflush(stderr);
	KernelTraceHostOp("HOST.UnblockMainThreadEarly sub_82442080 complete");

	// Verify the flag was set
	uint32_t flag_value = __builtin_bswap32(*flag_ptr);
	fprintf(stderr, "[UNBLOCK-DEBUG] Flag at 0x%08X = 0x%08X\n", flag_ea, flag_value);
	fflush(stderr);
	KernelTraceHostOpF("HOST.UnblockMainThreadEarly flag=%08X", flag_value);

	// Fallback: If sub_82442080 didn't set the flag, set it manually
	if (flag_value == 0) {
		fprintf(stderr, "[UNBLOCK-DEBUG] sub_82442080 didn't set flag, setting manually\n");
		fflush(stderr);
		*flag_ptr = __builtin_bswap32(1);
	}
}

void KickMinimalVideo() {
    static bool s_done = false;
    if(s_done) return;
    s_done = true;

    // 1) Ensure the system command buffer exists
    VdGetSystemCommandBuffer(nullptr, nullptr);

    // 2) Create a small ring buffer and write-back pointer in guest memory
    const uint32_t len_log2 = 12; // 4 KiB ring (small, dev-only)
    const uint32_t size_bytes = 1u << len_log2;
    void* ring_host = g_userHeap.Alloc(size_bytes);
    if(!ring_host) return;
    const uint32_t ring_guest = g_memory.MapVirtual(ring_host);

    void* wb_host = g_userHeap.Alloc(64);
    if(!wb_host) return;
    const uint32_t wb_guest = g_memory.MapVirtual(wb_host);

    // 3) Seed ring buffer state via host helpers
    VdInitializeRingBuffer(ring_guest, len_log2);
    VdEnableRingBufferRPtrWriteBack(wb_guest);
    VdSetSystemCommandBufferGpuIdentifierAddress(wb_guest + 8); // arbitrary within wb area
    VdInitializeEngines();
}

static std::atomic<bool> g_forcedGraphicsInit{false};

// Forward declare ExCreateThread and NtResumeThread
extern uint32_t ExCreateThread(be<uint32_t>* handle, uint32_t stackSize, be<uint32_t>* threadId, uint32_t xApiThreadStartup, uint32_t startAddress, uint32_t startContext, uint32_t creationFlags);
extern uint32_t NtResumeThread(GuestThreadHandle* hThread, uint32_t* suspendCount);

// CRITICAL FIX: Force creation of missing worker threads
// Thread #1 (entry=0x828508A8) is supposed to create 6 additional worker threads, but it's stuck in a busy loop
// This function manually creates the missing threads to unblock the game
static void Mw05ForceCreateMissingWorkerThreads() {
    static std::atomic<bool> s_created{false};
    if (s_created.exchange(true)) return;  // Only create once

    fprintf(stderr, "[FORCE_WORKERS] Creating missing worker threads...\n");
    fflush(stderr);

    // From Xenia log, Thread #1 creates these threads:
    // tid=9-12: entry=0x828508A8 (4 worker threads)
    // tid=13: entry=0x825AA970 (special thread)
    // tid=14: entry=0x828508A8 (1 more worker thread)

    // Allocate contexts for the threads (similar to how Thread #1 and #2 were created)
    // Each context is a simple structure with a few fields

    // CRITICAL FIX: Initialize worker thread contexts with callback pointers
    // The first worker thread (Thread #1) has a properly initialized context at 0x001616D0:
    //   +0x00: 0x00000000
    //   +0x04: 0xFFFFFFFF
    //   +0x08: 0x00000000
    //   +0x54 (84): 0x8261A558  <-- CALLBACK FUNCTION POINTER!
    //   +0x58 (88): 0x82A2B318  <-- CALLBACK PARAMETER!
    // We need to initialize the manually-created worker thread contexts with the same values.

    extern Memory g_memory;
    extern Heap g_userHeap;

    for (int i = 0; i < 5; ++i) {  // Create 5 worker threads with entry=0x828508A8
        be<uint32_t> thread_handle = 0;
        be<uint32_t> thread_id = 0;
        uint32_t stack_size = 0x40000;  // 256KB stack (same as other game threads)

        // Allocate a context structure on the heap (256 bytes to be safe)
        void* ctx_host = g_userHeap.Alloc(256);
        if (!ctx_host) {
            fprintf(stderr, "[FORCE_WORKERS] ERROR: Failed to allocate context for worker thread #%d\n", i + 3);
            fflush(stderr);
            continue;
        }

        // Zero out the context
        std::memset(ctx_host, 0, 256);

        // Map to guest address
        uint32_t ctx_addr = g_memory.MapVirtual(ctx_host);

        // Initialize the context structure (in big-endian format)
        be<uint32_t>* ctx_u32 = reinterpret_cast<be<uint32_t>*>(ctx_host);
        ctx_u32[0] = be<uint32_t>(0x00000000);  // +0x00
        ctx_u32[1] = be<uint32_t>(0xFFFFFFFF);  // +0x04
        ctx_u32[2] = be<uint32_t>(0x00000000);  // +0x08
        ctx_u32[84/4] = be<uint32_t>(0x8261A558);  // +0x54 (84) - callback function pointer
        ctx_u32[88/4] = be<uint32_t>(0x82A2B318);  // +0x58 (88) - callback parameter

        fprintf(stderr, "[FORCE_WORKERS] Creating worker thread #%d: entry=0x828508A8 ctx=0x%08X\n", i + 3, ctx_addr);
        fprintf(stderr, "[FORCE_WORKERS]   Context initialized: +0x54=0x8261A558, +0x58=0x82A2B318\n");
        fflush(stderr);

        uint32_t result = ExCreateThread(&thread_handle, stack_size, &thread_id, 0, 0x828508A8, ctx_addr, 0x00000000);  // NOT SUSPENDED

        if (result == 0) {  // STATUS_SUCCESS
            fprintf(stderr, "[FORCE_WORKERS] Worker thread #%d created: handle=0x%08X tid=0x%08X\n", i + 3, (uint32_t)thread_handle, (uint32_t)thread_id);
            fflush(stderr);
        } else {
            fprintf(stderr, "[FORCE_WORKERS] ERROR: Failed to create worker thread #%d: status=0x%08X\n", i + 3, result);
            fflush(stderr);
        }
    }

    // Create the special thread (entry=0x825AA970)
    {
        be<uint32_t> thread_handle = 0;
        be<uint32_t> thread_id = 0;
        uint32_t stack_size = 0x40000;
        uint32_t ctx_addr = 0x40009D2C;  // From Xenia log

        fprintf(stderr, "[FORCE_WORKERS] Creating special thread: entry=0x825AA970 ctx=0x%08X\n", ctx_addr);
        fflush(stderr);

        uint32_t result = ExCreateThread(&thread_handle, stack_size, &thread_id, 0, 0x825AA970, ctx_addr, 0x00000000);  // NOT SUSPENDED

        if (result == 0) {
            fprintf(stderr, "[FORCE_WORKERS] Special thread created: handle=0x%08X tid=0x%08X\n", (uint32_t)thread_handle, (uint32_t)thread_id);
            fflush(stderr);
        } else {
            fprintf(stderr, "[FORCE_WORKERS] ERROR: Failed to create special thread: status=0x%08X\n", result);
            fflush(stderr);
        }
    }

    fprintf(stderr, "[FORCE_WORKERS] All missing worker threads created!\n");
    fflush(stderr);
}


PPC_FUNC_IMPL(__imp__sub_828508A8);
PPC_FUNC(sub_828508A8) 
{
    KernelTraceHostOp("HOST.ThreadEntry.828508A8.enter");
    fprintf(stderr, "[THREAD_828508A8] ENTER tid=%lx r3=%08X\n", GetCurrentThreadId(), ctx.r3.u32);
    fflush(stderr);

    // CRITICAL DEBUG: Check what's in the context structure at offset +84
    // This should contain the callback function pointer that sub_82850820 will call
    if (ctx.r3.u32 != 0) {
        uint8_t* ctx_ptr = base + ctx.r3.u32;
        uint32_t* ctx_u32 = (uint32_t*)ctx_ptr;

        fprintf(stderr, "[THREAD_828508A8] Context structure at 0x%08X:\n", ctx.r3.u32);
        fprintf(stderr, "  +0x00: 0x%08X\n", __builtin_bswap32(ctx_u32[0]));
        fprintf(stderr, "  +0x04: 0x%08X\n", __builtin_bswap32(ctx_u32[1]));
        fprintf(stderr, "  +0x08: 0x%08X\n", __builtin_bswap32(ctx_u32[2]));
        fprintf(stderr, "  +0x54 (84): 0x%08X  <-- CALLBACK FUNCTION POINTER!\n", __builtin_bswap32(ctx_u32[84/4]));
        fprintf(stderr, "  +0x58 (88): 0x%08X  <-- CALLBACK PARAMETER!\n", __builtin_bswap32(ctx_u32[88/4]));
        fflush(stderr);

        // Check if the callback pointer is valid
        uint32_t callback_ptr = __builtin_bswap32(ctx_u32[84/4]);
        uint32_t callback_param = __builtin_bswap32(ctx_u32[88/4]);

        if (callback_ptr == 0) {
            fprintf(stderr, "[THREAD_828508A8] ERROR: Callback pointer at +84 is NULL!\n");
            fprintf(stderr, "[THREAD_828508A8] This is why sub_82850820 doesn't call sub_82441E80!\n");
            fprintf(stderr, "[THREAD_828508A8] The callback should be 0x823B0190 or similar.\n");
            fflush(stderr);
        } else if (callback_ptr >= 0x82000000 && callback_ptr < 0x83000000) {
            fprintf(stderr, "[THREAD_828508A8] Callback pointer looks valid: 0x%08X\n", callback_ptr);
            fflush(stderr);

            // Dump the callback parameter structure
            if (callback_param != 0 && callback_param >= 0x82000000 && callback_param < 0x83000000) {
                uint8_t* param_ptr = base + callback_param;
                uint32_t* param_u32 = (uint32_t*)param_ptr;

                fprintf(stderr, "[THREAD_828508A8] Callback parameter structure at 0x%08X:\n", callback_param);
                fprintf(stderr, "  +0x00 (0):  0x%08X\n", __builtin_bswap32(param_u32[0]));
                fprintf(stderr, "  +0x04 (4):  0x%08X\n", __builtin_bswap32(param_u32[1]));
                fprintf(stderr, "  +0x08 (8):  0x%08X  <-- STATE\n", __builtin_bswap32(param_u32[2]));
                fprintf(stderr, "  +0x0C (12): 0x%08X  <-- RESULT\n", __builtin_bswap32(param_u32[3]));
                fprintf(stderr, "  +0x10 (16): 0x%08X  <-- FUNCTION POINTER!\n", __builtin_bswap32(param_u32[4]));
                fprintf(stderr, "  +0x14 (20): 0x%08X  <-- FUNCTION PARAMETER!\n", __builtin_bswap32(param_u32[5]));
                fprintf(stderr, "  +0x18 (24): 0x%08X\n", __builtin_bswap32(param_u32[6]));
                fprintf(stderr, "  +0x1C (28): 0x%08X  <-- FLAG (2 params if non-zero)\n", __builtin_bswap32(param_u32[7]));
                fflush(stderr);

                uint32_t work_func = __builtin_bswap32(param_u32[4]);
                if (work_func == 0) {
                    fprintf(stderr, "[THREAD_828508A8] ERROR: Work function pointer at +16 is NULL!\n");
                    fprintf(stderr, "[THREAD_828508A8] This is why Thread #1 doesn't do any work!\n");
                    fprintf(stderr, "[THREAD_828508A8] The work queue at 0x829091C8 is probably empty.\n");
                    fflush(stderr);
                } else {
                    fprintf(stderr, "[THREAD_828508A8] Work function pointer: 0x%08X\n", work_func);
                    fflush(stderr);
                }
            }
        } else {
            fprintf(stderr, "[THREAD_828508A8] WARNING: Callback pointer looks suspicious: 0x%08X\n", callback_ptr);
            fflush(stderr);
        }
    }

    if(KickVideoInitEnabled()) KickMinimalVideo();
	if (ForceVdInitEnabled()) { Mw05ForceVdInitOnce(); Mw05LogIsrIfRegisteredOnce(); }

    // CRITICAL FIX: Force creation of render threads
    // Thread #1 is supposed to create these threads, but it gets stuck in a wait loop
    // waiting for work items that are never added to the queue at 0x829091C8.
    // As a workaround, we force-create the render threads here.
    static bool s_render_threads_created = false;
    if (!s_render_threads_created && std::getenv("MW05_FORCE_RENDER_THREADS")) {
        s_render_threads_created = true;

        fprintf(stderr, "[THREAD_828508A8] FORCE-CREATING RENDER THREADS\n");
        fflush(stderr);

        // Render thread entry points (from Xenia log)
        const uint32_t render_entries[] = {
            0x826E7B90,
            0x826E7BC0,
            0x826E7BF0,
            0x826E7C20
        };

        // Create 4 render threads (one for each entry point)
        for (int i = 0; i < 4; i++) {
            // Allocate context structure (256 bytes should be enough)
            void* ctx_host = g_userHeap.AllocPhysical(256, 16);
            uint32_t ctx_guest = g_memory.MapVirtual(ctx_host);

            // Zero the context
            memset(ctx_host, 0, 256);

            be<uint32_t> handle = 0;
            be<uint32_t> thread_id = 0;

            // Create thread (suspended)
            uint32_t result = ExCreateThread(
                &handle,
                0,  // Default stack size
                &thread_id,
                0,  // No API thread startup
                render_entries[i],
                ctx_guest,
                1  // CREATE_SUSPENDED
            );

            fprintf(stderr, "[THREAD_828508A8] Created render thread %d: entry=%08X ctx=%08X handle=%08X tid=%08X result=%08X\n",
                    i, render_entries[i], ctx_guest, (uint32_t)handle, (uint32_t)thread_id, result);
            fflush(stderr);

            // Resume the thread
            if (result == 0 && handle != 0) {
                // Call NtResumeThread to start the thread
                uint32_t prev_count = 0;
                GuestThreadHandle* hThread = GetKernelObject<GuestThreadHandle>((uint32_t)handle);
                NtResumeThread(hThread, &prev_count);

                fprintf(stderr, "[THREAD_828508A8] Resumed render thread %d: prev_count=%u\n", i, prev_count);
                fflush(stderr);
            }
        }

        fprintf(stderr, "[THREAD_828508A8] RENDER THREADS CREATED\n");
        fflush(stderr);
    }

    fprintf(stderr, "[THREAD_828508A8] Calling __imp__sub_828508A8 tid=%lx\n", GetCurrentThreadId());
    fflush(stderr);

    // CRITICAL: Add periodic logging to detect if thread is stuck
    static std::atomic<int> s_call_count{0};
    int call_num = ++s_call_count;

    // CRITICAL FIX: Force creation of missing worker threads after a short delay
    // Thread #1 is supposed to create these threads, but it's stuck in a busy loop
    // Create them manually to unblock the game
    std::thread force_workers([]() {
        // Wait 2 seconds to let Thread #1 create Thread #2 first
        std::this_thread::sleep_for(std::chrono::seconds(2));

        fprintf(stderr, "[FORCE_WORKERS] Triggering forced worker thread creation...\n");
        fflush(stderr);

        Mw05ForceCreateMissingWorkerThreads();
    });
    force_workers.detach();

    // Start a monitoring thread to detect if this thread gets stuck
    std::thread monitor([call_num]() {
        for (int i = 0; i < 60; ++i) {  // Monitor for 60 seconds
            std::this_thread::sleep_for(std::chrono::seconds(1));
            if (i % 10 == 0) {
                fprintf(stderr, "[THREAD_828508A8_MONITOR] Thread #%d still running after %d seconds\n", call_num, i);
                fflush(stderr);
            }
        }
        fprintf(stderr, "[THREAD_828508A8_MONITOR] Thread #%d completed or timed out after 60 seconds\n", call_num);
        fflush(stderr);
    });
    monitor.detach();

    // Call the original thread entry point
    __imp__sub_828508A8(ctx, base);

    fprintf(stderr, "[THREAD_828508A8] EXIT tid=%lx r3=%08X\n", GetCurrentThreadId(), ctx.r3.u32);
    fflush(stderr);
    KernelTraceHostOp("HOST.ThreadEntry.828508A8.exit");
}

PPC_FUNC_IMPL(__imp__sub_82812ED0);
PPC_FUNC(sub_82812ED0)
{
    DWORD thread2_tid = GetCurrentThreadId();
    fprintf(stderr, "[WRAPPER_82812ED0] ENTER - wrapper is being called! r3=0x%08X tid=0x%08X\n", ctx.r3.u32, thread2_tid);
    fflush(stderr);

    // Check what's at the context address
    if (ctx.r3.u32 != 0) {
        uint32_t* ctx_ptr = (uint32_t*)(base + ctx.r3.u32);
        fprintf(stderr, "[WRAPPER_82812ED0] Context structure at 0x%08X:\n", ctx.r3.u32);
        fprintf(stderr, "  +0x00 (state):    0x%08X\n", __builtin_bswap32(ctx_ptr[0]));
        fprintf(stderr, "  +0x04 (func_ptr): 0x%08X\n", __builtin_bswap32(ctx_ptr[1]));
        fprintf(stderr, "  +0x08 (context):  0x%08X\n", __builtin_bswap32(ctx_ptr[2]));

        // CORRUPTION DETECTION: Check if function pointer is corrupted
        uint32_t func_ptr = __builtin_bswap32(ctx_ptr[1]);
        const uint32_t expected_func_ptr = 0x828134E0;
        if (func_ptr != expected_func_ptr) {
            fprintf(stderr, "[CORRUPTION-DETECTED] Function pointer corrupted!\n");
            fprintf(stderr, "  Expected: 0x%08X\n", expected_func_ptr);
            fprintf(stderr, "  Actual:   0x%08X\n", func_ptr);
            fprintf(stderr, "  Context address: 0x%08X\n", ctx.r3.u32);
            fprintf(stderr, "  Memory address: %p\n", &ctx_ptr[1]);

            // FIX: Restore the correct function pointer
            fprintf(stderr, "[CORRUPTION-FIX] Restoring correct function pointer...\n");
            ctx_ptr[1] = __builtin_bswap32(expected_func_ptr);
            fprintf(stderr, "[CORRUPTION-FIX] Function pointer restored to 0x%08X\n", expected_func_ptr);
        }
        fflush(stderr);
    }

    SetPPCContext(ctx);
    KernelTraceHostOp("HOST.ThreadEntry.82812ED0");

    const uint32_t block_ptr = ctx.r3.u32;
    KernelTraceHostOpF("HOST.ThreadEntry.82812ED0.block ptr=%08X", block_ptr);
    if(block_ptr) {
        uint8_t* raw = static_cast<uint8_t*>(g_memory.Translate(block_ptr));
        if(raw) {
            struct ThreadStartBlock {
                be<uint32_t> state;
                be<uint32_t> entry;
                be<uint32_t> context;
                be<uint32_t> event;
                be<uint32_t> work_item_a;
                be<uint32_t> work_item_b;
            };
            const auto* block = reinterpret_cast<const ThreadStartBlock*>(raw);
            KernelTraceHostOpF("HOST.ThreadEntry.82812ED0.block fields state=%08X entry=%08X ctx=%08X evt=%08X w0=%08X w1=%08X",
                               static_cast<uint32_t>(block->state),
                               static_cast<uint32_t>(block->entry),
                               static_cast<uint32_t>(block->context),
                               static_cast<uint32_t>(block->event),
                               static_cast<uint32_t>(block->work_item_a),
                               static_cast<uint32_t>(block->work_item_b));
            KernelTraceHostOpF("HOST.ThreadEntry.82812ED0.block raw %02X %02X %02X %02X  %02X %02X %02X %02X  %02X %02X %02X %02X  %02X %02X %02X %02X",
                               raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                               raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]);
            const uint32_t eventEA = static_cast<uint32_t>(block->event);
            if(eventEA) {
                bool manualReset = false;
                if(auto* hdr = reinterpret_cast<XDISPATCHER_HEADER*>(g_memory.Translate(eventEA))) {
                    manualReset = (hdr->Type == 0);
                }
                Mw05RegisterVdInterruptEvent(eventEA, manualReset);
                KernelTraceHostOpF("HOST.ThreadEntry.82812ED0.event ea=%08X manual=%u", eventEA, manualReset ? 1u : 0u);
            }
        }
    }

    // Arm the writer watch for the scheduler slot as early as possible.
    // If the pump has already recorded the block EA, this will be non-zero.
    if(const uint32_t sched = Mw05PeekSchedulerBlockEA()) {
        const uint32_t watch = sched + 16;
        if(g_watchEA.load(std::memory_order_relaxed) != watch) {
            g_watchEA.store(watch, std::memory_order_relaxed);
            KernelTraceHostOpF("HOST.ThreadEntry.82812ED0.watch arm=%08X", watch);
        }
    }

    if(KickVideoInitEnabled()) KickMinimalVideo();
	if (ForceVdInitEnabled()) { Mw05ForceVdInitOnce(); Mw05LogIsrIfRegisteredOnce(); }

    fprintf(stderr, "[WRAPPER_82812ED0] About to call __imp__sub_82812ED0\n");
    fflush(stderr);

    // CRITICAL FIX: Explicitly set the state flag from host code BEFORE calling original
    // This ensures the flag is visible to other threads even if the PPC code caches it
    if (ctx.r3.u32 != 0) {
        uint32_t* ctx_ptr = (uint32_t*)(base + ctx.r3.u32);
        ctx_ptr[0] = __builtin_bswap32(1);  // Set state = 1 (big-endian)
        std::atomic_thread_fence(std::memory_order_seq_cst);
        fprintf(stderr, "[WRAPPER_82812ED0] Explicitly set state flag to 1 at 0x%08X\n", ctx.r3.u32);
        fflush(stderr);
    }

    // Check dword_828F1F90 (event handle) before calling worker
    const uint32_t dword_828F1F90_addr = 0x828F1F90;
    uint8_t* dword_host = base + dword_828F1F90_addr;
    if (dword_host) {
        uint32_t* dword_ptr = (uint32_t*)dword_host;
        uint32_t event_handle_be = __builtin_bswap32(*dword_ptr);
        uint32_t event_handle_le = *dword_ptr;
        fprintf(stderr, "[WRAPPER_82812ED0] dword_828F1F90 (event handle) BE=0x%08X LE=0x%08X raw=0x%08X\n",
                event_handle_be, event_handle_le, *dword_ptr);
        fflush(stderr);

        // Also check what the worker function will read using PPC_LOAD_U32
        // This simulates the exact same load that the worker function does
        uint32_t loaded_value = __builtin_bswap32(*dword_ptr);  // Same as PPC_LOAD_U32
        fprintf(stderr, "[WRAPPER_82812ED0] Worker will read handle as: 0x%08X (after byte-swap)\n", loaded_value);
        fflush(stderr);
    }

    __imp__sub_82812ED0(ctx, base);

    fprintf(stderr, "[WRAPPER_82812ED0] __imp__sub_82812ED0 returned\n");
    fflush(stderr);
}

// NOTE: sub_824411E0 is NOT a thread entry point - it's called directly via bl instruction
// It's a regular function that's part of the game's initialization sequence
// The recompiled PPC code will call it naturally, no wrapper needed

// Helper to check if CRT init loop breaking is enabled
static inline bool BreakCRTInitLoopEnabled() {
    // Check both MW05_BREAK_CRT_INIT and MW05_BREAK_8262DD80 (alias)
    if(const char* v = std::getenv("MW05_BREAK_CRT_INIT")) {
        if (!(v[0] == '0' && v[1] == '\0')) return true;
    }
    if(const char* v = std::getenv("MW05_BREAK_8262DD80")) {
        if (!(v[0] == '0' && v[1] == '\0')) return true;
    }
    return false;
}

// Wrapper for sub_8262DD80 to detect and break infinite string formatting loops
PPC_FUNC_IMPL(__imp__sub_8262DD80);
PPC_FUNC(sub_8262DD80)
{
    static std::atomic<uint64_t> s_callCount{0};
    static std::atomic<uint64_t> s_lastLogTime{0};

    uint64_t count = s_callCount.fetch_add(1);

    // Log every 10M calls
    if (count % 10000000 == 0) {
        uint64_t now = std::chrono::steady_clock::now().time_since_epoch().count();
        fprintf(stderr, "[STRING-LOOP] sub_8262DD80 called %llu times (infinite loop?)\n", count);
        fflush(stderr);
    }

    // Check if CRT init loop breaking is enabled
    if (BreakCRTInitLoopEnabled()) {
        KernelTraceHostOpF("HOST.sub_8262DD80.break_crt_init lr=%08llX count=%llu", ctx.lr, count);

        // The function is supposed to format a string and call callbacks.
        // During early init, the callback table at 0x820009FC is not initialized.
        // Initialize the pointer to NULL so the loop is skipped.
        constexpr uint32_t callback_table_ptr_addr = 0x820009FC;
        uint8_t* ptr = static_cast<uint8_t*>(g_memory.Translate(callback_table_ptr_addr));
        if (ptr) {
            // Write NULL (big-endian)
            *reinterpret_cast<uint32_t*>(ptr) = 0;
            KernelTraceHostOpF("HOST.sub_8262DD80.init_callback_table addr=%08X val=0", callback_table_ptr_addr);
        }

        // Return early - the function's purpose is to format and output debug strings,
        // which we don't need during early init
        return;
    }

    // Call original
    __imp__sub_8262DD80(ctx, base);
}

// Wrapper for sub_8262DE60 - frame update function (NOT CRT init!)
// This is called from the main game loop and should NOT be skipped
PPC_FUNC_IMPL(__imp__sub_8262DE60);
PPC_FUNC(sub_8262DE60)
{
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    // DEEP DEBUG: Track what the main thread is doing
    static const bool s_deep_debug = [](){
        if (const char* v = std::getenv("MW05_DEEP_DEBUG"))
            return !(v[0]=='0' && v[1]=='\0');
        return false;
    }();

    // Check the sleep-skip flag at 0x82A1FF40 BEFORE calling the original
    // The main loop checks this address: if it's non-zero, it skips sleep and calls this function
    static std::atomic<uint64_t> s_lastLogCount{0};
    if (s_deep_debug || count < 10 || (count % 1000) == 0) {
        uint32_t sleepSkipFlag = PPC_LOAD_U32(0x82A1FF40);

        // Sample some key memory locations to see what's changing
        uint32_t titleState = PPC_LOAD_U32(0x8208F518);  // TitleState base
        uint32_t mainLoopFlag = PPC_LOAD_U32(0x82A2CF40);  // Main thread unblock flag

        KernelTraceHostOpF("HOST.sub_8262DE60.called lr=%08llX count=%llu sleepSkipFlag=%08X titleState=%08X mainLoopFlag=%08X",
                          ctx.lr, count, sleepSkipFlag, titleState, mainLoopFlag);
        s_lastLogCount.store(count, std::memory_order_release);
    }

    // Always call the original - this is the frame update function!
    // DO NOT skip this or the game won't render
    __imp__sub_8262DE60(ctx, base);

    // CRITICAL FIX: The game's main loop has a goto that should jump back to the sleep check,
    // but for some reason the goto is not being executed! As a workaround, we'll call the
    // sleep function directly from here to simulate the correct behavior.
    static const bool s_force_sleep_call = [](){
        if (const char* v = std::getenv("MW05_FORCE_SLEEP_CALL"))
            return !(v[0]=='0' && v[1]=='\0');
        return true;  // Enable by default!
    }();

    if (s_force_sleep_call) {
        // Call the sleep function directly to make the game sleep between frames
        // This is what SHOULD happen via the goto in the generated code, but doesn't
        ctx.r3.s64 = 0;  // Set r3 to 0 (sleep parameter)
        if (count < 10) {
            KernelTraceHostOpF("HOST.sub_8262DE60.calling_sleep_directly count=%llu", count);
        }
        __imp__sub_8262D9D0(ctx, base);  // Call sleep function directly!
    }
}

// REMOVED: sub_82813598 wrapper - causes infinite recursion
// The generated code uses PPC_WEAK_FUNC, so we can't call the "original"
// We would need to copy the entire generated function body here to add logging

// Event creation function (called by sub_82813598)
PPC_FUNC_IMPL(__imp__sub_82814068);
PPC_FUNC(sub_82814068)
{
    uint64_t r30_before = ctx.r30.u64;
    fprintf(stderr, "[INIT-FUNC] sub_82814068 CALLED - Initialization function!\n");
    fprintf(stderr, "[INIT-FUNC] r30 BEFORE call: 0x%016llX\n", r30_before);
    fflush(stderr);

    SetPPCContext(ctx);
    __imp__sub_82814068(ctx, base);

    fprintf(stderr, "[INIT-FUNC] r30 AFTER call: 0x%016llX\n", ctx.r30.u64);
    if (ctx.r30.u64 != r30_before) {
        fprintf(stderr, "[INIT-FUNC] !!! WARNING: r30 WAS MODIFIED BY sub_82814068! This will cause the trap to trigger!\n");
    }
    fprintf(stderr, "[INIT-FUNC] sub_82814068 RETURNED\n");
    fflush(stderr);
}

PPC_FUNC_IMPL(__imp__sub_8284E6C0);
PPC_FUNC(sub_8284E6C0)
{
    uint64_t r30_before = ctx.r30.u64;
    fprintf(stderr, "[EVENT-CREATE] sub_8284E6C0 CALLED - Event creation!\n");
    fprintf(stderr, "[EVENT-CREATE] r30 BEFORE call: 0x%016llX (should be 0x00000064 if mr r30,r3 executed!)\n", r30_before);
    fflush(stderr);

    SetPPCContext(ctx);
    __imp__sub_8284E6C0(ctx, base);

    fprintf(stderr, "[EVENT-CREATE] r30 AFTER call: 0x%016llX\n", ctx.r30.u64);
    if (ctx.r30.u64 != r30_before) {
        fprintf(stderr, "[EVENT-CREATE] !!! WARNING: r30 WAS MODIFIED BY sub_8284E6C0! This will cause the trap to trigger!\n");
    }
    fprintf(stderr, "[EVENT-CREATE] sub_8284E6C0 RETURNED\n");
    fflush(stderr);
}

// Worker thread shutdown function (sets qword_828F1F98 to 0 and waits for Thread #2 to exit)
PPC_FUNC_IMPL(__imp__sub_82813678);
PPC_FUNC(sub_82813678)
{
    fprintf(stderr, "[WORKER-SHUTDOWN] sub_82813678 CALLED - Worker thread shutdown!\n");
    fflush(stderr);

    SetPPCContext(ctx);
    __imp__sub_82813678(ctx, base);

    fprintf(stderr, "[WORKER-SHUTDOWN] sub_82813678 RETURNED\n");
    fflush(stderr);
}

// REMOVED: All PPC_FUNC wrappers that call __imp__... functions
// These cause infinite recursion because __imp__... functions don't exist
// The generated code uses PPC_WEAK_FUNC, so when we override with PPC_WEAK_FUNC,
// we completely replace the function - there's no "original" to call back to
//
// To add logging, we would need to:
// 1. Copy the entire generated function body into our override, OR
// 2. Use a different hooking mechanism that doesn't replace the function

PPC_FUNC_IMPL(__imp__sub_8262D998);
PPC_FUNC(sub_8262D998)
{
    // Address of the global flag that controls worker thread execution
    const uint32_t qword_828F1F98_addr = 0x828F1F98;
    uint8_t* qword_host = base + qword_828F1F98_addr;

    // Save the value of qword_828F1F98 before calling the function
    uint64_t saved_value = 0;
    if (qword_host) {
        uint64_t* qword_ptr = (uint64_t*)qword_host;
        saved_value = __builtin_bswap64(*qword_ptr);
        fprintf(stderr, "[sub_8262D998_wrapper] BEFORE call: qword_828F1F98 = 0x%016llX\n", saved_value);
        fflush(stderr);
    }

    SetPPCContext(ctx);
    __imp__sub_8262D998(ctx, base);

    // Restore qword_828F1F98 if it was corrupted
    if (qword_host) {
        uint64_t* qword_ptr = (uint64_t*)qword_host;
        uint64_t current_value = __builtin_bswap64(*qword_ptr);
        fprintf(stderr, "[sub_8262D998_wrapper] AFTER call: qword_828F1F98 = 0x%016llX (saved was 0x%016llX)\n", current_value, saved_value);
        fflush(stderr);
        // Always restore if the value changed and saved value was non-zero
        if (current_value != saved_value && saved_value != 0) {
            fprintf(stderr, "[sub_8262D998_wrapper] RESTORING qword_828F1F98 to 0x%016llX\n", saved_value);
            fflush(stderr);
            *qword_ptr = __builtin_bswap64(saved_value);
        }
    }
}

// sub_823AF590 wrapper is defined below (line 854+)
// Removed duplicate definition here

PPC_FUNC_IMPL(__imp__sub_8215D598);
PPC_FUNC(sub_8215D598) 
{
    fprintf(stderr, "[INIT-TRACE] sub_8215D598 ENTER\n"); fflush(stderr);
    SetPPCContext(ctx);
    __imp__sub_8215D598(ctx, base);
    fprintf(stderr, "[INIT-TRACE] sub_8215D598 RETURN\n"); fflush(stderr);
}

PPC_FUNC_IMPL(__imp__sub_8262D010);
PPC_FUNC(sub_8262D010) 
{
    fprintf(stderr, "[INIT-TRACE] sub_8262D010 ENTER\n"); fflush(stderr);
    SetPPCContext(ctx);
    __imp__sub_8262D010(ctx, base);
    fprintf(stderr, "[INIT-TRACE] sub_8262D010 RETURN\n"); fflush(stderr);
}

PPC_FUNC_IMPL(__imp__sub_8215E510); 
PPC_FUNC(sub_8215E510) 
{
    fprintf(stderr, "[INIT-TRACE] sub_8215E510 ENTER\n"); fflush(stderr);
    SetPPCContext(ctx);
    __imp__sub_8215E510(ctx, base);
    fprintf(stderr, "[INIT-TRACE] sub_8215E510 RETURN\n"); fflush(stderr);
}

PPC_FUNC_IMPL(__imp__sub_8245FBD0);
PPC_FUNC(sub_8245FBD0) 
{
    fprintf(stderr, "[INIT-TRACE] sub_8245FBD0 ENTER (this creates Thread #2)\n"); fflush(stderr);
    SetPPCContext(ctx);
    __imp__sub_8245FBD0(ctx, base);
    fprintf(stderr, "[INIT-TRACE] sub_8245FBD0 RETURN (Thread #2 should be running)\n"); fflush(stderr);
}

PPC_FUNC_IMPL(__imp__sub_823BCBF0);
PPC_FUNC(sub_823BCBF0) 
{
    fprintf(stderr, "[INIT-TRACE] sub_823BCBF0 ENTER (file check)\n"); fflush(stderr);
    SetPPCContext(ctx);
    __imp__sub_823BCBF0(ctx, base);
    fprintf(stderr, "[INIT-TRACE] sub_823BCBF0 RETURN r3=%08X\n", ctx.r3.u32); fflush(stderr);
}

PPC_FUNC_IMPL(__imp__sub_82812F10);
PPC_FUNC(sub_82812F10)
{
    fprintf(stderr, "[INIT-TRACE] sub_82812F10 ENTER\n"); fflush(stderr);
    SetPPCContext(ctx);
    __imp__sub_82812F10(ctx, base);
    fprintf(stderr, "[INIT-TRACE] sub_82812F10 RETURN\n"); fflush(stderr);
}

// Wrapper for sub_82630378 to log the handle parameter
PPC_FUNC_IMPL(__imp__sub_82630378);
PPC_FUNC(sub_82630378)
{
    // Just call the original implementation - logging removed for performance
    SetPPCContext(ctx);
    __imp__sub_82630378(ctx, base);
}

// NOTE: sub_8245FBD0 wrapper is already defined above (lines 805-812)

// NOTE: sub_826346A8 wrapper is already defined in mw05_boot_shims.cpp
// We'll add memory tracking there instead of creating a duplicate wrapper here

// Wrapper for sub_82813598 to fix qword_828F1F98 initialization
// This function manually sets qword_828F1F98 before/after calling the original function
// to work around a bug in the recompiled PPC code.
PPC_FUNC_IMPL(__imp__sub_82813598);
PPC_FUNC(sub_82813598)
{
    static int s_callCount = 0;
    int callNum = ++s_callCount;

    if (callNum <= 5) {
        fprintf(stderr, "[WRAPPER-82813598] Worker init function called! r3=0x%08X\n", ctx.r3.u32);
        fflush(stderr);
    }

    // The expected calculation: divw r9, 0xFF676980, r3
    // When r3 = 0x64 (100 decimal):
    // 0xFF676980 / 0x64 = 0xFFFE7960 (sign-extended to 64-bit: 0xFFFFFFFFFFFE7960)
    const int32_t dividend = (int32_t)0xFF676980;  // -9999488 in decimal
    const int32_t divisor = (int32_t)ctx.r3.u32;

    if (divisor == 0) {
        fprintf(stderr, "[WRAPPER-82813598] ERROR: divisor is 0! Cannot divide!\n");
        fflush(stderr);
        ctx.r3.u64 = 0;
        return;
    }

    const int64_t result = (int64_t)dividend / (int64_t)divisor;

    if (callNum <= 5) {
        fprintf(stderr, "[WRAPPER-82813598] Calculation: 0x%08X / 0x%08X = 0x%016llX\n",
                (uint32_t)dividend, (uint32_t)divisor, (uint64_t)result);
        fflush(stderr);
    }

    // Store the result into qword_828F1F98 BEFORE calling the original function
    const uint32_t qword_addr = 0x828F1F98;
    void* qword_ptr = g_memory.Translate(qword_addr);
    if (qword_ptr) {
        // Write new value (big-endian)
        uint64_t value_be = __builtin_bswap64((uint64_t)result);
        *(uint64_t*)qword_ptr = value_be;

        if (callNum <= 5) {
            fprintf(stderr, "[WRAPPER-82813598] qword_828F1F98 set to 0x%016llX\n", (uint64_t)result);
            fflush(stderr);
        }
    } else {
        fprintf(stderr, "[WRAPPER-82813598] ERROR: Failed to translate address 0x%08X\n", qword_addr);
        fflush(stderr);
    }

    // Call the original recompiled function to do the rest of the work
    if (callNum <= 5) {
        fprintf(stderr, "[WRAPPER-82813598] Calling original function...\n");
        fflush(stderr);
    }

    SetPPCContext(ctx);
    __imp__sub_82813598(ctx, base);

    if (callNum <= 5) {
        fprintf(stderr, "[WRAPPER-82813598] Original function returned, r3=0x%08X\n", ctx.r3.u32);
        fflush(stderr);
    }

    // Verify qword_828F1F98 is still set correctly after the original function returns
    if (qword_ptr) {
        uint64_t final_value = __builtin_bswap64(*(uint64_t*)qword_ptr);

        if (callNum <= 5) {
            fprintf(stderr, "[WRAPPER-82813598] FINAL: qword_828F1F98 = 0x%016llX\n", final_value);
            fflush(stderr);
        }

        if (final_value != (uint64_t)result) {
            fprintf(stderr, "[WRAPPER-82813598] WARNING: Value was corrupted! Restoring...\n");
            fflush(stderr);

            // Restore the value
            uint64_t value_be = __builtin_bswap64((uint64_t)result);
            *(uint64_t*)qword_ptr = value_be;

            fprintf(stderr, "[WRAPPER-82813598] Value restored to 0x%016llX\n", (uint64_t)result);
            fflush(stderr);
        }
    }
}

// Register the thread entry point hooks
// These wrapper functions are registered via g_memory.InsertFunction in main.cpp
// Do NOT use GUEST_FUNCTION_HOOK here as it causes redefinition errors with the recompiled PPC code
