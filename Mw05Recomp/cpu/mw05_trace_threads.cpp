// Trace MW05 thread entries and optionally kick minimal video init.

#include <cpu/ppc_context.h>
#include <kernel/trace.h>
#include <kernel/memory.h>
#include <kernel/heap.h>
#include "xbox.h"
#include <cstdlib>
#include <atomic>
#include <chrono>
#include <thread>
#include <kernel/trace.h>

extern std::atomic<uint32_t> g_watchEA;

extern "C" {
    void __imp__sub_828508A8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_82812ED0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_824411E0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_82442080(PPCContext& ctx, uint8_t* base);
    void __imp__sub_823AF590(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8262F2A0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8262D9D0(PPCContext& ctx, uint8_t* base);  // Sleep function called from main loop
    void __imp__sub_82813598(PPCContext& ctx, uint8_t* base);  // Worker thread initialization
    void __imp__sub_82813678(PPCContext& ctx, uint8_t* base);  // Worker thread shutdown

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
    void* ring_host = g_userHeap.Alloc(size_bytes, 0x100);
    if(!ring_host) return;
    const uint32_t ring_guest = g_memory.MapVirtual(ring_host);

    void* wb_host = g_userHeap.Alloc(64, 4);
    if(!wb_host) return;
    const uint32_t wb_guest = g_memory.MapVirtual(wb_host);

    // 3) Seed ring buffer state via host helpers
    VdInitializeRingBuffer(ring_guest, len_log2);
    VdEnableRingBufferRPtrWriteBack(wb_guest);
    VdSetSystemCommandBufferGpuIdentifierAddress(wb_guest + 8); // arbitrary within wb area
    VdInitializeEngines();
}

static std::atomic<bool> g_forcedGraphicsInit{false};

void sub_828508A8(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOp("HOST.ThreadEntry.828508A8.enter");
    fprintf(stderr, "[THREAD_828508A8] ENTER tid=%lx\n", GetCurrentThreadId());
    fflush(stderr);

    if(KickVideoInitEnabled()) KickMinimalVideo();
	if (ForceVdInitEnabled()) { Mw05ForceVdInitOnce(); Mw05LogIsrIfRegisteredOnce(); }

    fprintf(stderr, "[THREAD_828508A8] Calling __imp__sub_828508A8 tid=%lx\n", GetCurrentThreadId());
    fflush(stderr);
    __imp__sub_828508A8(ctx, base);

    fprintf(stderr, "[THREAD_828508A8] __imp__sub_828508A8 returned tid=%lx\n", GetCurrentThreadId());
    fflush(stderr);
    KernelTraceHostOp("HOST.ThreadEntry.828508A8.returned");

    // After the first thread completes, try forcing graphics init
    if (!g_forcedGraphicsInit.exchange(true, std::memory_order_acq_rel)) {
        fprintf(stderr, "[THREAD_828508A8] Checking MW05_FORCE_GRAPHICS_INIT tid=%lx\n", GetCurrentThreadId());
        fflush(stderr);

        if (const char* force = std::getenv("MW05_FORCE_GRAPHICS_INIT")) {
            fprintf(stderr, "[THREAD_828508A8] MW05_FORCE_GRAPHICS_INIT=%s tid=%lx\n", force, GetCurrentThreadId());
            fflush(stderr);

            if (!(force[0]=='0' && force[1]=='\0')) {
                KernelTraceHostOp("HOST.sub_828508A8.FORCE_GRAPHICS_INIT calling sub_823AF590");
                fprintf(stderr, "[FORCE_GFX_INIT] Calling sub_823AF590 from thread %lx\n", GetCurrentThreadId());
                fflush(stderr);

                // Call the graphics init function
                __imp__sub_823AF590(ctx, base);

                KernelTraceHostOp("HOST.sub_828508A8.FORCE_GRAPHICS_INIT sub_823AF590 returned");
                fprintf(stderr, "[FORCE_GFX_INIT] sub_823AF590 returned\n");
                fflush(stderr);
            }
        } else {
            fprintf(stderr, "[THREAD_828508A8] MW05_FORCE_GRAPHICS_INIT not set tid=%lx\n", GetCurrentThreadId());
            fflush(stderr);
        }
    }

    fprintf(stderr, "[THREAD_828508A8] EXIT tid=%lx\n", GetCurrentThreadId());
    fflush(stderr);
    KernelTraceHostOp("HOST.ThreadEntry.828508A8.exit");
}


void sub_82812ED0(PPCContext& ctx, uint8_t* base) {
    fprintf(stderr, "[WRAPPER_82812ED0] ENTER - wrapper is being called! r3=0x%08X\n", ctx.r3.u32);
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
void sub_8262DD80(PPCContext& ctx, uint8_t* base) {
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
void sub_8262DE60(PPCContext& ctx, uint8_t* base) {
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

// Wrapper for sub_8262D9D0 - sleep function called from main loop
// This is called when the sleep-skip flag at 0x82A1FF40 is ZERO
void sub_8262D9D0(PPCContext& ctx, uint8_t* base) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    // Log every call - this should be called if the sleep-skip flag is ZERO
    KernelTraceHostOpF("HOST.sub_8262D9D0.called lr=%08llX count=%llu r3=%08X",
                      ctx.lr, count, ctx.r3.u32);

    // Call the original
    __imp__sub_8262D9D0(ctx, base);
}

// Wrapper for sub_8262D9A0 - another sleep function
// NOTE: This function is not actually called in our implementation, but we keep the wrapper for logging
// void sub_8262D9A0(PPCContext& ctx, uint8_t* base) {
//     static std::atomic<uint64_t> s_callCount{0};
//     uint64_t count = s_callCount.fetch_add(1);

//     // Log every call
//     KernelTraceHostOpF("HOST.sub_8262D9A0.called lr=%08llX count=%llu r3=%08X",
//                       ctx.lr, count, ctx.r3.u32);

//     // Call the original
//     __imp__sub_8262D9A0(ctx, base);
// }

// Worker thread initialization function (sets up qword_828F1F98 and creates Thread #2)
void sub_82813598(PPCContext& ctx, uint8_t* base) {
    fprintf(stderr, "[WORKER-INIT] sub_82813598 CALLED - Worker thread initialization!\n");
    fprintf(stderr, "[WORKER-INIT] Parameters: r3=0x%08X (used for division!)\n", ctx.r3.u32);
    fprintf(stderr, "[WORKER-INIT] This function should:\n");
    fprintf(stderr, "[WORKER-INIT]   1. Create event (call sub_8284E6C0)\n");
    fprintf(stderr, "[WORKER-INIT]   2. Calculate: divw r9, 0xFF676980, r3 (r3 MUST be > 0!)\n");
    fprintf(stderr, "[WORKER-INIT]   3. Store r9 into qword_828F1F98\n");
    fprintf(stderr, "[WORKER-INIT]   4. Create Thread #2 (call sub_82813418)\n");

    // Check if r3 is valid for division
    if (ctx.r3.u32 == 0) {
        fprintf(stderr, "[WORKER-INIT] ERROR: r3 is 0! Division will fail and trap!\n");
        fprintf(stderr, "[WORKER-INIT] This will prevent qword_828F1F98 from being set!\n");
    } else {
        // Calculate what the value should be
        int32_t r10 = (int32_t)0xFF676980;
        int32_t r30 = (int32_t)ctx.r3.u32;
        int32_t r9 = r10 / r30;
        int64_t r11 = (int64_t)r9; // extsw - sign extend
        fprintf(stderr, "[WORKER-INIT] Expected calculation: 0x%08X / 0x%08X = 0x%08X (sign-extended: 0x%016llX)\n",
                (uint32_t)r10, (uint32_t)r30, (uint32_t)r9, (uint64_t)r11);
    }

    // Check qword_828F1F98 BEFORE initialization
    const uint32_t qword_addr = 0x828F1F98;
    void* qword_host = g_memory.Translate(qword_addr);
    if (qword_host) {
        uint64_t* qword_ptr = (uint64_t*)qword_host;
        uint64_t value_before = __builtin_bswap64(*qword_ptr);
        fprintf(stderr, "[WORKER-INIT] BEFORE: qword_828F1F98 = 0x%016llX\n", value_before);
    }

    // CRITICAL FIX: Manually set qword_828F1F98 BEFORE calling the original function
    // The recompiled code has a bug where the value is not stored correctly
    if (ctx.r3.u32 != 0 && qword_host) {
        int32_t dividend = (int32_t)0xFF676980;
        int32_t divisor = (int32_t)ctx.r3.u32;
        int64_t result = (int64_t)dividend / (int64_t)divisor;

        uint64_t* qword_ptr = (uint64_t*)qword_host;
        uint64_t value_be = __builtin_bswap64((uint64_t)result);
        *qword_ptr = value_be;

        fprintf(stderr, "[WORKER-INIT-FIX] Manually set qword_828F1F98 to 0x%016llX\n", (uint64_t)result);
        fflush(stderr);
    }

    fflush(stderr);

    SetPPCContext(ctx);

    // DEBUG: Check register values BEFORE calling the function
    fprintf(stderr, "[WORKER-INIT-DEBUG] BEFORE call: r3=0x%016llX r30=0x%016llX r31=0x%016llX\n",
            ctx.r3.u64, ctx.r30.u64, ctx.r31.u64);

    // DEBUG: Check the initialization flag value
    // Address: 0x82A384B0 (r29 + 5932, where r29 = 0x82A36D84, 5932 = 0x172C)
    uint32_t init_flag_addr = 0x82A384B0;
    uint8_t* init_flag_host = base + init_flag_addr;
    if (init_flag_host) {
        uint32_t* init_flag_ptr = (uint32_t*)init_flag_host;
        uint32_t init_flag_before = __builtin_bswap32(*init_flag_ptr);
        fprintf(stderr, "[WORKER-INIT-DEBUG] BEFORE call: init_flag at 0x%08X = 0x%08X\n", init_flag_addr, init_flag_before);
        if (init_flag_before != 0) {
            fprintf(stderr, "[WORKER-INIT-DEBUG] WARNING: init_flag is already set! Function will skip initialization!\n");
            fprintf(stderr, "[WORKER-INIT-DEBUG] This means qword_828F1F98 will NOT be set!\n");
        }
    }
    fflush(stderr);

    __imp__sub_82813598(ctx, base);

    // DEBUG: Check register values AFTER calling the function
    fprintf(stderr, "[WORKER-INIT-DEBUG] AFTER call: r9=0x%016llX r10=0x%016llX r11=0x%016llX r30=0x%016llX r31=0x%016llX\n",
            ctx.r9.u64, ctx.r10.u64, ctx.r11.u64, ctx.r30.u64, ctx.r31.u64);
    fprintf(stderr, "[WORKER-INIT-DEBUG] r9.s32=0x%08X r9.s64=0x%016llX\n",
            ctx.r9.u32, ctx.r9.u64);
    fprintf(stderr, "[WORKER-INIT-DEBUG] r10.s32=0x%08X r10.s64=0x%016llX\n",
            ctx.r10.u32, ctx.r10.u64);
    fprintf(stderr, "[WORKER-INIT-DEBUG] r11.s32=0x%08X r11.s64=0x%016llX\n",
            ctx.r11.u32, ctx.r11.u64);
    fprintf(stderr, "[WORKER-INIT-DEBUG] r30.s32=0x%08X r30.s64=0x%016llX\n",
            ctx.r30.u32, ctx.r30.u64);
    fflush(stderr);

    // Check qword_828F1F98 AFTER initialization
    if (qword_host) {
        uint64_t* qword_ptr = (uint64_t*)qword_host;
        uint64_t value_after = __builtin_bswap64(*qword_ptr);
        fprintf(stderr, "[WORKER-INIT] AFTER: qword_828F1F98 = 0x%016llX\n", value_after);
        if (value_after == 0) {
            fprintf(stderr, "[WORKER-INIT] ERROR: qword_828F1F98 is still 0! Recompiler fix didn't work!\n");
            fprintf(stderr, "[WORKER-INIT] Applying FINAL FIX - setting value AFTER original function returns...\n");

            // FINAL FIX: Set the value AFTER the original function returns
            // The original function overwrites it back to 0, so we restore it here
            if (ctx.r3.u32 != 0) {
                int32_t dividend = (int32_t)0xFF676980;
                int32_t divisor = (int32_t)ctx.r3.u32;
                int64_t result = (int64_t)dividend / (int64_t)divisor;

                uint64_t value_be = __builtin_bswap64((uint64_t)result);
                *qword_ptr = value_be;

                uint64_t verified = __builtin_bswap64(*qword_ptr);
                fprintf(stderr, "[WORKER-INIT-FINAL-FIX] Set qword_828F1F98 to 0x%016llX (verified: 0x%016llX)\n",
                        (uint64_t)result, verified);
                fflush(stderr);
            }
        } else {
            fprintf(stderr, "[WORKER-INIT] SUCCESS: qword_828F1F98 is set to non-zero value! Recompiler fix works!\n");
        }
    }

    fprintf(stderr, "[WORKER-INIT] sub_82813598 RETURNED\n");
    fflush(stderr);
}

// Event creation function (called by sub_82813598)
extern "C" void __imp__sub_82814068(PPCContext&, uint8_t*);
extern "C" void __imp__sub_8284E6C0(PPCContext&, uint8_t*);

void sub_82814068_wrapper(PPCContext& ctx, uint8_t* base) {
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

void sub_8284E6C0(PPCContext& ctx, uint8_t* base) {
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
void sub_82813678(PPCContext& ctx, uint8_t* base) {
    fprintf(stderr, "[WORKER-SHUTDOWN] sub_82813678 CALLED - Worker thread shutdown!\n");
    fflush(stderr);

    SetPPCContext(ctx);
    __imp__sub_82813678(ctx, base);

    fprintf(stderr, "[WORKER-SHUTDOWN] sub_82813678 RETURNED\n");
    fflush(stderr);
}

// sub_8262D998 wrapper - this function corrupts qword_828F1F98
// ROOT CAUSE: sub_8262D998 is called by sub_82813418 and overwrites qword_828F1F98
// FIX: Save and restore qword_828F1F98 around the call
extern "C" void __imp__sub_8262D998(PPCContext& ctx, uint8_t* base);
void sub_8262D998_wrapper(PPCContext& ctx, uint8_t* base) {
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

// Register the thread entry point hooks
// These wrapper functions are registered via g_memory.InsertFunction in main.cpp
// Do NOT use GUEST_FUNCTION_HOOK here as it causes redefinition errors with the recompiled PPC code
