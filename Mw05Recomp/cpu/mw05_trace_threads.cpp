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

    uint32_t Mw05PeekSchedulerBlockEA();
	void Mw05RegisterVdInterruptEvent(uint32_t eventEA, bool manualReset);
    void Mw05ForceVdInitOnce();
    void Mw05LogIsrIfRegisteredOnce();

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
	// Graphics context is at 0x40007180
	// r10 = *(0x40007180 + 10388) = *(0x40009994)
	// r30 = *(r10 + 16) - this is the function pointer
	const uint32_t gfx_ctx_ea = 0x40007180;
	uint32_t* gfx_ctx_ptr = static_cast<uint32_t*>(g_memory.Translate(gfx_ctx_ea + 10388));
	if (gfx_ctx_ptr) {
		uint32_t r10_value = __builtin_bswap32(*gfx_ctx_ptr);  // Big-endian
		fprintf(stderr, "[UNBLOCK-DEBUG] GFX context+10388 = %08X\n", r10_value);
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

// Workaround: Start a background thread that continuously sets the flag.
// The main thread at sub_82441CF0 waits for dword_82A2CF40 to become non-zero.
// This flag should be set by sub_82442080, but the initialization chain is never triggered.
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

	// Set the flag to 1 initially (big-endian)
	*flag_ptr = __builtin_bswap32(1);

	// Read it back to verify
	uint32_t readback = __builtin_bswap32(*flag_ptr);
	fprintf(stderr, "[UNBLOCK-DEBUG] Set flag ea=%08X to 1, readback=%u ptr=%p\n", flag_ea, readback, flag_ptr);
	fflush(stderr);
	KernelTraceHostOpF("HOST.UnblockMainThreadEarly set flag ea=%08X to 1, readback=%u ptr=%p", flag_ea, readback, flag_ptr);

	// Start background thread to keep setting the flag
	if (!g_unblockThreadRunning.exchange(true, std::memory_order_acq_rel)) {
		g_unblockThread = std::thread(UnblockThreadFunc);
		fprintf(stderr, "[UNBLOCK-DEBUG] Started background thread\n");
		fflush(stderr);
		KernelTraceHostOp("HOST.UnblockMainThreadEarly started background thread");
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
    __imp__sub_82812ED0(ctx, base);
}


// Thread entry point that should call sub_82442080 to set the main thread unblock flag
// This is a proper fix to replace the MW05_UNBLOCK_MAIN workaround
void sub_824411E0(PPCContext& ctx, uint8_t* base) {
    SetPPCContext(ctx);
    KernelTraceHostOpF("HOST.ThreadEntry.824411E0 r3=%08X r4=%08X", ctx.r3.u32, ctx.r4.u32);

    // This thread entry is responsible for calling sub_82442080 which sets dword_82A2CF40
    // The condition check in the original code (at 0x8244129C) looks at dword_828FBB50
    // and calls sub_82442080 when dword_828FBB50 == 1
    // We'll ensure the condition is met by setting it to 1 before calling the original function
    const uint32_t condition_flag_ea = 0x828FBB50;
    if (uint32_t* flag_ptr = static_cast<uint32_t*>(g_memory.Translate(condition_flag_ea))) {
        uint32_t current = __builtin_bswap32(*flag_ptr);
        KernelTraceHostOpF("HOST.ThreadEntry.824411E0 condition_flag ea=%08X current=%u", condition_flag_ea, current);

        // Set the condition flag to 1 to ensure sub_82442080 gets called
        // This will cause the code path at 0x824412A8 to execute: bl sub_82442080
        *flag_ptr = __builtin_bswap32(1);
        KernelTraceHostOpF("HOST.ThreadEntry.824411E0 set condition_flag to 1");
    }

    __imp__sub_824411E0(ctx, base);
    KernelTraceHostOp("HOST.ThreadEntry.824411E0 complete");
}

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

// Register the thread entry point hooks
// These wrapper functions are registered via g_memory.InsertFunction in main.cpp
// Do NOT use GUEST_FUNCTION_HOOK here as it causes redefinition errors with the recompiled PPC code
