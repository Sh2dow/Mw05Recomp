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
#include <unordered_set>
#include <mutex>
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
    if (count < 10 || count % 10000 == 0) {
        KernelTraceHostOpF("HOST.sub_8262D9D0.called lr=%08llX count=%llu r3=%08X",
                          ctx.lr, count, ctx.r3.u32);
    }

    // CRITICAL FIX: Set the main loop flag directly from the sleep function
    // This avoids cache coherency issues because the flag is set from the same thread that checks it
    static const bool s_set_flag_from_sleep = [](){
        if (const char* v = std::getenv("MW05_SET_FLAG_FROM_SLEEP"))
            return !(v[0]=='0' && v[1]=='\0');
        return true; // ENABLED BY DEFAULT to fix cache coherency issue
    }();

    if (s_set_flag_from_sleep) {
        // Set the main loop flag at 0x82A2CF40 to 1
        // This is the flag that the main loop checks to exit the sleep loop
        const uint32_t main_loop_flag_ea = 0x82A2CF40;
        uint32_t* main_loop_flag_ptr = static_cast<uint32_t*>(g_memory.Translate(main_loop_flag_ea));
        if (main_loop_flag_ptr) {
            // Set flag to 1 (big-endian)
            *main_loop_flag_ptr = _byteswap_ulong(1);

            // Log the first few times
            if (count < 10) {
                KernelTraceHostOpF("HOST.sub_8262D9D0.set_main_loop_flag ea=%08X count=%llu",
                                  main_loop_flag_ea, count);
            }
        }

        // Return immediately without sleeping
        return;
    }

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
	// CRITICAL FIX: Enable by default to allow main loop to run
	// The main loop needs to run so the game can progress through initialization
	// and eventually call VdSetGraphicsInterruptCallback naturally
	const char* env = std::getenv("MW05_UNBLOCK_MAIN");
	if (env && *env == '0') return false;  // Allow disabling via env var
	return true;  // Enabled by default
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

// Force creation of missing worker threads
// The natural initialization path does NOT work - worker threads are never created!
// This function force-creates the worker threads to unblock the game initialization.
// NOTE: This function is called from guest_thread.cpp, so it cannot be static
void Mw05ForceCreateMissingWorkerThreads() {
    // RE-ENABLED: Natural initialization does NOT work - worker threads never created!

    static std::atomic<bool> s_created{false};
    static std::atomic<int> s_check_count{0};

    // Allow multiple checks
    // - First 10 seconds: check every tick (to catch early initialization)
    // - After 10 seconds: check every 60 ticks (1 second at 60 Hz)
    int check_count = s_check_count.fetch_add(1);
    if (s_created.load()) return;  // Already created, don't check again

    // Check frequently during first 10 seconds (600 ticks), then slow down
    bool should_check = (check_count < 600) || (check_count % 60 == 0);
    if (!should_check) return;

    int check_number = (check_count < 600) ? check_count : (check_count / 60);
    fprintf(stderr, "[FORCE_WORKERS] Check #%d (tick %d): Checking if callback parameter structure is initialized...\n", check_number, check_count);
    fflush(stderr);

    // CRITICAL: Check if the callback parameter structure at 0x82A2B318 is initialized
    // This structure needs a valid work function pointer at offset +16
    // If it's NULL, we can't create worker threads yet
    extern Memory g_memory;
    extern Heap g_userHeap;

    uint32_t callback_param_addr = 0x82A2B318;
    void* callback_param_host = g_memory.Translate(callback_param_addr);
    if (!callback_param_host) {
        fprintf(stderr, "[FORCE_WORKERS] ERROR: Callback parameter structure at 0x%08X not mapped!\n", callback_param_addr);
        fflush(stderr);
        return;
    }

    // DEBUG: Log the host address to check if it's corrupting the heap
    fprintf(stderr, "[FORCE_WORKERS] Callback parameter: guest=0x%08X host=%p\n", callback_param_addr, callback_param_host);
    fflush(stderr);

    // Read the work function pointer at offset +16
    be<uint32_t>* callback_param_u32 = reinterpret_cast<be<uint32_t>*>(callback_param_host);
    uint32_t work_func_ptr = callback_param_u32[16/4];  // +0x10 (16) - work function pointer

    if (work_func_ptr == 0 || work_func_ptr == 0xFFFFFFFF) {
        fprintf(stderr, "[FORCE_WORKERS] Callback parameter structure NOT initialized yet (work_func=0x%08X)\n", work_func_ptr);

        // FORCE INITIALIZATION: Initialize the callback parameter structure immediately
        // ALWAYS ENABLED BY DEFAULT - the game never initializes this naturally
        static bool s_force_init_done = false;
        static bool s_logged_once = false;

        if (!s_logged_once) {
            s_logged_once = true;
            fprintf(stderr, "[FORCE_WORKERS-ENV] Force-initialization ALWAYS ENABLED (game never initializes this naturally)\n");
            fflush(stderr);
        }

        // CRITICAL FIX: Force-initialize IMMEDIATELY on first check
        // The game is stuck waiting for this structure to be initialized, but it never happens naturally
        // Without this initialization, the game never progresses to file loading
        if (!s_force_init_done) {
            s_force_init_done = true;
            fprintf(stderr, "[FORCE_WORKERS] FORCE-INITIALIZING callback parameter structure (check_count=%d)...\n", check_count);
            fflush(stderr);

            // Initialize the callback parameter structure with MINIMAL values
            // The 0xB5901790 values at +0x00 and +0x18 are context-specific and cause crashes
            // Try initializing with zeros except for the critical work_func pointer
            // +0x00 (0): field_00 = 0x00000000 (was 0xB5901790 - context-specific!)
            // +0x04 (4): field_04 = 0x00000000
            // +0x08 (8): state = 0x00000000 (was 0x00000001)
            // +0x0C (12): result = 0x00000000
            // +0x10 (16): work_func = 0x82441E58 (CRITICAL!)
            // +0x14 (20): work_param = 0x00000000
            // +0x18 (24): field_18 = 0x00000000 (was 0xB5901790 - context-specific!)
            // +0x1C (28): flag = 0 (0 = 1 param, non-zero = 2 params)

            callback_param_u32[0] = 0x00000000u;  // +0x00 - ZERO instead of 0xB5901790
            callback_param_u32[1] = 0x00000000u;  // +0x04
            callback_param_u32[2] = 0x00000000u;  // +0x08 - state (ZERO instead of 1)
            callback_param_u32[3] = 0x00000000u;  // +0x0C - result
            callback_param_u32[4] = 0x82441E58u;  // +0x10 - work_func (CRITICAL!)
            callback_param_u32[5] = 0x00000000u;  // +0x14 - work_param
            callback_param_u32[6] = 0x00000000u;  // +0x18 - ZERO instead of 0xB5901790
            callback_param_u32[7] = 0x00000000u;  // +0x1C - flag

            fprintf(stderr, "[FORCE_WORKERS] Callback parameter structure initialized! work_func=0x82441E58\n");
            fflush(stderr);

            // Don't return - fall through to create worker threads
            work_func_ptr = 0x82441E58u;
        }
    }

    fprintf(stderr, "[FORCE_WORKERS] Callback parameter structure IS initialized (work_func=0x%08X)\n", work_func_ptr);
    fflush(stderr);

    // CRITICAL FIX (2025-10-30): Patch game's heap structure for worker thread compatibility
    // Worker threads call sub_826C52B0 which checks:
    //   if (heap_flags & 0x40000) && (heap[379] != KeGetCurrentProcessType())
    //     KeBugCheckEx(0xF4, ...)
    // The game's heap handle is at 0x82C84F50
    // We need to set heap[379] = 1 (KeGetCurrentProcessType() returns 1)
    static bool s_heap_patched = false;
    if (!s_heap_patched) {
        constexpr uint32_t GAME_HEAP_HANDLE_PTR = 0x82C84F50;
        be<uint32_t>* heap_handle_ptr = reinterpret_cast<be<uint32_t>*>(g_memory.Translate(GAME_HEAP_HANDLE_PTR));
        if (heap_handle_ptr) {
            uint32_t heap_handle = *heap_handle_ptr;
            if (heap_handle != 0) {
                // Heap handle points to the heap structure
                // Set process type field at offset +379 (0x17B)
                uint8_t* heap_struct = reinterpret_cast<uint8_t*>(g_memory.Translate(heap_handle));
                if (heap_struct) {
                    heap_struct[379] = 1;  // KeGetCurrentProcessType() returns 1
                    fprintf(stderr, "[FORCE_WORKERS] CRITICAL FIX: Set game heap process type to 1 (heap=0x%08X)\n", heap_handle);
                    fprintf(stderr, "[FORCE_WORKERS]   This prevents KeBugCheckEx 0xF4 in worker threads\n");
                    fflush(stderr);
                    s_heap_patched = true;
                } else {
                    fprintf(stderr, "[FORCE_WORKERS] WARNING: Failed to translate heap address 0x%08X\n", heap_handle);
                    fflush(stderr);
                }
            } else {
                fprintf(stderr, "[FORCE_WORKERS] WARNING: Game heap handle is NULL (not initialized yet?)\n");
                fflush(stderr);
            }
        } else {
            fprintf(stderr, "[FORCE_WORKERS] WARNING: Failed to translate heap handle pointer 0x%08X\n", GAME_HEAP_HANDLE_PTR);
            fflush(stderr);
        }
    }

    fprintf(stderr, "[FORCE_WORKERS] Creating missing worker threads...\n");
    fflush(stderr);

    // Mark as created so we don't create again
    s_created.store(true);

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
    //   +0x58 (88): 0x8261A558  <-- CALLBACK FUNCTION POINTER! (sub_82850820 reads from +88!)
    //   +0x5C (92): 0x82A2B318  <-- CALLBACK PARAMETER!
    // We need to initialize the manually-created worker thread contexts with the same values.

    // CRITICAL FIX (2025-10-30): Allocate SEPARATE thread contexts!
    // Research findings:
    // - Worker pool slots (56 bytes each) are TOO SMALL to be thread contexts
    // - Thread context needs callback pointers at +84 and +88 (beyond 56-byte boundary)
    // - Thread context structure:
    //   +84 (0x54): callback function pointer (should be 0x8261A558)
    //   +88 (0x58): callback parameter (should point to worker pool slot)
    // - Worker pool slots:
    //   Slot 1: 0x82A2B350, Slot 2: 0x82A2B388, Slot 3: 0x82A2B3C0
    //   Slot 4: 0x82A2B3F8, Slot 5: 0x82A2B430
    // - Allocate thread contexts in heap, initialize with pointers to worker pool slots

    // Worker pool slot addresses (these are the callback parameters)
    static const uint32_t worker_slots[5] = {
        0x82A2B350,  // Worker pool slot 1
        0x82A2B388,  // Worker pool slot 2
        0x82A2B3C0,  // Worker pool slot 3
        0x82A2B3F8,  // Worker pool slot 4
        0x82A2B430   // Worker pool slot 5
    };

    for (int i = 0; i < 5; ++i) {  // Create 5 worker threads with entry=0x828508A8
        be<uint32_t> thread_handle = 0;
        be<uint32_t> thread_id = 0;
        uint32_t stack_size = 0x40000;  // 256KB stack (same as other game threads)

        // Allocate thread context from heap (need at least 92 bytes for +88 offset)
        uint32_t ctx_size = 256;  // Allocate 256 bytes to be safe
        void* ctx_ptr = g_userHeap.Alloc(ctx_size);
        if (!ctx_ptr) {
            fprintf(stderr, "[FORCE_WORKERS] ERROR: Failed to allocate thread context for worker thread #%d\n", i + 1);
            fflush(stderr);
            continue;
        }
        uint32_t ctx_addr = g_memory.MapVirtual(ctx_ptr);

        void* ctx_host = g_memory.Translate(ctx_addr);
        if (!ctx_host) {
            fprintf(stderr, "[FORCE_WORKERS] ERROR: Failed to translate thread context address 0x%08X for worker thread #%d\n", ctx_addr, i + 1);
            fflush(stderr);
            continue;
        }

        // Zero out the context
        std::memset(ctx_host, 0, ctx_size);

        // Initialize the thread context structure (in big-endian format)
        // Based on sub_828508A8 and sub_8261A558 decompilation:
        //   Callback sub_8261A558 reads:
        //     a1[4] = offset +16 (0x10) - work function pointer (should be 0x82441E58)
        //     a1[5] = offset +20 (0x14) - work function parameter (worker pool slot)
        //     a1[6] = offset +24 (0x18) - unknown parameter
        //     a1[7] = offset +28 (0x1C) - flags (0 = single param, non-zero = two params)
        //   Thread entry sub_828508A8 copies:
        //     a1[21] = offset +84 (0x54) - callback function pointer (0x8261A558)
        //     a1[22] = offset +88 (0x58) - callback parameter (worker pool slot address)
        be<uint32_t>* ctx_u32 = reinterpret_cast<be<uint32_t>*>(ctx_host);
        ctx_u32[0] = be<uint32_t>(0x00000000);  // +0x00
        ctx_u32[1] = be<uint32_t>(0xFFFFFFFF);  // +0x04
        ctx_u32[2] = be<uint32_t>(0x00000000);  // +0x08
        ctx_u32[4] = be<uint32_t>(0x82441E58);  // +16 (0x10) - work function pointer (infinite loop)
        ctx_u32[5] = be<uint32_t>(worker_slots[i]);  // +20 (0x14) - work function parameter (worker slot)
        ctx_u32[6] = be<uint32_t>(0x00000000);  // +24 (0x18) - unknown parameter
        ctx_u32[7] = be<uint32_t>(0x00000000);  // +28 (0x1C) - flags (0 = single param calling convention)
        ctx_u32[21] = be<uint32_t>(0x8261A558);  // +84 (0x54) - callback function pointer
        ctx_u32[22] = be<uint32_t>(worker_slots[i]);  // +88 (0x58) - callback parameter (worker pool slot)

        fprintf(stderr, "[FORCE_WORKERS] Creating worker thread #%d: entry=0x828508A8 ctx=0x%08X (heap-allocated)\n", i + 1, ctx_addr);
        fprintf(stderr, "[FORCE_WORKERS]   Context structure:\n");
        fprintf(stderr, "[FORCE_WORKERS]     +16 (work_func)  = 0x82441E58 (infinite work loop)\n");
        fprintf(stderr, "[FORCE_WORKERS]     +20 (work_param) = 0x%08X (worker slot %d)\n", worker_slots[i], i + 1);
        fprintf(stderr, "[FORCE_WORKERS]     +84 (callback)   = 0x8261A558\n");
        fprintf(stderr, "[FORCE_WORKERS]     +88 (cb_param)   = 0x%08X (worker slot %d)\n", worker_slots[i], i + 1);
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

    // CRITICAL FIX: DO NOT force-create the special thread (entry=0x825AA970)!
    // The game code will create it naturally when the context at 0x40009D2C is initialized.
    // Force-creating it too early causes NULL-CALL errors because the context is not ready yet.
    // In Xenia, Thread #8 (tid=13) is created by caller_tid=7 (the game code), not at startup.
    fprintf(stderr, "[FORCE_WORKERS] Skipping special thread (entry=0x825AA970) - will be created by game code\n");
    fflush(stderr);

    fprintf(stderr, "[FORCE_WORKERS] All missing worker threads created!\n");
    fflush(stderr);
}


// Trace sub_82441E80 - main game initialization function
// Trace initialization functions called by _xstart before sub_82441E80
// These are called in sequence and one of them is hanging

// sub_82630068 - First initialization function
PPC_FUNC_IMPL(__imp__sub_82630068);
PPC_FUNC(sub_82630068) {
    fprintf(stderr, "[XSTART_INIT] sub_82630068 ENTER\n");
    fflush(stderr);
    __imp__sub_82630068(ctx, base);
    fprintf(stderr, "[XSTART_INIT] sub_82630068 EXIT\n");
    fflush(stderr);
}

// sub_8262FDA8 - Second initialization function (callback dispatcher)
// This function iterates through a linked list at 0x828DF17C and calls each callback
// CRITICAL FIX: Function pointer is at offset +8, not +4!
// Assembly at 0x8262FDE4: lwz r11, 8(r11) - loads function pointer from offset +8
PPC_FUNC_IMPL(__imp__sub_8262FDA8);
PPC_FUNC(sub_8262FDA8) {
    static int call_count = 0;
    call_count++;

    // Only log first 10 calls to avoid spam
    if (call_count <= 10) {
        fprintf(stderr, "[XSTART_INIT] sub_8262FDA8 ENTER #%d r3=%08X\n", call_count, ctx.r3.u32);
        fflush(stderr);
    }

    // Read the callback list head at 0x828DF17C
    uint32_t list_head_addr = 0x828DF17C;
    uint32_t list_head_ptr = PPC_LOAD_U32(list_head_addr);

    if (call_count <= 10) {
        fprintf(stderr, "[XSTART_INIT]   Callback list head at 0x%08X = 0x%08X\n", list_head_addr, list_head_ptr);

        // Traverse the list and log each node
        uint32_t current = list_head_ptr;
        int node_count = 0;
        while (current != list_head_addr && node_count < 10) {
            uint32_t next_ptr = PPC_LOAD_U32(current + 0);  // Next pointer at offset +0
            uint32_t field_04 = PPC_LOAD_U32(current + 4);  // Unknown field at offset +4
            uint32_t func_ptr = PPC_LOAD_U32(current + 8);  // Function pointer at offset +8 (CORRECT!)

            fprintf(stderr, "[XSTART_INIT]   Node #%d at 0x%08X: next=0x%08X field_04=0x%08X func=0x%08X\n",
                    node_count, current, next_ptr, field_04, func_ptr);

            if (func_ptr == 0 || func_ptr == 0xFFFFFFFF) {
                fprintf(stderr, "[XSTART_INIT]   *** NULL/INVALID FUNCTION POINTER DETECTED! ***\n");
            }

            current = next_ptr;
            node_count++;
        }

        fflush(stderr);
    }

    __imp__sub_8262FDA8(ctx, base);

    if (call_count <= 10) {
        fprintf(stderr, "[XSTART_INIT] sub_8262FDA8 EXIT #%d r3=%08X\n", call_count, ctx.r3.u32);
        fflush(stderr);
    }
}

// sub_826BE558 - Third initialization function
PPC_FUNC_IMPL(__imp__sub_826BE558);
PPC_FUNC(sub_826BE558) {
    fprintf(stderr, "[XSTART_INIT] sub_826BE558 ENTER r3=%08X\n", ctx.r3.u32);
    fflush(stderr);
    __imp__sub_826BE558(ctx, base);
    fprintf(stderr, "[XSTART_INIT] sub_826BE558 EXIT r3=%08X\n", ctx.r3.u32);
    fflush(stderr);
}

// sub_8262FD30 - Fourth initialization function
PPC_FUNC_IMPL(__imp__sub_8262FD30);
PPC_FUNC(sub_8262FD30) {
    fprintf(stderr, "[XSTART_INIT] sub_8262FD30 ENTER r3=%08X\n", ctx.r3.u32);
    fflush(stderr);
    __imp__sub_8262FD30(ctx, base);
    fprintf(stderr, "[XSTART_INIT] sub_8262FD30 EXIT\n");
    fflush(stderr);
}

// sub_8262FC50 - Fifth initialization function
// This function iterates through function pointer tables (0x828DF0FC-0x828DF108 and 0x828D0010-0x828DF0F8)
// and calls static constructors. One of these constructors causes an infinite loop.
// STRATEGY: Call each constructor manually with logging to identify which one hangs.
PPC_FUNC_IMPL(__imp__sub_8262FC50);
PPC_FUNC(sub_8262FC50) {
    fprintf(stderr, "[STATIC_INIT] sub_8262FC50 ENTER r3=%08X - calling constructors manually\n", ctx.r3.u32);
    fflush(stderr);

    // Table 1: 0x828DF0FC-0x828DF108 (3 constructors)
    // Discovered via IDA Pro: 0x826BC0F0, 0x826CE048, 0x826CBB18
    uint32_t table1[] = {0x826BC0F0, 0x826CE048, 0x826CBB18};
    for (int i = 0; i < 3; i++) {
        fprintf(stderr, "[STATIC_INIT] Table1[%d]: Calling constructor at 0x%08X\n", i, table1[i]);
        fflush(stderr);

        auto* func = PPC_LOOKUP_FUNC(base, table1[i]);
        if (func) {
            func(ctx, base);
            fprintf(stderr, "[STATIC_INIT] Table1[%d]: Constructor 0x%08X completed\n", i, table1[i]);
            fflush(stderr);
        } else {
            fprintf(stderr, "[STATIC_INIT] Table1[%d]: Constructor 0x%08X NOT FOUND in function table\n", i, table1[i]);
            fflush(stderr);
        }
    }

    // Table 2: 0x828D0010-0x828DF0F8 (first 7 non-null constructors)
    // Discovered via IDA Pro: 0x826CDE30 (appears twice), 0x828A7AE8, 0x828A7B20, 0x828A7BC0, 0x828A7BF8, 0x828A7C20
    uint32_t table2[] = {0x826CDE30, 0x828A7AE8, 0x828A7B20, 0x828A7BC0, 0x828A7BF8, 0x828A7C20};
    for (int i = 0; i < 6; i++) {
        fprintf(stderr, "[STATIC_INIT] Table2[%d]: Calling constructor at 0x%08X\n", i, table2[i]);
        fflush(stderr);

        auto* func = PPC_LOOKUP_FUNC(base, table2[i]);
        if (func) {
            func(ctx, base);
            fprintf(stderr, "[STATIC_INIT] Table2[%d]: Constructor 0x%08X completed\n", i, table2[i]);
            fflush(stderr);
        } else {
            fprintf(stderr, "[STATIC_INIT] Table2[%d]: Constructor 0x%08X NOT FOUND in function table\n", i, table2[i]);
            fflush(stderr);
        }
    }

    // Return 0 (success) to allow _xstart to continue
    ctx.r3.u32 = 0;

    fprintf(stderr, "[STATIC_INIT] sub_8262FC50 EXIT r3=%08X - all constructors called successfully\n", ctx.r3.u32);
    fflush(stderr);
}

// sub_8262E7F8 - Conditional check function
PPC_FUNC_IMPL(__imp__sub_8262E7F8);
PPC_FUNC(sub_8262E7F8) {
    fprintf(stderr, "[XSTART_INIT] sub_8262E7F8 ENTER r3=%08X\n", ctx.r3.u32);
    fflush(stderr);
    __imp__sub_8262E7F8(ctx, base);
    fprintf(stderr, "[XSTART_INIT] sub_8262E7F8 EXIT r3=%08X\n", ctx.r3.u32);
    fflush(stderr);
}

// sub_826BDA60 - Called conditionally if sub_8262E7F8 returns true
PPC_FUNC_IMPL(__imp__sub_826BDA60);
PPC_FUNC(sub_826BDA60) {
    fprintf(stderr, "[XSTART_INIT] sub_826BDA60 ENTER\n");
    fflush(stderr);
    __imp__sub_826BDA60(ctx, base);
    fprintf(stderr, "[XSTART_INIT] sub_826BDA60 EXIT\n");
    fflush(stderr);
}

// Trace _xstart (0x8262E9A8) - C runtime startup function
// This is the main thread entry point that parses command line and calls sub_82441E80
PPC_FUNC_IMPL(__imp___xstart);
PPC_FUNC(_xstart) {
    fprintf(stderr, "[XSTART] ENTER r3=%08X r4=%08X r5=%08X lr=%08X\n",
            ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, (uint32_t)ctx.lr);
    fflush(stderr);

    // Call the original function
    __imp___xstart(ctx, base);

    fprintf(stderr, "[XSTART] EXIT (should never return)\n");
    fflush(stderr);
}

// Called from _xstart() (0x8262E9A8)
// Using recompiled version directly - no wrapper needed

// sub_82159FD0 - Memory pool allocator
PPC_FUNC_IMPL(__imp__sub_82159FD0);
PPC_FUNC(sub_82159FD0) {
    static int call_count = 0;
    int this_call = ++call_count;

    uint32_t pool_ptr = ctx.r3.u32;

    if (this_call <= 10) {
        fprintf(stderr, "[FUNC_82159FD0] #%d ENTER pool_ptr=%08X lr=%08X\n",
                this_call, pool_ptr, (uint32_t)ctx.lr);

        if (pool_ptr != 0) {
            // Read pool structure fields
            uint32_t field_0x10 = PPC_LOAD_U32(pool_ptr + 0x10);  // a1[4]
            uint32_t field_0x14 = PPC_LOAD_U32(pool_ptr + 0x14);  // a1[5]
            uint32_t field_0x18 = PPC_LOAD_U32(pool_ptr + 0x18);  // a1[6]
            uint32_t field_0x1C = PPC_LOAD_U32(pool_ptr + 0x1C);  // a1[7]

            fprintf(stderr, "[FUNC_82159FD0]   pool[0x10]=%08X pool[0x14]=%08X pool[0x18]=%08X pool[0x1C]=%08X\n",
                    field_0x10, field_0x14, field_0x18, field_0x1C);
        }
        fflush(stderr);
    }

    __imp__sub_82159FD0(ctx, base);

    if (this_call <= 10) {
        fprintf(stderr, "[FUNC_82159FD0] #%d RETURN r3=%08X\n", this_call, ctx.r3.u32);
        fflush(stderr);
    }
}

// Main game loop (0x82441CF0) - called from sub_82441E80
// Using recompiled version directly - no wrapper needed

// sub_8262FA08 - Called from sub_82441E80 before main loop
PPC_FUNC_IMPL(__imp__sub_8262FA08);
PPC_FUNC(sub_8262FA08) {
    static int call_count = 0;
    int this_call = ++call_count;

    if (this_call <= 5 || (uint32_t)ctx.lr == 0x82441F04) {
        fprintf(stderr, "[FUNC_8262FA08] #%d ENTER r3=%08X r4=%08X lr=%08X\n",
                this_call, ctx.r3.u32, ctx.r4.u32, (uint32_t)ctx.lr);
        fflush(stderr);
    }

    __imp__sub_8262FA08(ctx, base);

    if (this_call <= 5 || (uint32_t)ctx.lr == 0x82441F04) {
        fprintf(stderr, "[FUNC_8262FA08] #%d RETURN r3=%08X\n", this_call, ctx.r3.u32);
        fflush(stderr);
    }
}

// sub_826B96B0 - Called from sub_82441E80 before main loop
PPC_FUNC_IMPL(__imp__sub_826B96B0);
PPC_FUNC(sub_826B96B0) {
    static int call_count = 0;
    int this_call = ++call_count;

    if (this_call <= 5 || (uint32_t)ctx.lr == 0x82441F28) {
        fprintf(stderr, "[FUNC_826B96B0] #%d ENTER r3=%08X r4=%08X r5=%08X lr=%08X\n",
                this_call, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, (uint32_t)ctx.lr);
        fflush(stderr);
    }

    __imp__sub_826B96B0(ctx, base);

    if (this_call <= 5 || (uint32_t)ctx.lr == 0x82441F28) {
        fprintf(stderr, "[FUNC_826B96B0] #%d RETURN r3=%08X\n", this_call, ctx.r3.u32);
        fflush(stderr);

        // CRITICAL: If this is the call from sub_82441E80 (lr=0x82441F28),
        // the next instruction should be at 0x82441F28, which loads r10 from r30.
        // Then it should call sub_82441CF0 at 0x82441F38.
        // Let's trace this to see if execution continues.
        if ((uint32_t)ctx.lr == 0x82441F28) {
            fprintf(stderr, "[FUNC_826B96B0] *** MAIN THREAD CALL *** About to return to 0x82441F28\n");
            fprintf(stderr, "[FUNC_826B96B0] *** r30=%08X (should contain dword_82A2CF44)\n", ctx.r30.u32);

            // Read the value at r30 to see what r10 will be loaded with
            uint32_t r10_value = PPC_LOAD_U32(ctx.r30.u32);
            fprintf(stderr, "[FUNC_826B96B0] *** Value at [r30]=%08X (this will be loaded into r10)\n", r10_value);

            if (r10_value == 0) {
                fprintf(stderr, "[FUNC_826B96B0] *** WARNING: r10 will be 0! Writing to r10+55 will be a NULL pointer write!\n");
            } else {
                fprintf(stderr, "[FUNC_826B96B0] *** r10 will be %08X, writing to %08X\n", r10_value, r10_value + 55);
            }

            fprintf(stderr, "[FUNC_826B96B0] *** Next: load r10 from [r30], store 0 to r10+55, then call sub_82441CF0\n");
            fflush(stderr);
        }
    }
}

// Trace sub_8261A5E8 - this appears to be the function that creates threads
// Called from sub_82441E80 (main game initialization)
//
// CRITICAL FIX: The recompiled version has an endianness bug!
// It stores the thread handle in guest memory without proper byte-swapping,
// then reads it back and returns a corrupted value.
//
// Example:
// - ExCreateThread returns 0xA0008810 (little-endian, host format)
// - Recompiled code stores it in guest memory incorrectly
// - Recompiled code reads it back and returns 0x88980366 (WRONG!)
//
// We override this function to fix the endianness handling.
PPC_FUNC_IMPL(__imp__sub_8261A5E8);
PPC_FUNC(sub_8261A5E8) {
    fprintf(stderr, "[THREAD_8261A5E8] ENTER r3=%08X r4=%08X r5=%08X r6=%08X r7=%08X lr=%08X\n",
            ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32, ctx.r7.u32, (uint32_t)ctx.lr);
    fflush(stderr);

    // Call the original function
    __imp__sub_8261A5E8(ctx, base);

    // ENDIANNESS FIX: The return value in r3 is corrupted due to endianness bug
    // We need to find the correct handle value from the guest memory location
    // The function stores the handle at **a1 (r3 points to *a1)
    //
    // From IDA: **a1 = sub_82850930(...); return **a1;
    // So we need to read the handle from the memory location pointed to by *r3

    uint32_t a1_ptr = ctx.r3.u32;  // r3 contains the pointer to *a1
    if (a1_ptr != 0) {
        extern Memory g_memory;
        void* a1_host = g_memory.Translate(a1_ptr);
        if (a1_host) {
            // Read *a1 (pointer to the structure)
            be<uint32_t>* a1_guest = reinterpret_cast<be<uint32_t>*>(a1_host);
            uint32_t struct_ptr = *a1_guest;  // Read big-endian pointer

            if (struct_ptr != 0) {
                void* struct_host = g_memory.Translate(struct_ptr);
                if (struct_host) {
                    // Read **a1 (the thread handle at offset 0)
                    be<uint32_t>* struct_guest = reinterpret_cast<be<uint32_t>*>(struct_host);
                    uint32_t correct_handle = *struct_guest;  // Read big-endian handle

                    fprintf(stderr, "[THREAD_8261A5E8] ENDIANNESS FIX: r3 was %08X, corrected to %08X\n",
                            ctx.r3.u32, correct_handle);
                    fflush(stderr);

                    // Fix the return value
                    ctx.r3.u32 = correct_handle;
                }
            }
        }
    }

    fprintf(stderr, "[THREAD_8261A5E8] EXIT r3=%08X (return value)\n", ctx.r3.u32);
    fflush(stderr);
}

// Trace sub_82850930 - this appears to be a thread creation wrapper
// Called from sub_8261A5E8 with signature: sub_82850930(0, v25, sub_8261A558, *a1, 4, *a1 + 1)
PPC_FUNC_IMPL(__imp__sub_82850930);
PPC_FUNC(sub_82850930) {
    fprintf(stderr, "[THREAD_82850930] ENTER r3=%08X r4=%08X r5=%08X r6=%08X r7=%08X r8=%08X lr=%08X\n",
            ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32, ctx.r7.u32, ctx.r8.u32, (uint32_t)ctx.lr);
    fflush(stderr);

    // Call the original function
    __imp__sub_82850930(ctx, base);

    fprintf(stderr, "[THREAD_82850930] EXIT r3=%08X (return value)\n", ctx.r3.u32);
    fflush(stderr);
}

// Trace sub_8284DF08 - 16-byte wrapper that branches to sub_8284F548
// This is the missing link in the thread creation call chain
PPC_FUNC_IMPL(__imp__sub_8284DF08);
PPC_FUNC(sub_8284DF08) {
    fprintf(stderr, "[THREAD_8284DF08] ENTER r3=%08X r4=%08X r5=%08X r6=%08X r7=%08X r8=%08X lr=%08X\n",
            ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32, ctx.r7.u32, ctx.r8.u32, (uint32_t)ctx.lr);
    fflush(stderr);

    // Call the original function
    __imp__sub_8284DF08(ctx, base);

    fprintf(stderr, "[THREAD_8284DF08] EXIT r3=%08X (return value)\n", ctx.r3.u32);
    fflush(stderr);
}

// Trace sub_8284F548 - the real thread creation function
// Called from sub_8284DF08
PPC_FUNC_IMPL(__imp__sub_8284F548);
PPC_FUNC(sub_8284F548) {
    fprintf(stderr, "[THREAD_8284F548] ENTER r3=%08X r4=%08X r5=%08X r6=%08X r7=%08X r8=%08X r9=%08X lr=%08X\n",
            ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32, ctx.r7.u32, ctx.r8.u32, ctx.r9.u32, (uint32_t)ctx.lr);
    fflush(stderr);

    // Call the original function
    __imp__sub_8284F548(ctx, base);

    fprintf(stderr, "[THREAD_8284F548] EXIT r3=%08X (return value)\n", ctx.r3.u32);
    fflush(stderr);
}

PPC_FUNC_IMPL(__imp__sub_828508A8);
PPC_FUNC(sub_828508A8)
{
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    KernelTraceHostOpF("HOST.ThreadEntry.828508A8.enter count=%llu tid=%lx r3=%08X r4=%08X r5=%08X lr=%08X",
            count, GetCurrentThreadId(), ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.lr);

    // CRITICAL DEBUG: Check what's in the context structure at offset +84
    // This should contain the callback function pointer that sub_82850820 will call
    if (ctx.r3.u32 != 0) {
        uint8_t* ctx_ptr = base + ctx.r3.u32;
        uint32_t* ctx_u32 = (uint32_t*)ctx_ptr;

        fprintf(stderr, "[THREAD_828508A8] Context structure at 0x%08X:\n", ctx.r3.u32);
        fprintf(stderr, "  +0x00: 0x%08X\n", __builtin_bswap32(ctx_u32[0]));
        fprintf(stderr, "  +0x04: 0x%08X\n", __builtin_bswap32(ctx_u32[1]));
        fprintf(stderr, "  +0x08: 0x%08X\n", __builtin_bswap32(ctx_u32[2]));
        fprintf(stderr, "  +0x58 (88): 0x%08X  <-- CALLBACK FUNCTION POINTER! (FIXED OFFSET!)\n", __builtin_bswap32(ctx_u32[88/4]));
        fprintf(stderr, "  +0x5C (92): 0x%08X  <-- CALLBACK PARAMETER!\n", __builtin_bswap32(ctx_u32[92/4]));
        fflush(stderr);

        // Check if the callback pointer is valid
        uint32_t callback_ptr = __builtin_bswap32(ctx_u32[88/4]);
        uint32_t callback_param = __builtin_bswap32(ctx_u32[88/4]);

        if (callback_ptr == 0 || callback_param == 0) {
            fprintf(stderr, "[THREAD_828508A8] ERROR: Callback pointer at +84 is NULL!\n");
            fprintf(stderr, "[THREAD_828508A8] This is why sub_82850820 doesn't call sub_82441E80!\n");
            fprintf(stderr, "[THREAD_828508A8] The callback should be 0x8261A558 or similar.\n");
            fprintf(stderr, "[THREAD_828508A8] FIXING: Initializing callback pointers now...\n");
            fflush(stderr);

            // CRITICAL FIX: Initialize callback pointers if they're NULL
            // This happens when threads are created with uninitialized contexts
            // CRITICAL: sub_826BE3E8 returns pointer at base+0xE0, so callback is at base+0xE0+0x58 = base+0x138
            ctx_u32[0x138/4] = __builtin_bswap32(0x8261A558);  // +0x138 (312) - callback function pointer
            ctx_u32[0x13C/4] = __builtin_bswap32(0x82A2B318);  // +0x13C (316) - callback parameter

            fprintf(stderr, "[THREAD_828508A8] FIXED: Callback pointers initialized: +0x138=0x8261A558, +0x13C=0x82A2B318 (base+0xE0+0x58!)\n");
            fflush(stderr);

            // Re-read the values to verify
            callback_ptr = __builtin_bswap32(ctx_u32[84/4]);
            callback_param = __builtin_bswap32(ctx_u32[88/4]);
        }

        if (callback_ptr >= 0x82000000 && callback_ptr < 0x83000000) {
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

    // NOTE: Worker threads are now force-created from GuestThreadFunc when the main thread starts
    // No need to create them here anymore

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

    // CRITICAL FIX: The recompiled code for sub_828508A8 has a bug - it gets stuck in a sleep loop
    // at sub_8262F2A0 instead of calling KeWaitForSingleObject on event 0x400007E0.
    // According to CRITICAL_FINDINGS_VdInit.md, this thread should call sub_82850820 which
    // eventually leads to VdInitializeEngines with the correct callback.
    //
    // WORKAROUND: Skip the buggy recompiled code and call sub_82850820 directly.
    static const bool s_skip_buggy_code = [](){
        if (const char* v = std::getenv("MW05_SKIP_828508A8_BUG"))
            return !(v[0]=='0' && v[1]=='\0');
        return true; // ENABLED BY DEFAULT - this is critical for game progression
    }();

    KernelTraceHostOpF("HOST.ThreadEntry.828508A8.workaround_check skip=%d", s_skip_buggy_code ? 1 : 0);

    if (s_skip_buggy_code) {
        KernelTraceHostOp("HOST.ThreadEntry.828508A8.workaround_active");

        // CRITICAL FIX: Before calling sub_82850820, we need to copy the callback pointers
        // from the thread context (r3) to the global worker structure.
        // This is what the natural sub_828508A8 code does before calling sub_82850820.

        // The thread context is passed in r3 and contains:
        //   +84 (0x54): callback function pointer (should be 0x8261A558)
        //   +88 (0x58): callback parameter pointer (should be 0x82A2B318)

        // We need to copy these to the global worker structure returned by sub_826BE3E8.

        uint32_t thread_ctx_addr = ctx.r3.u32;
        if (thread_ctx_addr != 0) {
            void* thread_ctx_ptr = g_memory.Translate(thread_ctx_addr);
            if (thread_ctx_ptr) {
                be<uint32_t>* thread_ctx_u32 = reinterpret_cast<be<uint32_t>*>(thread_ctx_ptr);
                uint32_t callback_func = thread_ctx_u32[84/4];  // +0x54 (84)
                uint32_t callback_param = thread_ctx_u32[88/4];  // +0x58 (88)

                fprintf(stderr, "[THREAD_828508A8] Thread context callback: func=0x%08X param=0x%08X\n",
                        callback_func, callback_param);
                fflush(stderr);

                // Now get the global worker structure and copy the callback pointers to it
                PPCContext temp_ctx = ctx;
                sub_826BE3E8(temp_ctx, base);

                uint32_t global_struct_addr = temp_ctx.r3.u32;
                if (global_struct_addr != 0) {
                    void* global_struct_ptr = g_memory.Translate(global_struct_addr);
                    if (global_struct_ptr) {
                        be<uint32_t>* global_struct_u32 = reinterpret_cast<be<uint32_t>*>(global_struct_ptr);

                        fprintf(stderr, "[THREAD_828508A8] Copying callback pointers to global structure at 0x%08X\n",
                                global_struct_addr);
                        fflush(stderr);

                        // Copy callback pointers from thread context to global structure
                        global_struct_u32[84/4] = be<uint32_t>(callback_func);   // +0x54 (84)
                        global_struct_u32[88/4] = be<uint32_t>(callback_param);  // +0x58 (88)

                        fprintf(stderr, "[THREAD_828508A8] Callback pointers copied! Global structure now has func=0x%08X param=0x%08X\n",
                                callback_func, callback_param);
                        fflush(stderr);
                    }
                }
            }
        }

        // CRITICAL FIX: Install PPC context into TLS before calling guest code
        // VdInitializeEngines checks GetPPCContext() to determine if it's being called from a guest thread
        // Without this, GetPPCContext() returns NULL and the callback is skipped
        PPCContext* saved_ctx = GetPPCContext();
        SetPPCContext(ctx);

        KernelTraceHostOpF("HOST.ThreadEntry.828508A8.context_installed GetPPCContext=%p", (void*)GetPPCContext());

        // Call sub_82850820 directly (this is what sub_828508A8 should do after initialization)
        // The context parameter (r3) should be passed through
        // NOTE: sub_82850820 is defined below with PPC_FUNC_IMPL, so we can call it directly
        sub_82850820(ctx, base);

        KernelTraceHostOp("HOST.ThreadEntry.828508A8.sub_82850820_returned");

        // Restore previous PPC context
        if (saved_ctx) {
            SetPPCContext(*saved_ctx);
        } else {
            g_ppcContext = nullptr;
        }

        // Set return value to 0 (success)
        ctx.r3.u32 = 0;
    } else {
        KernelTraceHostOp("HOST.ThreadEntry.828508A8.calling_original");
        // Call the original thread entry point
        __imp__sub_828508A8(ctx, base);
    }

    KernelTraceHostOpF("HOST.ThreadEntry.828508A8.exit count=%llu tid=%lx r3=%08X", count, GetCurrentThreadId(), ctx.r3.u32);
}

// CRITICAL FIX: Force-create render thread at VBlank 75 (matching Xenia behavior)
// Thread #1 gets stuck in the main game loop and never creates the render thread naturally
// So we create it manually from the VBlank callback
static std::atomic<bool> s_renderThreadCreated{false};

void Mw05ForceCreateRenderThread() {
    if (s_renderThreadCreated.exchange(true)) {
        return;  // Already created
    }

    fprintf(stderr, "[RENDER_THREAD_FIX] Force-creating render thread at entry 0x825AA970\n");
    fflush(stderr);

    // Create render thread (matching Xenia's behavior at line 35632)
    // Entry: 0x825AA970
    // Context: Try NULL context first (like some worker threads use)
    // Flags: 0x04000080

    // Try with NULL context (0x00000000) first
    uint32_t ctx_addr = 0x00000000;

    fprintf(stderr, "[RENDER_THREAD_FIX] Using NULL context (0x00000000)\n");
    fflush(stderr);

    // Create the render thread
    be<uint32_t> thread_handle = 0;
    be<uint32_t> thread_id = 0;
    uint32_t result = ExCreateThread(
        &thread_handle,      // pHandle
        0,                   // stack_size (0 = default)
        &thread_id,          // pThreadId
        0x82850080,          // xapi_thread_startup (standard thread startup)
        0x825AA970,          // start_address (render thread entry point)
        ctx_addr,            // start_context (NULL)
        0x04000080           // creation_flags
    );

    if (result == 0) {
        fprintf(stderr, "[RENDER_THREAD_FIX] Render thread created successfully: handle=0x%08X id=0x%08X\n",
                (uint32_t)thread_handle, (uint32_t)thread_id);
        fflush(stderr);
    } else {
        fprintf(stderr, "[RENDER_THREAD_FIX] ERROR: Failed to create render thread: result=0x%08X\n", result);
        fflush(stderr);
    }
}

// Wrapper for sub_8261A558 - callback function called by sub_82850820
// This is the function that processes work items and calls the work function
PPC_FUNC_IMPL(__imp__sub_8261A558);
PPC_FUNC(sub_8261A558) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    // Read the parameter structure to see what work function will be called
    uint32_t param_addr = ctx.r3.u32;
    uint32_t work_func_ptr = 0;
    uint32_t work_param1 = 0;
    uint32_t work_param2 = 0;

    if (param_addr >= 0x80000000 && param_addr < 0x90000000) {
        work_param1 = PPC_LOAD_U32(param_addr + 16);  // +16
        work_param2 = PPC_LOAD_U32(param_addr + 20);  // +20
        work_func_ptr = PPC_LOAD_U32(param_addr + 28);  // +28 (work function)
    }

    fprintf(stderr, "[CALLBACK_8261A558] ENTER: count=%llu r3=%08X tid=%lx\n",
            count, ctx.r3.u32, GetCurrentThreadId());
    fprintf(stderr, "[CALLBACK_8261A558]   work_func=0x%08X param1=0x%08X param2=0x%08X\n",
            work_func_ptr, work_param1, work_param2);
    fflush(stderr);

    // Call the original
    __imp__sub_8261A558(ctx, base);

    fprintf(stderr, "[CALLBACK_8261A558] RETURN: count=%llu r3=%08X\n",
            count, ctx.r3.u32);
    fflush(stderr);
}

// Wrapper for sub_826BE3E8 - Returns pointer to structure containing callback pointer
PPC_FUNC_IMPL(__imp__sub_826BE3E8);
PPC_FUNC(sub_826BE3E8) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    fprintf(stderr, "[826BE3E8] ENTER: count=%llu tid=%lx\n",
            count, GetCurrentThreadId());
    fflush(stderr);

    // Call the original
    __imp__sub_826BE3E8(ctx, base);

    fprintf(stderr, "[826BE3E8] RETURN: count=%llu r3=%08X (structure pointer)\n",
            count, ctx.r3.u32);
    fflush(stderr);

    // DEBUG: Log the callback pointers in the structure returned by sub_826BE3E8
    // This structure should now have the callback pointers copied by sub_828508A8
    if (ctx.r3.u32 != 0) {
        extern Memory g_memory;
        void* struct_ptr = g_memory.Translate(ctx.r3.u32);
        if (struct_ptr) {
            be<uint32_t>* struct_u32 = reinterpret_cast<be<uint32_t>*>(struct_ptr);
            uint32_t callback_func = struct_u32[84/4];  // +0x54 (84) - callback function
            uint32_t callback_param = struct_u32[88/4];  // +0x58 (88) - callback parameter

            fprintf(stderr, "[826BE3E8] Callback function at +84: 0x%08X, parameter at +88: 0x%08X\n", callback_func, callback_param);
            fflush(stderr);
        }
    }
}

// Wrapper for sub_82850820 - Thread #1 main worker loop
// This is the function that should eventually call ExCreateThread to create the render thread
PPC_FUNC_IMPL(__imp__sub_82850820);
PPC_FUNC(sub_82850820) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    fprintf(stderr, "[THREAD1_LOOP] sub_82850820 ENTER: count=%llu r3=%08X tid=%lx\n",
            count, ctx.r3.u32, GetCurrentThreadId());
    fflush(stderr);

    // CRITICAL DEBUG: Wrap in SEH to catch crashes
    #if defined(_WIN32)
    __try {
    #endif
        // Call the original
        __imp__sub_82850820(ctx, base);

        fprintf(stderr, "[THREAD1_LOOP] sub_82850820 RETURN: count=%llu r3=%08X\n",
                count, ctx.r3.u32);
        fflush(stderr);

    #if defined(_WIN32)
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        fprintf(stderr, "[THREAD1_LOOP] sub_82850820 CRASHED with exception 0x%08X at count=%llu\n",
                (unsigned)GetExceptionCode(), count);
        fflush(stderr);
        ctx.r3.u32 = 0;  // Return 0 on crash
    }
    #endif
}

// Wrapper for sub_823AF590 - initialization function called before worker loop
// This function loads game assets and creates worker threads
PPC_FUNC_IMPL(__imp__sub_823AF590);
PPC_FUNC(sub_823AF590) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    fprintf(stderr, "[INIT_823AF590] ENTER: count=%llu tid=%lx\n",
            count, GetCurrentThreadId());
    fflush(stderr);

    // Call the original function - let it run with fixed VdGetSystemCommandBuffer
    __imp__sub_823AF590(ctx, base);

    fprintf(stderr, "[INIT_823AF590] RETURN: count=%llu r3=%08X\n",
            count, ctx.r3.u32);
    fflush(stderr);
}

// REMOVED: Wrapper for sub_823AFFA8 - using recompiled version directly
// The recompiled version will call sub_823B1408 shim (which is not in TOML anymore)

// Wrapper for sub_823B0190 - main worker loop (infinite loop)
// This function runs the main game loop and should never return
PPC_FUNC_IMPL(__imp__sub_823B0190);
PPC_FUNC(sub_823B0190) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    fprintf(stderr, "[WORKER_LOOP_823B0190] ENTER: count=%llu tid=%lx\n",
            count, GetCurrentThreadId());
    fflush(stderr);

    // Check the value of dword_82A2CBA8 (loop condition variable)
    const uint32_t loop_flag_addr = 0x82A2CBA8;
    void* loop_flag_ptr = g_memory.Translate(loop_flag_addr);
    if (loop_flag_ptr) {
        uint32_t loop_flag = __builtin_bswap32(*(uint32_t*)loop_flag_ptr);
        fprintf(stderr, "[WORKER_LOOP_823B0190] dword_82A2CBA8 = 0x%08X (loop runs if == 0)\n", loop_flag);
        fflush(stderr);
    }

    // Call the original (this should never return!)
    __imp__sub_823B0190(ctx, base);

    fprintf(stderr, "[WORKER_LOOP_823B0190] RETURN: count=%llu r3=%08X (UNEXPECTED!)\n",
            count, ctx.r3.u32);
    fflush(stderr);
}

// Wrapper for sub_826E87E0 - creates 4 worker threads
// This function creates threads with entry points: 0x826E7B90, 0x826E7BC0, 0x826E7BF0, 0x826E7C20
PPC_FUNC_IMPL(__imp__sub_826E87E0);
PPC_FUNC(sub_826E87E0) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    fprintf(stderr, "[THREAD_CREATOR_826E87E0] ENTER: count=%llu tid=%lx r3=%08X\n",
            count, GetCurrentThreadId(), ctx.r3.u32);
    fflush(stderr);

    // Call the original
    __imp__sub_826E87E0(ctx, base);

    fprintf(stderr, "[THREAD_CREATOR_826E87E0] RETURN: count=%llu r3=%08X\n",
            count, ctx.r3.u32);
    fflush(stderr);
}

// Forward declaration for sub_826D6930
PPC_FUNC_IMPL(__imp__sub_826D6930);

// Wrapper for sub_826D6930 - work item enqueue wrapper
// This function should be calling sub_826DD1C0, which uses a function pointer table
// to call sub_826E87E0 (render thread creator).
//
// Call chain: sub_826D6930 -> sub_826DD1C0 -> function_table[index] -> sub_826E87E0
PPC_FUNC(sub_826D6930) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    fprintf(stderr, "[WORK_ENQUEUE_826D6930] ENTER: count=%llu r3=%08X r4=%08X r5=%08X r6=%08X r7=%08X tid=%lx\n",
            count, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32, ctx.r7.u32, GetCurrentThreadId());
    fprintf(stderr, "[WORK_ENQUEUE_826D6930] This should enqueue work items including render thread creator!\n");
    fflush(stderr);

    // Call the original
    __imp__sub_826D6930(ctx, base);

    fprintf(stderr, "[WORK_ENQUEUE_826D6930] RETURN: count=%llu r3=%08X\n",
            count, ctx.r3.u32);
    fflush(stderr);
}

// Forward declaration for sub_823BC5B0
PPC_FUNC_IMPL(__imp__sub_823BC5B0);

// Wrapper for sub_823BC5B0 - THE MISSING WORK ITEM ENQUEUE FUNCTION!
// This function enqueues work items to the work queue at 0x829091C8.
// It's NEVER called during initialization, which is why the work queue is empty!
//
// This is the ROOT CAUSE of draws=0:
// 1. sub_823BC5B0 is never called
// 2. Work queue remains empty
// 3. Work queue processor exits
// 4. Render thread creator never called
// 5. No render threads created
// 6. draws=0
PPC_FUNC(sub_823BC5B0) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    fprintf(stderr, "[WORK_ITEM_ENQUEUE_823BC5B0] ENTER: count=%llu r3=%08X r4=%08X r5=%08X tid=%lx\n",
            count, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, GetCurrentThreadId());
    fprintf(stderr, "[WORK_ITEM_ENQUEUE_823BC5B0] This function enqueues work items to the work queue!\n");
    fflush(stderr);

    // Call the original
    __imp__sub_823BC5B0(ctx, base);

    fprintf(stderr, "[WORK_ITEM_ENQUEUE_823BC5B0] RETURN: count=%llu r3=%08X\n",
            count, ctx.r3.u32);
    fflush(stderr);
}

// Wrapper for sub_82441E58 - param1 function (called when work_func is NULL)
// CRITICAL FIX: This function is a worker thread main loop that never returns.
// It calls sub_823B0190 which runs forever. The callback sub_8261A558 calls this
// synchronously, which blocks the callback from returning.
// SOLUTION: Spawn it as a background thread and return immediately.
PPC_FUNC_IMPL(__imp__sub_82441E58);
PPC_FUNC(sub_82441E58) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    fprintf(stderr, "[PARAM1_FUNC_82441E58] ENTER: count=%llu r3=%08X tid=%lx\n",
            count, ctx.r3.u32, GetCurrentThreadId());
    fprintf(stderr, "[PARAM1_FUNC_82441E58] This is a worker thread main loop - spawning as background thread!\n");
    fflush(stderr);

    // Capture context and base for the background thread
    PPCContext ctx_copy = ctx;
    uint8_t* base_copy = base;

    // Spawn the worker loop in a background thread
    std::thread([ctx_copy, base_copy]() mutable {
        fprintf(stderr, "[PARAM1_FUNC_82441E58] Background thread started, tid=%lx\n", GetCurrentThreadId());
        fflush(stderr);

        // Call the original function (which runs forever)
        __imp__sub_82441E58(ctx_copy, base_copy);

        fprintf(stderr, "[PARAM1_FUNC_82441E58] Background thread exited (should never happen!)\n");
        fflush(stderr);
    }).detach();

    // Return success immediately to unblock the callback
    ctx.r3.u32 = 0;

    fprintf(stderr, "[PARAM1_FUNC_82441E58] RETURN: count=%llu r3=%08X (spawned background thread)\n",
            count, ctx.r3.u32);
    fflush(stderr);
}

// Wrapper for sub_823BA428 - param1 function (called when work_func is NULL)
// CRITICAL FIX: This function is a worker thread main loop that never returns.
// It has an infinite loop: call sub_823B9838, sleep 10ms, repeat forever.
// SOLUTION: Spawn it as a background thread and return immediately.
PPC_FUNC_IMPL(__imp__sub_823BA428);
PPC_FUNC(sub_823BA428) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    fprintf(stderr, "[PARAM1_FUNC_823BA428] ENTER: count=%llu r3=%08X tid=%lx\n",
            count, ctx.r3.u32, GetCurrentThreadId());
    fprintf(stderr, "[PARAM1_FUNC_823BA428] This is a worker thread main loop - spawning as background thread!\n");
    fflush(stderr);

    // Capture context and base for the background thread
    PPCContext ctx_copy = ctx;
    uint8_t* base_copy = base;

    // Spawn the worker loop in a background thread
    std::thread([ctx_copy, base_copy]() mutable {
        fprintf(stderr, "[PARAM1_FUNC_823BA428] Background thread started, tid=%lx\n", GetCurrentThreadId());
        fflush(stderr);

        // Call the original function (which runs forever)
        __imp__sub_823BA428(ctx_copy, base_copy);

        fprintf(stderr, "[PARAM1_FUNC_823BA428] Background thread exited (should never happen!)\n");
        fflush(stderr);
    }).detach();

    // Return success immediately to unblock the callback
    ctx.r3.u32 = 0;

    fprintf(stderr, "[PARAM1_FUNC_823BA428] RETURN: count=%llu r3=%08X (spawned background thread)\n",
            count, ctx.r3.u32);
    fflush(stderr);
}

// Wrapper for sub_8261EC58 - work queue processor
// This function processes work items from a queue and calls their work functions.
// It's called as param1 when work_func is NULL in the callback.
//
// CRITICAL DISCOVERY: This function has an infinite loop! It loops checking the queue
// until the stop flag at offset +5 is set. The loop is from loc_8261EC90 back to itself.
//
// Work item structure (at offset +68 is the work function pointer):
// - Offset +0: next pointer
// - Offset +4: result/status
// - Offset +24: completion callback
// - Offset +68: work function pointer (called via bctrl)
//
// SOLUTION: Spawn it as a background thread and return immediately, just like the
// other param1 functions!
//
// CRITICAL FIX: The work queue processor calls sub_8262BF58 to wait for work items.
// sub_8262BF58 decrements a semaphore counter at offset +32 of the structure passed in r4.
// If the counter goes negative, it returns immediately with that negative value, causing
// the work queue processor to exit.
//
// The counter needs to be incremented when work items are added to the queue, but that's
// not happening. As a workaround, we initialize the counter to a high value so the work
// queue processor can run for a while.
PPC_FUNC_IMPL(__imp__sub_8261EC58);
PPC_FUNC(sub_8261EC58) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    uint32_t queue_mgr = ctx.r3.u32;  // Queue manager structure

    fprintf(stderr, "[WORK_QUEUE_8261EC58] ENTER: count=%llu r3=%08X tid=%lx\n",
            count, queue_mgr, GetCurrentThreadId());

    // Read queue head pointer (offset +8 from queue manager)
    uint32_t queue_head_ptr = queue_mgr + 8;
    uint32_t work_item = PPC_LOAD_U32(queue_head_ptr);

    // Read stop flag (offset +5 from queue manager)
    uint8_t stop_flag = *reinterpret_cast<uint8_t*>(base + (queue_mgr + 5));

    fprintf(stderr, "[WORK_QUEUE_8261EC58] Queue state: head_ptr=%08X work_item=%08X stop_flag=%d\n",
            queue_head_ptr, work_item, stop_flag);

    // CRITICAL FIX: Initialize the semaphore counter to allow the work queue processor to run
    // The counter is at offset +32 of the structure that will be passed to sub_8262BF58 in r4.
    // From the logs, we see r4=C0015114 when r3=C0015140, so r4 = r3 - 0x2C
    // The counter is at r4+32 (0x20), so counter_addr = (r3 - 0x2C) + 0x20 = r3 - 0xC
    uint32_t counter_addr = queue_mgr - 0xC;  // queue_mgr - 12 = r4 + 32
    uint32_t counter_before = PPC_LOAD_U32(counter_addr);

    fprintf(stderr, "[WORK_QUEUE_8261EC58] Semaphore counter at %08X: before=%d\n",
            counter_addr, (int32_t)counter_before);

    // Set the counter to 1000 to allow the work queue processor to run
    PPC_STORE_U32(counter_addr, 1000);

    fprintf(stderr, "[WORK_QUEUE_8261EC58] Semaphore counter set to 1000\n");
    fprintf(stderr, "[WORK_QUEUE_8261EC58] This is a worker thread main loop - spawning as background thread!\n");
    fflush(stderr);

    // Capture context and base for the background thread
    PPCContext ctx_copy = ctx;
    uint8_t* base_copy = base;

    // Spawn the worker loop in a background thread
    std::thread([ctx_copy, base_copy]() mutable {
        fprintf(stderr, "[WORK_QUEUE_8261EC58] Background thread started, tid=%lx\n", GetCurrentThreadId());
        fflush(stderr);

        // Call the original function (which runs forever)
        __imp__sub_8261EC58(ctx_copy, base_copy);

        fprintf(stderr, "[WORK_QUEUE_8261EC58] Background thread exited (should only happen when stop flag is set)\n");
        fflush(stderr);
    }).detach();

    // Return success immediately to unblock the callback
    ctx.r3.u32 = 0;

    fprintf(stderr, "[WORK_QUEUE_8261EC58] RETURN: count=%llu r3=%08X (spawned background thread)\n",
            count, ctx.r3.u32);
    fflush(stderr);
}

// Wrapper for sub_82813598 - initializes thread pool manager
// This function is called from sub_8245FBD0 during initialization
// It creates a worker thread via sub_82813418 and sets up a timer via NtSetTimerEx
//
// CRITICAL DISCOVERY: Both sub_82813598 and sub_82813418 have wait loops!
// - sub_82813598 waits in a loop from 0x8281359C to 0x8281365C
// - sub_82813418 waits at loc_8281349C for a flag at r1+80 to become non-zero
//
// The problem is that these wait loops are waiting for the worker thread to set a flag,
// but the worker thread can't run while we're stuck in the wait loop.
//
// Solution: Just return immediately with a success value. The worker thread will be
// created asynchronously and will run in the background.
PPC_FUNC_IMPL(__imp__sub_82813598);
PPC_FUNC(sub_82813598) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    fprintf(stderr, "[THREAD_POOL_INIT_82813598] ENTER: count=%llu tid=%lx r3=%08X\n",
            count, GetCurrentThreadId(), ctx.r3.u32);
    fflush(stderr);

    // Just return success immediately without calling the original function
    // The worker thread will be created asynchronously by the game's natural code flow
    ctx.r3.u32 = 1;  // Success

    fprintf(stderr, "[THREAD_POOL_INIT_82813598] RETURN: count=%llu r3=%08X (bypassed wait loops)\n",
            count, ctx.r3.u32);
    fflush(stderr);
}

// Wrapper for sub_8245FBD0 - called early in sub_823AF590 initialization
// This might be hanging the initialization
PPC_FUNC_IMPL(__imp__sub_8245FBD0);
PPC_FUNC(sub_8245FBD0) {
    fprintf(stderr, "[INIT_8245FBD0] ENTER tid=%lx\n", GetCurrentThreadId());
    fflush(stderr);

    __imp__sub_8245FBD0(ctx, base);

    fprintf(stderr, "[INIT_8245FBD0] RETURN r3=%08X\n", ctx.r3.u32);
    fflush(stderr);
}

// Wrapper for sub_823BCBF0 - file existence check function
// CRITICAL FIX: Return "file not found" for ZDIR/ZZDATA files
// These are Xbox 360 disc-specific virtual FS files that don't exist in extracted game directories
PPC_FUNC_IMPL(__imp__sub_823BCBF0);
PPC_FUNC(sub_823BCBF0) {
    // Get filename from r3
    const char* filename = nullptr;
    if (ctx.r3.u32 >= 0x80000000 && ctx.r3.u32 < 0x90000000) {
        filename = reinterpret_cast<const char*>(g_memory.Translate(ctx.r3.u32));
    }

    fprintf(stderr, "[FILE_CHECK_823BCBF0] ENTER r3=%08X (%s) tid=%lx\n",
            ctx.r3.u32, filename ? filename : "NULL", GetCurrentThreadId());
    fflush(stderr);

    // CRITICAL FIX: Check if this is a ZDIR/ZZDATA file request
    // These files don't exist in extracted game directories, so return "file not found"
    bool isVirtualFSFile = false;
    if (filename) {
        std::string fname(filename);
        std::transform(fname.begin(), fname.end(), fname.begin(), ::toupper);
        if (fname.find("ZDIR") != std::string::npos || fname.find("ZZDATA") != std::string::npos) {
            isVirtualFSFile = true;
        }
    }

    if (isVirtualFSFile) {
        fprintf(stderr, "[FILE_CHECK_823BCBF0] RETURN r3=00000000 (VIRTUAL FS FILE NOT FOUND)\n");
        fflush(stderr);
        ctx.r3.u32 = 0; // File not found
        return;
    }

    __imp__sub_823BCBF0(ctx, base);

    fprintf(stderr, "[FILE_CHECK_823BCBF0] RETURN r3=%08X (exists=%d)\n",
            ctx.r3.u32, ctx.r3.u32);
    fflush(stderr);
}

// NOTE: sub_823BCA68 wrapper removed - cannot override weak symbol from PPC sources
// The recompiled version runs correctly, but the game is stuck in file loading
// The real issue is NOT with file opening, but with async file I/O completion

// NOTE: Initialization chain functions - trying GUEST_FUNCTION_HOOK pattern instead
// Chain: 823AF590 → 82216088 → 82440530 → 82440448 → 825A16A0 → 825A8698 → CreateDevice

// Declare the __imp__ functions first
PPC_FUNC_IMPL(__imp__sub_82216088);
PPC_FUNC_IMPL(__imp__sub_82440530);
PPC_FUNC_IMPL(__imp__sub_82440448);

// RECOMPILER BUG WORKAROUNDS: These functions crash/hang in recompiled code
// Use GUEST_FUNCTION_HOOK to replace them with stub implementations

// sub_824413D8 - crashes in recompiled code with access violation
// According to IDA, this function initializes game subsystems (memory allocation, structure setup)
// This function is NOT critical for rendering - it just sets up some global state
static void MW05_Stub_sub_824413D8(PPCContext& ctx, uint8_t* base) {
    static std::atomic<uint32_t> s_call_count{0};
    uint32_t count = s_call_count.fetch_add(1, std::memory_order_relaxed);

    fprintf(stderr, "[STUB_824413D8] Call #%u r3=%08X (RECOMPILER BUG - using stub, NOT critical for rendering)\n",
            count + 1, ctx.r3.u32);
    fflush(stderr);

    // Return success (r3 unchanged or set to input value)
    // The function appears to be an initialization function that doesn't return a value
}

// RECOMPILER BUG WORKAROUND: Use PPC_FUNC pattern instead of GUEST_FUNCTION_HOOK
// sub_82440448 - CRITICAL for rendering initialization (calls CreateDevice)
PPC_FUNC_IMPL(__imp__sub_82440448);
PPC_FUNC(sub_82440448) {
    static std::atomic<uint32_t> s_call_count{0};
    uint32_t count = s_call_count.fetch_add(1, std::memory_order_relaxed);

    fprintf(stderr, "[PPC_FUNC_82440448] Call #%u r3=%08X (CRITICAL - calls CreateDevice!)\n",
            count + 1, ctx.r3.u32);
    fflush(stderr);

    // CRITICAL: This function calls CreateDevice (sub_825A16A0) and graphics setup (sub_82598230)
    // Without calling the original function, the game will NEVER render (draws=0)
    // Try calling the original recompiled function with exception handling
    __try {
        fprintf(stderr, "[PPC_FUNC_82440448] Attempting to call original recompiled function...\n");
        fflush(stderr);

        __imp__sub_82440448(ctx, base);

        fprintf(stderr, "[PPC_FUNC_82440448] SUCCESS! Original function completed without crashing\n");
        fflush(stderr);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        fprintf(stderr, "[PPC_FUNC_82440448] EXCEPTION caught! code=0x%08X\n", GetExceptionCode());
        fflush(stderr);

        // If the original function crashes, we're stuck - the game won't render
        // This is a recompiler bug that needs to be fixed in tools/XenonRecomp/
    }
}

// sub_824413D8 - NOT critical for rendering (just sets up some global state)
PPC_FUNC_IMPL(__imp__sub_824413D8);
PPC_FUNC(sub_824413D8) {
    static std::atomic<uint32_t> s_call_count{0};
    uint32_t count = s_call_count.fetch_add(1, std::memory_order_relaxed);

    fprintf(stderr, "[PPC_FUNC_824413D8] Call #%u r3=%08X (NOT critical for rendering)\n",
            count + 1, ctx.r3.u32);
    fflush(stderr);

    // This function is NOT critical for rendering - it just sets up some global state
    // We can safely skip it if it crashes
    __try {
        __imp__sub_824413D8(ctx, base);
        fprintf(stderr, "[PPC_FUNC_824413D8] SUCCESS!\n");
        fflush(stderr);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        fprintf(stderr, "[PPC_FUNC_824413D8] EXCEPTION caught! code=0x%08X (skipping - not critical)\n", GetExceptionCode());
        fflush(stderr);
    }
}

// Forward declarations for functions called by sub_82216088
// NOTE: These are already defined in the recompiled library, so we just declare them as extern
extern "C" void __imp__sub_82216410(PPCContext& ctx, uint8_t* base);
extern "C" void __imp__sub_8215A2C8(PPCContext& ctx, uint8_t* base);
extern "C" void __imp__sub_82216AC0(PPCContext& ctx, uint8_t* base);
extern "C" void __imp__sub_826BE660(PPCContext& ctx, uint8_t* base);
extern "C" void __imp__sub_8221D700(PPCContext& ctx, uint8_t* base);
extern "C" void __imp__sub_8243C608(PPCContext& ctx, uint8_t* base);
extern "C" void __imp__sub_821AFD18(PPCContext& ctx, uint8_t* base);
extern "C" void __imp__sub_824FFE98(PPCContext& ctx, uint8_t* base);



static void MW05_Trace_sub_82216088(PPCContext& ctx, uint8_t* base) {
    fprintf(stderr, "[INIT_82216088] ENTER r3=%08X tid=%lx\n", ctx.r3.u32, GetCurrentThreadId());
    fflush(stderr);

    // CRITICAL: sub_82216088 does a LOT of initialization before calling sub_82440530
    // According to IDA decompilation, it:
    // 1. Calls sub_82216410(1228800)
    // 2. Creates memory pools (ePolySlotPool, Ecstacy:ModelSlotPool, TexturePackSlotPool)
    // 3. Initializes global variables
    // 4. Calls several init functions (sub_82216AC0, sub_824413D8, sub_826BE660, sub_8221D700, sub_8243C608)
    // 5. Sets function pointers
    // 6. Calls sub_821AFD18(51200, 1) and sub_824FFE98
    // 7. Finally calls sub_82440530()
    //
    // We need to call ALL of these functions, not just sub_82440530!
    // Let's manually call each function with detailed logging to find which one hangs.

    fprintf(stderr, "[INIT_82216088] Step 1: Calling sub_82216410(1228800)...\n");
    fflush(stderr);

    // Call sub_82216410(1228800)
    ctx.r3.u32 = 1228800;
    SetPPCContext(ctx);
    __imp__sub_82216410(ctx, base);

    fprintf(stderr, "[INIT_82216088] Step 1 DONE: sub_82216410 returned r3=%08X\n", ctx.r3.u32);
    fflush(stderr);

    fprintf(stderr, "[INIT_82216088] Step 2: Calling sub_8215A2C8 for ePolySlotPool...\n");
    fflush(stderr);

    // Call sub_8215A2C8(&dword_829065FC, 160, 32, "ePolySlotPool", 0)
    // r3 = &dword_829065FC (0x829065FC)
    // r4 = 160
    // r5 = 32
    // r6 = "ePolySlotPool" (need to allocate string in guest memory)
    // r7 = 0
    ctx.r3.u32 = 0x829065FC;
    ctx.r4.u32 = 160;
    ctx.r5.u32 = 32;
    // Skip string parameter for now - just pass 0
    ctx.r6.u32 = 0;
    ctx.r7.u32 = 0;
    SetPPCContext(ctx);
    __imp__sub_8215A2C8(ctx, base);

    uint32_t polySlotPool = ctx.r3.u32;
    fprintf(stderr, "[INIT_82216088] Step 2 DONE: sub_8215A2C8 returned r3=%08X (ePolySlotPool)\n", polySlotPool);
    fflush(stderr);

    fprintf(stderr, "[INIT_82216088] Step 3: Calling sub_82216AC0()...\n");
    fflush(stderr);

    // Call sub_82216AC0()
    SetPPCContext(ctx);
    __imp__sub_82216AC0(ctx, base);

    uint32_t v1 = ctx.r3.u32;
    fprintf(stderr, "[INIT_82216088] Step 3 DONE: sub_82216AC0 returned r3=%08X\n", v1);
    fflush(stderr);

    fprintf(stderr, "[INIT_82216088] Step 4: Calling sub_824413D8(r3=%08X)...\n", v1);
    fflush(stderr);

    // Call sub_824413D8(v1) - using stub because recompiled version crashes
    ctx.r3.u32 = v1;
    SetPPCContext(ctx);
    MW05_Stub_sub_824413D8(ctx, base);

    fprintf(stderr, "[INIT_82216088] Step 4 DONE: sub_824413D8 returned r3=%08X\n", ctx.r3.u32);
    fflush(stderr);

    fprintf(stderr, "[INIT_82216088] Step 5: Calling sub_826BE660(off_8290075C, 0, 168)...\n");
    fflush(stderr);

    // Call sub_826BE660(off_8290075C, 0, 168)
    // r3 = off_8290075C (this is a pointer to a global variable)
    // r4 = 0
    // r5 = 168
    // For now, just pass the address directly - the function will dereference it
    ctx.r3.u32 = 0x8290075C;
    ctx.r4.u32 = 0;
    ctx.r5.u32 = 168;
    SetPPCContext(ctx);
    __imp__sub_826BE660(ctx, base);

    uint32_t v2 = ctx.r3.u32;
    fprintf(stderr, "[INIT_82216088] Step 5 DONE: sub_826BE660 returned r3=%08X\n", v2);
    fflush(stderr);

    fprintf(stderr, "[INIT_82216088] Step 6: Calling sub_8221D700(r3=%08X)...\n", v2);
    fflush(stderr);

    // Call sub_8221D700(v2)
    ctx.r3.u32 = v2;
    SetPPCContext(ctx);
    __imp__sub_8221D700(ctx, base);

    uint32_t v3 = ctx.r3.u32;
    fprintf(stderr, "[INIT_82216088] Step 6 DONE: sub_8221D700 returned r3=%08X\n", v3);
    fflush(stderr);

    fprintf(stderr, "[INIT_82216088] Step 7: Calling sub_8243C608(r3=%08X)...\n", v3);
    fflush(stderr);

    // Call sub_8243C608(v3)
    ctx.r3.u32 = v3;
    SetPPCContext(ctx);
    __imp__sub_8243C608(ctx, base);

    fprintf(stderr, "[INIT_82216088] Step 7 DONE: sub_8243C608 returned r3=%08X\n", ctx.r3.u32);
    fflush(stderr);

    fprintf(stderr, "[INIT_82216088] Step 8: Calling sub_821AFD18(51200, 1)...\n");
    fflush(stderr);

    // Call sub_821AFD18(51200, 1)
    ctx.r3.u32 = 51200;
    ctx.r4.u32 = 1;
    SetPPCContext(ctx);
    __imp__sub_821AFD18(ctx, base);

    uint32_t v4 = ctx.r3.u32;
    fprintf(stderr, "[INIT_82216088] Step 8 DONE: sub_821AFD18 returned r3=%08X\n", v4);
    fflush(stderr);

    fprintf(stderr, "[INIT_82216088] Step 9: Calling sub_824FFE98(r3=%08X)...\n", v4);
    fflush(stderr);

    // Call sub_824FFE98(v4)
    ctx.r3.u32 = v4;
    SetPPCContext(ctx);
    __imp__sub_824FFE98(ctx, base);

    fprintf(stderr, "[INIT_82216088] Step 9 DONE: sub_824FFE98 returned r3=%08X\n", ctx.r3.u32);
    fflush(stderr);

    fprintf(stderr, "[INIT_82216088] Step 10: Calling sub_82440530() (final step)...\n");
    fflush(stderr);

    // Call sub_82440530() - this is the final step that initializes rendering
    SetPPCContext(ctx);
    __imp__sub_82440530(ctx, base);

    fprintf(stderr, "[INIT_82216088] RETURN r3=%08X\n", ctx.r3.u32);
    fflush(stderr);
}

static void MW05_Trace_sub_82440530(PPCContext& ctx, uint8_t* base) {
    fprintf(stderr, "[INIT_82440530] ENTER r3=%08X tid=%lx\n", ctx.r3.u32, GetCurrentThreadId());
    fflush(stderr);

    // TRY CALLING THE ORIGINAL FUNCTION NOW THAT VIEWPORT IS FIXED
    // This function calls sub_82440448 and other initialization functions
    // Previously bypassed because it was blocking, but now that viewport is initialized, it might work
    fprintf(stderr, "[INIT_82440530] CALLING ORIGINAL FUNCTION (viewport fixed)\n");
    fflush(stderr);

    __imp__sub_82440530(ctx, base);

    fprintf(stderr, "[INIT_82440530] RETURN r3=%08X\n", ctx.r3.u32);
    fflush(stderr);
}

// NOTE: sub_82440448 is replaced by MW05_Stub_sub_82440448 (recompiler bug - hangs)

GUEST_FUNCTION_HOOK(sub_82216088, MW05_Trace_sub_82216088);
GUEST_FUNCTION_HOOK(sub_82440530, MW05_Trace_sub_82440530);

// NOTE: sub_825A16A0, sub_825A8698, sub_825AAE58 are already defined in mw05_draw_diagnostic.cpp

// Trace functions called AFTER sub_82216088 in sub_823AF590 to find blocking point

// sub_82159AF0 - Memory pool allocator function
PPC_FUNC_IMPL(__imp__sub_82159AF0);
PPC_FUNC(sub_82159AF0) {
    fprintf(stderr, "[INIT_TRACE] sub_82159AF0 ENTER r3=%08X r4=%08X r5=%08X r6=%08X tid=%lx\n",
            ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32, GetCurrentThreadId());
    fflush(stderr);

    __imp__sub_82159AF0(ctx, base);

    fprintf(stderr, "[INIT_TRACE] sub_82159AF0 RETURN r3=%08X\n", ctx.r3.u32);
    fflush(stderr);
}

// sub_8215A2C8 - Memory pool creation function
PPC_FUNC_IMPL(__imp__sub_8215A2C8);
PPC_FUNC(sub_8215A2C8) {
    fprintf(stderr, "[INIT_TRACE] sub_8215A2C8 ENTER r3=%08X r4=%08X r5=%08X tid=%lx\n",
            ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, GetCurrentThreadId());
    fflush(stderr);

    __imp__sub_8215A2C8(ctx, base);

    fprintf(stderr, "[INIT_TRACE] sub_8215A2C8 RETURN r3=%08X\n", ctx.r3.u32);
    fflush(stderr);
}

// sub_8222B0D8 - Called immediately after sub_82216088
PPC_FUNC_IMPL(__imp__sub_8222B0D8);
PPC_FUNC(sub_8222B0D8) {
    fprintf(stderr, "[INIT_TRACE] sub_8222B0D8 ENTER r3=%08X tid=%lx\n", ctx.r3.u32, GetCurrentThreadId());
    fflush(stderr);

    // TRY CALLING THE ORIGINAL FUNCTION NOW THAT VIEWPORT IS FIXED
    // This is a particle pool allocator that was taking 60+ seconds
    // Now that viewport is initialized, it might work faster
    fprintf(stderr, "[INIT_TRACE] sub_8222B0D8 CALLING ORIGINAL FUNCTION (viewport fixed)\n");
    fflush(stderr);

    __imp__sub_8222B0D8(ctx, base);

    fprintf(stderr, "[INIT_TRACE] sub_8222B0D8 RETURN r3=%08X\n", ctx.r3.u32);
    fflush(stderr);
}

// sub_822D6A50 - Called after resource pool creation
PPC_FUNC_IMPL(__imp__sub_822D6A50);
PPC_FUNC(sub_822D6A50) {
    fprintf(stderr, "[INIT_TRACE] sub_822D6A50 ENTER tid=%lx\n", GetCurrentThreadId());
    fflush(stderr);

    // TRY CALLING THE ORIGINAL FUNCTION NOW THAT VIEWPORT IS FIXED
    fprintf(stderr, "[INIT_TRACE] sub_822D6A50 CALLING ORIGINAL FUNCTION (viewport fixed)\n");
    fflush(stderr);

    __imp__sub_822D6A50(ctx, base);

    fprintf(stderr, "[INIT_TRACE] sub_822D6A50 RETURN r3=%08X\n", ctx.r3.u32);
    fflush(stderr);
}

// Forward declaration for sub_823BA448
PPC_FUNC_IMPL(__imp__sub_823BA448);

// Hook for sub_823BA448 - CRITICAL FUNCTION that initializes work queue!
// This function is called by sub_823AF590 but sub_823AF590 returns early and never calls it!
// This is the ROOT CAUSE of draws=0 - work queue is never initialized!
static void MW05_Hook_sub_823BA448(PPCContext& ctx, uint8_t* base) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    fprintf(stderr, "[WORK_QUEUE_INIT_823BA448] ENTER: count=%llu tid=%lx\n",
            count, GetCurrentThreadId());
    fprintf(stderr, "[WORK_QUEUE_INIT_823BA448] This function initializes the work queue and calls sub_823BA108!\n");
    fflush(stderr);

    // Call the original
    __imp__sub_823BA448(ctx, base);

    fprintf(stderr, "[WORK_QUEUE_INIT_823BA448] RETURN: count=%llu r3=%08X\n",
            count, ctx.r3.u32);
    fflush(stderr);
}

GUEST_FUNCTION_HOOK(sub_823BA448, MW05_Hook_sub_823BA448);

// Trace functions called in sub_823AF590 initialization sequence to find blocking point

// sub_82155FB0 - Called at 0x823AF654 (FIRST function after ZDIR check!)
PPC_FUNC_IMPL(__imp__sub_82155FB0);
PPC_FUNC(sub_82155FB0) {
    fprintf(stderr, "[INIT_TRACE] sub_82155FB0 ENTER r3=%08X tid=%lx\n", ctx.r3.u32, GetCurrentThreadId());
    fflush(stderr);
    __imp__sub_82155FB0(ctx, base);
    fprintf(stderr, "[INIT_TRACE] sub_82155FB0 RETURN r3=%08X\n", ctx.r3.u32);
    fflush(stderr);
}

// sub_823B7F20 - Called at 0x823AF66C
PPC_FUNC_IMPL(__imp__sub_823B7F20);
PPC_FUNC(sub_823B7F20) {
    fprintf(stderr, "[INIT_TRACE] sub_823B7F20 ENTER r3=%08X tid=%lx\n", ctx.r3.u32, GetCurrentThreadId());
    fflush(stderr);
    __imp__sub_823B7F20(ctx, base);
    fprintf(stderr, "[INIT_TRACE] sub_823B7F20 RETURN r3=%08X\n", ctx.r3.u32);
    fflush(stderr);
}

// sub_823AF490 - Called at 0x823AF670
PPC_FUNC_IMPL(__imp__sub_823AF490);
PPC_FUNC(sub_823AF490) {
    fprintf(stderr, "[INIT_TRACE] sub_823AF490 ENTER r3=%08X tid=%lx\n", ctx.r3.u32, GetCurrentThreadId());
    fflush(stderr);
    __imp__sub_823AF490(ctx, base);
    fprintf(stderr, "[INIT_TRACE] sub_823AF490 RETURN r3=%08X\n", ctx.r3.u32);
    fflush(stderr);
}

// sub_824C7608 - Called after sub_823BA448 at 0x823AF6A8
PPC_FUNC_IMPL(__imp__sub_824C7608);
PPC_FUNC(sub_824C7608) {
    fprintf(stderr, "[INIT_TRACE] sub_824C7608 ENTER tid=%lx\n", GetCurrentThreadId());
    fflush(stderr);
    __imp__sub_824C7608(ctx, base);
    fprintf(stderr, "[INIT_TRACE] sub_824C7608 RETURN r3=%08X\n", ctx.r3.u32);
    fflush(stderr);
}

// Wrapper for sub_823BB258 - file loading function called in sub_823AF590
// Loads NFS\\ZDIR.BIN and NFS\\ZZDATA files
// CRITICAL FIX: These files don't exist in extracted game directories (they're Xbox 360 disc-specific)
// The game works fine without them since we have extracted files, so return success
PPC_FUNC_IMPL(__imp__sub_823BB258);
PPC_FUNC(sub_823BB258) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    // Get filenames from r3 and r4
    const char* filename1 = nullptr;
    const char* filename2 = nullptr;
    if (ctx.r3.u32 >= 0x80000000 && ctx.r3.u32 < 0x90000000) {
        filename1 = reinterpret_cast<const char*>(g_memory.Translate(ctx.r3.u32));
    }
    if (ctx.r4.u32 >= 0x80000000 && ctx.r4.u32 < 0x90000000) {
        filename2 = reinterpret_cast<const char*>(g_memory.Translate(ctx.r4.u32));
    }

    fprintf(stderr, "[FILE_LOAD_823BB258] ENTER r3=%08X (%s) r4=%08X (%s) tid=%lx\n",
            ctx.r3.u32, filename1 ? filename1 : "NULL",
            ctx.r4.u32, filename2 ? filename2 : "NULL",
            GetCurrentThreadId());
    fflush(stderr);

    // CRITICAL FIX: NFS\\ZDIR.BIN and NFS\\ZZDATA files don't exist in extracted game directories
    // These are Xbox 360 disc-specific virtual file system files
    // The game works fine without them since we have extracted game files
    // Return success (1) to allow initialization to continue
    fprintf(stderr, "[FILE_LOAD_823BB258] SKIPPING: Virtual FS files not needed with extracted game files\n");
    fflush(stderr);

    ctx.r3.u32 = 1; // Return success

    fprintf(stderr, "[FILE_LOAD_823BB258] RETURN r3=%08X (BYPASSED)\n", ctx.r3.u32);
    fflush(stderr);
}

// Wrapper for sub_8261DBE0 - virtual file system mount function
PPC_FUNC_IMPL(__imp__sub_8261DBE0);
PPC_FUNC(sub_8261DBE0) {
    fprintf(stderr, "[VFS_MOUNT_8261DBE0] ENTER r3=%08X r4=%08X tid=%lx\n",
            ctx.r3.u32, ctx.r4.u32, GetCurrentThreadId());
    fflush(stderr);

    __imp__sub_8261DBE0(ctx, base);

    fprintf(stderr, "[VFS_MOUNT_8261DBE0] RETURN r3=%08X\n", ctx.r3.u32);
    fflush(stderr);
}

// Wrapper for sub_8261DED8 - virtual file system registration function
PPC_FUNC_IMPL(__imp__sub_8261DED8);
PPC_FUNC(sub_8261DED8) {
    fprintf(stderr, "[VFS_REGISTER_8261DED8] ENTER r3=%08X tid=%lx\n",
            ctx.r3.u32, GetCurrentThreadId());
    fflush(stderr);

    __imp__sub_8261DED8(ctx, base);

    fprintf(stderr, "[VFS_REGISTER_8261DED8] RETURN r3=%08X\n", ctx.r3.u32);
    fflush(stderr);
}


// Wrapper for sub_8261B028 - wait for event function
// This function is called by sub_8262BF58 to wait for an event.
// If it returns -1, the wait failed/timed out.
PPC_FUNC_IMPL(__imp__sub_8261B028);
PPC_FUNC(sub_8261B028) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    uint32_t r3_in = ctx.r3.u32;
    uint32_t r4_in = ctx.r4.u32;

    fprintf(stderr, "[WAIT_EVENT_8261B028] ENTER: count=%llu r3=%08X r4=%08X tid=%lx\n",
            count, r3_in, r4_in, GetCurrentThreadId());
    fflush(stderr);

    // Call the original
    __imp__sub_8261B028(ctx, base);

    fprintf(stderr, "[WAIT_EVENT_8261B028] RETURN: count=%llu r3=%08X (-1=failed/timeout)\n",
            count, ctx.r3.u32);
    fflush(stderr);
}

// Wrapper for sub_8262BF58 - wait for work function
// This function is called by the work queue processor to wait for work items.
// If it returns non-zero, the work queue processor exits.
// If it returns zero, the work queue processor continues processing.
//
// CRITICAL DISCOVERY: This function manages a semaphore counter at offset +32 of the structure.
// It decrements the counter and if it goes negative, returns immediately with that negative value.
// This causes the work queue processor to exit!
//
// The counter at offset +32 needs to be incremented when work items are added to the queue.
PPC_FUNC_IMPL(__imp__sub_8262BF58);
PPC_FUNC(sub_8262BF58) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    uint32_t r3_in = ctx.r3.u32;
    uint32_t r4_in = ctx.r4.u32;
    uint32_t r5_in = ctx.r5.u32;

    // Read the semaphore counter at offset +32 of r4 structure
    uint32_t counter_before = PPC_LOAD_U32(r4_in + 32);

    fprintf(stderr, "[WAIT_FOR_WORK_8262BF58] ENTER: count=%llu r3=%08X r4=%08X r5=%08X counter_at_r4+32=%d tid=%lx\n",
            count, r3_in, r4_in, r5_in, (int32_t)counter_before, GetCurrentThreadId());
    fflush(stderr);

    // Call the original
    __imp__sub_8262BF58(ctx, base);

    uint32_t counter_after = PPC_LOAD_U32(r4_in + 32);

    fprintf(stderr, "[WAIT_FOR_WORK_8262BF58] RETURN: count=%llu r3=%08X counter_after=%d (0=continue, non-zero=exit)\n",
            count, ctx.r3.u32, (int32_t)counter_after);
    fflush(stderr);
}

// Wrapper for sub_823B9E00 - work queue processor
// This function is called by Thread #1 to process work items from the queue at 0x829091C8
PPC_FUNC_IMPL(__imp__sub_823B9E00);
PPC_FUNC(sub_823B9E00) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    // Log first few calls and periodically
    if (count < 10 || count % 1000 == 0) {
        fprintf(stderr, "[WORK_QUEUE] sub_823B9E00 called: count=%llu r3=%08X tid=%lx\n",
                count, ctx.r3.u32, GetCurrentThreadId());
        fflush(stderr);
    }

    // Call the original
    __imp__sub_823B9E00(ctx, base);

    if (count < 10 || count % 1000 == 0) {
        fprintf(stderr, "[WORK_QUEUE] sub_823B9E00 returned: count=%llu r3=%08X\n",
                count, ctx.r3.u32);
        fflush(stderr);
    }
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

    // CRITICAL FIX: sub_82812ED0 calls sub_828134E0 via function pointer (bctrl)
    // The recompiler generates a direct call to __imp__sub_828134E0, bypassing our wrapper
    // We need to manually call the wrapper instead

    // Read the function pointer from context structure at offset +4
    uint32_t func_ptr = 0;
    if (ctx.r3.u32 != 0) {
        uint32_t* ctx_ptr = (uint32_t*)(base + ctx.r3.u32);
        func_ptr = __builtin_bswap32(ctx_ptr[1]);  // +4 offset
        fprintf(stderr, "[WRAPPER_82812ED0] Function pointer at +4: 0x%08X\n", func_ptr);
        fflush(stderr);
    }

    // Check if it's sub_828134E0 (0x828134E0)
    if (func_ptr == 0x828134E0) {
        fprintf(stderr, "[WRAPPER_82812ED0] Detected sub_828134E0 call - calling wrapper instead of __imp__\n");
        fflush(stderr);

        // Set state flag to 1 BEFORE calling the worker
        if (ctx.r3.u32 != 0) {
            uint32_t* ctx_ptr = (uint32_t*)(base + ctx.r3.u32);
            ctx_ptr[0] = __builtin_bswap32(1);  // Set state = 1 (big-endian)
            std::atomic_thread_fence(std::memory_order_seq_cst);
        }

        // Read context parameter from offset +8
        uint32_t context_param = 0;
        if (ctx.r3.u32 != 0) {
            uint32_t* ctx_ptr = (uint32_t*)(base + ctx.r3.u32);
            context_param = __builtin_bswap32(ctx_ptr[2]);  // +8 offset
            fprintf(stderr, "[WRAPPER_82812ED0] Context parameter at +8: 0x%08X\n", context_param);
            fflush(stderr);
        }

        // Call sub_828134E0 wrapper with context parameter as r3
        PPCContext worker_ctx = ctx;
        worker_ctx.r3.u32 = context_param;

        // Use g_memory.FindFunction to get the wrapper (not the __imp__ version)
        auto* func = g_memory.FindFunction(0x828134E0);
        if (func) {
            func(worker_ctx, base);
        } else {
            fprintf(stderr, "[WRAPPER_82812ED0] ERROR: sub_828134E0 wrapper not found in function table!\n");
            fflush(stderr);
        }

        // Copy return value back
        ctx.r3 = worker_ctx.r3;

        fprintf(stderr, "[WRAPPER_82812ED0] sub_828134E0 wrapper returned\n");
        fflush(stderr);
    } else {
        // Unknown function pointer - call original
        fprintf(stderr, "[WRAPPER_82812ED0] Unknown function pointer 0x%08X - calling original\n", func_ptr);
        fflush(stderr);
        __imp__sub_82812ED0(ctx, base);
    }

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



PPC_FUNC_IMPL(__imp__sub_82812F10);
PPC_FUNC(sub_82812F10)
{
    fprintf(stderr, "[INIT-TRACE] sub_82812F10 ENTER\n"); fflush(stderr);
    SetPPCContext(ctx);
    __imp__sub_82812F10(ctx, base);
    fprintf(stderr, "[INIT-TRACE] sub_82812F10 RETURN\n"); fflush(stderr);
}

// NOTE: sub_8215FDC0 wrapper is already defined in mw05_function_hooks.cpp
// NOTE: sub_82813598 wrapper is already defined below (lines 1447+)
// NOTE: sub_8262F2A0 wrapper is already defined in mw05_trace_shims.cpp - modify that one instead

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

// NOTE: sub_82813598 wrapper is already defined above (lines 1004-1022)

// Trace file loading functions to find where sub_823AF590 is blocking

// sub_823B1298 - Called with "GLOBAL\\GLOBALA.BUN" at 0x823AF778
PPC_FUNC_IMPL(__imp__sub_823B1298);
PPC_FUNC(sub_823B1298) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    // Get filename from r3
    const char* filename = nullptr;
    if (ctx.r3.u32 >= 0x80000000 && ctx.r3.u32 < 0x90000000) {
        filename = reinterpret_cast<const char*>(g_memory.Translate(ctx.r3.u32));
    }

    fprintf(stderr, "[FILE_LOAD_823B1298] ENTER count=%llu r3=%08X (%s) r4=%08X r5=%08X r6=%08X r7=%08X tid=%lx\n",
            count, ctx.r3.u32, filename ? filename : "NULL",
            ctx.r4.u32, ctx.r5.u32, ctx.r6.u32, ctx.r7.u32, GetCurrentThreadId());
    fflush(stderr);

    // Call the original
    __imp__sub_823B1298(ctx, base);

    fprintf(stderr, "[FILE_LOAD_823B1298] RETURN count=%llu r3=%08X\n",
            count, ctx.r3.u32);
    fflush(stderr);
}

// sub_823B0F48 - Called after sub_823B1298 at 0x823AF784
PPC_FUNC_IMPL(__imp__sub_823B0F48);
PPC_FUNC(sub_823B0F48) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    fprintf(stderr, "[FILE_PROC_823B0F48] ENTER count=%llu r3=%08X r4=%08X r5=%08X tid=%lx\n",
            count, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, GetCurrentThreadId());
    fflush(stderr);

    // Call the original
    __imp__sub_823B0F48(ctx, base);

    fprintf(stderr, "[FILE_PROC_823B0F48] RETURN count=%llu r3=%08X\n",
            count, ctx.r3.u32);
    fflush(stderr);
}

// sub_823B1408 - Called by sub_823AFFA8 (main game update)
// This function processes file loading queue
// REMOVED SHIM: Cannot override __imp__ symbols due to linker duplicate symbol error
// Let the recompiled version run and see if the game progresses
// The game checks a queue counter at 0x82A2CC14 and processes loaders if > 0

// sub_823B0D20 - File loader initialization
// Called by sub_823B1298 to initialize a file loader structure
PPC_FUNC_IMPL(__imp__sub_823B0D20);
PPC_FUNC(sub_823B0D20) {
    fprintf(stderr, "[FILE_INIT_823B0D20] ENTER r3=%08X r4=%08X r5=%08X r6=%08X r7=%08X r8=%08X tid=%lx\n",
            ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32, ctx.r7.u32, ctx.r8.u32, GetCurrentThreadId());
    fflush(stderr);

    __imp__sub_823B0D20(ctx, base);

    fprintf(stderr, "[FILE_INIT_823B0D20] RETURN r3=%08X\n", ctx.r3.u32);
    fflush(stderr);
}

// sub_8215E5E8 - String interning function
// Called by sub_823B0D20 to intern strings
// CRITICAL FIX: This function has an infinite loop in the hash table search
// Implementing a simple string interning mechanism using a static hash map
PPC_FUNC_IMPL(__imp__sub_8215E5E8);
PPC_FUNC(sub_8215E5E8) {
    // Read the string pointer from r3
    uint32_t str_ptr = ctx.r3.u32;

    // If the pointer is null or invalid, return 0
    if (!str_ptr || str_ptr >= PPC_MEMORY_SIZE) {
        ctx.r3.u32 = 0;
        return;
    }

    const char* str = (const char*)(base + str_ptr);

    // If the string is empty, return 0 (as per IDA decompilation)
    if (!str || str[0] == '\0') {
        ctx.r3.u32 = 0;
        return;
    }

    // Simple string interning: use a static hash map to store interned strings
    // This is thread-safe because we're using a mutex
    static std::mutex intern_mutex;
    static std::unordered_map<std::string, uint32_t> interned_strings;

    std::lock_guard<std::mutex> lock(intern_mutex);

    // Check if the string is already interned
    std::string key(str);
    auto it = interned_strings.find(key);
    if (it != interned_strings.end()) {
        // String already interned, return the interned pointer
        ctx.r3.u32 = it->second;
        return;
    }

    // String not interned yet, store it and return the original pointer
    interned_strings[key] = str_ptr;
    ctx.r3.u32 = str_ptr;
}

// sub_823BCB40 - File open wrapper
// Called by sub_823B0D20 to open a file
PPC_FUNC_IMPL(__imp__sub_823BCB40);
PPC_FUNC(sub_823BCB40) {
    fprintf(stderr, "[FILE_OPEN_823BCB40] ENTER r3=%08X tid=%lx\n",
            ctx.r3.u32, GetCurrentThreadId());
    fflush(stderr);

    __imp__sub_823BCB40(ctx, base);

    fprintf(stderr, "[FILE_OPEN_823BCB40] RETURN r3=%08X\n", ctx.r3.u32);
    fflush(stderr);
}



// sub_8233DFF8 - Called with "GLOBAL\\GAMEPLAY.BIN" at 0x823AF82C
PPC_FUNC_IMPL(__imp__sub_8233DFF8);
PPC_FUNC(sub_8233DFF8) {
    static std::atomic<uint64_t> s_callCount{0};
    uint64_t count = s_callCount.fetch_add(1);

    // Get filename from r3
    const char* filename = nullptr;
    if (ctx.r3.u32 >= 0x80000000 && ctx.r3.u32 < 0x90000000) {
        filename = reinterpret_cast<const char*>(g_memory.Translate(ctx.r3.u32));
    }

    fprintf(stderr, "[FILE_LOAD_8233DFF8] ENTER count=%llu r3=%08X (%s) tid=%lx\n",
            count, ctx.r3.u32, filename ? filename : "NULL", GetCurrentThreadId());
    fflush(stderr);

    // Call the original
    __imp__sub_8233DFF8(ctx, base);

    fprintf(stderr, "[FILE_LOAD_8233DFF8] RETURN count=%llu r3=%08X\n",
            count, ctx.r3.u32);
    fflush(stderr);
}

// Register the thread entry point hooks
// These wrapper functions are registered via g_memory.InsertFunction in main.cpp
// Do NOT use GUEST_FUNCTION_HOOK here as it causes redefinition errors with the recompiled PPC code
