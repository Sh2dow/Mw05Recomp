// system_threads.cpp - System threads that the game expects to exist
// These threads are created by Xenia BEFORE the game module loads
// The game waits for these threads to be running before it starts rendering

#include <stdafx.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include "kernel/trace.h"
#include "kernel/memory.h"

// Forward declarations
extern Memory g_memory;
extern "C" {
    // XKEVENT is a typedef for XDISPATCHER_HEADER in xbox.h, don't redeclare it
    uint32_t KeSetEvent(XKEVENT* Event, int32_t Increment, bool Wait);

    // Ring buffer accessors from imports.cpp
    uint32_t GetRbWriteBackPtr();
    uint32_t GetRbLen();

    // From mw05_trace_shims.cpp namespace
    uint32_t Mw05GetRingBaseEA();
}

// PM4 parser functions from pm4_parser.cpp
extern void PM4_OnRingBufferWrite(uint32_t writePtr);
extern uint64_t PM4_GetDrawCount();

// VD callback accessors from imports.cpp
extern "C" uint32_t GetVdGraphicsCallback();
extern "C" uint32_t GetVdGraphicsCallbackCtx();

// System thread entry points - these are stub implementations that just sleep
// The game doesn't actually use these threads, but it expects them to exist

static std::atomic<bool> g_systemThreadsRunning{false};

// GPU Commands thread - processes PM4 commands from the ring buffer
static void GpuCommandsThreadEntry()
{
    KernelTraceHostOp("HOST.SystemThread.GPUCommands.start");
    fprintf(stderr, "[SYSTEM-THREAD] GPU Commands thread started\n");
    fflush(stderr);

    // Get the render thread event address from environment
    // The render thread waits on event at ctx+0x20
    const char* ctx_str = std::getenv("MW05_RENDER_THREAD_CTX");
    uint32_t ctx = ctx_str ? (uint32_t)std::strtoul(ctx_str, nullptr, 0) : 0x40009D2Cu;
    uint32_t event_ea = ctx + 0x20;  // Event is at ctx+0x20 (0x40009D4C)

    fprintf(stderr, "[SYSTEM-THREAD] GPU Commands will process PM4 ring buffer and signal event at 0x%08X (ctx=0x%08X)\n", event_ea, ctx);
    fflush(stderr);

    // Wait a bit for the ring buffer to be initialized
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    uint32_t signal_count = 0;
    uint32_t last_rptr = 0;
    uint64_t last_draw_count = 0;
    bool logged_state = false;

    while (g_systemThreadsRunning.load(std::memory_order_acquire))
    {
        // Get ring buffer state
        uint32_t wb_ea = GetRbWriteBackPtr();
        uint32_t rb_base = Mw05GetRingBaseEA();
        uint32_t rb_len_log2 = GetRbLen();

        // Log ring buffer state once
        if (!logged_state && wb_ea && rb_base && rb_len_log2) {
            fprintf(stderr, "[GPU-COMMANDS] Ring buffer state: wb_ea=0x%08X rb_base=0x%08X rb_len_log2=%u\n",
                    wb_ea, rb_base, rb_len_log2);
            fflush(stderr);
            logged_state = true;
        }

        if (wb_ea && rb_base && rb_len_log2) {
            // Read current read pointer (rptr) from writeback address
            auto* rptr_host = reinterpret_cast<uint32_t*>(g_memory.Translate(wb_ea));
            if (rptr_host) {
                uint32_t rptr = *rptr_host;

                // CRITICAL FIX (2025-10-31): Validate rptr to prevent reading corrupted memory
                // If rptr is 0xFFFFFFFF, the memory is uninitialized or corrupted
                // Valid rptr values should be within the ring buffer range (0 to ring_size-1)
                uint32_t ring_size = (1u << rb_len_log2);
                bool rptr_valid = (rptr != 0xFFFFFFFF) && (rptr < ring_size);

                // Log first few rptr values
                if (signal_count <= 5) {
                    fprintf(stderr, "[GPU-COMMANDS] rptr=0x%08X (last=0x%08X) valid=%d ring_size=0x%X\n",
                            rptr, last_rptr, rptr_valid, ring_size);
                    fflush(stderr);
                }

                // Only process if rptr is valid
                if (!rptr_valid) {
                    if (signal_count <= 5) {
                        fprintf(stderr, "[GPU-COMMANDS] ⚠️ Invalid rptr=0x%08X detected, skipping PM4 processing\n", rptr);
                        fflush(stderr);
                    }
                    // Don't update last_rptr, wait for valid value
                } else if (rptr != last_rptr) {
                    // Check if there are new commands to process (rptr changed)
                    // Reduced spam: only log every 100th rptr change
                    static std::atomic<int> s_rptr_change_count{0};
                    if (s_rptr_change_count.fetch_add(1) % 100 == 0) {
                        fprintf(stderr, "[GPU-COMMANDS] rptr changed from 0x%08X to 0x%08X, processing PM4 commands (logged every 100 changes)\n",
                            last_rptr, rptr);
                        fflush(stderr);
                    }

                    // Process PM4 commands from ring buffer
                    PM4_OnRingBufferWrite(rptr);

                    // Check if we found any draw commands
                    uint64_t draw_count = PM4_GetDrawCount();
                    if (draw_count != last_draw_count) {
                        fprintf(stderr, "[GPU-COMMANDS] Processed PM4 commands, draws=%llu (new: %llu)\n",
                                draw_count, draw_count - last_draw_count);
                        fflush(stderr);
                        last_draw_count = draw_count;
                    }

                    // DISABLED: VD ISR source=1 call causes crash
                    // The crash happens because we're calling from a host thread without proper guest context
                    // Instead, we'll set a flag that the VBlank ISR can check and call VD ISR source=1 from there
                    // This way, the VD ISR will be called from a thread with proper guest context
                    #if 0
                    uint32_t vd_callback = GetVdGraphicsCallback();
                    uint32_t vd_ctx = GetVdGraphicsCallbackCtx();
                    if (vd_callback != 0 && vd_ctx != 0) {
                        static uint32_t s_vd_isr_call_count = 0;
                        s_vd_isr_call_count++;

                        if (s_vd_isr_call_count <= 5 || s_vd_isr_call_count % 60 == 0) {
                            fprintf(stderr, "[GPU-COMMANDS] Calling VD ISR with source=1 (CPU interrupt) cb=0x%08X ctx=0x%08X count=%u\n",
                                    vd_callback, vd_ctx, s_vd_isr_call_count);
                            fflush(stderr);
                        }

                        // Call the VD ISR with source=1 (CPU interrupt)
                        // This tells the game that PM4 commands have been processed
                        // Wrapped in try-catch to debug crash
                        __try {
                            GuestToHostFunction<void>(vd_callback, 1u, vd_ctx);
                        } __except(EXCEPTION_EXECUTE_HANDLER) {
                            fprintf(stderr, "[GPU-COMMANDS] VD ISR source=1 crashed! Exception code: 0x%08X\n", GetExceptionCode());
                            fflush(stderr);
                        }
                    }
                    #endif

                    last_rptr = rptr;
                }
            }
        }

        // Signal the render thread event to wake it up
        if (auto* evt = reinterpret_cast<XKEVENT*>(g_memory.Translate(event_ea))) {
            KeSetEvent(evt, 1, false);
            signal_count++;

            // Log first few signals for debugging
            if (signal_count <= 5 || signal_count % 60 == 0) {
                fprintf(stderr, "[SYSTEM-THREAD] GPU Commands signaled event 0x%08X (count=%u, draws=%llu)\n",
                        event_ea, signal_count, PM4_GetDrawCount());
                fflush(stderr);
            }
        }

        // Sleep for 16ms (60 FPS)
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }

    fprintf(stderr, "[SYSTEM-THREAD] GPU Commands signaled event %u times total, processed %llu draws\n",
            signal_count, PM4_GetDrawCount());
    fflush(stderr);
    KernelTraceHostOp("HOST.SystemThread.GPUCommands.exit");
}

// GPU Frame limiter thread - manages frame timing
static void GpuFrameLimiterThreadEntry()
{
    KernelTraceHostOp("HOST.SystemThread.GPUFrameLimiter.start");
    fprintf(stderr, "[SYSTEM-THREAD] GPU Frame limiter thread started\n");
    fflush(stderr);
    
    while (g_systemThreadsRunning.load(std::memory_order_acquire))
    {
        // Sleep for 16ms (60 FPS)
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }
    
    KernelTraceHostOp("HOST.SystemThread.GPUFrameLimiter.exit");
}

// XMA Decoder thread - decodes XMA audio
static void XmaDecoderThreadEntry()
{
    KernelTraceHostOp("HOST.SystemThread.XMADecoder.start");
    fprintf(stderr, "[SYSTEM-THREAD] XMA Decoder thread started\n");
    fflush(stderr);
    
    while (g_systemThreadsRunning.load(std::memory_order_acquire))
    {
        // Sleep for 10ms
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    KernelTraceHostOp("HOST.SystemThread.XMADecoder.exit");
}

// Audio Worker thread - processes audio
static void AudioWorkerThreadEntry()
{
    KernelTraceHostOp("HOST.SystemThread.AudioWorker.start");
    fprintf(stderr, "[SYSTEM-THREAD] Audio Worker thread started\n");
    fflush(stderr);

    while (g_systemThreadsRunning.load(std::memory_order_acquire))
    {
        // Sleep for 10ms
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    KernelTraceHostOp("HOST.SystemThread.AudioWorker.exit");
}

// REMOVED: Main Loop Flag Setter thread
// The flag should be set by VBlank pump, not continuously by a background thread
// The game uses a consume-and-clear pattern: reads flag, processes frame, clears flag
// Setting it continuously creates a race condition

// Kernel Dispatch thread - dispatches kernel events
static void KernelDispatchThreadEntry()
{
    KernelTraceHostOp("HOST.SystemThread.KernelDispatch.start");
    fprintf(stderr, "[SYSTEM-THREAD] Kernel Dispatch thread started\n");
    fflush(stderr);
    
    while (g_systemThreadsRunning.load(std::memory_order_acquire))
    {
        // Sleep for 5ms
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    
    KernelTraceHostOp("HOST.SystemThread.KernelDispatch.exit");
}

// Create all system threads
void Mw05CreateSystemThreads()
{
    KernelTraceHostOp("HOST.SystemThreads.create.start");
    fprintf(stderr, "[SYSTEM-THREADS] Creating system threads...\n");
    fflush(stderr);
    
    // Mark threads as running
    g_systemThreadsRunning.store(true, std::memory_order_release);
    
    // Create GPU Commands thread
    std::thread gpuCommandsThread(GpuCommandsThreadEntry);
    gpuCommandsThread.detach();
    fprintf(stderr, "[SYSTEM-THREADS] GPU Commands thread created\n");
    fflush(stderr);
    
    // Create GPU Frame limiter thread
    std::thread gpuFrameLimiterThread(GpuFrameLimiterThreadEntry);
    gpuFrameLimiterThread.detach();
    fprintf(stderr, "[SYSTEM-THREADS] GPU Frame limiter thread created\n");
    fflush(stderr);
    
    // Create XMA Decoder thread
    std::thread xmaDecoderThread(XmaDecoderThreadEntry);
    xmaDecoderThread.detach();
    fprintf(stderr, "[SYSTEM-THREADS] XMA Decoder thread created\n");
    fflush(stderr);
    
    // Create Audio Worker thread
    std::thread audioWorkerThread(AudioWorkerThreadEntry);
    audioWorkerThread.detach();
    fprintf(stderr, "[SYSTEM-THREADS] Audio Worker thread created\n");
    fflush(stderr);
    
    // Create Kernel Dispatch thread
    std::thread kernelDispatchThread(KernelDispatchThreadEntry);
    kernelDispatchThread.detach();
    fprintf(stderr, "[SYSTEM-THREADS] Kernel Dispatch thread created\n");
    fflush(stderr);

    // Give threads time to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    KernelTraceHostOp("HOST.SystemThreads.create.complete");
    fprintf(stderr, "[SYSTEM-THREADS] All system threads created and running\n");
    fflush(stderr);
}

// Shutdown all system threads
extern "C" void Mw05ShutdownSystemThreads()
{
    KernelTraceHostOp("HOST.SystemThreads.shutdown.start");
    fprintf(stderr, "[SYSTEM-THREADS] Shutting down system threads...\n");
    fflush(stderr);
    
    // Signal threads to exit
    g_systemThreadsRunning.store(false, std::memory_order_release);
    
    // Give threads time to exit
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    KernelTraceHostOp("HOST.SystemThreads.shutdown.complete");
    fprintf(stderr, "[SYSTEM-THREADS] All system threads shut down\n");
    fflush(stderr);
}

