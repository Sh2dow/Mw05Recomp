// Temporary test to manually queue a loader job to see if the loader system is functional
// This is a workaround to test if the issue is just a missing trigger
#include <cpu/ppc_context.h>
#include <kernel/memory.h>
#include <kernel/trace.h>
#include <cstdio>
#include <cstdint>

// Test function to manually queue a loader job
// This will be called from a hook to trigger the loader system
void ForceQueueLoaderJob()
{
    static bool s_queued = false;

    if (s_queued) {
        return; // Only queue once
    }

    s_queued = true;

    fprintf(stderr, "[LOADER-TEST] Attempting to manually queue a loader job...\n");
    fflush(stderr);

    // Loader callback structure is at 0x82A2B318
    uint32_t callback_param_addr = 0x82A2B318;

    // Access the structure in guest memory
    // Structure layout (from research):
    //   +0x00: unknown
    //   +0x04: unknown
    //   +0x08: unknown
    //   +0x0C: unknown
    //   +0x10: param1 (work function address)
    //   +0x14: param2
    //   +0x18: unknown
    //   +0x1C: work_func (if NULL, use param1 as function)

    // Read current values
    uint32_t* callback_struct = reinterpret_cast<uint32_t*>(g_memory.base + callback_param_addr);
    
    fprintf(stderr, "[LOADER-TEST] Current callback structure at 0x%08X:\n", callback_param_addr);
    fprintf(stderr, "[LOADER-TEST]   +0x00 = 0x%08X\n", __builtin_bswap32(callback_struct[0]));
    fprintf(stderr, "[LOADER-TEST]   +0x04 = 0x%08X\n", __builtin_bswap32(callback_struct[1]));
    fprintf(stderr, "[LOADER-TEST]   +0x08 = 0x%08X\n", __builtin_bswap32(callback_struct[2]));
    fprintf(stderr, "[LOADER-TEST]   +0x0C = 0x%08X\n", __builtin_bswap32(callback_struct[3]));
    fprintf(stderr, "[LOADER-TEST]   +0x10 (param1) = 0x%08X\n", __builtin_bswap32(callback_struct[4]));
    fprintf(stderr, "[LOADER-TEST]   +0x14 (param2) = 0x%08X\n", __builtin_bswap32(callback_struct[5]));
    fprintf(stderr, "[LOADER-TEST]   +0x18 = 0x%08X\n", __builtin_bswap32(callback_struct[6]));
    fprintf(stderr, "[LOADER-TEST]   +0x1C (work_func) = 0x%08X\n", __builtin_bswap32(callback_struct[7]));
    fflush(stderr);
    
    // According to the research document, param1 is already set to 0x82441E58 (work function)
    // We just need to trigger the loader callback to process it
    // But the research says work_func=0x00000000, which means no work is queued
    
    // Let's try a different approach: look for a function that queues work
    // The game must have a function that writes to this structure
    
    // For now, let's just log that we're here and see what happens
    fprintf(stderr, "[LOADER-TEST] Loader job queue test complete. Waiting to see if loader activates...\n");
    fflush(stderr);
}

// Hook to be called early in the main loop to trigger the loader test
void MainLoopLoaderTest()
{
    static uint32_t s_call_count = 0;
    s_call_count++;
    
    // Only try to queue on the 10th iteration (give the game time to initialize)
    if (s_call_count == 10) {
        fprintf(stderr, "[LOADER-TEST] Main loop iteration %u - triggering loader test\n", s_call_count);
        fflush(stderr);
        ForceQueueLoaderJob();
    }
}

