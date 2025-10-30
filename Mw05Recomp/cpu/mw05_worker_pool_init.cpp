#include <stdafx.h>
#include <kernel/init_manager.h>
#include <kernel/memory.h>
#include <kernel/heap.h>
#include <cstdio>

/**
 * MW05 Worker Thread Pool Constants Initializer
 * 
 * This module initializes the worker thread pool constants that the game expects
 * to be set up before worker threads are created.
 * 
 * Background:
 * - The game has a static worker thread pool at 0x82A2B318 (12 slots, 56 bytes each)
 * - Each slot needs to be initialized with work_func = 0x82441E58 at offset +16
 * - The game calls sub_8261A158() to allocate contexts from this pool
 * - BUT the pool structure is never initialized naturally by the game
 * 
 * This initializer sets up the pool structure BEFORE the game code runs,
 * allowing natural thread creation to work correctly.
 */

extern Memory g_memory;
extern Heap g_userHeap;

namespace Mw05WorkerPoolInit {

// Worker thread pool constants
constexpr uint32_t WORKER_POOL_BASE = 0x82A2B318;      // Base address of worker thread pool
constexpr uint32_t WORKER_POOL_SLOTS = 12;             // Number of pre-allocated slots
constexpr uint32_t WORKER_SLOT_SIZE = 56;              // Size of each slot in bytes
constexpr uint32_t WORKER_ENTRY_POINT = 0x82441E58;    // Worker thread entry point function
constexpr uint32_t ALLOCATION_BITMAP = 0x82C5E2AC;     // Bitmap tracking which slots are in use

/**
 * Initialize the worker thread pool structure
 * 
 * This function sets up the callback parameter structure at 0x82A2B318
 * with the correct work_func pointer so that when the game calls
 * sub_8261A158() to allocate a worker context, it gets a properly
 * initialized structure.
 */
void InitializeWorkerPoolConstants()
{
    fprintf(stderr, "[WORKER-POOL-INIT] ========================================\n");
    fprintf(stderr, "[WORKER-POOL-INIT] Initializing worker thread pool constants...\n");
    fprintf(stderr, "[WORKER-POOL-INIT] ========================================\n");
    fflush(stderr);

    // Verify memory is initialized
    if (!g_memory.base) {
        fprintf(stderr, "[WORKER-POOL-INIT] ERROR: Memory not initialized!\n");
        fflush(stderr);
        return;
    }

    // Get pointer to worker pool base
    uint8_t* pool_base = static_cast<uint8_t*>(g_memory.Translate(WORKER_POOL_BASE));
    if (!pool_base) {
        fprintf(stderr, "[WORKER-POOL-INIT] ERROR: Failed to translate pool address 0x%08X\n", WORKER_POOL_BASE);
        fflush(stderr);
        return;
    }

    // Get pointer to allocation bitmap
    uint8_t* bitmap_base = static_cast<uint8_t*>(g_memory.Translate(ALLOCATION_BITMAP));
    if (!bitmap_base) {
        fprintf(stderr, "[WORKER-POOL-INIT] ERROR: Failed to translate bitmap address 0x%08X\n", ALLOCATION_BITMAP);
        fflush(stderr);
        return;
    }

    fprintf(stderr, "[WORKER-POOL-INIT] Pool base: 0x%08X (host: %p)\n", WORKER_POOL_BASE, pool_base);
    fprintf(stderr, "[WORKER-POOL-INIT] Bitmap base: 0x%08X (host: %p)\n", ALLOCATION_BITMAP, bitmap_base);
    fprintf(stderr, "[WORKER-POOL-INIT] Slots: %u, Slot size: %u bytes\n", WORKER_POOL_SLOTS, WORKER_SLOT_SIZE);
    fprintf(stderr, "[WORKER-POOL-INIT] Worker entry point: 0x%08X\n", WORKER_ENTRY_POINT);
    fflush(stderr);

    // Initialize allocation bitmap (all slots free initially)
    // The bitmap uses 1 DWORD per slot (0 = free, 1 = allocated)
    be<uint32_t>* bitmap = reinterpret_cast<be<uint32_t>*>(bitmap_base);
    for (uint32_t i = 0; i < WORKER_POOL_SLOTS; i++) {
        bitmap[i] = 0;  // Mark all slots as free
    }
    fprintf(stderr, "[WORKER-POOL-INIT] Initialized allocation bitmap (%u slots, all free)\n", WORKER_POOL_SLOTS);
    fflush(stderr);

    // Initialize each slot in the pool
    // Each slot is a worker thread context structure (56 bytes)
    // Layout (based on IDA analysis):
    //   +0x00: thread_id (DWORD)
    //   +0x04: unknown (DWORD)
    //   +0x08: unknown (DWORD)
    //   +0x0C: exit_code (DWORD)
    //   +0x10: work_func (DWORD) - CRITICAL! Must be 0x82441E58
    //   +0x14: work_param (DWORD)
    //   +0x18: unknown (DWORD)
    //   +0x1C: flag (DWORD)
    //   ... rest of structure ...

    for (uint32_t slot = 0; slot < WORKER_POOL_SLOTS; slot++) {
        uint32_t slot_offset = slot * WORKER_SLOT_SIZE;
        be<uint32_t>* slot_ptr = reinterpret_cast<be<uint32_t>*>(pool_base + slot_offset);

        // Initialize slot structure
        slot_ptr[0] = 0x00000000u;  // +0x00 - thread_id (will be set when thread is created)
        slot_ptr[1] = 0x00000000u;  // +0x04 - unknown
        slot_ptr[2] = 0x00000000u;  // +0x08 - unknown
        slot_ptr[3] = 0x00000000u;  // +0x0C - exit_code
        slot_ptr[4] = WORKER_ENTRY_POINT;  // +0x10 - work_func (CRITICAL!)
        slot_ptr[5] = 0x00000000u;  // +0x14 - work_param
        slot_ptr[6] = 0x00000000u;  // +0x18 - unknown
        slot_ptr[7] = 0x00000000u;  // +0x1C - flag

        // Zero out the rest of the structure
        for (uint32_t i = 8; i < WORKER_SLOT_SIZE / 4; i++) {
            slot_ptr[i] = 0x00000000u;
        }

        fprintf(stderr, "[WORKER-POOL-INIT] Initialized slot %u at 0x%08X (work_func=0x%08X)\n",
                slot, WORKER_POOL_BASE + slot_offset, WORKER_ENTRY_POINT);
        fflush(stderr);
    }

    // CRITICAL FIX (2025-10-30): Patch game's heap structure for worker thread compatibility
    // Worker threads call sub_826C52B0 which checks:
    //   if (heap_flags & 0x40000) && (heap[379] != KeGetCurrentProcessType())
    //     KeBugCheckEx(0xF4, ...)
    // The game's heap handle is at 0x82C84F50
    // We need to set heap[379] = 1 (KeGetCurrentProcessType() returns 1)
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
                fprintf(stderr, "[WORKER-POOL-INIT] CRITICAL FIX: Set game heap process type to 1 (heap=0x%08X)\n", heap_handle);
                fprintf(stderr, "[WORKER-POOL-INIT]   This prevents KeBugCheckEx 0xF4 in worker threads\n");
                fflush(stderr);
            } else {
                fprintf(stderr, "[WORKER-POOL-INIT] WARNING: Failed to translate heap address 0x%08X\n", heap_handle);
                fflush(stderr);
            }
        } else {
            fprintf(stderr, "[WORKER-POOL-INIT] WARNING: Game heap handle is NULL (not initialized yet?)\n");
            fflush(stderr);
        }
    } else {
        fprintf(stderr, "[WORKER-POOL-INIT] WARNING: Failed to translate heap handle pointer 0x%08X\n", GAME_HEAP_HANDLE_PTR);
        fflush(stderr);
    }

    fprintf(stderr, "[WORKER-POOL-INIT] ========================================\n");
    fprintf(stderr, "[WORKER-POOL-INIT] Worker thread pool initialization complete!\n");
    fprintf(stderr, "[WORKER-POOL-INIT] ========================================\n");
    fflush(stderr);
}

} // namespace Mw05WorkerPoolInit

// CRITICAL: Add a dummy function to ensure this file is linked
// Without this, the linker may optimize away the entire file if it thinks
// there are no references to it
extern "C" void Mw05WorkerPoolInit_ForceLink() {
    fprintf(stderr, "[WORKER-POOL-INIT] Force link function called!\n");
    fflush(stderr);
}

// Register the initialization callback with HIGHEST priority (runs first)
// Priority 10 = Very early initialization (before game hooks)
REGISTER_INIT_CALLBACK_PRIORITY("WorkerPoolConstants", 10, []() {
    fprintf(stderr, "[WORKER-POOL-INIT] REGISTER_INIT_CALLBACK_PRIORITY lambda executing!\n");
    fflush(stderr);
    Mw05WorkerPoolInit::InitializeWorkerPoolConstants();
});

