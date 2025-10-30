// MW05 heap allocation shims to fix worker thread compatibility issues.
// These override weak recompiled functions to skip bugchecks that prevent
// worker threads from allocating memory.

#include <cpu/ppc_context.h>
#include <kernel/trace.h>
#include <kernel/memory.h>
#include <ppc/ppc_config.h>
#include <cstdlib>
#include <cstring>

extern Memory g_memory;

// Forward declaration for the original recompiled function
PPC_FUNC_IMPL(__imp__sub_82632570);

// CRITICAL FIX (2025-10-30): Override sub_82632570 to skip process type bugcheck
// 
// Problem: Worker threads call sub_826BE2B0 -> sub_82632570 to allocate memory
// The allocation function has a bugcheck:
//   if ((heap_flags & 0x40000) && (heap[379] != KeGetCurrentProcessType()))
//     KeBugCheckEx(0xF4, ...)
// 
// This bugcheck fails because:
// - heap[379] contains the process type from when the heap was initialized
// - KeGetCurrentProcessType() returns 1 (current process type)
// - These don't match, causing bugcheck 0xF4 (CRITICAL_OBJECT_TERMINATION)
//
// Solution: Override sub_82632570 to skip the bugcheck and call the rest of the function
//
// Function signature (from IDA):
//   void __fastcall __noreturn sub_82632570(DWORD a1, int a2, DWORD a3)
//   a1 = heap handle
//   a2 = flags
//   a3 = size
//
PPC_FUNC(sub_82632570)
{
    // Get parameters from PPC registers
    uint32_t heap_handle = ctx.r3.u32;  // a1
    uint32_t flags = ctx.r4.u32;        // a2
    uint32_t size = ctx.r5.u32;         // a3

    // CRITICAL: Skip the bugcheck by NOT checking heap[379] vs KeGetCurrentProcessType()
    // The bugcheck is at the very beginning of the function, so we can just skip it
    // and let the rest of the function run normally.

    // However, we can't easily skip just the bugcheck without rewriting the entire function.
    // Instead, we'll patch the heap structure to set heap[379] = 1 BEFORE calling the original function.

    if (heap_handle != 0) {
        uint8_t* heap_struct = reinterpret_cast<uint8_t*>(g_memory.Translate(heap_handle));
        if (heap_struct) {
            // Check if heap[379] needs patching
            if (heap_struct[379] != 1) {
                static bool s_logged = false;
                if (!s_logged) {
                    fprintf(stderr, "[HEAP-SHIM] CRITICAL FIX: Patching heap process type (heap=0x%08X, old_type=%u, new_type=1)\n", 
                            heap_handle, heap_struct[379]);
                    fprintf(stderr, "[HEAP-SHIM]   This prevents KeBugCheckEx 0xF4 in worker threads\n");
                    fflush(stderr);
                    s_logged = true;
                }
                heap_struct[379] = 1;  // KeGetCurrentProcessType() returns 1
            }
        }
    }

    // Now call the original function - the bugcheck will pass because heap[379] == 1
    __imp__sub_82632570(ctx, base);
}

