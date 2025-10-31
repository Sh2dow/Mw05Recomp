// Simple stub for the game's memory allocator sub_8215CB08
// This function is called during main thread initialization to allocate 4 bytes
#include <cpu/ppc_context.h>
#include <kernel/memory.h>
#include <kernel/trace.h>
#include <cstdio>

// Override for sub_8215CB08 - game's memory pool allocator
// Parameters:
//   r3 = size to allocate
//   r4 = unused (0)
//   r5 = unused (0)
//   r6 = allocation flags/pool ID
// Returns:
//   r3 = pointer to allocated memory (or 0 on failure)
PPC_FUNC_IMPL(__imp__sub_8215CB08);
PPC_FUNC(sub_8215CB08)
{
    uint32_t size = ctx.r3.u32;
    uint32_t flags = ctx.r6.u32;
    
    static uint32_t s_call_count = 0;
    s_call_count++;
    
    // Log first 5 allocations
    if (s_call_count <= 5) {
        fprintf(stderr, "[ALLOC-STUB] Call #%u: Allocating %u bytes with flags 0x%08X\n", 
                s_call_count, size, flags);
        fflush(stderr);
    }
    
    // Use the user heap to allocate memory
    // The game expects a guest address, so we need to allocate in guest memory
    uint32_t guest_addr = kernel::memory::UserHeapAlloc(size, 16); // 16-byte alignment
    
    if (guest_addr == 0) {
        fprintf(stderr, "[ALLOC-STUB] ERROR: Failed to allocate %u bytes!\n", size);
        fflush(stderr);
    } else if (s_call_count <= 5) {
        fprintf(stderr, "[ALLOC-STUB] Call #%u: Allocated %u bytes at guest address 0x%08X\n", 
                s_call_count, size, guest_addr);
        fflush(stderr);
    }
    
    // Return the guest address in r3
    ctx.r3.u32 = guest_addr;
}

