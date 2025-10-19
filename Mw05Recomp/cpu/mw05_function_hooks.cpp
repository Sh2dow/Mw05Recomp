#include <stdafx.h>
#include <kernel/function.h>
#include <kernel/memory.h>
#include <cpu/ppc_context.h>

// MW05-specific function hooks to fix bugs in recompiled PPC code
// NOTE: Most hooks have been converted to PPC_FUNC_IMPL wrappers in mw05_trace_threads.cpp
// This file is kept for legacy hooks that haven't been converted yet

// sub_82813598_hook: Wrapper for worker thread initialization function
// This function manually sets qword_828F1F98 before/after calling the original function
// to work around a bug in the recompiled PPC code.

// sub_8215FDC0_hook: Memory pool initialization function
// This function is called lazily by sub_8215CB08 when dword_82A2BF44 is 0
PPC_FUNC_IMPL(__imp__sub_8215FDC0);
PPC_FUNC(sub_8215FDC0)
{
    fprintf(stderr, "[HOOK-8215FDC0] Memory pool init called! lr=0x%08llX\n", (unsigned long long)ctx.lr);
    fflush(stderr);

    // Call the original function
    extern void sub_8215FDC0(PPCContext& ctx, uint8_t* base);
    __imp__sub_8215FDC0(ctx, base);

    fprintf(stderr, "[HOOK-8215FDC0] Memory pool init completed, r3=0x%08X\n", ctx.r3.u32);
    fflush(stderr);
}

// sub_8215CB08_hook: Memory allocator function
// This function checks dword_82A2BF44 and calls sub_8215FDC0 if it's 0
// PPC_FUNC_IMPL(__imp__sub_8215CB08);
// PPC_FUNC(sub_8215CB08)
// {
//     // Check dword_82A2BF44 value
//     const uint32_t dword_addr = 0x82A2BF44;
//     void* dword_ptr = g_memory.Translate(dword_addr);
//     uint32_t dword_value = 0;
//     if (dword_ptr) {
//         dword_value = __builtin_bswap32(*(uint32_t*)dword_ptr);
//     }
// 
//     fprintf(stderr, "[HOOK-8215CB08] Allocator called! r3=0x%08X dword_82A2BF44=0x%08X lr=0x%08llX\n",
//             ctx.r3.u32, dword_value, (unsigned long long)ctx.lr);
//     fflush(stderr);
// 
//     // Call the original function
//     __imp__sub_8215CB08(ctx, base);
// 
//     fprintf(stderr, "[HOOK-8215CB08] Allocator returned, r3=0x%08X\n", ctx.r3.u32);
//     fflush(stderr);
// }

// sub_8211E470_hook: Vector resize function
// This function is crashing because the structure is not properly initialized
PPC_FUNC_IMPL(__imp__sub_8211E470);
PPC_FUNC(sub_8211E470)
{
    static int call_count = 0;
    call_count++;

    uint32_t struct_addr = ctx.r3.u32;
    uint32_t new_size = ctx.r4.u32;

    // Check if struct_addr is valid BEFORE trying to translate it
    bool is_valid_addr = (struct_addr >= 0x82000000 && struct_addr < 0xA0000000);

    // Log ALL calls with invalid addresses, and first 10 calls with valid addresses
    if (!is_valid_addr || call_count <= 10) {
        fprintf(stderr, "[HOOK-8211E470] call#%d struct=0x%08X new_size=%u lr=0x%08llX %s\n",
                call_count, struct_addr, new_size, (unsigned long long)ctx.lr,
                is_valid_addr ? "" : "*** INVALID ADDRESS ***");
        fflush(stderr);
    }

    if (!is_valid_addr) {
        fprintf(stderr, "[HOOK-8211E470] ERROR: Invalid structure address 0x%08X (should be in range 0x82000000-0xA0000000)\n", struct_addr);
        fprintf(stderr, "[HOOK-8211E470] Caller lr=0x%08llX\n", (unsigned long long)ctx.lr);
        fflush(stderr);

        // Don't call the original function - just return to avoid crash
        ctx.r3.u32 = 0;
        return;
    }

    // Read structure fields (big-endian) only for first 10 valid calls
    if (call_count <= 10) {
        void* struct_ptr = g_memory.Translate(struct_addr);
        if (struct_ptr) {
            uint32_t* fields = (uint32_t*)struct_ptr;
            uint32_t vtable = __builtin_bswap32(fields[0]);
            uint32_t data_ptr = __builtin_bswap32(fields[1]);
            uint32_t capacity = __builtin_bswap32(fields[2]);
            uint32_t count = __builtin_bswap32(fields[3]);

            fprintf(stderr, "[HOOK-8211E470] Structure contents:\n");
            fprintf(stderr, "  +0 (vtable):   0x%08X\n", vtable);
            fprintf(stderr, "  +4 (data_ptr): 0x%08X\n", data_ptr);
            fprintf(stderr, "  +8 (capacity): %u\n", capacity);
            fprintf(stderr, "  +12 (count):   %u\n", count);
            fflush(stderr);

            // Check if vtable is valid
            if (vtable == 0 || vtable < 0x82000000 || vtable >= 0x82CD0000) {
                fprintf(stderr, "[HOOK-8211E470] ERROR: Invalid vtable pointer!\n");
                fflush(stderr);
            }

            // Check if data_ptr is valid (can be 0 if not allocated yet)
            if (data_ptr != 0 && (data_ptr < 0x1000 || data_ptr >= 0xC0000000)) {
                fprintf(stderr, "[HOOK-8211E470] ERROR: Invalid data pointer!\n");
                fflush(stderr);
            }
        }
    }

    // Call the original function
    __imp__sub_8211E470(ctx, base);

    if (call_count <= 10) {
        fprintf(stderr, "[HOOK-8211E470] Vector resize completed, r3=0x%08X\n", ctx.r3.u32);
        fflush(stderr);
    }
}

// sub_820EA958_hook: Constructor that initializes the problematic vector
// This function sets up the structure that later crashes
PPC_FUNC_IMPL(__imp__sub_820EA958);
PPC_FUNC(sub_820EA958)
{
    uint32_t a1 = ctx.r3.u32;

    fprintf(stderr, "[HOOK-820EA958] Constructor called! a1=0x%08X lr=0x%08llX\n",
            a1, (unsigned long long)ctx.lr);
    fflush(stderr);

    // Call the original function
    __imp__sub_820EA958(ctx, base);

    // After the original function, check the vector structure at a1+196
    uint32_t vector_addr = a1 + 196;
    void* vector_ptr = g_memory.Translate(vector_addr);
    if (vector_ptr) {
        uint32_t* fields = (uint32_t*)vector_ptr;
        uint32_t vtable = __builtin_bswap32(fields[0]);
        uint32_t data_ptr = __builtin_bswap32(fields[1]);
        uint32_t capacity = __builtin_bswap32(fields[2]);
        uint32_t count = __builtin_bswap32(fields[3]);

        fprintf(stderr, "[HOOK-820EA958] Vector at 0x%08X after init:\n", vector_addr);
        fprintf(stderr, "  +0 (vtable):   0x%08X\n", vtable);
        fprintf(stderr, "  +4 (data_ptr): 0x%08X\n", data_ptr);
        fprintf(stderr, "  +8 (capacity): %u\n", capacity);
        fprintf(stderr, "  +12 (count):   %u\n", count);
        fflush(stderr);
    }

    fprintf(stderr, "[HOOK-820EA958] Constructor completed, r3=0x%08X\n", ctx.r3.u32);
    fflush(stderr);
}

// NOTE: sub_821135D0 is just a branch to sub_82112168, not a real function
// So we don't need a hook for it

// Forward declaration of the original function
PPC_FUNC_IMPL(__imp__sub_82112168);
PPC_FUNC(sub_82112168)
{
    fprintf(stderr, "[MW05-HOOKS] sub_82112168 called with r3=%08X\n", (uint32_t)ctx.r3.u32);
    fflush(stderr);
    // Call the original function
    __imp__sub_82112168(ctx, base);
}

// Register the hook at static initialization time
static void RegisterMw05FunctionHooks() {
    fprintf(stderr, "[MW05-HOOKS] Registering function hooks...\n");
    fflush(stderr);

    // NOTE: sub_82813598 hook has been converted to PPC_FUNC_IMPL wrapper in mw05_trace_threads.cpp
    // No hooks to register at this time

    fprintf(stderr, "[MW05-HOOKS] No legacy hooks to register (all converted to PPC_FUNC_IMPL)\n");
    fflush(stderr);
}

// Use static constructor to register hooks early
#if defined(_MSC_VER)
#  pragma section(".CRT$XCU",read)
    static void __cdecl mw05_function_hooks_ctor();
    __declspec(allocate(".CRT$XCU")) void (__cdecl*mw05_function_hooks_ctor_)(void) = mw05_function_hooks_ctor;
    static void __cdecl mw05_function_hooks_ctor() { RegisterMw05FunctionHooks(); }
#else
    __attribute__((constructor)) static void mw05_function_hooks_ctor() { RegisterMw05FunctionHooks(); }
#endif

