#include <stdafx.h>
#include <kernel/function.h>
#include <kernel/memory.h>
#include <cpu/ppc_context.h>

// MW05-specific function hooks to fix bugs in recompiled PPC code

// Forward declare the original recompiled function
extern void sub_82813598(PPCContext& __restrict ctx, uint8_t* base);

// sub_82813598_hook: Wrapper for worker thread initialization function
// This function manually sets qword_828F1F98 before/after calling the original function
// to work around a bug in the recompiled PPC code.
static void sub_82813598_hook(PPCContext& __restrict ctx, uint8_t* base) {
    fprintf(stderr, "[HOOK-82813598] Worker init function called! r3=0x%08X\n", ctx.r3.u32);
    fflush(stderr);

    // The expected calculation: divw r9, 0xFF676980, r3
    // When r3 = 0x64 (100 decimal):
    // 0xFF676980 / 0x64 = 0xFFFE7960 (sign-extended to 64-bit: 0xFFFFFFFFFFFE7960)
    const int32_t dividend = (int32_t)0xFF676980;  // -9999488 in decimal
    const int32_t divisor = (int32_t)ctx.r3.u32;

    if (divisor == 0) {
        fprintf(stderr, "[HOOK-82813598] ERROR: divisor is 0! Cannot divide!\n");
        fflush(stderr);
        ctx.r3.u64 = 0;
        return;
    }

    const int64_t result = (int64_t)dividend / (int64_t)divisor;

    fprintf(stderr, "[HOOK-82813598] Calculation: 0x%08X / 0x%08X = 0x%016llX\n",
            (uint32_t)dividend, (uint32_t)divisor, (uint64_t)result);
    fflush(stderr);

    // Store the result into qword_828F1F98 BEFORE calling the original function
    const uint32_t qword_addr = 0x828F1F98;
    void* qword_ptr = g_memory.Translate(qword_addr);
    if (qword_ptr) {
        // Write new value (big-endian)
        uint64_t value_be = __builtin_bswap64((uint64_t)result);
        *(uint64_t*)qword_ptr = value_be;

        fprintf(stderr, "[HOOK-82813598] qword_828F1F98 set to 0x%016llX\n", (uint64_t)result);
        fflush(stderr);
    } else {
        fprintf(stderr, "[HOOK-82813598] ERROR: Failed to translate address 0x%08X\n", qword_addr);
        fflush(stderr);
    }

    // Call the original recompiled function to do the rest of the work
    fprintf(stderr, "[HOOK-82813598] Calling original function...\n");
    fflush(stderr);

    sub_82813598(ctx, base);

    fprintf(stderr, "[HOOK-82813598] Original function returned, r3=0x%08X\n", ctx.r3.u32);
    fflush(stderr);

    // Verify qword_828F1F98 is still set correctly after the original function returns
    if (qword_ptr) {
        uint64_t final_value = __builtin_bswap64(*(uint64_t*)qword_ptr);
        fprintf(stderr, "[HOOK-82813598] FINAL: qword_828F1F98 = 0x%016llX\n", final_value);
        fflush(stderr);

        if (final_value != (uint64_t)result) {
            fprintf(stderr, "[HOOK-82813598] WARNING: Value was corrupted! Restoring...\n");
            fflush(stderr);

            // Restore the value
            uint64_t value_be = __builtin_bswap64((uint64_t)result);
            *(uint64_t*)qword_ptr = value_be;

            fprintf(stderr, "[HOOK-82813598] Value restored to 0x%016llX\n", (uint64_t)result);
            fflush(stderr);
        }
    }
}

// Register the hook at static initialization time
static void RegisterMw05FunctionHooks() {
    fprintf(stderr, "[MW05-HOOKS] Registering function hooks...\n");
    fflush(stderr);

    // Override sub_82813598 with our hook
    g_memory.InsertFunction(0x82813598, sub_82813598_hook);

    fprintf(stderr, "[MW05-HOOKS] sub_82813598 hook installed at 0x82813598\n");
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

