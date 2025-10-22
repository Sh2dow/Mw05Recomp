// Manual hook overrides to guard problematic guest functions and install research shims.
// Keep minimal; prefer targeted guards that return gracefully.

#include <kernel/memory.h>
#include <kernel/trace.h>
#include <cpu/ppc_context.h>
#include <ppc/ppc_recomp_shared.h>

// Decls for GPU/scheduler trace shims (defined in gpu/mw05_trace_shims.cpp)
// Stub for NULL vtable methods - these are optional vtable methods that some objects don't implement
// The game calls these through vtables, but some objects have NULL pointers for these methods
static void vtable_method_stub_noop(PPCContext& ctx, uint8_t* /*base*/) {
    // Do nothing - this is a no-op vtable method
    // Return 0 in r3 to indicate success/no-op
    ctx.r3.u32 = 0;
}

// Loop breaker for wait functions called in infinite loop at 0x825CEE18/0x825CEE28
// These are code snippets (not full functions) that are part of a wait loop
static inline bool BreakWaitLoopEnabled() {
    if (const char* v = std::getenv("MW05_BREAK_WAIT_LOOP")) {
        return !(v[0] == '0' && v[1] == '\0');
    }
    return false;
}

// Stub for code snippet at 0x825CEE18 - part of wait loop
PPC_FUNC_IMPL(__imp__sub_825CEE18);
PPC_FUNC(sub_825CEE18)
{
    static int call_count = 0;
    static const bool s_break_loop = BreakWaitLoopEnabled();

    if (s_break_loop && ++call_count > 100) {
        // Break the loop by returning a value that will exit the wait
        KernelTraceHostOpF("HOST.BreakWaitLoop.825CEE18 count=%d", call_count);
        ctx.r3.u32 = 1;  // Return "ready" to break the loop
        return;
    }

    // Otherwise, return 0 to continue waiting
    ctx.r3.u32 = 0;
}

// Stub for code snippet at 0x825CEE28 - part of wait loop
PPC_FUNC_IMPL(__imp__sub_825CEE28);
PPC_FUNC(sub_825CEE28)
{
    static int call_count = 0;
    static const bool s_break_loop = BreakWaitLoopEnabled();

    if (s_break_loop && ++call_count > 100) {
        // Break the loop by returning a value that will exit the wait
        KernelTraceHostOpF("HOST.BreakWaitLoop.825CEE28 count=%d", call_count);
        ctx.r3.u32 = 1;  // Return "ready" to break the loop
        return;
    }

    // Otherwise, return 0 to continue waiting
    ctx.r3.u32 = 0;
}



static void RegisterHookOverridesManual() {
    KernelTraceHostOp("HOST.ManualOverridesCtor");
    // Safety guard
    g_memory.InsertFunction(0x82625D60, sub_82625D60);

    // CRITICAL: These shims are required for PM4 queue processing and scheduler management
    // g_memory.InsertFunction(0x82812E20, sub_82812E20);
    // NOTE: The following functions are now auto-registered via PPC_FUNC pattern:
    // - sub_82595FC8, sub_825972B0, sub_8262F248, sub_8262F2A0, sub_8262F330, sub_82812E20
    // - sub_825979A8, sub_82598A20, sub_82625D60, sub_82849D40
    // They are defined in mw05_trace_shims.cpp and mw05_boot_shims.cpp
    // No need to manually register them here.

    // CRITICAL: Wait loop breakers - these code snippets are called in an infinite loop
    g_memory.InsertFunction(0x825CEE18, sub_825CEE18);
    g_memory.InsertFunction(0x825CEE28, sub_825CEE28);

    // NOTE: sub_82849D40 is auto-registered by gen_ppc_overrides.py, no need to register manually

    // CRITICAL: NULL vtable method stubs - these are optional vtable methods that some objects don't implement
    // Register at fake addresses that can be used to replace NULL pointers in vtables
    g_memory.InsertFunction(0x82FF2000, vtable_method_stub_noop);  // Stub for vtable method at offset +0x50
    g_memory.InsertFunction(0x82FF2010, vtable_method_stub_noop);  // Stub for vtable method at offset +0x2C

    // DISABLED: Thread creation shims - investigating if these cause address space issues
    // g_memory.InsertFunction(0x82880FA0, MW05Shim_sub_82880FA0);
    // g_memory.InsertFunction(0x82885A70, MW05Shim_sub_82885A70);

    // Install a host allocator callback at a stable guest EA for MW05 to call if its fp is null
    // Using address in the gap after code section (will be covered by extended PPC_CODE_SIZE)
    extern void MW05HostAllocCb(PPCContext& ctx, uint8_t* base);
    g_memory.InsertFunction(0x82FF1000, MW05HostAllocCb);
}

// Ensure registration runs exactly once regardless of toolchain constructor quirks
static void RegisterHookOverridesManualOnce() {
    static bool s_done = false;
    if (!s_done) { RegisterHookOverridesManual(); s_done = true; }
}

#if defined(_MSC_VER)
#  pragma section(".CRT$XCU",read)
    static void __cdecl ppc_hook_overrides_manual_ctor();
    __declspec(allocate(".CRT$XCU")) void (*ppc_hook_overrides_manual_ctor_)(void) = ppc_hook_overrides_manual_ctor;
    static void __cdecl ppc_hook_overrides_manual_ctor() { RegisterHookOverridesManualOnce(); }
#else
    // DISABLED: Static constructor causes crash during global construction
    // RegisterHookOverridesManualOnce() is now called manually in main() after memory is initialized
    // __attribute__((constructor)) static void ppc_hook_overrides_manual_ctor() { RegisterHookOverridesManualOnce(); }
#endif

// Fallback: a global object to trigger registration via C++ static initialization
struct ManualHookInit {
    ManualHookInit() { RegisterHookOverridesManualOnce(); }
};
static ManualHookInit g_manual_hook_init;

