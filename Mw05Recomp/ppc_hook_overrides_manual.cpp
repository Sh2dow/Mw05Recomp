// Manual hook overrides to guard problematic guest functions and install research shims.
// Keep minimal; prefer targeted guards that return gracefully.

#include <kernel/memory.h>
#include <kernel/trace.h>
#include <cpu/ppc_context.h>
#include <ppc/ppc_recomp_shared.h>

// Decls for GPU/scheduler trace shims (defined in gpu/mw05_trace_shims.cpp)
extern void MW05Shim_sub_82595FC8(PPCContext&, uint8_t*);
extern void MW05Shim_sub_825972B0(PPCContext&, uint8_t*);
extern void MW05Shim_sub_8262F248(PPCContext&, uint8_t*);
extern void MW05Shim_sub_8262F2A0(PPCContext&, uint8_t*);
extern void MW05Shim_sub_8262F330(PPCContext&, uint8_t*);
extern void MW05Shim_sub_82812E20(PPCContext&, uint8_t*);

// Guard for guest function at 0x82625D60 which repeatedly AVs while booting.
// Behavior is unknown; until we understand it, stub it to a no-op that returns 0.
static void sub_82625D60_guard(PPCContext& ctx, uint8_t* /*base*/) {
    KernelTraceHostOpF("HOST.HookGuard.call addr=0x82625D60 r3=%08X r4=%08X r5=%08X r6=%08X",
                       ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32);
    // Conservative: return 0 and do not touch memory
    ctx.r3.u32 = 0;
}

static void RegisterHookOverridesManual() {
    // Safety guard
    g_memory.InsertFunction(0x82625D60, sub_82625D60_guard);

    // Research: scheduler/PM4-related shims to capture r3 (context) early and often
    // These addresses are derived from the recompiled guest symbol names.
    g_memory.InsertFunction(0x82595FC8, MW05Shim_sub_82595FC8);
    g_memory.InsertFunction(0x825972B0, MW05Shim_sub_825972B0);
    g_memory.InsertFunction(0x8262F248, MW05Shim_sub_8262F248);
    g_memory.InsertFunction(0x8262F2A0, MW05Shim_sub_8262F2A0);
    g_memory.InsertFunction(0x8262F330, MW05Shim_sub_8262F330);
    g_memory.InsertFunction(0x82812E20, MW05Shim_sub_82812E20);

    // Install a host allocator callback at a stable guest EA for MW05 to call if its fp is null
    extern void MW05HostAllocCb(PPCContext& ctx, uint8_t* base);
    g_memory.InsertFunction(0x82FF1000, MW05HostAllocCb);
}

#if defined(_MSC_VER)
#  pragma section(".CRT$XCU",read)
    static void __cdecl ppc_hook_overrides_manual_ctor();
    __declspec(allocate(".CRT$XCU")) void (*ppc_hook_overrides_manual_ctor_)(void) = ppc_hook_overrides_manual_ctor;
    static void __cdecl ppc_hook_overrides_manual_ctor() { RegisterHookOverridesManual(); }
#else
    __attribute__((constructor)) static void ppc_hook_overrides_manual_ctor() { RegisterHookOverridesManual(); }
#endif

