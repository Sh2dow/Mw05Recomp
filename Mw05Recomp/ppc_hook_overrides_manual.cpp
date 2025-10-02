// Manual hook overrides to guard problematic guest functions that AV before render init.
// Keep minimal; prefer targeted guards that return gracefully.

#include <kernel/memory.h>
#include <kernel/trace.h>
#include <cpu/ppc_context.h>
#include <ppc/ppc_recomp_shared.h>

// Guard for guest function at 0x82625D60 which repeatedly AVs while booting.
// Behavior is unknown; until we understand it, stub it to a no-op that returns 0.
static void sub_82625D60_guard(PPCContext& ctx, uint8_t* /*base*/) {
    KernelTraceHostOpF("HOST.HookGuard.call addr=0x82625D60 r3=%08X r4=%08X r5=%08X r6=%08X",
                       ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32);
    // Conservative: return 0 and do not touch memory
    ctx.r3.u32 = 0;
}

static void RegisterHookOverridesManual() {
    g_memory.InsertFunction(0x82625D60, sub_82625D60_guard);
}

#if defined(_MSC_VER)
#  pragma section(".CRT$XCU",read)
    static void __cdecl ppc_hook_overrides_manual_ctor();
    __declspec(allocate(".CRT$XCU")) void (*ppc_hook_overrides_manual_ctor_)(void) = ppc_hook_overrides_manual_ctor;
    static void __cdecl ppc_hook_overrides_manual_ctor() { RegisterHookOverridesManual(); }
#else
    __attribute__((constructor)) static void ppc_hook_overrides_manual_ctor() { RegisterHookOverridesManual(); }
#endif

