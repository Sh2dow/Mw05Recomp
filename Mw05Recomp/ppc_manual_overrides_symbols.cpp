// Strong symbol overrides for specific guest functions; these take precedence over
// weak alias declarations in the generated PPC sources.

#include <cstdlib>
#include <kernel/trace.h>
#include <cpu/ppc_context.h>
#include <ppc/ppc_recomp_shared.h>

static inline bool OverridesDisabled() {
    if (const char* v = std::getenv("MW05_DISABLE_OVERRIDES")) {
        return v[0] && v[0] != '0';
    }
    return false;
}


// Guard for guest function at 0x82625D60 which repeatedly AVs while booting.
// Behavior is unknown; until we understand it, stub it to a no-op that returns 0.
PPC_FUNC_IMPL(__imp__sub_82625D60);
PPC_FUNC(sub_82625D60)
{
    if (OverridesDisabled()) { __imp__sub_82625D60(ctx, base); return; }
    KernelTraceHostOpF("HOST.SymbolOverride.sub_82625D60 stub r3=%08X r4=%08X r5=%08X r6=%08X",
                       ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32);
    // Conservative default: report success(0) to avoid propagating errors until we understand it
    ctx.r3.u32 = 0;
}

PPC_FUNC_IMPL(__imp__sub_8261E320);
PPC_FUNC(sub_8261E320)
{
    if (OverridesDisabled()) { __imp__sub_8261E320(ctx, base); return; }
    KernelTraceHostOpF("HOST.SymbolOverride.sub_8261E320 stub r3=%08X r4=%08X r5=%08X r6=%08X",
                       ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32);
    ctx.r3.u32 = 0;
}

PPC_FUNC_IMPL(__imp__sub_82855308);
PPC_FUNC(sub_82855308)
{
    if (OverridesDisabled()) { __imp__sub_82855308(ctx, base); return; }
    KernelTraceHostOpF("HOST.SymbolOverride.sub_82855308 stub r3=%08X r4=%08X r5=%08X r6=%08X",
                       ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32);
    ctx.r3.u32 = 0;
}

// CRITICAL: Override sub_825960B8 to check structure validity before calling sub_825968B0
// This function is called with a structure pointer in r3, and it calls sub_825968B0(a1[4], ...)
// If a1[4] is NULL, sub_825968B0 fails. We need to intercept this and provide a valid allocator.
PPC_FUNC_IMPL(__imp__sub_825960B8);
PPC_FUNC(sub_825960B8)
{
    if (OverridesDisabled()) { __imp__sub_825960B8(ctx, base); return; }

    uint32_t a1 = ctx.r3.u32;

    // Check if a1 is valid (must be in guest address space)
    if (a1 < 0x1000) {
        KernelTraceHostOpF("HOST.825960B8.invalid_a1 r3=%08X - returning 0", a1);
        ctx.r3.u32 = 0;
        return;
    }

    // Log the call for debugging
    uint32_t* a1_ptr = (uint32_t*)g_memory.Translate(a1);
    if (a1_ptr) {
        uint32_t a1_4 = __builtin_bswap32(a1_ptr[4]);  // Read a1[4] with byte-swapping

        if (a1_4 == 0) {
            // a1[4] is NULL, the original function will use the fallback allocator
            // Let's check what VdGlobalDevice contains
            extern be<uint32_t> VdGlobalDevice;
            uint32_t vd_ptr_ea = VdGlobalDevice;

            if (vd_ptr_ea != 0) {
                // Read the pointer that VdGlobalDevice points to
                uint32_t* vd_ptr_host = (uint32_t*)g_memory.Translate(vd_ptr_ea);
                if (vd_ptr_host) {
                    uint32_t ctx_ea = __builtin_bswap32(*vd_ptr_host);

                    // Read the fallback pointer from offset 0x3D0C
                    uint32_t* ctx_host = (uint32_t*)g_memory.Translate(ctx_ea);
                    if (ctx_host) {
                        uint32_t fallback_ea = __builtin_bswap32(*(uint32_t*)((uint8_t*)ctx_host + 0x3D0C));

                        fprintf(stderr, "[HOST.825960B8] VdGlobalDevice=0x%08X → ctx=0x%08X → fallback=0x%08X\n",
                                vd_ptr_ea, ctx_ea, fallback_ea);
                        fflush(stderr);
                    }
                }
            }
        }
    }

    // Always call the original function - it has proper error handling
    SetPPCContext(ctx);
    __imp__sub_825960B8(ctx, base);
}

// CRITICAL: Override sub_825968B0 to handle NULL pointer gracefully
// This function is an allocator that expects r3 to be a valid pointer to an allocator structure
// If r3 is NULL, the function should return NULL to trigger the fallback path in the caller
PPC_FUNC_IMPL(__imp__sub_825968B0);
PPC_FUNC(sub_825968B0)
{
    if (OverridesDisabled()) { __imp__sub_825968B0(ctx, base); return; }

    // Check if r3 (first parameter) is NULL
    if (ctx.r3.u32 == 0) {
        static int null_count = 0;
        if (null_count++ < 3) {
            fprintf(stderr, "[sub_825968B0] NULL pointer detected (call #%d), returning NULL\n", null_count);
            fflush(stderr);
        }
        // Return NULL to trigger fallback path in caller
        ctx.r3.u32 = 0;
        return;
    }

    // Call the original function
    SetPPCContext(ctx);
    __imp__sub_825968B0(ctx, base);
}
