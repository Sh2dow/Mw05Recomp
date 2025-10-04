// Strong symbol overrides for specific guest functions; these take precedence over
// weak alias declarations in the generated PPC sources.

#include <cstdlib>
#include <kernel/trace.h>
#include <cpu/ppc_context.h>
#include <ppc/ppc_recomp_shared.h>

// Forward to original recompiled bodies when overrides are disabled
extern "C" 
{
    void __imp__sub_82625D60(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8261E320(PPCContext& ctx, uint8_t* base);
    void __imp__sub_82855308(PPCContext& ctx, uint8_t* base);
}

static inline bool OverridesDisabled() {
    if (const char* v = std::getenv("MW05_DISABLE_OVERRIDES")) {
        return v[0] && v[0] != '0';
    }
    return false;
}

void sub_82625D60(PPCContext& ctx, uint8_t* base)
{
    if (OverridesDisabled()) { __imp__sub_82625D60(ctx, base); return; }
    KernelTraceHostOpF("HOST.SymbolOverride.sub_82625D60 stub r3=%08X r4=%08X r5=%08X r6=%08X",
                       ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32);
    // Conservative default: report success(0) to avoid propagating errors until we understand it
    ctx.r3.u32 = 0;
}

void sub_8261E320(PPCContext& ctx, uint8_t* base)
{
    if (OverridesDisabled()) { __imp__sub_8261E320(ctx, base); return; }
    KernelTraceHostOpF("HOST.SymbolOverride.sub_8261E320 stub r3=%08X r4=%08X r5=%08X r6=%08X",
                       ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32);
    ctx.r3.u32 = 0;
}

void sub_82855308(PPCContext& ctx, uint8_t* base)
{
    if (OverridesDisabled()) { __imp__sub_82855308(ctx, base); return; }
    KernelTraceHostOpF("HOST.SymbolOverride.sub_82855308 stub r3=%08X r4=%08X r5=%08X r6=%08X",
                       ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32);
    ctx.r3.u32 = 0;
}
