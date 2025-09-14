// MW05 dynamic discovery shims for frequently used engine helpers.
// They log the caller (LR) and then tail-call the original recompiled function.

#include <cpu/ppc_context.h>
#include <kernel/trace.h>

extern "C" {
    // Forward decls of the recompiled originals
    void __imp__sub_82595FC8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825972B0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A54F0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A6DF0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A65A8(PPCContext& ctx, uint8_t* base);
}

#define SHIM(name) \
    void name(PPCContext& ctx, uint8_t* base) { \
        KernelTraceHostOp(#name); \
        __imp__##name(ctx, base); \
    }

// Add shims for research helpers used by MW05 during rendering.
SHIM(sub_82595FC8)
SHIM(sub_825972B0)
SHIM(sub_825A54F0)
SHIM(sub_825A6DF0)
SHIM(sub_825A65A8)
