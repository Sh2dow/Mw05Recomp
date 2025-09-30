// MW05 dynamic discovery shims for frequently used engine helpers.
// They log the caller (LR) and common arg regs, then tail-call the original.

#include <cpu/ppc_context.h>
#include <kernel/trace.h>

extern "C" {
    // Forward decls of the recompiled originals
    void __imp__sub_82595FC8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825972B0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A54F0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A6DF0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A65A8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825986F8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825987E0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825988B0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A7A40(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A7DE8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A7E60(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A7EA0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_82599010(PPCContext& ctx, uint8_t* base);
    void __imp__sub_82599208(PPCContext& ctx, uint8_t* base);
    void __imp__sub_82599338(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A7208(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A74B8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A7F10(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A7F88(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A8040(PPCContext& ctx, uint8_t* base);
    // New: functions near LRs observed in HOST.Store64BE_W traces
    void __imp__sub_8262F248(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8262F2A0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8262F330(PPCContext& ctx, uint8_t* base);
    void __imp__sub_823BC638(PPCContext& ctx, uint8_t* base);
    void __imp__sub_82812E20(PPCContext& ctx, uint8_t* base);
}

#define SHIM(name) \
    void MW05Shim_##name(PPCContext& ctx, uint8_t* base) { \
        KernelTraceHostOpF(#name ".lr=%08llX r3=%08X r4=%08X r5=%08X", \
                           (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32); \
        __imp__##name(ctx, base); \
    }
SHIM(sub_82599010)
SHIM(sub_82599208)
SHIM(sub_82599338)
SHIM(sub_825A7208)
// Scheduler/notify-adjacent shims (log and forward)
SHIM(sub_8262F248)
SHIM(sub_8262F2A0)
SHIM(sub_8262F330)
SHIM(sub_823BC638)
SHIM(sub_82812E20)

SHIM(sub_825A74B8)
SHIM(sub_825A7F10)
SHIM(sub_825A7F88)
SHIM(sub_825A8040)


// Candidate MW05 render/viewport/draw-adjacent helpers to log-and-forward
SHIM(sub_825986F8)
SHIM(sub_825987E0)
SHIM(sub_825988B0)
SHIM(sub_825A7A40)
SHIM(sub_825A7DE8)
SHIM(sub_825A7E60)
SHIM(sub_825A7EA0)

// Add shims for research helpers used by MW05 during rendering.
SHIM(sub_82595FC8)
SHIM(sub_825972B0)
SHIM(sub_825A54F0)
SHIM(sub_825A6DF0)
SHIM(sub_825A65A8)
