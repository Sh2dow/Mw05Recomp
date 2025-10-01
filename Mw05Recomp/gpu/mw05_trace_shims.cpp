// MW05 dynamic discovery shims for frequently used engine helpers.
// They log the caller (LR) and common arg regs, then tail-call the original.

#include <cpu/ppc_context.h>
#include <kernel/trace.h>
#include <kernel/memory.h>
#include <cstdlib>

static inline bool TitleStateTraceOn() {
    if (const char* v = std::getenv("MW05_TITLE_STATE_TRACE")) return !(v[0]=='0' && v[1]=='\0');
    return false;
}

static inline void DumpEAWindow(const char* tag, uint32_t ea) {
    if (!TitleStateTraceOn() || !ea) return;
    if (uint8_t* p = (uint8_t*)g_memory.Translate(ea)) {
        uint32_t w0 = *(uint32_t*)(p + 0);
        uint32_t w1 = *(uint32_t*)(p + 4);
        uint32_t w2 = *(uint32_t*)(p + 8);
        uint32_t w3 = *(uint32_t*)(p + 12);
    #if defined(_MSC_VER)
        w0 = _byteswap_ulong(w0); w1 = _byteswap_ulong(w1); w2 = _byteswap_ulong(w2); w3 = _byteswap_ulong(w3);
    #else
        w0 = __builtin_bswap32(w0); w1 = __builtin_bswap32(w1); w2 = __builtin_bswap32(w2); w3 = __builtin_bswap32(w3);
    #endif
        KernelTraceHostOpF("HOST.TitleState.%s ea=%08X w0=%08X w1=%08X w2=%08X w3=%08X", tag, ea, w0, w1, w2, w3);
    }
}

// Small helpers to read guest memory as big-endian safely for diagnostics
static inline uint32_t ReadBE32(uint32_t ea) {
    if (!ea) return 0u;
    if (auto* p = reinterpret_cast<const uint32_t*>(g_memory.Translate(ea))) {
    #if defined(_MSC_VER)
        return _byteswap_ulong(*p);
    #else
        return __builtin_bswap32(*p);
    #endif
    }
    return 0u;
}

static inline void DumpSchedState(const char* tag, uint32_t baseEA) {
    if (!TitleStateTraceOn() || !baseEA) return;
    // Best-effort peek at a few plausible fields (head/tail/flags) near the control block
    const uint32_t qhead = ReadBE32(baseEA + 0x10);
    const uint32_t qtail = ReadBE32(baseEA + 0x14);
    const uint32_t flags = ReadBE32(baseEA + 0x1C);
    KernelTraceHostOpF("HOST.Sched.%s base=%08X qhead=%08X qtail=%08X flags=%08X",
                       tag, baseEA, qhead, qtail, flags);
}


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

// Default log-and-forward shims
SHIM(sub_82599010)
SHIM(sub_82599208)
SHIM(sub_82599338)
SHIM(sub_825A7208)
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

// Scheduler/notify-adjacent shims (log, dump key pointers, and forward)
void MW05Shim_sub_8262F248(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_8262F248.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    DumpEAWindow("8262F248.r3", ctx.r3.u32);
    DumpEAWindow("8262F248.r4", ctx.r4.u32);
    DumpEAWindow("8262F248.r5", ctx.r5.u32);
    __imp__sub_8262F248(ctx, base);
}
void MW05Shim_sub_8262F2A0(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_8262F2A0.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    DumpEAWindow("8262F2A0.r3", ctx.r3.u32);
    DumpEAWindow("8262F2A0.r4", ctx.r4.u32);
    DumpEAWindow("8262F2A0.r5", ctx.r5.u32);
    DumpSchedState("8262F2A0", ctx.r3.u32);
    __imp__sub_8262F2A0(ctx, base);
}
void MW05Shim_sub_8262F330(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_8262F330.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    DumpEAWindow("8262F330.r3", ctx.r3.u32);
    DumpEAWindow("8262F330.r4", ctx.r4.u32);
    DumpEAWindow("8262F330.r5", ctx.r5.u32);
    DumpSchedState("8262F330", ctx.r3.u32);
    __imp__sub_8262F330(ctx, base);
}
void MW05Shim_sub_823BC638(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_823BC638.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    DumpEAWindow("823BC638.r3", ctx.r3.u32);
    DumpEAWindow("823BC638.r4", ctx.r4.u32);
    DumpEAWindow("823BC638.r5", ctx.r5.u32);
    __imp__sub_823BC638(ctx, base);
}
void MW05Shim_sub_82812E20(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_82812E20.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    DumpEAWindow("82812E20.r3", ctx.r3.u32);
    DumpEAWindow("82812E20.r4", ctx.r4.u32);
    DumpEAWindow("82812E20.r5", ctx.r5.u32);
    DumpSchedState("82812E20", ctx.r3.u32);
    __imp__sub_82812E20(ctx, base);
}

// Add shims for research helpers used by MW05 during rendering.
SHIM(sub_82595FC8)
SHIM(sub_825972B0)
SHIM(sub_825A54F0)
SHIM(sub_825A6DF0)
SHIM(sub_825A65A8)
