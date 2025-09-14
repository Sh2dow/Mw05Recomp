// MW05 bring-up shims to accelerate or instrument tight guest waits during boot.
// These override weak recompiled functions and tail-call the originals unless
// MW05_FAST_BOOT is set, in which case we return early to skip long delays.

#include <cpu/ppc_context.h>
#include <kernel/trace.h>
#include <cstdlib>

extern "C" {
    void __imp__sub_8262F330(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8262F3F0(PPCContext& ctx, uint8_t* base);
}

static inline bool FastBootEnabled() {
    if (const char* v = std::getenv("MW05_FAST_BOOT")) {
        // Enable unless explicitly "0"
        return !(v[0] == '0' && v[1] == '\0');
    }
    return false;
}

static inline uint64_t FastBootReturnValue() {
    if (const char* v = std::getenv("MW05_FAST_RET")) {
        // Accept decimal (0/192) or hex (0xC0)
        char* end = nullptr;
        unsigned long val = std::strtoul(v, &end, 0);
        return (val <= 0xFFFFFFFFu) ? val : 0u;
    }
    return 0u;
}

// sub_8262F330: tight delay/yield helper used during early init
void sub_8262F330(PPCContext& ctx, uint8_t* base)
{
    KernelTraceHostOp("HOST.sub_8262F330");
    if (FastBootEnabled()) {
        // Skip internal KeDelayExecutionThread loops during fast boot. Return a configured value (default 0).
        ctx.r3.u64 = FastBootReturnValue();
        return;
    }
    __imp__sub_8262F330(ctx, base);
}

// sub_8262F3F0: sibling helper of the same pattern
void sub_8262F3F0(PPCContext& ctx, uint8_t* base)
{
    KernelTraceHostOp("HOST.sub_8262F3F0");
    if (FastBootEnabled()) {
        ctx.r3.u64 = FastBootReturnValue();
        return;
    }
    __imp__sub_8262F3F0(ctx, base);
}
