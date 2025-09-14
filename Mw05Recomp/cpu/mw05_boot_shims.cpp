// MW05 bring-up shims to accelerate or instrument tight guest waits during boot.
// These override weak recompiled functions and tail-call the originals unless
// MW05_FAST_BOOT is set, in which case we return early to skip long delays.

#include <cpu/ppc_context.h>
#include <kernel/trace.h>
#include <cstdlib>

extern "C" {
    void __imp__sub_8262F330(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8262F3F0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_826346A8(PPCContext& ctx, uint8_t* base);
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

// sub_826346A8: wrapper around a NtWaitForSingleObjectEx loop
void sub_826346A8(PPCContext& ctx, uint8_t* base)
{
    KernelTraceHostOp("HOST.sub_826346A8");
    if (FastBootEnabled()) {
        // Targeted break for the tight loop at lr=0x82813514
        // Caller is sub_828134E0 pump; it loops until [r29+8] becomes 0.
        // We proactively zero that field to let it exit early during fast boot.
        if (ctx.lr == 0x82813514ull) {
            constexpr uint32_t kR29_Base = 0x828F1F90u; // computed from lis/addi in caller
            constexpr uint32_t kR29_Plus8 = kR29_Base + 8u; // ld r11,8(r29)
            if (kR29_Plus8 < PPC_MEMORY_SIZE) {
                KernelTraceHostOp("HOST.FastBoot.BreakLoop.82813514");
                // Zero 64 bits at [r29+8]
                *reinterpret_cast<uint64_t*>(base + kR29_Plus8) = 0ull;
            }
        }
        // Mark the dispatcher header as signaled if r3 is a guest pointer
        const uint32_t handle = ctx.r3.u32;
        if (handle && handle < PPC_MEMORY_SIZE) {
            // Best-effort: set SignalState=1 at the expected header location
            struct XDISPATCHER_HEADER { int8_t Type; int8_t Absolute; int16_t Size; int32_t SignalState; };
            auto* hdr = reinterpret_cast<XDISPATCHER_HEADER*>(base + handle);
            hdr->SignalState = 1;
        }
        // Return success to break the caller's wait loop cleanly
        ctx.r3.u64 = 0;
        return;
    }
    __imp__sub_826346A8(ctx, base);
}
