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

constexpr uint64_t kPpcMemLimit = static_cast<uint64_t>(PPC_MEMORY_SIZE);

static inline bool FastBootEnabled() {
    if (const char* v = std::getenv("MW05_FAST_BOOT")) {
        // Enable unless explicitly "0"
        return !(v[0] == '0' && v[1] == '\0');
    }
    return false;
}

static inline bool BreakLoop82813514Enabled() {
    if (const char* v = std::getenv("MW05_BREAK_82813514")) {
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
    if (FastBootEnabled() || BreakLoop82813514Enabled()) {
        // Targeted break for the tight loop at lr=0x82813514
        // Caller is sub_828134E0 pump; it loops until [r29+8] becomes 0.
        // We proactively zero that field to let it exit early during fast boot.
        if (ctx.lr == 0x82813514ull) {
            // Use the live r29 value rather than a compiled-in constant; MW05 variants differ.
            const uint32_t r29  = ctx.r29.u32;
            const uint64_t addr64 = static_cast<uint64_t>(r29) + 8ull;
            if (addr64 + sizeof(uint64_t) <= kPpcMemLimit) {
                const uint32_t addr = static_cast<uint32_t>(addr64); // for logging / pointer math
                KernelTraceHostOpF("HOST.FastBoot.BreakLoop.82813514 addr=%08X", addr);
                *reinterpret_cast<uint64_t*>(base + addr) = 0ull;
            }
        }
        if (FastBootEnabled()) {
            // Mark the dispatcher header as signaled if r3 is a guest pointer
            const uint32_t handle = ctx.r3.u32;
            if (handle != 0) {
                struct XDISPATCHER_HEADER { int8_t Type; int8_t Absolute; int16_t Size; int32_t SignalState; };
                const uint64_t h64 = static_cast<uint64_t>(handle);
                if (h64 + sizeof(XDISPATCHER_HEADER) <= kPpcMemLimit) {
                    auto* hdr = reinterpret_cast<XDISPATCHER_HEADER*>(base + handle);
                    hdr->SignalState = 1;
                }
            }
            // Return success to break the caller's wait loop cleanly
            ctx.r3.u64 = 0;
            return;
        }
    }
    __imp__sub_826346A8(ctx, base);
}
