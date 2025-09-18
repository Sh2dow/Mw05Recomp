// MW05 bring-up shims to accelerate or instrument tight guest waits during boot.
// These override weak recompiled functions and tail-call the originals unless
// MW05_FAST_BOOT is set, in which case we return early to skip long delays.

#include <cpu/ppc_context.h>
#include <kernel/trace.h>
#include <cstdlib>
#include <cstring>
#include <atomic>
#include <kernel/memory.h>
#include <ppc/ppc_config.h>

extern "C" {
    void __imp__sub_8262F330(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8262F3F0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_826346A8(PPCContext& ctx, uint8_t* base);
}

constexpr uint64_t kPpcMemLimit = static_cast<uint64_t>(PPC_MEMORY_SIZE);
constexpr uint64_t kPpcImageBase = static_cast<uint64_t>(PPC_IMAGE_BASE);
constexpr uint64_t kPpcImageLimit = static_cast<uint64_t>(PPC_IMAGE_BASE) + static_cast<uint64_t>(PPC_IMAGE_SIZE);

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace
{
    inline uint32_t LoadGuestU32(uint8_t* base, uint32_t ea)
    {
        uint32_t value = 0;
        std::memcpy(&value, base + ea, sizeof(value));
#if defined(_MSC_VER)
        value = _byteswap_ulong(value);
#else
        value = __builtin_bswap32(value);
#endif
        return value;
    }
}

static std::atomic<uint32_t> g_lastSchedulerBlockEA{0};
static std::atomic<uint32_t> g_lastSchedulerHandleEA{0};
static std::atomic<uint32_t> g_lastSchedulerTimeoutEA{0};

extern "C" uint32_t Mw05ConsumeSchedulerBlockEA()
{
    return g_lastSchedulerBlockEA.exchange(0, std::memory_order_acq_rel);
}

extern "C" uint32_t Mw05PeekSchedulerBlockEA()
{
    return g_lastSchedulerBlockEA.load(std::memory_order_acquire);
}

extern "C" uint32_t Mw05GetSchedulerHandleEA()
{
    return g_lastSchedulerHandleEA.load(std::memory_order_acquire);
}

extern "C" uint32_t Mw05GetSchedulerTimeoutEA()
{
    return g_lastSchedulerTimeoutEA.load(std::memory_order_acquire);
}

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

    const uint32_t handleEA = ctx.r3.u32;
    const uint32_t blockEA = ctx.r29.u32;
    const uint32_t timeoutEA = ctx.r30.u32;
    g_lastSchedulerHandleEA.store(handleEA, std::memory_order_release);
    g_lastSchedulerBlockEA.store(blockEA, std::memory_order_release);
    g_lastSchedulerTimeoutEA.store(timeoutEA, std::memory_order_release);

    KernelTraceHostOpF("HOST.sub_826346A8.wait handle=%08X block=%08X timeout=%08X",
                       handleEA, blockEA, timeoutEA);

    if (!blockEA) {
        KernelTraceHostOpF("HOST.sub_826346A8.block ea=%08X (null)", blockEA);
    } else {
        const uint64_t blockEnd = static_cast<uint64_t>(blockEA) + 20ull;
        if (blockEnd > kPpcMemLimit) {
            KernelTraceHostOpF("HOST.sub_826346A8.block ea=%08X (out_of_range)", blockEA);
        } else if (g_memory.Translate(blockEA)) {
            const uint32_t w0 = LoadGuestU32(base, blockEA);
            const uint32_t w1 = LoadGuestU32(base, blockEA + 4);
            const uint32_t w2 = LoadGuestU32(base, blockEA + 8);
            const uint32_t w3 = LoadGuestU32(base, blockEA + 12);
            const uint32_t w4 = LoadGuestU32(base, blockEA + 16);
            KernelTraceHostOpF("HOST.sub_826346A8.block ea=%08X w0=%08X w1=%08X w2=%08X w3=%08X w4=%08X",
                               blockEA, w0, w1, w2, w3, w4);
            if (w4) {
                const uint64_t target64 = static_cast<uint64_t>(w4);
                const bool inImage = target64 >= kPpcImageBase && target64 < kPpcImageLimit;
                const bool hasStub = g_memory.FindFunction(w4) != nullptr;
                KernelTraceHostOpF("HOST.sub_826346A8.target ea=%08X in_image=%u has_stub=%u",
                                   w4, inImage ? 1u : 0u, hasStub ? 1u : 0u);
                if (target64 + 16ull <= kPpcMemLimit) {
                    if (g_memory.Translate(w4)) {
                        const uint32_t vptrEA = LoadGuestU32(base, w4 + 0);
                        const uint32_t targetW1 = LoadGuestU32(base, w4 + 4);
                        const uint32_t targetW2 = LoadGuestU32(base, w4 + 8);
                        const uint32_t targetW3 = LoadGuestU32(base, w4 + 12);
                        KernelTraceHostOpF("HOST.sub_826346A8.target.w ea=%08X vptr=%08X w1=%08X w2=%08X w3=%08X",
                                           w4, vptrEA, targetW1, targetW2, targetW3);
                        const uint32_t vtableEA = vptrEA;
                        const uint64_t vtable64 = static_cast<uint64_t>(vtableEA);
                        if (vtableEA && vtable64 + 20ull <= kPpcMemLimit) {
                            if (g_memory.Translate(vtableEA)) {
                                const uint32_t slot0 = LoadGuestU32(base, vtableEA + 0);
                                const uint32_t slot1 = LoadGuestU32(base, vtableEA + 4);
                                const uint32_t slot2 = LoadGuestU32(base, vtableEA + 8);
                                const uint32_t slot3 = LoadGuestU32(base, vtableEA + 12);
                                const uint32_t slot4 = LoadGuestU32(base, vtableEA + 16);
                                KernelTraceHostOpF("HOST.sub_826346A8.vtable ea=%08X s0=%08X s1=%08X s2=%08X s3=%08X s4=%08X",
                                                   vtableEA, slot0, slot1, slot2, slot3, slot4);
                            } else {
                                KernelTraceHostOpF("HOST.sub_826346A8.vtable ea=%08X (unmapped)", vtableEA);
                            }
                        }
                    } else {
                        KernelTraceHostOpF("HOST.sub_826346A8.target ea=%08X (unmapped)", w4);
                    }
                }
            }
        } else {
            KernelTraceHostOpF("HOST.sub_826346A8.block ea=%08X (unmapped)", blockEA);
        }
    }

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
