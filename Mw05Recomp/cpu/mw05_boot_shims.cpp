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

constexpr uint64_t kPpcMemLimit = static_cast<uint64_t>(PPC_MEMORY_SIZE);
constexpr uint64_t kPpcImageBase = static_cast<uint64_t>(PPC_IMAGE_BASE);
constexpr uint64_t kPpcImageLimit = static_cast<uint64_t>(PPC_IMAGE_BASE) + static_cast<uint64_t>(PPC_IMAGE_SIZE);

static std::atomic<uint32_t> g_lastSchedulerBlockEA{0};
static std::atomic<uint32_t> g_lastSchedulerHandleEA{0};
static std::atomic<uint32_t> g_lastSchedulerTimeoutEA{0};
extern std::atomic<uint32_t> g_watchEA;

static inline void ResetSchedulerTracking() {
    g_lastSchedulerBlockEA.store(0, std::memory_order_release);
    g_lastSchedulerHandleEA.store(0, std::memory_order_release);
    g_lastSchedulerTimeoutEA.store(0, std::memory_order_release);
}

extern "C"
{
    void __imp__sub_8262F330(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8262F3F0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_826346A8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_828134E0(PPCContext& ctx, uint8_t* base);

    uint32_t Mw05ConsumeSchedulerBlockEA() {
        return g_lastSchedulerBlockEA.exchange(0, std::memory_order_acq_rel);
    }

    uint32_t Mw05PeekSchedulerBlockEA() {
        return g_lastSchedulerBlockEA.load(std::memory_order_acquire);
    }

    uint32_t Mw05GetSchedulerHandleEA() {
        return g_lastSchedulerHandleEA.load(std::memory_order_acquire);
    }

    uint32_t Mw05GetSchedulerTimeoutEA() {
        return g_lastSchedulerTimeoutEA.load(std::memory_order_acquire);
    }

    void HostSchedulerWake(PPCContext& ctx, uint8_t* /*base*/) {
        ctx.r3.u64 = 0;
        KernelTraceHostOp("HOST.HostSchedulerWake");
    }
}


#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace {
inline bool GuestRangeValid(uint32_t ea, size_t bytes = 4) {
    if(!ea) {
        return false;
    }
    const uint64_t end = static_cast<uint64_t>(ea) + static_cast<uint64_t>(bytes);
    return end <= PPC_MEMORY_SIZE;
}

inline uint32_t LoadGuestU32(uint8_t* base, uint32_t ea) {
    uint32_t value = 0;
    std::memcpy(&value, base + ea, sizeof(value));
#if defined(_MSC_VER)
    value = _byteswap_ulong(value);
#else
    value = __builtin_bswap32(value);
#endif
    return value;
}

inline bool GuestCodeRangeContains(uint32_t ea) {
    const uint64_t codeBegin = static_cast<uint64_t>(PPC_CODE_BASE);
    const uint64_t codeEnd = codeBegin + static_cast<uint64_t>(PPC_CODE_SIZE);
    const uint64_t value = static_cast<uint64_t>(ea);
    return value >= codeBegin && value < codeEnd;
}

inline void ClearSchedulerBlock(uint8_t* base, uint32_t blockEA) {
    PPC_STORE_U32(blockEA + 0, 0);
    PPC_STORE_U32(blockEA + 4, 0);
    PPC_STORE_U32(blockEA + 8, 0);
    PPC_STORE_U32(blockEA + 12, 0);
    PPC_STORE_U32(blockEA + 16, 0);
}
}

static inline bool FastBootEnabled() {
    if(const char* v = std::getenv("MW05_FAST_BOOT")) {
        // Enable unless explicitly "0"
        return !(v[0] == '0' && v[1] == '\0');
    }
    return false;
}

static inline bool BreakLoop82813514Enabled() {
    if(const char* v = std::getenv("MW05_BREAK_82813514")) {
        return !(v[0] == '0' && v[1] == '\0');
    }
    return false;
}

static inline uint64_t FastBootReturnValue() {
    if(const char* v = std::getenv("MW05_FAST_RET")) {
        // Accept decimal (0/192) or hex (0xC0)
        char* end = nullptr;
        unsigned long val = std::strtoul(v, &end, 0);
        return (val <= 0xFFFFFFFFu) ? val : 0u;
    }
    return 0u;
}

static inline void DumpGuestStackWindow(uint8_t* base, uint32_t spEA, int count = 8) {
    if(!spEA) return;
    for(int i = 0; i < count; ++i) {
        const uint32_t ea = spEA + static_cast<uint32_t>(i * 4);
        uint32_t word = LoadGuestU32(base, ea);
        KernelTraceHostOpF("HOST.sub_826346A8.stack[%d] ea=%08X val=%08X", i, ea, word);
    }
}

// sub_8262F330: tight delay/yield helper used during early init
void sub_8262F330(PPCContext& ctx, uint8_t* base) {
    SetPPCContext(ctx);
    KernelTraceHostOp("HOST.sub_8262F330");
    if(FastBootEnabled()) {
        // Skip internal KeDelayExecutionThread loops during fast boot. Return a configured value (default 0).
        ctx.r3.u64 = FastBootReturnValue();
        return;
    }
    __imp__sub_8262F330(ctx, base);
}

// sub_8262F3F0: sibling helper of the same pattern
void sub_8262F3F0(PPCContext& ctx, uint8_t* base) {
    SetPPCContext(ctx);
    KernelTraceHostOp("HOST.sub_8262F3F0");
    if(FastBootEnabled()) {
        ctx.r3.u64 = FastBootReturnValue();
        return;
    }
    __imp__sub_8262F3F0(ctx, base);
}
// sub_826346A8: wrapper around a NtWaitForSingleObjectEx loop
void sub_826346A8(PPCContext& ctx, uint8_t* base) {
    SetPPCContext(ctx);
    KernelTraceHostOp("HOST.sub_826346A8");

    const uint32_t handleEA = ctx.r3.u32;
    const uint32_t blockEA = ctx.r29.u32;
    const uint32_t timeoutEA = ctx.r30.u32;
    g_lastSchedulerHandleEA.store(handleEA, std::memory_order_release);
    g_lastSchedulerBlockEA.store(blockEA, std::memory_order_release);
    g_lastSchedulerTimeoutEA.store(timeoutEA, std::memory_order_release);

    KernelTraceHostOpF("HOST.sub_826346A8.wait handle=%08X block=%08X timeout=%08X",
                       handleEA, blockEA, timeoutEA);

    // ALWAYS log to verify this code path executes
    KernelTraceHostOp("HOST.sub_826346A8.ALWAYS_LOG");

    // CRITICAL: Check loop breaker FIRST before any early returns
    // This allows us to break out of infinite wait loops during initialization
    const bool fastBootEnabled = FastBootEnabled();
    const bool breakLoopEnabled = BreakLoop82813514Enabled();
    KernelTraceHostOpF("HOST.sub_826346A8.loop_breaker_check fastBoot=%d breakLoop=%d lr=%08llX",
                       fastBootEnabled, breakLoopEnabled, ctx.lr);

    if(fastBootEnabled || breakLoopEnabled) {
        // Targeted break for the tight loop at lr=0x82813514
        // Caller is sub_828134E0 pump; it loops until [blockEA+8] becomes 0.
        // We proactively zero that field to let it exit early during fast boot.
        if(ctx.lr == 0x82813514ull) {
            // blockEA is in r29 (0x828F1F90 in the logs)
            // We need to zero [blockEA+8] to break the loop
            if(blockEA != 0) {
                const uint64_t addr64 = static_cast<uint64_t>(blockEA) + 8ull;
                if(addr64 + sizeof(uint64_t) <= kPpcMemLimit) {
                    const uint32_t addr = static_cast<uint32_t>(addr64);
                    KernelTraceHostOpF("HOST.FastBoot.BreakLoop.82813514 blockEA=%08X addr=%08X", blockEA, addr);
                    *reinterpret_cast<uint64_t*>(base + addr) = 0ull;
                }
            } else {
                KernelTraceHostOpF("HOST.FastBoot.BreakLoop.82813514 SKIP blockEA=00000000");
            }
        }
        if(FastBootEnabled()) {
            // Mark the dispatcher header as signaled if r3 is a guest pointer
            const uint32_t handle = ctx.r3.u32;
            if(handle != 0) {
                struct XDISPATCHER_HEADER {
                    int8_t Type;
                    int8_t Absolute;
                    int16_t Size;
                    int32_t SignalState;
                };
                const uint64_t h64 = static_cast<uint64_t>(handle);
                if(h64 + sizeof(XDISPATCHER_HEADER) <= kPpcMemLimit) {
                    auto* hdr = reinterpret_cast<XDISPATCHER_HEADER*>(base + handle);
                    hdr->SignalState = 1;
                }
            }
            // Return success to break the caller's wait loop cleanly
            ctx.r3.u64 = 0;
            return;
        }
    }

    if(!blockEA) {
        KernelTraceHostOpF("HOST.sub_826346A8.block ea=%08X (null)", blockEA);
    } else {
        const uint64_t blockEnd = static_cast<uint64_t>(blockEA) + 20ull;
        if(blockEnd > kPpcMemLimit) {
            KernelTraceHostOpF("HOST.sub_826346A8.block ea=%08X (out_of_range)", blockEA);
        } else if(g_memory.Translate(blockEA)) {
            // arm the writer watch for [blockEA + 16] every iteration
            const uint32_t watch = blockEA + 16;
            if(g_watchEA.load(std::memory_order_relaxed) != watch) {
                g_watchEA.store(watch, std::memory_order_relaxed);
                KernelTraceHostOpF("HOST.sub_826346A8.watch arm=%08X", watch);
            }

            const uint32_t w0 = LoadGuestU32(base, blockEA);
            const uint32_t w1 = LoadGuestU32(base, blockEA + 4);
            const uint32_t w2 = LoadGuestU32(base, blockEA + 8);
            const uint32_t w3 = LoadGuestU32(base, blockEA + 12);
            uint32_t w4 = LoadGuestU32(base, blockEA + 16);
            KernelTraceHostOpF("HOST.sub_826346A8.block ea=%08X w0=%08X w1=%08X w2=%08X w3=%08X w4=%08X",
                               blockEA, w0, w1, w2, w3, w4);
            // Out-of-image target handling
            if(w4 && !GuestCodeRangeContains(w4)) {

                // Treat 0x0A000000 (heap base) as a known “wake” sentinel.
                // Consume the entry and return success without calling into guest code.
                if (w4 == 0x0A000000u) {
                    const uint32_t watch = blockEA + 16;
                    // Arm (idempotent) so any follow-up stores hit your hooks
                    if (g_watchEA.load(std::memory_order_relaxed) != watch) {
                        g_watchEA.store(watch, std::memory_order_relaxed);
                        KernelTraceHostOpF("HOST.sub_826346A8.watch arm=%08X", watch);
                    }
                    // Synthetic 'any' at the true point of observation
                    KernelTraceHostOpF("HOST.watch.any(read) val=0A000000 ea=%08X lr=%08llX",
                                       watch, (unsigned long long)ctx.lr);

                    // (optional) dump the sentinel target area (as you already do elsewhere)
                    if (g_memory.Translate(w4)) {
                        const uint32_t d0 = LoadGuestU32(base, w4 + 0);
                        const uint32_t d1 = LoadGuestU32(base, w4 + 4);
                        const uint32_t d2 = LoadGuestU32(base, w4 + 8);
                        const uint32_t d3 = LoadGuestU32(base, w4 + 12);
                        KernelTraceHostOpF("HOST.sub_826346A8.target.dump ea=%08X d0=%08X d1=%08X d2=%08X d3=%08X",
                                           w4, d0, d1, d2, d3);
                    } else {
                        KernelTraceHostOpF("HOST.sub_826346A8.target.unmapped ea=%08X", w4);
                    }

                    // Synth wake - call the entry function if present
                    KernelTraceHostOpF("HOST.sub_826346A8.synth_wake block=%08X target=%08X entry=%08X", blockEA, w4, w1);

                    // Check if there's an entry function to call (w1 at offset +4)
                    // Scheduler block format: [state, entry, ctx, evt, ...]
                    if (w1 && GuestCodeRangeContains(w1)) {
                        KernelTraceHostOpF("HOST.sub_826346A8.synth_wake.call_entry entry=%08X", w1);

                        // Clear the block before calling the entry function
                        ClearSchedulerBlock(base, blockEA);

                        // Call the entry function - it will do the actual work
                        // The entry function is responsible for initialization (e.g., creating threads, calling CreateDevice)
                        auto* entryFunc = g_memory.FindFunction(w1);
                        if (entryFunc) {
                            KernelTraceHostOpF("HOST.sub_826346A8.synth_wake.invoke entry=%08X", w1);
                            entryFunc(ctx, base);
                            // Return success after calling the entry function
                            ctx.r3.u64 = 0;
                            return;
                        } else {
                            KernelTraceHostOpF("HOST.sub_826346A8.synth_wake.no_stub entry=%08X", w1);
                            // Fall through to clear and return
                        }
                    } else {
                        KernelTraceHostOpF("HOST.sub_826346A8.synth_wake.no_entry w1=%08X", w1);
                    }

                    // Clear and return success
                    ClearSchedulerBlock(base, blockEA);
                    ctx.r3.u64 = 0;
                    return;
                }


                // Your existing diagnostics for genuine bad targets
                KernelTraceHostOpF("HOST.sub_826346A8.bad_target lr=%08llX block=%08X target=%08X",
                                   (unsigned long long)ctx.lr, blockEA, w4);
                DumpGuestStackWindow(base, ctx.r1.u32, 8);

                if(uint8_t* dump = (uint8_t*)g_memory.Translate(w4)) {
                    const uint32_t d0 = LoadGuestU32(base, w4 + 0);
                    const uint32_t d1 = LoadGuestU32(base, w4 + 4);
                    const uint32_t d2 = LoadGuestU32(base, w4 + 8);
                    const uint32_t d3 = LoadGuestU32(base, w4 + 12);
                    KernelTraceHostOpF("HOST.sub_826346A8.invalid_target.dump ea=%08X d0=%08X d1=%08X d2=%08X d3=%08X",
                                       w4, d0, d1, d2, d3);
                } else {
                    KernelTraceHostOpF("HOST.sub_826346A8.invalid_target.unmapped ea=%08X", w4);
                }

                // (optional) your frame-walk stays if you still want it…

                // Unknown out-of-image target => clear and return success
                ClearSchedulerBlock(base, blockEA);
                ctx.r3.u64 = 0;
                return;
            }

            if(w4) {
                const uint64_t target64 = static_cast<uint64_t>(w4);
                const bool inImage = target64 >= kPpcImageBase && target64 < kPpcImageLimit;
                const bool hasStub = g_memory.FindFunction(w4) != nullptr;
                KernelTraceHostOpF("HOST.sub_826346A8.target ea=%08X in_image=%u has_stub=%u",
                                   w4, inImage ? 1u : 0u, hasStub ? 1u : 0u);
                if(target64 + 16ull <= kPpcMemLimit) {
                    if(g_memory.Translate(w4)) {
                        const uint32_t vptrEA = LoadGuestU32(base, w4 + 0);
                        const uint32_t targetW1 = LoadGuestU32(base, w4 + 4);
                        const uint32_t targetW2 = LoadGuestU32(base, w4 + 8);
                        const uint32_t targetW3 = LoadGuestU32(base, w4 + 12);
                        KernelTraceHostOpF("HOST.sub_826346A8.target.w ea=%08X vptr=%08X w1=%08X w2=%08X w3=%08X",
                                           w4, vptrEA, targetW1, targetW2, targetW3);
                        const uint32_t vtableEA = vptrEA;
                        const uint64_t vtable64 = static_cast<uint64_t>(vtableEA);
                        if(vtableEA && vtable64 + 20ull <= kPpcMemLimit) {
                            if(g_memory.Translate(vtableEA)) {
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

    // Loop breaker already handled at the top of the function - removed duplicate
    __imp__sub_826346A8(ctx, base);
}

PPC_FUNC(sub_828134E0)
{
    // Make ctx visible to the watched-store hook (so it can log lr)
    SetPPCContext(ctx);

    // Arm the watch **before** the loop/producer touches the block
    KernelTraceHostOp("HOST.sub_828134E0.enter");
    KernelTraceHostOpF("HOST.sub_828134E0.regs r29=%08X r30=%08X r31=%08X lr=%08llX",
                       ctx.r29.u32, ctx.r30.u32, ctx.r31.u32, ctx.lr);

    // Check if the link register (return address) is valid
    uint32_t lr32 = static_cast<uint32_t>(ctx.lr);
    if (lr32 < 0x82000000 || lr32 >= 0x82CD0000) {
        KernelTraceHostOpF("HOST.sub_828134E0.INVALID_LR lr=0x%08X (outside valid range)", lr32);
    }

    // Check if we can read from the addresses that sub_828134E0 will access
    // According to the disassembly, it calculates r29 = 0x82813090 and reads from it
    const uint32_t test_addr = 0x82813090;
    auto* test_ptr = g_memory.Translate(test_addr);
    if (test_ptr) {
        uint32_t test_val = __builtin_bswap32(*(volatile uint32_t*)test_ptr);
        KernelTraceHostOpF("HOST.sub_828134E0.memtest [0x%08X]=0x%08X (accessible)", test_addr, test_val);
    } else {
        KernelTraceHostOpF("HOST.sub_828134E0.memtest [0x%08X]=NULL (NOT MAPPED!)", test_addr);
    }

    // Prefer the block recorded by sub_826346A8; r29 may not be set yet at entry
    uint32_t block = Mw05PeekSchedulerBlockEA();
    if (!block) block = ctx.r29.u32;   // fallback once the loop is live

    if (block) {
        const uint32_t watch = block + 16;
        if (g_watchEA.load(std::memory_order_relaxed) != watch) {
            g_watchEA.store(watch, std::memory_order_relaxed);
            KernelTraceHostOpF("HOST.sub_828134E0.watch arm=%08X", watch);
        }
    } else {
        KernelTraceHostOp("HOST.sub_828134E0.watch deferred (block==0)");
    }

    __imp__sub_828134E0(ctx, base);

    KernelTraceHostOpF("HOST.sub_828134E0.exit lr=%08llX", ctx.lr);
}
