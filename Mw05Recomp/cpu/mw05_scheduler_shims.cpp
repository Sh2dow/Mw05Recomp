// Scheduler callback guard shims to prevent invalid guest pointers from triggering host crashes.

#include <cpu/ppc_context.h>
#include <kernel/memory.h>
#include <kernel/trace.h>
#include <ppc/ppc_config.h>
#include <cstring>
#include <algorithm>
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#if defined(_WIN32)
#include <windows.h>
#endif

extern "C"
{
    uint32_t Mw05PeekSchedulerBlockEA();
    uint32_t Mw05GetSchedulerHandleEA();
    uint32_t Mw05GetSchedulerTimeoutEA();
    void __imp__sub_82621640(PPCContext &ctx, uint8_t *base);
    void __imp__sub_8284E658(PPCContext &ctx, uint8_t *base);
}

namespace
{
    inline bool GuestRangeValid(uint32_t ea, size_t bytes = 4)
    {
        if (!ea)
        {
            return false;
        }
        const uint64_t end = static_cast<uint64_t>(ea) + static_cast<uint64_t>(bytes);
        return end <= PPC_MEMORY_SIZE;
    }

    // PPC_LOOKUP_FUNC only maps compiled code; reject anything outside that window.
    inline bool GuestCodeRangeContains(uint32_t ea)
    {
        const uint64_t codeBegin = static_cast<uint64_t>(PPC_CODE_BASE);
        const uint64_t codeEnd = codeBegin + static_cast<uint64_t>(PPC_CODE_SIZE);
        const uint64_t value = static_cast<uint64_t>(ea);
        return value >= codeBegin && value < codeEnd;
    }

    inline bool GuestPointerReadable(uint8_t *base, uint32_t ea, size_t bytes)
    {
        if (!GuestRangeValid(ea, bytes))
        {
            return false;
        }
#if defined(_WIN32)
        const uint8_t *ptr = base + ea;
        size_t remaining = bytes;
        while (remaining)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(ptr, &mbi, sizeof(mbi)))
            {
                return false;
            }
            if ((mbi.State & MEM_COMMIT) == 0)
            {
                return false;
            }
            const DWORD protect = mbi.Protect & 0xFFu;
            if (protect == PAGE_NOACCESS || protect == PAGE_EXECUTE || (mbi.Protect & PAGE_GUARD))
            {
                return false;
            }
            const auto *regionBegin = static_cast<const uint8_t *>(mbi.BaseAddress);
            const auto *regionEnd = regionBegin + mbi.RegionSize;
            if (regionEnd <= ptr)
            {
                return false;
            }
            const size_t chunk = std::min<size_t>(remaining, static_cast<size_t>(regionEnd - ptr));
            ptr += chunk;
            remaining -= chunk;
        }
        return true;
#else
        (void)base;
        (void)ea;
        (void)bytes;
        return true;
#endif
    }

    inline bool TryLoadGuestU32(uint8_t *base, uint32_t ea, uint32_t &outValue)
    {
        if (!GuestPointerReadable(base, ea, sizeof(outValue)))
        {
            return false;
        }
        std::memcpy(&outValue, base + ea, sizeof(outValue));
#if defined(_MSC_VER)
        outValue = _byteswap_ulong(outValue);
#else
        outValue = __builtin_bswap32(outValue);
#endif
        return true;
    }

    inline uint32_t LoadGuestU32(uint8_t *base, uint32_t ea)
    {
        uint32_t value = 0;
        TryLoadGuestU32(base, ea, value);
        return value;
    }

    inline void ClearSchedulerBlock(uint8_t *base, uint32_t blockEA)
    {
        PPC_STORE_U32(blockEA + 4, 0);
        PPC_STORE_U32(blockEA + 8, 0);
        PPC_STORE_U32(blockEA + 12, 0);
        PPC_STORE_U32(blockEA + 16, 0);
        PPC_STORE_U32(blockEA + 0, 0);
    }

    inline void TraceSchedulerBlock(const char *tag, uint32_t blockEA)
    {
        if (!blockEA)
        {
            KernelTraceHostOpF("%s ea=%08X (null)", tag, blockEA);
            return;
        }
        if (!GuestRangeValid(blockEA, 20))
        {
            KernelTraceHostOpF("%s ea=%08X (out_of_range)", tag, blockEA);
            return;
        }
        if (auto *host = static_cast<uint8_t *>(g_memory.Translate(blockEA)))
        {
            uint32_t w0 = 0, w1 = 0, w2 = 0, w3 = 0, w4 = 0;
            std::memcpy(&w0, host + 0, sizeof(w0));
            std::memcpy(&w1, host + 4, sizeof(w1));
            std::memcpy(&w2, host + 8, sizeof(w2));
            std::memcpy(&w3, host + 12, sizeof(w3));
            std::memcpy(&w4, host + 16, sizeof(w4));
#if defined(_MSC_VER)
            w0 = _byteswap_ulong(w0);
            w1 = _byteswap_ulong(w1);
            w2 = _byteswap_ulong(w2);
            w3 = _byteswap_ulong(w3);
            w4 = _byteswap_ulong(w4);
#else
            w0 = __builtin_bswap32(w0);
            w1 = __builtin_bswap32(w1);
            w2 = __builtin_bswap32(w2);
            w3 = __builtin_bswap32(w3);
            w4 = __builtin_bswap32(w4);
#endif
            KernelTraceHostOpF("%s ea=%08X w0=%08X w1=%08X w2=%08X w3=%08X w4=%08X",
                               tag, blockEA, w0, w1, w2, w3, w4);
        }
        else
        {
            KernelTraceHostOpF("%s ea=%08X (unmapped)", tag, blockEA);
        }
    }

    inline void TraceSchedulerProducerSnapshot(const char *reason, uint32_t blockEA, uint32_t flagsEA,
                                               uint32_t targetEA, uint32_t vtableEA, uint32_t funcEA)
    {
        const uint32_t lastBlockEA = Mw05PeekSchedulerBlockEA();
        const uint32_t handleEA = Mw05GetSchedulerHandleEA();
        const uint32_t timeoutEA = Mw05GetSchedulerTimeoutEA();
        KernelTraceHostOpF("HOST.sub_82621640.skip reason=%s block=%08X flags=%08X target=%08X vtable=%08X func=%08X last_block=%08X handle=%08X timeout=%08X",
                           reason, blockEA, flagsEA, targetEA, vtableEA, funcEA, lastBlockEA, handleEA, timeoutEA);
        TraceSchedulerBlock("HOST.sub_82621640.skip.block", blockEA);
        if (lastBlockEA && lastBlockEA != blockEA)
        {
            TraceSchedulerBlock("HOST.sub_82621640.skip.last", lastBlockEA);
        }
    }
}

static inline uint32_t LoadGuestU32_BE(uint8_t *base, uint32_t ea)
{
    uint32_t v = 0;
    std::memcpy(&v, base + ea, sizeof(v));
#if defined(_MSC_VER)
    return _byteswap_ulong(v);
#else
    return __builtin_bswap32(v);
#endif
}

PPC_FUNC(sub_82621640)
{
    SetPPCContext(ctx);
    const uint32_t blockEA = ctx.r3.u32;
    if (!blockEA)
    {
        // nothing pending; leave block + handle state unchanged
        return;
    }

    if (!GuestRangeValid(blockEA, 20))
    {
        KernelTraceHostOpF("HOST.sub_82621640.bad_block ea=%08X", blockEA);
        TraceSchedulerProducerSnapshot("bad_block", blockEA, 0, 0, 0, 0);
        return;
    }

    uint32_t flagsEA = 0;
    if (!TryLoadGuestU32(base, blockEA + 8, flagsEA))
    {
        KernelTraceHostOpF("HOST.sub_82621640.read_flags_fail block=%08X", blockEA);
        TraceSchedulerProducerSnapshot("flags_load_fail", blockEA, 0, 0, 0, 0);
        return;
    }
    KernelTraceHostOpF("HOST.sub_82621640.enter block=%08X flags=%08X", blockEA, flagsEA);

    uint32_t targetEA = 0;
    uint32_t vtableEA = 0;
    uint32_t funcEA = 0;
    PPCFunc *dispatchFunc = nullptr;
    bool skipCallback = false;
    const char *skipReason = nullptr;

    if (flagsEA)
    {
        if (!TryLoadGuestU32(base, blockEA + 16, targetEA))
        {
            KernelTraceHostOpF("HOST.sub_82621640.bad_target_load block=%08X", blockEA);
            skipCallback = true;
            skipReason = "target_load";
        }
        else if (!GuestRangeValid(targetEA, 4))
        {
            KernelTraceHostOpF("HOST.sub_82621640.bad_target block=%08X target=%08X", blockEA, targetEA);
            skipCallback = true;
            skipReason = "bad_target";
        }
        else if (!TryLoadGuestU32(base, targetEA, vtableEA))
        {
            KernelTraceHostOpF("HOST.sub_82621640.bad_vtable_load block=%08X target=%08X", blockEA, targetEA);
            skipCallback = true;
            skipReason = "vtable_load";
        }
        else if (!GuestRangeValid(vtableEA, 20))
        {
            KernelTraceHostOpF("HOST.sub_82621640.bad_vtable block=%08X target=%08X vtable=%08X", blockEA, targetEA, vtableEA);
            skipCallback = true;
            skipReason = "bad_vtable";
        }
        else if (!GuestRangeValid(vtableEA + 16, 4))
        {
            KernelTraceHostOpF("HOST.sub_82621640.bad_vtable_slot block=%08X vtable=%08X", blockEA, vtableEA);
            skipCallback = true;
            skipReason = "bad_vtable_slot";
        }
        else if (!TryLoadGuestU32(base, vtableEA + 16, funcEA))
        {
            KernelTraceHostOpF("HOST.sub_82621640.bad_func_load block=%08X vtable=%08X", blockEA, vtableEA);
            skipCallback = true;
            skipReason = "func_load";
        }
        else if (!funcEA)
        {
            KernelTraceHostOpF("HOST.sub_82621640.bad_func block=%08X func=%08X", blockEA, funcEA);
            skipCallback = true;
            skipReason = "bad_func";
        }
        else if (!GuestRangeValid(funcEA, 4))
        {
            KernelTraceHostOpF("HOST.sub_82621640.bad_func_range block=%08X func=%08X", blockEA, funcEA);
            skipCallback = true;
            skipReason = "bad_func_range";
        }
        else if (!GuestCodeRangeContains(funcEA))
        {
            KernelTraceHostOpF("HOST.sub_82621640.bad_func_segment block=%08X func=%08X", blockEA, funcEA);
            skipCallback = true;
            skipReason = "bad_func_segment";
        }
        else
        {
            dispatchFunc = g_memory.FindFunction(funcEA);
            if (!dispatchFunc)
            {
                KernelTraceHostOpF("HOST.sub_82621640.missing_func block=%08X func=%08X", blockEA, funcEA);
                skipCallback = true;
                skipReason = "missing_func";
            }
            else
            {
                KernelTraceHostOpF("HOST.sub_82621640.call block=%08X target=%08X func=%08X host=%p", blockEA, targetEA, funcEA, reinterpret_cast<const void *>(dispatchFunc));
            }
        }

        if (skipCallback)
        {
            TraceSchedulerProducerSnapshot(skipReason ? skipReason : "unknown", blockEA, flagsEA, targetEA, vtableEA, funcEA);
            ClearSchedulerBlock(base, blockEA);
            return;
        }

        if (!dispatchFunc)
        {
            KernelTraceHostOpF("HOST.sub_82621640.missing_host block=%08X func=%08X", blockEA, funcEA);
            TraceSchedulerProducerSnapshot("missing_host", blockEA, flagsEA, targetEA, vtableEA, funcEA);
            ClearSchedulerBlock(base, blockEA);
            return;
        }

        KernelTraceHostOpF("HOST.sub_82621640.dispatch block=%08X target=%08X vtable=%08X func=%08X", blockEA, targetEA, vtableEA, funcEA);
    }
    else
    {
        KernelTraceHostOpF("HOST.sub_82621640.no_flags block=%08X", blockEA);
    }

    // --- snapshot the slot before calling the original
    uint32_t before_w4 = 0;
    const bool can_probe =
        GuestRangeValid(blockEA + 16, 4) && (g_memory.Translate(blockEA + 16) != nullptr);
    if (can_probe) {
        before_w4 = LoadGuestU32_BE(base, blockEA + 16);

        // NEW: if sentinel is already set and this slot isn’t watched yet, log it now
        const uint32_t watch = blockEA + 16;
        if (before_w4 == 0x0A000000u && g_watchEA.load(std::memory_order_relaxed) != watch) {
            KernelTraceHostOpF("HOST.watch.any(pre) val=0A000000 ea=%08X lr=%08llX",
                               watch, (unsigned long long)ctx.lr);
        }
    }

    __imp__sub_82621640(ctx, base);

    // --- read-after-write: did the producer touch [block+0x10]?
    if (can_probe) {
        const uint32_t after_w4 = LoadGuestU32_BE(base, blockEA + 16);
        if (after_w4 != before_w4) {
            KernelTraceHostOpF(
                "HOST.sub_82621640.write block=%08X w4: %08X -> %08X (lr=%08llX)",
                blockEA, before_w4, after_w4,
                (unsigned long long)ctx.lr);

            // Arm the slot watch so subsequent stores get attributed
            const uint32_t watch = blockEA + 16;
            g_watchEA.store(watch, std::memory_order_relaxed);
            KernelTraceHostOpF("HOST.sub_82621640.watch arm=%08X", watch);

            // NEW: synth “any” if producer set sentinel
            if (after_w4 == 0x0A000000u) {
                KernelTraceHostOpF("HOST.watch.any(read) val=0A000000 ea=%08X lr=%08llX",
                                   watch, (unsigned long long)ctx.lr);
            }

            if (after_w4 == 0x0A000000u) {
                if (g_memory.Translate(after_w4)) {
                    const uint32_t d0 = LoadGuestU32_BE(base, after_w4 + 0);
                    const uint32_t d1 = LoadGuestU32_BE(base, after_w4 + 4);
                    const uint32_t d2 = LoadGuestU32_BE(base, after_w4 + 8);
                    const uint32_t d3 = LoadGuestU32_BE(base, after_w4 + 12);
                    KernelTraceHostOpF("HOST.sub_82621640.target.dump ea=%08X d0=%08X d1=%08X d2=%08X d3=%08X",
                                       after_w4, d0, d1, d2, d3);
                } else {
                    KernelTraceHostOpF("HOST.sub_82621640.target.unmapped ea=%08X", after_w4);
                }
            }
        }
    }
}

PPC_FUNC(sub_8284E658)
{
    SetPPCContext(ctx);

    // Prefer the live block from this call; fallback to the last peek if needed
    uint32_t blockEA = ctx.r3.u32;
    if (!blockEA) blockEA = Mw05PeekSchedulerBlockEA();
    if (!blockEA) {
        KernelTraceHostOpF("HOST.sub_8284E658.peek block=%08X before=%08X after=%08X", 0u, 0u, 0u);
        return;
    }

    // Snapshot before
    uint32_t before_w4 = 0;
    const bool can_probe =
        GuestRangeValid(blockEA + 16, 4) && (g_memory.Translate(blockEA + 16) != nullptr);
    if (can_probe) {
        before_w4 = LoadGuestU32_BE(base, blockEA + 16);

        // If sentinel is already there and watch isn't armed yet, log it
        const uint32_t watch = blockEA + 16;
        if (before_w4 == 0x0A000000u && g_watchEA.load(std::memory_order_relaxed) != watch) {
            KernelTraceHostOpF("HOST.watch.any(pre) val=0A000000 ea=%08X lr=%08llX",
                               watch, (unsigned long long)ctx.lr);
        }
    }

    // Tail-call original
    __imp__sub_8284E658(ctx, base);

    if (!can_probe) {
        KernelTraceHostOpF("HOST.sub_8284E658.peek block=%08X before=%08X after=%08X",
                           blockEA, before_w4, before_w4);
        return;
    }

    // Read-after-write
    const uint32_t after_w4 = LoadGuestU32_BE(base, blockEA + 16);
    if (after_w4 != before_w4) {
        KernelTraceHostOpF("HOST.sub_8284E658.write block=%08X w4: %08X -> %08X (lr=%08llX)",
                           blockEA, before_w4, after_w4, (unsigned long long)ctx.lr);

        // Arm the watch so later scalar/wide stores get attributed
        const uint32_t watch = blockEA + 16;
        g_watchEA.store(watch, std::memory_order_relaxed);
        KernelTraceHostOpF("HOST.sub_8284E658.watch arm=%08X", watch);

        // Synthetic 'any' on change to sentinel
        if (after_w4 == 0x0A000000u) {
            KernelTraceHostOpF("HOST.watch.any(read) val=0A000000 ea=%08X lr=%08llX",
                               watch, (unsigned long long)ctx.lr);

            if (g_memory.Translate(after_w4)) {
                const uint32_t d0 = LoadGuestU32_BE(base, after_w4 + 0);
                const uint32_t d1 = LoadGuestU32_BE(base, after_w4 + 4);
                const uint32_t d2 = LoadGuestU32_BE(base, after_w4 + 8);
                const uint32_t d3 = LoadGuestU32_BE(base, after_w4 + 12);
                KernelTraceHostOpF("HOST.sub_8284E658.target.dump ea=%08X d0=%08X d1=%08X d2=%08X d3=%08X",
                                   after_w4, d0, d1, d2, d3);
            } else {
                KernelTraceHostOpF("HOST.sub_8284E658.target.unmapped ea=%08X", after_w4);
            }
        }
    }

    KernelTraceHostOpF("HOST.sub_8284E658.peek block=%08X before=%08X after=%08X",
                       blockEA, before_w4, after_w4);
}
