// Scheduler callback guard shims to prevent invalid guest pointers from triggering host crashes.

#include <cpu/ppc_context.h>
#include <kernel/memory.h>
#include <kernel/trace.h>
#include <ppc/ppc_config.h>
#include <cstring>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

extern "C" void __imp__sub_82621640(PPCContext& ctx, uint8_t* base);
extern "C" uint32_t Mw05PeekSchedulerBlockEA();
extern "C" uint32_t Mw05GetSchedulerHandleEA();
extern "C" uint32_t Mw05GetSchedulerTimeoutEA();

namespace
{
    inline bool GuestRangeValid(uint32_t ea, size_t bytes = 4)
    {
        if (!ea) {
            return false;
        }
        const uint64_t end = static_cast<uint64_t>(ea) + static_cast<uint64_t>(bytes);
        return end <= PPC_MEMORY_SIZE;
    }

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

    inline void ClearSchedulerBlock(uint8_t* base, uint32_t blockEA)
    {
        PPC_STORE_U32(blockEA + 4, 0);
        PPC_STORE_U32(blockEA + 8, 0);
        PPC_STORE_U32(blockEA + 12, 0);
        PPC_STORE_U32(blockEA + 16, 0);
        PPC_STORE_U32(blockEA + 0, 0);
    }

    inline void TraceSchedulerBlock(const char* tag, uint32_t blockEA)
    {
        if (!blockEA) {
            KernelTraceHostOpF("%s ea=%08X (null)", tag, blockEA);
            return;
        }
        if (!GuestRangeValid(blockEA, 20)) {
            KernelTraceHostOpF("%s ea=%08X (out_of_range)", tag, blockEA);
            return;
        }
        if (auto* host = static_cast<uint8_t*>(g_memory.Translate(blockEA))) {
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
        } else {
            KernelTraceHostOpF("%s ea=%08X (unmapped)", tag, blockEA);
        }
    }

    inline void TraceSchedulerProducerSnapshot(const char* reason, uint32_t blockEA, uint32_t flagsEA,
                                               uint32_t targetEA, uint32_t vtableEA, uint32_t funcEA)
    {
        const uint32_t lastBlockEA = Mw05PeekSchedulerBlockEA();
        const uint32_t handleEA = Mw05GetSchedulerHandleEA();
        const uint32_t timeoutEA = Mw05GetSchedulerTimeoutEA();
        KernelTraceHostOpF("HOST.sub_82621640.skip reason=%s block=%08X flags=%08X target=%08X vtable=%08X func=%08X last_block=%08X handle=%08X timeout=%08X",
                           reason, blockEA, flagsEA, targetEA, vtableEA, funcEA, lastBlockEA, handleEA, timeoutEA);
        TraceSchedulerBlock("HOST.sub_82621640.skip.block", blockEA);
        if (lastBlockEA && lastBlockEA != blockEA) {
            TraceSchedulerBlock("HOST.sub_82621640.skip.last", lastBlockEA);
        }
    }
}

extern "C" void __imp__sub_82621640(PPCContext& ctx, uint8_t* base);

PPC_FUNC(sub_82621640)
{
    const uint32_t blockEA = ctx.r3.u32;
    if (!GuestRangeValid(blockEA, 20)) {
        KernelTraceHostOpF("HOST.sub_82621640.bad_block ea=%08X", blockEA);
        TraceSchedulerProducerSnapshot("bad_block", blockEA, 0, 0, 0, 0);
        return;
    }

    const uint32_t flagsEA = LoadGuestU32(base, blockEA + 8);
    KernelTraceHostOpF("HOST.sub_82621640.enter block=%08X flags=%08X", blockEA, flagsEA);

    uint32_t targetEA = 0;
    uint32_t vtableEA = 0;
    uint32_t funcEA = 0;
    PPCFunc* dispatchFunc = nullptr;
    bool skipCallback = false;
    const char* skipReason = nullptr;

    if (flagsEA) {
        targetEA = LoadGuestU32(base, blockEA + 16);

        if (!GuestRangeValid(targetEA, 4)) {
            KernelTraceHostOpF("HOST.sub_82621640.bad_target block=%08X target=%08X", blockEA, targetEA);
            skipCallback = true;
            skipReason = "bad_target";
        } else {
            vtableEA = LoadGuestU32(base, targetEA);
            if (!GuestRangeValid(vtableEA, 20)) {
                KernelTraceHostOpF("HOST.sub_82621640.bad_vtable block=%08X target=%08X vtable=%08X", blockEA, targetEA, vtableEA);
                skipCallback = true;
                skipReason = "bad_vtable";
            } else if (!GuestRangeValid(vtableEA + 16, 4)) {
                KernelTraceHostOpF("HOST.sub_82621640.bad_vtable_slot block=%08X vtable=%08X", blockEA, vtableEA);
                skipCallback = true;
                skipReason = "bad_vtable_slot";
            } else {
                funcEA = LoadGuestU32(base, vtableEA + 16);
                if (!funcEA) {
                    KernelTraceHostOpF("HOST.sub_82621640.bad_func block=%08X func=%08X", blockEA, funcEA);
                    skipCallback = true;
                    skipReason = "bad_func";
                } else if (!GuestRangeValid(funcEA, 4)) {
                    KernelTraceHostOpF("HOST.sub_82621640.bad_func_range block=%08X func=%08X", blockEA, funcEA);
                    skipCallback = true;
                    skipReason = "bad_func_range";
                } else {
                    dispatchFunc = g_memory.FindFunction(funcEA);
                    if (!dispatchFunc) {
                        KernelTraceHostOpF("HOST.sub_82621640.missing_func block=%08X func=%08X", blockEA, funcEA);
                        skipCallback = true;
                        skipReason = "missing_func";
                    } else {
                        KernelTraceHostOpF("HOST.sub_82621640.call block=%08X target=%08X func=%08X host=%p", blockEA, targetEA, funcEA, reinterpret_cast<const void*>(dispatchFunc));
                    }
                }
            }
        }

        if (skipCallback) {
            TraceSchedulerProducerSnapshot(skipReason ? skipReason : "unknown", blockEA, flagsEA, targetEA, vtableEA, funcEA);
            ClearSchedulerBlock(base, blockEA);
            return;
        }

        if (!dispatchFunc) {
            KernelTraceHostOpF("HOST.sub_82621640.missing_host block=%08X func=%08X", blockEA, funcEA);
            TraceSchedulerProducerSnapshot("missing_host", blockEA, flagsEA, targetEA, vtableEA, funcEA);
            ClearSchedulerBlock(base, blockEA);
            return;
        }

        KernelTraceHostOpF("HOST.sub_82621640.dispatch block=%08X target=%08X vtable=%08X func=%08X", blockEA, targetEA, vtableEA, funcEA);
    } else {
        KernelTraceHostOpF("HOST.sub_82621640.no_flags block=%08X", blockEA);
    }

    __imp__sub_82621640(ctx, base);
}

