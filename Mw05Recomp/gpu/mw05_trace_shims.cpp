// MW05 dynamic discovery shims for frequently used engine helpers.
// They log the caller (LR) and common arg regs, then tail-call the original.

#include <cpu/ppc_context.h>
#include <kernel/trace.h>
#include <kernel/memory.h>
#include <cstdlib>
#include <atomic>

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

// Write helpers mirroring ReadBE32
static inline void WriteBE32(uint32_t ea, uint32_t value) {
    if (!ea) return;
    if (auto* p = reinterpret_cast<uint32_t*>(g_memory.Translate(ea))) {
    #if defined(_MSC_VER)
        *p = _byteswap_ulong(value);
    #else
        *p = __builtin_bswap32(value);
    #endif
    }
}
static inline void WriteBE8(uint32_t ea, uint8_t value) {
    if (!ea) return;
    if (auto* p = reinterpret_cast<uint8_t*>(g_memory.Translate(ea))) {
        *p = value;
    }
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

// Track last-seen scheduler/context pointer to optionally nudge present-wrapper once
static std::atomic<uint32_t> s_lastSchedR3{0};
static std::atomic<bool> s_schedR3Logged{false};
static std::atomic<uint32_t> s_schedR3Seen{0};
extern "C" uint32_t Mw05Trace_SchedR3SeenCount() { return s_schedR3Seen.load(std::memory_order_acquire); }

static inline void MaybeLogSchedCapture(uint32_t r3) {
    if (r3 >= 0x1000 && r3 < PPC_MEMORY_SIZE) {
        if (!s_schedR3Logged.exchange(true, std::memory_order_acq_rel)) {
            KernelTraceHostOpF("HOST.SchedR3.Captured r3=%08X", r3);
        }
    }
}
extern "C" uint32_t Mw05Trace_LastSchedR3() { return s_lastSchedR3.load(std::memory_order_acquire); }
extern "C" void Mw05Trace_SeedSchedR3_NoLog(uint32_t r3) {
    if (r3 >= 0x1000 && r3 < PPC_MEMORY_SIZE) {
        s_lastSchedR3.store(r3, std::memory_order_release);
        s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel);
    }
}

extern "C" void Mw05Trace_ConsiderSchedR3(uint32_t r3) {
    if (r3 >= 0x1000 && r3 < PPC_MEMORY_SIZE) {
        MaybeLogSchedCapture(r3);
        s_lastSchedR3.store(r3, std::memory_order_release);
        s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel);
    }
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
    void __imp__sub_82596E40(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825968B0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_82597650(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825976D8(PPCContext& ctx, uint8_t* base);


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
    void __imp__sub_82596978(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825979A8(PPCContext& ctx, uint8_t* base);

    void __imp__sub_825A97B8(PPCContext& ctx, uint8_t* base);

    void __imp__sub_82441CF0(PPCContext& ctx, uint8_t* base);

    void __imp__sub_82598A20(PPCContext& ctx, uint8_t* base);


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

// Forward decls of local shim helpers used before their definitions (C++ linkage)
struct PPCContext;
void MW05Shim_sub_825972B0(PPCContext& ctx, uint8_t* base);
void MW05Shim_sub_82597650(PPCContext& ctx, uint8_t* base);
void MW05Shim_sub_825976D8(PPCContext& ctx, uint8_t* base);
void MW05Shim_sub_825968B0(PPCContext& ctx, uint8_t* base);
void MW05Shim_sub_82596E40(PPCContext& ctx, uint8_t* base);


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
    auto looks_ptr = [](uint32_t ea){ return ea >= 0x1000 && ea < PPC_MEMORY_SIZE; };
    uint32_t seed = ctx.r3.u32;
    if (!looks_ptr(seed) && looks_ptr(ctx.r5.u32)) seed = ctx.r5.u32; // MW05: loop passes ctx in r5
    if (looks_ptr(seed)) { MaybeLogSchedCapture(seed); s_lastSchedR3.store(seed, std::memory_order_release); s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel); }
    DumpEAWindow("8262F2A0.r3", ctx.r3.u32);
    DumpEAWindow("8262F2A0.r4", ctx.r4.u32);
    DumpEAWindow("8262F2A0.r5", ctx.r5.u32);
    DumpSchedState("8262F2A0", seed);

    static const bool s_loop_try_pm4_pre = [](){ if (const char* v = std::getenv("MW05_LOOP_TRY_PM4_PRE")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    static const bool s_loop_try_pm4 = [](){ if (const char* v = std::getenv("MW05_LOOP_TRY_PM4")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    static const bool s_loop_try_pm4_deep = [](){ if (const char* v = std::getenv("MW05_LOOP_TRY_PM4_DEEP")) return !(v[0]=='0' && v[1]=='\0'); return false; }();

    if (s_loop_try_pm4_pre && looks_ptr(seed)) {
        uint32_t saved_r3 = ctx.r3.u32;
        ctx.r3.u32 = seed;
        KernelTraceHostOpF("HOST.sub_8262F2A0.pre.try_825972B0 r3=%08X (seed)", ctx.r3.u32);
        MW05Shim_sub_825972B0(ctx, base);
        if (s_loop_try_pm4_deep) {
            KernelTraceHostOpF("HOST.sub_8262F2A0.pre.try_deep r3=%08X", ctx.r3.u32);
            MW05Shim_sub_82597650(ctx, base);
            MW05Shim_sub_825976D8(ctx, base);
            // Additional allocator/callback prep + gating clear
            MW05Shim_sub_825968B0(ctx, base);
            MW05Shim_sub_82596E40(ctx, base);
        }
        ctx.r3.u32 = saved_r3;
    }

    __imp__sub_8262F2A0(ctx, base);

    if (s_loop_try_pm4 && looks_ptr(seed)) {
        uint32_t saved_r3 = ctx.r3.u32;
        ctx.r3.u32 = seed;
        KernelTraceHostOpF("HOST.sub_8262F2A0.post.try_825972B0 r3=%08X (seed)", ctx.r3.u32);
        MW05Shim_sub_825972B0(ctx, base);
        if (s_loop_try_pm4_deep) {
            KernelTraceHostOpF("HOST.sub_8262F2A0.post.try_deep r3=%08X", ctx.r3.u32);
            MW05Shim_sub_82597650(ctx, base);
            MW05Shim_sub_825976D8(ctx, base);
            // Additional allocator/callback prep + gating clear
            MW05Shim_sub_825968B0(ctx, base);
            MW05Shim_sub_82596E40(ctx, base);
        }
        ctx.r3.u32 = saved_r3;
    }
}
void MW05Shim_sub_8262F330(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_8262F330.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    if (ctx.r3.u32 >= 0x1000 && ctx.r3.u32 < PPC_MEMORY_SIZE) { MaybeLogSchedCapture(ctx.r3.u32); s_lastSchedR3.store(ctx.r3.u32, std::memory_order_release); s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel); }
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
    if (ctx.r3.u32 >= 0x1000 && ctx.r3.u32 < PPC_MEMORY_SIZE) { MaybeLogSchedCapture(ctx.r3.u32); s_lastSchedR3.store(ctx.r3.u32, std::memory_order_release); s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel); }
    DumpEAWindow("82812E20.r3", ctx.r3.u32);
    DumpEAWindow("82812E20.r4", ctx.r4.u32);
    DumpEAWindow("82812E20.r5", ctx.r5.u32);
    DumpSchedState("82812E20", ctx.r3.u32);
    __imp__sub_82812E20(ctx, base);
}

void MW05Shim_sub_82596978(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_82596978.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    DumpEAWindow("82596978.r3", ctx.r3.u32);
    DumpEAWindow("82596978.r4", ctx.r4.u32);
    __imp__sub_82596978(ctx, base);
}

void MW05Shim_sub_825979A8(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_825979A8.lr=%08llX r3=%08X r4=%08X r5=%08X",
                       (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);

    auto looks_ptr = [](uint32_t ea) {
        return ea >= 0x1000 && ea < PPC_MEMORY_SIZE;
    };

    // Opt-in: swap params at ISR entry so scheduler/context lands in r3.
    static const bool s_swap_entry = [](){
        if (const char* v = std::getenv("MW05_VD_ISR_SWAP_AT_ENTRY")) return !(v[0]=='0' && v[1]=='\0');
        // Default off unless explicitly enabled by runner/diag
        return false;
    }();
    if (s_swap_entry) {
        const bool r3_ok = looks_ptr(ctx.r3.u32);
        const bool r4_ok = looks_ptr(ctx.r4.u32);
        if (!r3_ok && r4_ok) {
            KernelTraceHostOp("HOST.sub_825979A8.swap@entry r3<->r4");
        #if defined(_MSC_VER)
            std::swap(ctx.r3.u32, ctx.r4.u32);
        #else
            uint32_t tmp = ctx.r3.u32; ctx.r3.u32 = ctx.r4.u32; ctx.r4.u32 = tmp;
        #endif
        }
    }

    // Optional: force r3 from last-seen scheduler or env if r3 is null/unusable.
    static const bool s_force_r3 = [](){
        if (const char* v = std::getenv("MW05_VD_ISR_FORCE_R3")) return !(v[0]=='0' && v[1]=='\0');
        return false;
    }();
    if (s_force_r3) {
        uint32_t seed = 0;
        if (const char* v = std::getenv("MW05_SCHED_R3_EA")) {
            // Accept both hex (0x...) and decimal
            seed = static_cast<uint32_t>(std::strtoul(v, nullptr, 0));
        }
        if (!seed) {
            seed = s_lastSchedR3.load(std::memory_order_acquire);
        }
        if (looks_ptr(seed) && !looks_ptr(ctx.r3.u32)) {
            KernelTraceHostOpF("HOST.sub_825979A8.force r3=%08X", seed);
            ctx.r3.u32 = seed;
        }
    }

    // Record scheduler/context sighting so host gates can proceed
    Mw05Trace_ConsiderSchedR3(ctx.r3.u32);

    DumpEAWindow("825979A8.r3", ctx.r3.u32);
    DumpEAWindow("825979A8.r4", ctx.r4.u32);
    DumpSchedState("825979A8", ctx.r3.u32);

    __imp__sub_825979A8(ctx, base);
}


void MW05Shim_sub_825A97B8(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_825A97B8.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    DumpEAWindow("825A97B8.r3", ctx.r3.u32);
    __imp__sub_825A97B8(ctx, base);
}

// Host allocator callback to be installed into scheduler if game leaves it null
// Contract: return r3 = pointer to writable PM4 space (we use System Command Buffer payload)
void MW05HostAllocCb(PPCContext& ctx, uint8_t* base) {
    const uint32_t sys_base    = 0x00140400u;
    const uint32_t sys_payload = sys_base + 0x10u;
    const uint32_t sys_end     = sys_base + 0x10000u;

    // Treat r3 (or r4 if non-zero) as scheduler EA
    uint32_t sched = ctx.r3.u32 ? ctx.r3.u32 : ctx.r4.u32;
    if (!(sched >= 0x1000 && sched + 14024 < PPC_MEMORY_SIZE)) {
        // Fallback: just return the payload start
        KernelTraceHostOpF("HOST.MW05HostAllocCb.fallback.ret r3=%08X", sys_payload);
        ctx.r3.u32 = sys_payload;
        return;
    }

    // Ensure allocator fields are initialized
    uint32_t cur = ReadBE32(sched + 14012);
    uint32_t end = ReadBE32(sched + 14020);
    if (cur == 0 || end == 0) {
        WriteBE32(sched + 14012, sys_payload);
        WriteBE32(sched + 14016, sys_payload);
        WriteBE32(sched + 14020, sys_end);
        cur = sys_payload;
        end = sys_end;
    }

    // Size heuristic: use r5 (count), assume dwords if small; fall back to 16 dwords
    uint32_t count = ctx.r5.u32;
    if (count == 0 || count > 0x10000u) count = 16; // safety bound
    uint32_t bytes = count * 4u;

    uint32_t ret = cur;
    uint32_t next = cur + bytes;
    if (next > end) {
        // Clamp and wrap to start of payload to avoid overflow
        ret = sys_payload;
        next = sys_payload + bytes;
    }

    // Publish tail and current write pointer
    WriteBE32(sched + 0x14, next);      // qtail (best-effort)
    WriteBE32(sched + 14012, next);     // current write ptr

    KernelTraceHostOpF("HOST.MW05HostAllocCb.alloc ret=%08X bytes=%u next=%08X lr=%08llX r5=%u", ret, (unsigned)bytes, next, (unsigned long long)ctx.lr, (unsigned)ctx.r5.u32);
    ctx.r3.u32 = ret;
}


// Add shims for research helpers used by MW05 during rendering.
// Specialize 82595FC8/825972B0 to dump more state
void MW05Shim_sub_82595FC8(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_82595FC8.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    if (ctx.r3.u32 >= 0x1000 && ctx.r3.u32 < PPC_MEMORY_SIZE) {
        MaybeLogSchedCapture(ctx.r3.u32);
        s_lastSchedR3.store(ctx.r3.u32, std::memory_order_release);
        s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel);
    }
    uint32_t v13520 = ReadBE32(ctx.r3.u32 + 13520);
    uint8_t v10432 = (uint8_t)(ReadBE32(ctx.r3.u32 + 10432) & 0xFF);
    KernelTraceHostOpF("HOST.82595FC8.pre 13520=%08X 10432=%02X", v13520, (unsigned)v10432);
    DumpEAWindow("82595FC8.r3", ctx.r3.u32);
    DumpEAWindow("82595FC8.r4", ctx.r4.u32);
    DumpEAWindow("82595FC8.r5", ctx.r5.u32);
    DumpSchedState("82595FC8", ctx.r3.u32);
    __imp__sub_82595FC8(ctx, base);
}

void MW05Shim_sub_825972B0(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_825972B0.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    if (ctx.r3.u32 >= 0x1000 && ctx.r3.u32 < PPC_MEMORY_SIZE) {
        MaybeLogSchedCapture(ctx.r3.u32);
        s_lastSchedR3.store(ctx.r3.u32, std::memory_order_release);
        s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel);
    }
    uint32_t v13520b = ReadBE32(ctx.r3.u32 + 13520);
    uint8_t v10432b = (uint8_t)(ReadBE32(ctx.r3.u32 + 10432) & 0xFF);
    KernelTraceHostOpF("HOST.825972B0.pre 13520=%08X 10432=%02X", v13520b, (unsigned)v10432b);

    // Seed syscmd payload pointer if missing (game expects this for PM4 emission)
    if (v13520b == 0) {
        const uint32_t sys_payload = 0x00140410u; // system command buffer payload start
        WriteBE32(ctx.r3.u32 + 13520, sys_payload);
        KernelTraceHostOpF("HOST.825972B0.seed 13520=%08X", sys_payload);
        v13520b = sys_payload;
    }

    // If allocator callback is null, install our host callback so builder can proceed
    uint32_t fp_ea = ReadBE32(ctx.r3.u32 + 13620);
    uint32_t cbctx = ReadBE32(ctx.r3.u32 + 13624);
    if (fp_ea == 0) {
        WriteBE32(ctx.r3.u32 + 13620, 0x82FF1000u);
        WriteBE32(ctx.r3.u32 + 13624, ctx.r3.u32);
        KernelTraceHostOpF("HOST.825972B0.install_alloc_cb fp=%08X ctx=%08X", 0x82FF1000u, ctx.r3.u32);
    }

    // Conservative ready-bit nudge: set bit0 at +0x1C if not set yet
    {
        uint32_t ready = ReadBE32(ctx.r3.u32 + 0x1C);
        if ((ready & 0x1u) == 0) {
            WriteBE32(ctx.r3.u32 + 0x1C, ready | 0x1u);
            KernelTraceHostOpF("HOST.825972B0.ready_flag %08X->%08X", ready, ready | 0x1u);
        }
    }

    // Keep dumps minimal; avoid heavy structure mutation here (XEX variant sensitive)
    DumpEAWindow("825972B0.r3", ctx.r3.u32);
    DumpSchedState("825972B0", ctx.r3.u32);
    __imp__sub_825972B0(ctx, base);
}

void MW05Shim_sub_825968B0(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_825968B0.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    if (ctx.r3.u32 >= 0x1000 && ctx.r3.u32 < PPC_MEMORY_SIZE) { MaybeLogSchedCapture(ctx.r3.u32); s_lastSchedR3.store(ctx.r3.u32, std::memory_order_release); s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel); }
    uint32_t fp_ea = ReadBE32(ctx.r3.u32 + 13620);
    uint32_t cbctx = ReadBE32(ctx.r3.u32 + 13624);
    KernelTraceHostOpF("HOST.825968B0.cb fp=%08X ctx=%08X", fp_ea, cbctx);
    uint32_t f10432w = ReadBE32(ctx.r3.u32 + 10432);
    uint8_t b10433 = (uint8_t)(f10432w & 0xFF);
    KernelTraceHostOpF("HOST.825968B0.flags10433=%02X", (unsigned)b10433);
    // If the allocator callback is NULL, optionally fake an allocation into the System Command Buffer payload
    static const bool s_fake_alloc = [](){ if (const char* v = std::getenv("MW05_FAKE_ALLOC_SYSBUF")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    if (s_fake_alloc && fp_ea == 0) {
        // Known default guest EA for syscmd buffer base from our bridge: 0x00140400
        // Return a pointer just past the 16-byte header we seed (payload begins at +0x10)
        const uint32_t sys_base    = 0x00140400u;
        const uint32_t sys_payload = sys_base + 0x10u;
        const uint32_t sys_end     = sys_base + 0x10000u; // 64 KiB
        // Seed basic allocator state so subsequent code can advance pointers
        WriteBE32(ctx.r3.u32 + 14012, sys_payload); // current write ptr
        WriteBE32(ctx.r3.u32 + 14016, sys_payload); // running end ptr


        WriteBE32(ctx.r3.u32 + 14020, sys_end);     // buffer end
        // Clear forbid bit (top bit of 10433) if set, to avoid early exits
        uint32_t f10432w2 = ReadBE32(ctx.r3.u32 + 10432);
        uint8_t b10433_2 = (uint8_t)(f10432w2 & 0xFF);
        if (b10433_2 & 0x80) {
            WriteBE8(ctx.r3.u32 + 10433, (uint8_t)(b10433_2 & ~0x80));
        }
        KernelTraceHostOpF("HOST.825968B0.fake ret=%08X", sys_payload);
        ctx.r3.u32 = sys_payload;
        return;
    }
    __imp__sub_825968B0(ctx, base);
    KernelTraceHostOpF("HOST.825968B0.ret r3=%08X", ctx.r3.u32);
}

void MW05Shim_sub_82596E40(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_82596E40.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    if (ctx.r3.u32 >= 0x1000 && ctx.r3.u32 < PPC_MEMORY_SIZE) { MaybeLogSchedCapture(ctx.r3.u32); s_lastSchedR3.store(ctx.r3.u32, std::memory_order_release); s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel); }
    uint32_t v13520c = ReadBE32(ctx.r3.u32 + 13520);
    uint8_t v10432c = (uint8_t)(ReadBE32(ctx.r3.u32 + 10432) & 0xFF);
    KernelTraceHostOpF("HOST.82596E40.pre 13520=%08X 10432=%02X", v13520c, (unsigned)v10432c);
    __imp__sub_82596E40(ctx, base);
}
void MW05Shim_sub_82597650(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_82597650.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    if (ctx.r3.u32 >= 0x1000 && ctx.r3.u32 < PPC_MEMORY_SIZE) {
        MaybeLogSchedCapture(ctx.r3.u32);
        s_lastSchedR3.store(ctx.r3.u32, std::memory_order_release);
        s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel);
        // Clear forbid bits like in 825972B0 shim
        uint32_t f10432 = ReadBE32(ctx.r3.u32 + 10432);
        uint8_t b10433 = (uint8_t)(f10432 & 0xFF);
        uint8_t nb = (uint8_t)(b10433 & ~0x84u);
        if (nb != b10433) {
            uint32_t nw = (f10432 & 0xFFFFFF00u) | nb;
            WriteBE32(ctx.r3.u32 + 10432, nw);
            KernelTraceHostOpF("HOST.82597650.flags10433 %02X->%02X", (unsigned)b10433, (unsigned)nb);
        }
        // Seed allocator state if missing
        uint32_t a_wptr = ReadBE32(ctx.r3.u32 + 14012);
        uint32_t a_rend = ReadBE32(ctx.r3.u32 + 14016);
        uint32_t a_end  = ReadBE32(ctx.r3.u32 + 14020);
        if (a_wptr == 0 || a_end == 0) {
            uint32_t sysbufBase = 0x00140400u;
            uint32_t sysbufSize = 0x00010000u; // 64 KB
            WriteBE32(ctx.r3.u32 + 14012, sysbufBase + 0x10u);
            WriteBE32(ctx.r3.u32 + 14016, sysbufBase + sysbufSize);
            WriteBE32(ctx.r3.u32 + 14020, sysbufBase + sysbufSize);
            KernelTraceHostOpF("HOST.82597650.seed alloc w=%08X re=%08X end=%08X", sysbufBase+0x10, sysbufBase+sysbufSize, sysbufBase+sysbufSize);
        }
        DumpSchedState("82597650.pre", ctx.r3.u32);
    }
    __imp__sub_82597650(ctx, base);
}

void MW05Shim_sub_825976D8(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_825976D8.lr=%08llX r3=%08X r4=%08X r5=%08X", (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    if (ctx.r3.u32 >= 0x1000 && ctx.r3.u32 < PPC_MEMORY_SIZE) {
        MaybeLogSchedCapture(ctx.r3.u32);
        s_lastSchedR3.store(ctx.r3.u32, std::memory_order_release);
        s_schedR3Seen.fetch_add(1, std::memory_order_acq_rel);
        uint32_t f10432 = ReadBE32(ctx.r3.u32 + 10432);
        uint8_t b10433 = (uint8_t)(f10432 & 0xFF);
        uint8_t nb = (uint8_t)(b10433 & ~0x84u);
        if (nb != b10433) {
            uint32_t nw = (f10432 & 0xFFFFFF00u) | nb;
            WriteBE32(ctx.r3.u32 + 10432, nw);
            KernelTraceHostOpF("HOST.825976D8.flags10433 %02X->%02X", (unsigned)b10433, (unsigned)nb);
        }
        // Ensure allocator fields look valid
        uint32_t a_wptr = ReadBE32(ctx.r3.u32 + 14012);
        if (a_wptr == 0) {
            uint32_t sysbufBase = 0x00140400u;
            WriteBE32(ctx.r3.u32 + 14012, sysbufBase + 0x10u);
            WriteBE32(ctx.r3.u32 + 14016, sysbufBase + 0x00010000u);
            WriteBE32(ctx.r3.u32 + 14020, sysbufBase + 0x00010000u);
            KernelTraceHostOpF("HOST.825976D8.seed alloc w=%08X", sysbufBase+0x10);
        }
        DumpSchedState("825976D8.pre", ctx.r3.u32);
    }
    __imp__sub_825976D8(ctx, base);
}

void MW05Shim_sub_825A54F0(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_825A54F0.lr=%08llX r3=%08X r4=%08X r5=%08X",
                       (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    // Ensure r3 looks like a pointer; if not, seed from last-sched
    if (!(ctx.r3.u32 >= 0x1000 && ctx.r3.u32 < PPC_MEMORY_SIZE)) {
        uint32_t seed = s_lastSchedR3.load(std::memory_order_acquire);
        if (seed >= 0x1000 && seed < PPC_MEMORY_SIZE) {
            KernelTraceHostOpF("HOST.sub_825A54F0.force r3=%08X", seed);
            ctx.r3.u32 = seed;
        }
    }
    // Record scheduler sighting
    Mw05Trace_ConsiderSchedR3(ctx.r3.u32);
    // Nudge a plausible scheduler-flag bit if it appears unset to unlock PM4 path
    // Heuristic: flags at +0x1C, set bit0 if zero
    uint32_t flags_ea = ctx.r3.u32 + 0x1C;
    if (flags_ea >= 0x1000 && flags_ea + 4 <= PPC_MEMORY_SIZE) {
        if (auto* pf = reinterpret_cast<uint32_t*>(g_memory.Translate(flags_ea))) {
        #if defined(_MSC_VER)
            uint32_t le = _byteswap_ulong(*pf);
        #else
            uint32_t le = __builtin_bswap32(*pf);
        #endif
            if ((le & 0x1u) == 0u) {
                uint32_t nle = le | 0x1u;
            #if defined(_MSC_VER)
                *pf = _byteswap_ulong(nle);
            #else
                *pf = __builtin_bswap32(nle);
            #endif
                KernelTraceHostOpF("HOST.sub_825A54F0.flags.bump ea=%08X %08X->%08X", flags_ea, le, nle);
            }
        }
    }
    DumpEAWindow("825A54F0.r3.pre", ctx.r3.u32);
    DumpEAWindow("825A54F0.r3+40.pre", ctx.r3.u32 ? ctx.r3.u32 + 0x40 : 0);
    DumpSchedState("825A54F0.pre", ctx.r3.u32);
    __imp__sub_825A54F0(ctx, base);
    DumpEAWindow("825A54F0.r3.post", ctx.r3.u32);
    DumpEAWindow("825A54F0.r3+40.post", ctx.r3.u32 ? ctx.r3.u32 + 0x40 : 0);
    DumpSchedState("825A54F0.post", ctx.r3.u32);
    // Optionally attempt a PM4 build pass right after inner present-manager, within same guest context
    static const bool s_try_pm4_after_inner = [](){ if (const char* v = std::getenv("MW05_INNER_TRY_PM4")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    static const bool s_try_pm4_deep = [](){ if (const char* v = std::getenv("MW05_INNER_TRY_PM4_DEEP")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    if (s_try_pm4_after_inner) {
        uint32_t saved_r3 = ctx.r3.u32;
        // Force r3 to the last known scheduler context before calling the builder
        uint32_t seed = s_lastSchedR3.load(std::memory_order_acquire);
        if (seed >= 0x1000 && seed < PPC_MEMORY_SIZE) {
            ctx.r3.u32 = seed;
        }
        KernelTraceHostOpF("HOST.sub_825A54F0.post.try_825972B0 r3=%08X", ctx.r3.u32);
        // Call the PM4 builder through our shim so gating clears and fake alloc run
        MW05Shim_sub_825972B0(ctx, base);
        if (s_try_pm4_deep) {
            KernelTraceHostOpF("HOST.sub_825A54F0.post.try_deep r3=%08X", ctx.r3.u32);
            // Route through our deep shims to keep gating clears and allocator seeding
            MW05Shim_sub_82597650(ctx, base);
            MW05Shim_sub_825976D8(ctx, base);
            // Additional allocator/callback prep + gating clear
            MW05Shim_sub_825968B0(ctx, base);
            MW05Shim_sub_82596E40(ctx, base);
        }
        ctx.r3.u32 = saved_r3;
    }
}

// Main loop caller shim observed in logs (lr=82441D4C around TitleState calls)
void MW05Shim_sub_82441CF0(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_82441CF0.lr=%08llX r3=%08X r4=%08X r5=%08X",
                       (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    // Heuristic: r5 looks like a small control block observed at TitleState; capture as scheduler seed
    Mw05Trace_ConsiderSchedR3(ctx.r5.u32);
    DumpEAWindow("82441CF0.r5", ctx.r5.u32);
    DumpSchedState("82441CF0", ctx.r5.u32);

    static const bool s_loop_try_pm4_pre = [](){ if (const char* v = std::getenv("MW05_LOOP_TRY_PM4_PRE")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    static const bool s_loop_try_pm4 = [](){ if (const char* v = std::getenv("MW05_LOOP_TRY_PM4")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    static const bool s_loop_try_pm4_deep = [](){ if (const char* v = std::getenv("MW05_LOOP_TRY_PM4_DEEP")) return !(v[0]=='0' && v[1]=='\0'); return false; }();

    if (s_loop_try_pm4_pre && ctx.r5.u32 >= 0x1000 && ctx.r5.u32 < PPC_MEMORY_SIZE) {
        uint32_t saved_r3 = ctx.r3.u32;
        ctx.r3.u32 = ctx.r5.u32;
        KernelTraceHostOpF("HOST.sub_82441CF0.pre.try_825972B0 r3=%08X (from r5)", ctx.r3.u32);
        MW05Shim_sub_825972B0(ctx, base);
        if (s_loop_try_pm4_deep) {
            KernelTraceHostOpF("HOST.sub_82441CF0.pre.try_deep r3=%08X", ctx.r3.u32);
            MW05Shim_sub_82597650(ctx, base);
            MW05Shim_sub_825976D8(ctx, base);
            // Additional allocator/callback prep + gating clear
            MW05Shim_sub_825968B0(ctx, base);
            MW05Shim_sub_82596E40(ctx, base);
        }
        ctx.r3.u32 = saved_r3;
    }

    __imp__sub_82441CF0(ctx, base);

    if (s_loop_try_pm4 && ctx.r5.u32 >= 0x1000 && ctx.r5.u32 < PPC_MEMORY_SIZE) {
        uint32_t saved_r3 = ctx.r3.u32;
        ctx.r3.u32 = ctx.r5.u32;
        KernelTraceHostOpF("HOST.sub_82441CF0.post.try_825972B0 r3=%08X (from r5)", ctx.r3.u32);
        MW05Shim_sub_825972B0(ctx, base);
        if (s_loop_try_pm4_deep) {
            KernelTraceHostOpF("HOST.sub_82441CF0.post.try_deep r3=%08X", ctx.r3.u32);
            MW05Shim_sub_82597650(ctx, base);
            MW05Shim_sub_825976D8(ctx, base);
            // Additional allocator/callback prep + gating clear
            MW05Shim_sub_825968B0(ctx, base);
            MW05Shim_sub_82596E40(ctx, base);
        }
        ctx.r3.u32 = saved_r3;
    }
}


// Present wrapper shim: log + dump scheduler block, then forward
void MW05Shim_sub_82598A20(PPCContext& ctx, uint8_t* base) {
    KernelTraceHostOpF("sub_82598A20.lr=%08llX r3=%08X r4=%08X r5=%08X",
                       (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32);
    // Record and dump scheduler/context state if present
    Mw05Trace_ConsiderSchedR3(ctx.r3.u32);
    DumpEAWindow("82598A20.r3", ctx.r3.u32);
    DumpSchedState("82598A20", ctx.r3.u32);
    __imp__sub_82598A20(ctx, base);
    // Optionally force a PM4 build attempt after present returns, using last known scheduler
    static const bool s_pres_try_pm4 = [](){ if (const char* v = std::getenv("MW05_PRES_TRY_PM4")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    static const bool s_pres_try_pm4_deep = [](){ if (const char* v = std::getenv("MW05_PRES_TRY_PM4_DEEP")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    if (s_pres_try_pm4) {
        uint32_t saved_r3 = ctx.r3.u32;
        uint32_t seed = s_lastSchedR3.load(std::memory_order_acquire);
        if (seed >= 0x1000 && seed < PPC_MEMORY_SIZE) {
            ctx.r3.u32 = seed;
        }
        KernelTraceHostOpF("HOST.sub_82598A20.post.try_825972B0 r3=%08X", ctx.r3.u32);
        MW05Shim_sub_825972B0(ctx, base);
        if (s_pres_try_pm4_deep) {
            KernelTraceHostOpF("HOST.sub_82598A20.post.try_deep r3=%08X", ctx.r3.u32);
            MW05Shim_sub_82597650(ctx, base);
            MW05Shim_sub_825976D8(ctx, base);
            // Additional allocator/callback prep + gating clear
            MW05Shim_sub_825968B0(ctx, base);
            MW05Shim_sub_82596E40(ctx, base);
        }
        ctx.r3.u32 = saved_r3;
    }

}

SHIM(sub_825A6DF0)
SHIM(sub_825A65A8)
