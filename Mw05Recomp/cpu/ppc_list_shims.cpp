// MW05 list shims: safely drain intrusive LIST_ENTRY queues used by the guest.
// These override weak recompiled functions. When MW05_LIST_SHIMS=1, we perform
// a guarded drain with basic invariants; otherwise we tail-call the original.

#include <cpu/ppc_context.h>
#include <kernel/trace.h>
#include <cstdlib>
#include <cstdint>
#include <cstddef>

// ---- host fallbacks if your emulator helpers are missing ----
#ifndef HAVE_READ_GUEST_HELPERS
  // Define this macro in your build if you already have read_guest_i64/host_sleep.
  static inline int64_t read_guest_i64(const void* p) {
      // Fallback assumes guest pointer is directly addressable (dev-only).
      return p ? *reinterpret_cast<const int64_t*>(p) : 0;
  }
static inline void host_sleep(int ms) {
      if (ms <= 0) std::this_thread::yield();
      else std::this_thread::sleep_for(std::chrono::milliseconds(ms));
  }
#endif

extern "C" {
    // originals from the recompiled lib
    void __imp__sub_820E25C0(PPCContext& ctx, uint8_t* base); // IsListEmpty(head) -> r3=1/0
    void __imp__sub_8215CDA0(PPCContext& ctx, uint8_t* base); // process/free node
    void __imp__sub_8215FEF0(PPCContext& ctx, uint8_t* base);
}



// Seed helper from GPU trace to capture candidate scheduler/context pointer safely (no logging)
extern "C" void Mw05Trace_SeedSchedR3_NoLog(uint32_t r3);

// simple feature gate (mirrors mw05_boot_shims style)
static inline bool Mw05ListShimsEnabled() {
    if (const char* v = std::getenv("MW05_LIST_SHIMS"))
        return !(v[0] == '0' && v[1] == '\0');
    return false;
}

// If you want a tiny-yield helper:
inline void HostSleepTiny() {
    // use whichever you prefer in your project
    host_sleep(0);
    // or: std::this_thread::yield();
}

// helper (place near the top of the file with other helpers)
inline bool GuestOffsetInRange(uint32_t off, size_t bytes = 1) {
    if (off == 0) return false;
    if (off < 4096) return false; // guard page
    return (size_t)off + bytes <= PPC_MEMORY_SIZE;
}

// Fast, non-recursive empty check: head->Flink == head
static inline bool ListIsEmpty(uint8_t* base, uint32_t headEA) {
    const uint32_t flink = PPC_LOAD_U32(headEA + 0);
    return flink == headEA;
}

// Replacement for sub_8215FEF0 (the list-drain routine)
PPC_FUNC_IMPL(__imp__sub_8215FEF0);
PPC_FUNC(sub_8215FEF0)
{
    KernelTraceHostOp("HOST.ListShim.Enter");
    if (!Mw05ListShimsEnabled()) 
    { 
        __imp__sub_8215FEF0(ctx, base); 
        return; 
    }

    const uint32_t head = ctx.r3.u32;

    auto is_empty = [&]() -> bool {
        auto tmp = ctx; tmp.r3.u32 = head;
        __imp__sub_820E25C0(tmp, base);              // do NOT use the recompiled name here
        return tmp.r3.u32 != 0;                      // 0 == non-empty in the original logic
    };

    if (!GuestOffsetInRange(head, 8)) {              // FLINK/BLINK exist?
        KernelTraceHostOp("HOST.ListShim.BadHead");
        return;
    }

    if (is_empty()) {
        KernelTraceHostOp("HOST.ListShim.Empty");
        return;
    }

    int guard = 200000;      // hard cap
    int traced = 0;
    while (guard-- > 0) {
        const uint32_t entry = PPC_LOAD_U32(head + 0);   // head->Flink
        if (!GuestOffsetInRange(entry, 8)) {
            KernelTraceHostOp("HOST.ListShim.BadEntry");
            break;
        }
        const uint32_t next  = PPC_LOAD_U32(entry + 0);  // entry->Flink
        const uint32_t prev  = PPC_LOAD_U32(entry + 4);  // entry->Blink

        // Basic invariants
        if (!GuestOffsetInRange(prev, 8) || !GuestOffsetInRange(next, 8) ||
            PPC_LOAD_U32(prev + 0) != entry || PPC_LOAD_U32(next + 4) != entry) {
            KernelTraceHostOp("HOST.ListShim.Corruption");
            break;
        }

        // Unlink
        PPC_STORE_U32(next + 4, prev);
        PPC_STORE_U32(prev + 0, next);

        // Process node
        auto call = ctx; call.r3.u32 = entry;
        __imp__sub_8215CDA0(call, base);

        if ((++traced & 0x3FFF) == 0) KernelTraceHostOp("HOST.ListShim.Progress");

        if (is_empty()) {
            KernelTraceHostOp("HOST.ListShim.Drained");
            break;
        }
    }
    if (guard <= 0) KernelTraceHostOp("HOST.ListShim.GuardTrip");
}


// Replacement for sub_820E25C0 (IsListEmpty)
// Keep a minimal, side-effect-free implementation; otherwise tail-call original.
PPC_FUNC_IMPL(__imp__sub_820E25C0);
PPC_FUNC(sub_820E25C0)
{
    KernelTraceHostOp("HOST.sub_820E25C0");

    // Opportunistically seed scheduler/context pointer candidate (no logging to avoid early crashes)
    Mw05Trace_SeedSchedR3_NoLog(ctx.r3.u32);

    if (!Mw05ListShimsEnabled()) {
        __imp__sub_820E25C0(ctx, base);
        return;
    }

    const uint32_t head  = ctx.r3.u32;
    const uint32_t flink = PPC_LOAD_U32(head + 0);
    ctx.cr6.compare<uint32_t>(flink, head, ctx.xer);
    ctx.r3.s64 = ctx.cr6.eq ? 1 : 0;
}
