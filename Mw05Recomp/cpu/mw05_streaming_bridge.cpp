// Host bridge for MW05 resource streaming/fast-file queues.
//
// This provides a first-pass implementation similar in spirit to the
// Unleashed Recompiled approach: detect when the loader drops a sentinel
// callback (0x0A000000) into a scheduler block and ensure the queue entry
// is completed so the dispatcher advances. As we learn the job layout, this
// can be extended to schedule real host I/O and post completions back.

#include <cpu/ppc_context.h>
#include <kernel/memory.h>
#include <kernel/trace.h>
#include <ppc/ppc_config.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cctype>

// Global watch slot (shared with trace helpers)
extern std::atomic<uint32_t> g_watchEA;

namespace {
    inline bool GuestRangeValid(uint32_t ea, size_t bytes = 4) {
        if (!ea) return false;
        const uint64_t end = static_cast<uint64_t>(ea) + static_cast<uint64_t>(bytes);
        return end <= PPC_MEMORY_SIZE;
    }

    // Heuristic: loader/asset system dispatcher lives around 0x8215BE00..0x8215C3FF
    inline bool LRInLoaderDispatcher(uint64_t lr) {
        return lr >= 0x8215BE00ull && lr < 0x8215C400ull;
    }

    inline bool ReadEnvBool(const char* name, bool defValue=false) {
        const char* v = std::getenv(name);
        if (!v) return defValue;
        if (v[0]=='0' && v[1]=='\0') return false;
        auto eq_ci = [](const char* a, const char* b){
            for (; *a && *b; ++a, ++b) if (std::tolower(*a) != std::tolower(*b)) return false;
            return *a == 0 && *b == 0; };
        if (eq_ci(v, "false") || eq_ci(v, "off") || eq_ci(v, "no")) return false;
        return true;
    }

    // Best-effort clear of a scheduler block at blockEA (five u32 words)
    inline void ClearSchedulerBlock(uint32_t blockEA) {
        if (!GuestRangeValid(blockEA, 20)) return;
        if (auto* p = static_cast<uint8_t*>(g_memory.Translate(blockEA))) {
            std::memset(p, 0, 20);
        }
    }
    inline uint32_t LoadU32_BE(uint32_t ea) {
        uint32_t v = 0; if (auto* p = static_cast<uint8_t*>(g_memory.Translate(ea))) { std::memcpy(&v, p, 4); }
#if defined(_MSC_VER)
        return _byteswap_ulong(v);
#else
        return __builtin_bswap32(v);
#endif
    }

    inline void DumpBlockSnapshot(uint32_t blockEA) {
        if (!GuestRangeValid(blockEA, 32) || !g_memory.Translate(blockEA)) {
            KernelTraceHostOpF("HOST.StreamBridge.block.bad ea=%08X", blockEA);
            return;
        }
        const uint32_t w0 = LoadU32_BE(blockEA + 0);
        const uint32_t w1 = LoadU32_BE(blockEA + 4);
        const uint32_t w2 = LoadU32_BE(blockEA + 8);
        const uint32_t w3 = LoadU32_BE(blockEA + 12);
        const uint32_t w4 = LoadU32_BE(blockEA + 16);
        KernelTraceHostOpF("HOST.StreamBridge.block ea=%08X w0=%08X w1=%08X w2=%08X w3=%08X w4=%08X",
                           blockEA, w0, w1, w2, w3, w4);

        auto probe_ptr = [&](const char* tag, uint32_t ea){
            if (!GuestRangeValid(ea, 64)) return;
            if (auto* s = static_cast<const uint8_t*>(g_memory.Translate(ea))) {
                // dump first 16 bytes and any ascii
                char ascii[64]{}; size_t j=0; for (; j<63 && s[j]; ++j) { if (s[j] < 0x20 || s[j] > 0x7E) break; ascii[j] = char(s[j]); }
                ascii[j] = 0;
                if (j >= 4) KernelTraceHostOpF("HOST.StreamBridge.%s.str ea=%08X '%s'", tag, ea, ascii);
                uint32_t d0=0,d1=0,d2=0,d3=0; std::memcpy(&d0,s+0,4); std::memcpy(&d1,s+4,4); std::memcpy(&d2,s+8,4); std::memcpy(&d3,s+12,4);
#if defined(_MSC_VER)
                d0=_byteswap_ulong(d0); d1=_byteswap_ulong(d1); d2=_byteswap_ulong(d2); d3=_byteswap_ulong(d3);
#else
                d0=__builtin_bswap32(d0); d1=__builtin_bswap32(d1); d2=__builtin_bswap32(d2); d3=__builtin_bswap32(d3);
#endif
                KernelTraceHostOpF("HOST.StreamBridge.%s.words %08X %08X %08X %08X", tag, d0,d1,d2,d3);
            }
        };

        if (w0) probe_ptr("w0", w0);
        if (w1) probe_ptr("w1", w1);
        if (w2) probe_ptr("w2", w2);
        if (w3) probe_ptr("w3", w3);
        if (w4) probe_ptr("w4", w4);

        // Deep scan of w0/w1 regions for pointer-like fields that may be strings/paths
        auto deep_scan = [&](const char* tag, uint32_t baseEA){
            if (!GuestRangeValid(baseEA, 0x100)) return;
            auto* p = static_cast<const uint8_t*>(g_memory.Translate(baseEA));
            if (!p) return;
            int hits = 0;
            for (int i = 0; i < 0x80 && hits < 6; i += 4) {
                uint32_t v=0; std::memcpy(&v, p + i, 4);
#if defined(_MSC_VER)
                const uint32_t be = _byteswap_ulong(v);
#else
                const uint32_t be = __builtin_bswap32(v);
#endif
                if (!GuestRangeValid(be, 128)) continue;
                const char* sp = reinterpret_cast<const char*>(g_memory.Translate(be));
                if (!sp) continue;
                // ASCII probe
                bool ok=false; char buf[128]{}; size_t k=0;
                for (; k<sizeof(buf)-1 && sp[k]; ++k){ char c=sp[k]; if (c<0x20||c>0x7E) { ok=false; break; } buf[k]=c; ok=true; }
                buf[k]=0;
                if (ok && k>=4) {
                    KernelTraceHostOpF("HOST.StreamBridge.%s.deep+%X -> %08X '%s'", tag, i, be, buf);
                    ++hits; continue;
                }
                // UTF-16LE narrow probe
                const uint16_t* w = reinterpret_cast<const uint16_t*>(sp);
                char a[128]{}; size_t n=0; bool ok16=false;
                for (; n<63 && w[n]; ++n){ uint16_t ch=w[n]; if (ch<0x20||ch>0x7E){ ok16=false; break; } a[n]=char(ch); ok16=true; }
                a[n]=0;
                if (ok16 && n>=4) {
                    KernelTraceHostOpF("HOST.StreamBridge.%s.deep16+%X -> %08X '%s'", tag, i, be, a);
                    ++hits; continue;
                }
            }
        };

        if (w0) deep_scan("w0", w0);
        if (w1) deep_scan("w1", w1);

        // Follow first pointer-sized fields in w0/w1 as candidates
        if (w0 && GuestRangeValid(w0, 4)) {
            uint32_t p0 = LoadU32_BE(w0 + 0);
            if (GuestRangeValid(p0, 16) && g_memory.Translate(p0)) {
                KernelTraceHostOpF("HOST.StreamBridge.w0.ptr0=%08X", p0);
                probe_ptr("w0.ptr0", p0);
                deep_scan("w0.ptr0", p0);
            }
        }
        if (w1 && GuestRangeValid(w1, 8)) {
            uint32_t p1_1 = LoadU32_BE(w1 + 4);
            if (GuestRangeValid(p1_1, 16) && g_memory.Translate(p1_1)) {
                KernelTraceHostOpF("HOST.StreamBridge.w1.ptr1=%08X", p1_1);
                probe_ptr("w1.ptr1", p1_1);
                deep_scan("w1.ptr1", p1_1);
            }
        }
    }
}

// Called by watched store helpers when a 0x0A000000 sentinel is about to be
// written to a slot (typically [block+0x10]). Return true if handled and the
// store should be suppressed, false to let the write proceed normally.
extern "C" bool Mw05HandleSchedulerSentinel(uint8_t* base, uint32_t slotEA, uint64_t lr)
{
    // Feature gate (default ON): set MW05_STREAM_BRIDGE=0 to disable.
    static const bool s_enabled = ReadEnvBool("MW05_STREAM_BRIDGE", true);
    if (!s_enabled) return false;

    // Only claim loader/asset dispatcher sentinels here; kernel fast-delay
    // watchdogs are handled in dedicated shims.
    if (!LRInLoaderDispatcher(lr)) {
        return false;
    }

    // Expect the slot to be [block+0x10]. Guard for underflow.
    if (slotEA < 16) {
        KernelTraceHostOpF("HOST.StreamBridge.slot_oor ea=%08X lr=%08llX", slotEA, (unsigned long long)lr);
        return false;
    }

    const uint32_t blockEA = slotEA - 16u;
    if (!GuestRangeValid(blockEA, 20) || g_memory.Translate(blockEA) == nullptr) {
        KernelTraceHostOpF("HOST.StreamBridge.bad_block ea=%08X lr=%08llX", blockEA, (unsigned long long)lr);
        return false;
    }

    // For now, consume the placeholder and mark the block as complete so the
    // loader pump advances. This mimics the hardware path where host code
    // fills in a valid callback and posts a completion; we synthesize the
    // completion by clearing the block immediately.
    KernelTraceHostOpF("HOST.StreamBridge.consume block=%08X slot=%08X lr=%08llX", blockEA, slotEA, (unsigned long long)lr);

    // Always dump a minimal snapshot so we can fingerprint the job layout.
    DumpBlockSnapshot(blockEA);

    // Arm watch for the slot to attribute any follow-up writes.
    if (g_watchEA.load(std::memory_order_relaxed) != slotEA) {
        g_watchEA.store(slotEA, std::memory_order_relaxed);
        KernelTraceHostOpF("HOST.StreamBridge.watch arm=%08X", slotEA);
    }

    // Clear the entire scheduler block so the producer sees a completed entry.
    ClearSchedulerBlock(blockEA);

    // Store handled: suppress the sentinel write.
    return true;
}
