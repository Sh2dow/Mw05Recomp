#include "stdafx.h"
#include <atomic>
#include <cstdint>
#include "kernel/trace.h"
#include "kernel/memory.h"
#include "mw05_micro_interpreter.h"

// Forward for the existing debug clear used to force visible frames
extern "C" void Mw05DebugKickClear();

// From pm4_parser.cpp
void PM4_ScanLinear(uint32_t addr, uint32_t bytes);

// Simple guard to avoid spamming clears multiple times per tight loop
static std::atomic<uint32_t> s_clearCounter{0};

static inline uint32_t be32_to_le(uint32_t v) {
#if defined(_MSC_VER)
    return _byteswap_ulong(v);
#else
    return __builtin_bswap32(v);
#endif
}

extern "C" void Mw05InterpretMicroIB(uint32_t ib_addr, uint32_t ib_size)
{
    KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.Interpret start ea=%08X size=%u", ib_addr, ib_size);

    // Heuristic: look at dwords at +0x00 and +0x20.. to find a pointer and a size and try scanning as PM4.
    uint32_t* p = reinterpret_cast<uint32_t*>(g_memory.Translate(ib_addr));
    if (p) {
        uint32_t d[16]{};
        for (int i = 0; i < 16; ++i) d[i] = be32_to_le(p[i]);
        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.dump0 d0=%08X d1=%08X d2=%08X d3=%08X d4=%08X d5=%08X d6=%08X d7=%08X", d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]);
        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.dump1 d8=%08X d9=%08X d10=%08X d11=%08X d12=%08X d13=%08X d14=%08X d15=%08X", d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);

        // Verify magic 'MW05' (BE) = 0x3530574D in LE after swap
        if (d[0] == 0x3530574Du) {
            uint32_t ptr = d[8];   // at +0x20
            int32_t  rel = static_cast<int32_t>(d[9]);   // at +0x24 (often small signed)
            uint32_t sz  = d[10];  // at +0x28
            KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.follow ptr=%08X off=%d sz=%u", ptr, rel, sz);

            // Prefer absolute pointer when it looks like syscmd region
            if ((ptr & 0xFFFF0000u) == 0x00140000u && sz > 0 && sz <= 0x8000) {
                PM4_ScanLinear(ptr, sz);
                // Also scan the ring buffer for any standard PM4 draws the title may have emitted
                const uint32_t rb_base = Mw05GetRingBaseEA();
                const uint32_t rb_size = Mw05GetRingSizeBytes();
                if (rb_base && rb_size) {
                    const uint32_t rb_scan = (rb_size > 0x8000u) ? 0x8000u : rb_size;
                    KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.scan_ring base=%08X size=%u", rb_base, rb_scan);
                    PM4_ScanLinear(rb_base, rb_scan);
                }
                return;
            }
            // Try relative pointer if absolute failed the range check
            uint32_t ptr2 = static_cast<uint32_t>(static_cast<int32_t>(ptr) + rel);
            if ((ptr2 & 0xFFFF0000u) == 0x00140000u && sz > 0 && sz <= 0x8000) {
                PM4_ScanLinear(ptr2, sz);
                const uint32_t rb_base = Mw05GetRingBaseEA();
                const uint32_t rb_size = Mw05GetRingSizeBytes();
                if (rb_base && rb_size) {
                    const uint32_t rb_scan = (rb_size > 0x8000u) ? 0x8000u : rb_size;
                    KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.scan_ring base=%08X size=%u", rb_base, rb_scan);
                    PM4_ScanLinear(rb_base, rb_scan);
                }
                return;
            }

            // As a last resort, scan a small neighborhood around the IB for PM4 packets
            uint32_t start = (ib_addr >= 0x80u) ? (ib_addr - 0x80u) : ib_addr;
            uint32_t end = ib_addr + 0x200u;
            if (end > 0x00150000u) end = 0x00150000u;
            if (end > start) {
                PM4_ScanLinear(start, end - start);
                const uint32_t rb_base = Mw05GetRingBaseEA();
                const uint32_t rb_size = Mw05GetRingSizeBytes();
                if (rb_base && rb_size) {
                    const uint32_t rb_scan = (rb_size > 0x8000u) ? 0x8000u : rb_size;
                    KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.scan_ring base=%08X size=%u", rb_base, rb_scan);
                    PM4_ScanLinear(rb_base, rb_scan);
                }
                return;
            }
        }
    }

}

