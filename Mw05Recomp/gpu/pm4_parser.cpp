// PM4 packet parser for MW05 ring buffer commands
// This intercepts ring buffer writes and logs PM4 draw commands

#include <kernel/memory.h>
#include <kernel/trace.h>
#include <cstdint>
#include <atomic>
#include <cstdlib>

extern "C" void Mw05RunHostDefaultVdIsrNudge(const char* tag);

extern "C" void Mw05DebugKickClear();
extern "C" void Mw05InterpretMicroIB(uint32_t ib_addr, uint32_t ib_size);

// Forward decls for helpers implemented later in this file
void PM4_DumpOpcodeHistogram();

// PM4 packet types (Xbox 360 GPU)
enum PM4Type {
    PM4_TYPE0 = 0,  // Register write
    PM4_TYPE1 = 1,  // Reserved
    PM4_TYPE2 = 2,  // Reserved
    PM4_TYPE3 = 3   // Command packet
};

// PM4 Type-3 opcodes (common draw commands)
enum PM4Opcode {
    PM4_ME_INIT = 0x48,
    PM4_NOP = 0x10,
    PM4_INDIRECT_BUFFER = 0x3F,
    PM4_WAIT_REG_MEM = 0x3C,
    PM4_REG_RMW = 0x21,
    PM4_COND_WRITE = 0x45,
    PM4_EVENT_WRITE = 0x46,
    PM4_EVENT_WRITE_SHD = 0x58,
    PM4_EVENT_WRITE_CFL = 0x59,
    PM4_EVENT_WRITE_EXT = 0x5A,
    PM4_DRAW_INDX = 0x22,           // Draw indexed primitives
    PM4_DRAW_INDX_2 = 0x36,         // Draw indexed primitives (variant)
    PM4_VIZ_QUERY = 0x23,
    PM4_SET_STATE = 0x25,
    PM4_SET_CONSTANT = 0x2D,
    PM4_LOAD_ALU_CONSTANT = 0x2F,
    PM4_SET_SHADER_CONSTANTS = 0x32,
    PM4_IM_LOAD = 0x27,
    PM4_IM_LOAD_IMMEDIATE = 0x2B,
    PM4_INVALIDATE_STATE = 0x3B,
    PM4_SET_BIN_MASK = 0x50,
    PM4_SET_BIN_SELECT = 0x51,
};

// Ring buffer state
// Optional ring scratch instrumentation
static std::atomic<uint32_t> g_rbScratchPattern{0};
static std::atomic<bool>     g_rbScratchArmed{false};

static std::atomic<uint32_t> g_rbBase{0};
static std::atomic<uint32_t> g_rbSize{0};
static std::atomic<uint32_t> g_rbWritePtr{0};

// Statistics
// Histogram of observed TYPE3 opcodes (for discovery)
static std::atomic<uint64_t> g_opcodeCounts[128];
// Count packets by type to validate stream composition/alignment
static std::atomic<uint64_t> g_typeCounts[4]; // 0..3

static std::atomic<uint64_t> g_pm4DrawCount{0};
static std::atomic<uint64_t> g_pm4PacketCount{0};

static inline bool IsPM4TracingEnabled() {
    // Evaluate environment each time so launching scripts can control tracing reliably.
    // Enable if either MW05_PM4_TRACE or MW05_TRACE_KERNEL is set to a non-'0' value.
    if (const char* env = std::getenv("MW05_PM4_TRACE")) {
        if (*env && *env != '0') return true;
    }
    if (const char* kenv = std::getenv("MW05_TRACE_KERNEL")) {
        if (*kenv && *kenv != '0') return true;
    }
    return false;
}

static inline bool IsSnoopEnabled() {
    if (const char* v = std::getenv("MW05_PM4_SNOOP")) {
        if (*v && *v != '0') return true;
    }
    return false;
}

static void DumpHexWindow(uint32_t addr, uint32_t dwords) {
    if (!IsPM4TracingEnabled()) return;
    uint32_t* p = reinterpret_cast<uint32_t*>(g_memory.Translate(addr));
    if (!p) return;
    // Print up to 16 dwords per call to keep logs compact
    const uint32_t n = dwords > 16 ? 16 : dwords;
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t be = p[i];
    #if defined(_MSC_VER)
        uint32_t le = _byteswap_ulong(be);
    #else
        uint32_t le = __builtin_bswap32(be);
    #endif
        if (i == 0) {
            uint32_t header = le;
            uint32_t type = (header >> 30) & 0x3;
            uint32_t opcode = (header >> 8) & 0x7F;
            uint32_t count = (header >> 16) & 0x3FFF;
            KernelTraceHostOpF("HOST.PM4.Snoop %08X: %08X (type=%u opc=%02X cnt=%u)", addr + i * 4, le, type, opcode, count);
        } else {
            KernelTraceHostOpF("HOST.PM4.Snoop %08X: %08X", addr + i * 4, le);
        }
    }
}

void PM4_SetRingBuffer(uint32_t base, uint32_t size_log2) {
    g_rbBase.store(base, std::memory_order_release);
    const uint32_t size = (size_log2 < 32) ? (1u << size_log2) : 0;
    g_rbSize.store(size, std::memory_order_release);
    g_rbWritePtr.store(0, std::memory_order_release);

    if (IsPM4TracingEnabled()) {
        KernelTraceHostOpF("HOST.PM4.SetRingBuffer base=%08X size_log2=%u size=%08X",
                          base, size_log2, size);
    }

    // Optional: Arm ring scratch pattern to detect any guest writes even if they bypass
    // watched store shims. Controlled by MW05_PM4_ARM_RING_SCRATCH=1.
    static const bool s_arm_scratch = [](){
        if (const char* v = std::getenv("MW05_PM4_ARM_RING_SCRATCH"))
            return !(v[0]=='0' && v[1]=='\0');
        return false;
    }();
    if (s_arm_scratch && base && size) {
        uint32_t* p = reinterpret_cast<uint32_t*>(g_memory.Translate(base));
        if (p) {
            const uint32_t pat = 0xDEADBEEFu;
            g_rbScratchPattern.store(pat, std::memory_order_release);
            for (uint32_t off = 0; off < size; off += 4) {
            #if defined(_MSC_VER)
                p[off / 4] = _byteswap_ulong(pat);
            #else
                p[off / 4] = __builtin_bswap32(pat);
            #endif
            }
            g_rbScratchArmed.store(true, std::memory_order_release);
            KernelTraceHostOpF("HOST.PM4.RingScratch.armed base=%08X size=%u pattern=%08X", base, size, pat);
        }
    }
}

static uint32_t ParsePM4Packet(uint32_t addr);
static void     ParsePM4Indirect(uint32_t ib_addr, uint32_t ib_dword_count);

// Parse an indirect buffer pointed to by a PM4 packet (file-scope)
static void ParsePM4Indirect(uint32_t ib_addr, uint32_t ib_dword_count) {
    const uint32_t ib_size_bytes = ib_dword_count * 4u;
    uint32_t consumed = 0;
    uint32_t safety = 0;
    while (consumed + 4 <= ib_size_bytes && safety < 16384) {
        uint32_t pkt_addr = ib_addr + consumed;
        uint32_t pkt_size = ParsePM4Packet(pkt_addr);
        if (pkt_size == 0) { pkt_size = 4; }
        consumed += pkt_size;
        safety++;
    }
    if (IsPM4TracingEnabled()) {
        KernelTraceHostOpF("HOST.PM4.INDIRECT_BUFFER.end addr=%08X bytes=%u safety=%u draws=%llu",
                           ib_addr, ib_size_bytes, safety,
                           (unsigned long long)g_pm4DrawCount.load(std::memory_order_relaxed));
    }
}
// Scan a linear buffer of PM4 packets starting at addr for up to `bytes`
void PM4_ScanLinear(uint32_t addr, uint32_t bytes) {
    if (!addr || bytes == 0) return;
    KernelTraceHostOpF("HOST.PM4.ScanLinear.begin addr=%08X bytes=%u", addr, bytes);
    uint32_t consumed = 0;
    uint32_t safety = 0;
    const uint32_t maxScan = 32768; // cap to avoid runaway
    while (consumed + 4 <= bytes && safety < maxScan) {
        uint32_t pkt_addr = addr + consumed;
        uint32_t pkt_size = ParsePM4Packet(pkt_addr);
        if (pkt_size == 0) { pkt_size = 4; }
        consumed += pkt_size;
        safety++;
    }
    KernelTraceHostOpF("HOST.PM4.ScanLinear.end consumed=%u draws=%llu", consumed,
                       (unsigned long long)g_pm4DrawCount.load(std::memory_order_relaxed));
    // Also report packet type composition and opcode presence for linear scans
    {
        uint64_t t0 = g_typeCounts[0].load(std::memory_order_relaxed);
        uint64_t t1 = g_typeCounts[1].load(std::memory_order_relaxed);
        uint64_t t2 = g_typeCounts[2].load(std::memory_order_relaxed);
        uint64_t t3 = g_typeCounts[3].load(std::memory_order_relaxed);
        KernelTraceHostOpF("HOST.PM4.Types t0=%llu t1=%llu t2=%llu t3=%llu",
            (unsigned long long)t0, (unsigned long long)t1,
            (unsigned long long)t2, (unsigned long long)t3);
    }
    PM4_DumpOpcodeHistogram();
}


// Parse a single PM4 packet at the given address
static uint32_t ParsePM4Packet(uint32_t addr) {
    uint32_t* ptr = reinterpret_cast<uint32_t*>(g_memory.Translate(addr));
    if (!ptr) return 4;

static const bool s_pm4_le = [](){ if (const char* v = std::getenv("MW05_PM4_LE")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
    uint32_t header;
    if (s_pm4_le) {
        header = *ptr; // Treat commands as little-endian (no swap)
    } else {
    #if defined(_MSC_VER)
        header = _byteswap_ulong(*ptr);  // Big-endian -> host
    #else
        header = __builtin_bswap32(*ptr);  // Big-endian -> host
    #endif
    }
    uint32_t type = (header >> 30) & 0x3;

    g_pm4PacketCount.fetch_add(1, std::memory_order_relaxed);
    if (type < 4) g_typeCounts[type].fetch_add(1, std::memory_order_relaxed);

    if (type == PM4_TYPE3) {
        uint32_t opcode = (header >> 8) & 0x7F;
        uint32_t count = (header >> 16) & 0x3FFF;
        uint32_t size = (count + 2) * 4;  // +1 for header, +1 for count encoding
        if (opcode < 128) {
            g_opcodeCounts[opcode].fetch_add(1, std::memory_order_relaxed);
        }


        // Handle indirect buffers to discover nested draws
        if (opcode == PM4_INDIRECT_BUFFER && count >= 2) {
            uint32_t* params = ptr + 1;
            uint32_t p0 = __builtin_bswap32(params[0]);
            uint32_t p1 = __builtin_bswap32(params[1]);
            // Heuristic decode (R5xx IB): p0 = address, p1 lower 16 bits = dwords
            uint32_t ib_addr = p0 & ~0x3u;
            uint32_t ib_dwords = p1 & 0xFFFFu;
            if (IsPM4TracingEnabled()) {
                KernelTraceHostOpF("HOST.PM4.INDIRECT_BUFFER addr=%08X dwords=%u", ib_addr, ib_dwords);
            }
            if (ib_addr && ib_dwords) {
                ParsePM4Indirect(ib_addr, ib_dwords);
            }
            return size;
        }

        // Log draw commands
        if (opcode == PM4_DRAW_INDX || opcode == PM4_DRAW_INDX_2) {
            g_pm4DrawCount.fetch_add(1, std::memory_order_relaxed);

            if (IsPM4TracingEnabled()) {
                // Read draw parameters
                uint32_t* params = ptr + 1;
                uint32_t p0 = params[0] ? __builtin_bswap32(params[0]) : 0;

                uint32_t p1 = (count >= 1 && params[1]) ? __builtin_bswap32(params[1]) : 0;
                uint32_t p2 = (count >= 2 && params[2]) ? __builtin_bswap32(params[2]) : 0;

                KernelTraceHostOpF("HOST.PM4.DRAW_%s addr=%08X count=%u p0=%08X p1=%08X p2=%08X total_draws=%llu",
                                  (opcode == PM4_DRAW_INDX) ? "INDX" : "INDX_2",
                                  addr, count, p0, p1, p2,
                                  (unsigned long long)g_pm4DrawCount.load(std::memory_order_relaxed));
            }
        }
        // Heuristic: MW05 micro-IB wrapper observed as TYPE3 opc=0x04 followed by pattern
        //   0x81000001, 0xFFFAFEFD, <ea in 0x0014xxxx>, <signed>, <small size> ...
        // Try to recover an indirect buffer target from the next parameters and scan it.
        else if (opcode == 0x04) {
            uint32_t* params = ptr + 1;
            uint32_t beParams[8] = {};
            for (uint32_t i = 0; i < 8 && i < count; ++i) beParams[i] = __builtin_bswap32(params[i]);
            // Find a likely guest EA in 0x0014xxxx range, then a small positive size nearby
            uint32_t ib_addr = 0;
            uint32_t ib_size = 0;
            for (uint32_t i = 0; i < 8 && i < count; ++i) {
                uint32_t v = beParams[i];
                if ((v & 0xFFFF0000u) == 0x00140000u) {
                    ib_addr = v;
                    // Search up to next 4 params for a plausible size (<= 64 KiB)
                    for (uint32_t j = i + 1; j < i + 5 && j < 8 && j < count; ++j) {
                        uint32_t sz = beParams[j];
                        if (sz > 0 && sz <= 0x00010000u) { ib_size = sz; break; }
                    }
                    break;
                }
            }
            if (ib_addr && ib_size) {
                // If inline params match sentinel pattern, adjust address by signed dword offset
                for (uint32_t i = 0; i + 3 < 8 && i + 3 < count; ++i) {
                    if (beParams[i] == 0xFFFAFEFDu && (beParams[i+1] & 0xFFFF0000u) == 0x00140000u) {
                        int32_t off = (int32_t)beParams[i+2];
                        uint32_t adj = beParams[i+1] + (uint32_t)(off * 4);
                        if ((adj & 0xFFFF0000u) == 0x00140000u) {
                            ib_addr = adj;
                        }
                        break;
                    }
                }
                if (IsPM4TracingEnabled()) {
                    // Dump first few dwords from the target so we can understand the micro-IB payload
                    uint32_t preview[16] = {};
                    uint32_t* dump_ptr = reinterpret_cast<uint32_t*>(g_memory.Translate(ib_addr));
                    if (dump_ptr) {
                        uint32_t n = (ib_size / 4);
                        if (n > 16) n = 16;
                        for (uint32_t i = 0; i < n; ++i) {
                        #if defined(_MSC_VER)
                            preview[i] = _byteswap_ulong(dump_ptr[i]);
                        #else
                            preview[i] = __builtin_bswap32(dump_ptr[i]);
                        #endif
                        }
                        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB addr=%08X size=%u (opc=04) d0=%08X d1=%08X d2=%08X d3=%08X d4=%08X d5=%08X",
                                            ib_addr, ib_size,
                                            preview[0], preview[1], preview[2], preview[3], preview[4], preview[5]);
                        if (n > 8) {
                            KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.tail d8=%08X d9=%08X d10=%08X d11=%08X d12=%08X d13=%08X d14=%08X d15=%08X",
                                                preview[8], preview[9], preview[10], preview[11], preview[12], preview[13], preview[14], preview[15]);
                        }

                        // Also log up to 16 payload params for analysis (first 8 already in beParams)
                        {
                            uint32_t p[16] = {};
                            uint32_t n = count < 16 ? count : 16;
                            for (uint32_t i = 0; i < n && i < 8; ++i) p[i] = beParams[i];
                            for (uint32_t i = 8; i < n; ++i) {
                            #if defined(_MSC_VER)
                                p[i] = _byteswap_ulong(params[i]);
                            #else
                                p[i] = __builtin_bswap32(params[i]);
                            #endif
                            }
                            KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.params opc=04 count=%u p0=%08X p1=%08X p2=%08X p3=%08X p4=%08X p5=%08X p6=%08X p7=%08X",
                                                count, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
                            if (n > 8) {
                                KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.params.tail p8=%08X p9=%08X p10=%08X p11=%08X p12=%08X p13=%08X p14=%08X p15=%08X",
                                                    p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
                            }
                        }
                        // Detect MW05 micro buffer magic ('MW05' in BE) and self-referential wrapper
                        if (preview[0] == 0x3530574Du) {
                            KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.magic addr=%08X size=%u", ib_addr, ib_size);

                                // One-time wider neighborhood dump around the 0x001402xx..0x001404xx window for offline analysis
                                static thread_local bool s_dumped_microib_window_once = false;
                                if (!s_dumped_microib_window_once) {
                                #if defined(_MSC_VER)
                                    uint32_t base_lo = 0x00140200u;
                                    uint32_t base_hi = 0x00140480u; // exclusive
                                #else
                                    uint32_t base_lo = 0x00140200u;
                                    uint32_t base_hi = 0x00140480u; // exclusive
                                #endif
                                    for (uint32_t a = base_lo; a < base_hi; a += 32) {
                                        auto* p = reinterpret_cast<uint32_t*>(g_memory.Translate(a));
                                        if (!p) { continue; }
                                        uint32_t d[8] = {};
                                        for (int j = 0; j < 8; ++j) {
                                        #if defined(_MSC_VER)
                                            d[j] = _byteswap_ulong(p[j]);
                                        #else
                                            d[j] = __builtin_bswap32(p[j]);
                                        #endif
                                        }
                                        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.window ea=%08X d0=%08X d1=%08X d2=%08X d3=%08X d4=%08X d5=%08X d6=%08X d7=%08X",
                                                            a, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]);
                                    }
                                    s_dumped_microib_window_once = true;
                                }

                            // Follow pointer at d1 (BE) to dump potential micro list
                        #if defined(_MSC_VER)
                            uint32_t micro_list_ea = _byteswap_ulong(preview[1]);
                        #else
                            uint32_t micro_list_ea = __builtin_bswap32(preview[1]);
                        #endif
                            if ((micro_list_ea & 0xFFFF0000u) == 0x00140000u) {
                                uint32_t* follow = reinterpret_cast<uint32_t*>(g_memory.Translate(micro_list_ea));
                                if (follow) {
                                    uint32_t d[32] = {};
                                    for (uint32_t j = 0; j < 32; ++j) {
                                    #if defined(_MSC_VER)
                                        d[j] = _byteswap_ulong(follow[j]);
                                    #else
                                        d[j] = __builtin_bswap32(follow[j]);
                                    #endif
                                    }
                                    KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.follow ea=%08X d0=%08X d1=%08X d2=%08X d3=%08X d4=%08X d5=%08X d6=%08X d7=%08X",
                                                        micro_list_ea, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]);
                                    KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.follow.tail d8=%08X d9=%08X d10=%08X d11=%08X d12=%08X d13=%08X d14=%08X d15=%08X",
                                                        d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
                                    // Heuristic neighborhood scan around the micro list ea to surface nested PM4
                                    if ((micro_list_ea & 0xFFFF0000u) == 0x00140000u) {
                                        uint32_t base_lo2 = 0x00140000u;
                                        uint32_t base_hi2 = 0x00150000u; // exclusive
                                        uint32_t start2 = micro_list_ea > 0x400u ? (micro_list_ea - 0x400u) : micro_list_ea;
                                        if (start2 < base_lo2) start2 = base_lo2;
                                        uint32_t end2 = micro_list_ea + 0x1000u;
                                        if (end2 > base_hi2) end2 = base_hi2;
                                        if (end2 > start2) {
                                            static thread_local int s_microib_neighborhood_depth4 = 0;
                                            if (s_microib_neighborhood_depth4 == 0) {
                                                ++s_microib_neighborhood_depth4;
                                                PM4_ScanLinear(start2, end2 - start2);
                                                --s_microib_neighborhood_depth4;
                                            }
                                        }
                                    }
                                } else {
                                // Heuristic neighborhood scan around the micro list ea to surface nested PM4
                                if ((micro_list_ea & 0xFFFF0000u) == 0x00140000u) {
                                    uint32_t base_lo2 = 0x00140000u;
                                    uint32_t base_hi2 = 0x00150000u; // exclusive
                                    uint32_t start2 = micro_list_ea > 0x100u ? (micro_list_ea - 0x100u) : micro_list_ea;
                                    if (start2 < base_lo2) start2 = base_lo2;
                                    uint32_t end2 = micro_list_ea + 0x400u;
                                    if (end2 > base_hi2) end2 = base_hi2;
                                    if (end2 > start2) {
                                        static thread_local int s_microib_neighborhood_depth3 = 0;
                                        if (s_microib_neighborhood_depth3 == 0) {
                                            ++s_microib_neighborhood_depth3;
                                            PM4_ScanLinear(start2, end2 - start2);
                                            --s_microib_neighborhood_depth3;
                                        }
                                    }
                                }

                                    KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.follow ea=%08X translate=null", micro_list_ea);
                                }
                            }


                            // Try additional pointers encoded in header dwords and opportunistic scan for other MW05 blocks
                            {
                                // Peek any plausible EA in header dwords [1..7]
                                for (uint32_t k = 1; k < 8; ++k) {
                                #if defined(_MSC_VER)
                                    uint32_t ea = _byteswap_ulong(preview[k]);
                                #else
                                    uint32_t ea = __builtin_bswap32(preview[k]);
                                #endif
                                    if ((ea & 0xFFFF0000u) == 0x00140000u) {
                                        uint32_t* p = reinterpret_cast<uint32_t*>(g_memory.Translate(ea));
                                        if (p) {
                                            uint32_t d[8] = {};
                                            for (uint32_t j = 0; j < 8; ++j) {
                                            #if defined(_MSC_VER)
                                                d[j] = _byteswap_ulong(p[j]);
                                            #else
                                                d[j] = __builtin_bswap32(p[j]);
                                            #endif
                                            }
                                            KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.peek ea[%u]=%08X d0=%08X d1=%08X d2=%08X d3=%08X d4=%08X d5=%08X d6=%08X d7=%08X",
                                                                k, ea, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]);
                                        } else {
                                            KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.peek ea[%u]=%08X translate=null", k, ea);
                                        }
                                    }
                                }
                                // Limit scan to a few hits to avoid log spam
                                static thread_local int s_scan_hits = 0;
                                if (s_scan_hits < 4) {
                                    uint32_t scan_lo = 0x00140000u;
                                    uint32_t scan_hi = 0x00150000u; // exclusive
                                    uint32_t* basep = reinterpret_cast<uint32_t*>(g_memory.Translate(scan_lo));
                                    if (basep) {
                                        for (uint32_t ea = scan_lo; ea < scan_hi; ea += 4) {
                                            uint32_t be = *reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(basep) + (ea - scan_lo));
                                        #if defined(_MSC_VER)
                                            uint32_t le = _byteswap_ulong(be);
                                        #else
                                            uint32_t le = __builtin_bswap32(be);
                                        #endif
                                            if (le == 0x3530574Du) {
                                                KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.scan.hit ea=%08X", ea);
                                                uint32_t* hp = reinterpret_cast<uint32_t*>(g_memory.Translate(ea));
                                                if (hp) {
                                                    uint32_t dd[8] = {};
                                                    for (uint32_t j = 0; j < 8; ++j) {
                                                    #if defined(_MSC_VER)
                                                        dd[j] = _byteswap_ulong(hp[j]);
                                                    #else
                                                        dd[j] = __builtin_bswap32(hp[j]);
                                                    #endif
                                                    }
                                                    KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.scan.d ea=%08X d0=%08X d1=%08X d2=%08X d3=%08X d4=%08X d5=%08X d6=%08X d7=%08X",
                                                                        ea, dd[0], dd[1], dd[2], dd[3], dd[4], dd[5], dd[6], dd[7]);
                                                #if defined(_MSC_VER)
                                                    uint32_t follow_ea = _byteswap_ulong(dd[1]);
                                                #else
                                                    uint32_t follow_ea = __builtin_bswap32(dd[1]);
                                                #endif
                                                    // Derive candidate from 16-bit signed offset stored in BE low 16 bits of d3
                                                    // dd[] holds LE-swapped values; BE low16 corresponds to bytes [b2,b3] of dd[3]
                                                    {
                                                        uint8_t b2 = static_cast<uint8_t>((dd[3] >> 16) & 0xFF);
                                                        uint8_t b3 = static_cast<uint8_t>((dd[3] >> 24) & 0xFF);
                                                        int16_t be_off16 = static_cast<int16_t>(static_cast<uint16_t>((static_cast<uint16_t>(b2) << 8) | b3));
                                                        uint32_t cand2 = follow_ea + static_cast<int32_t>(be_off16);
                                                        if ((cand2 & 0xFFFF0000u) == 0x00140000u) {
                                                            uint32_t base_lo3 = 0x00140000u;
                                                            uint32_t base_hi3 = 0x00150000u; // exclusive
                                                            uint32_t s3 = cand2 > 0x400u ? (cand2 - 0x400u) : cand2;
                                                            if (s3 < base_lo3) s3 = base_lo3;
                                                            uint32_t e3 = cand2 + 0x1000u;
                                                            if (e3 > base_hi3) e3 = base_hi3;
                                                            if (e3 > s3) {
                                                                static thread_local int s_microib_neighborhood_depth5 = 0;
                                                                if (s_microib_neighborhood_depth5 == 0) {
                                                                    ++s_microib_neighborhood_depth5;
                                                                    PM4_ScanLinear(s3, e3 - s3);
                                                                    --s_microib_neighborhood_depth5;
                                                                }
                                                            }
                                                        }
                                                    }

                                                    if ((follow_ea & 0xFFFF0000u) == 0x00140000u) {
                                                        uint32_t* fp = reinterpret_cast<uint32_t*>(g_memory.Translate(follow_ea));
                                                        if (fp) {
                                                            uint32_t fd[16] = {};
                                                            for (uint32_t jj = 0; jj < 16; ++jj) {
                                                            #if defined(_MSC_VER)
                                                                fd[jj] = _byteswap_ulong(fp[jj]);
                                                            #else
                                                                fd[jj] = __builtin_bswap32(fp[jj]);
                                                            #endif
                                                            }
                                                            KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.scan.follow ea=%08X -> %08X f0=%08X f1=%08X f2=%08X f3=%08X f4=%08X f5=%08X f6=%08X f7=%08X",
                                                                                ea, follow_ea, fd[0], fd[1], fd[2], fd[3], fd[4], fd[5], fd[6], fd[7]);
                                                        } else {
                                                            KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.scan.follow ea=%08X -> %08X translate=null", ea, follow_ea);
                                                        }
                                                    }

                                                }
                                                if (++s_scan_hits >= 4) break;
                                            }
                                        }
                                    }
                                }
                            }

                            Mw05InterpretMicroIB(ib_addr, ib_size);
                            return size;
                        }
                        bool is_type3 = (((preview[0] >> 30) & 0x3u) == 3u);
                        uint32_t opc = (preview[0] >> 8) & 0x7Fu;
                        if (is_type3 && opc == 0x04u) {
                            KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.selfref addr=%08X size=%u", ib_addr, ib_size);
                            // Heuristic neighborhood scan: scan around the wrapper to find nearby real PM4
                            // Clamp to the known syscmd buffer range [0x00140000, 0x00150000)
                            uint32_t base_lo = 0x00140000u;
                            uint32_t base_hi = 0x00150000u; // exclusive
                            uint32_t start = ib_addr > 0x400u ? (ib_addr - 0x400u) : ib_addr;
                            if (start < base_lo) start = base_lo;
                            uint32_t end = ib_addr + ib_size + 0x2000u;
                            if (end > base_hi) end = base_hi;
                            if (end > start) {
                                uint32_t neigh_size = end - start;
                                if (IsPM4TracingEnabled()) {
                                    KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.neighborhood start=%08X size=%u", start, neigh_size);
                                }
                                static thread_local int s_microib_neighborhood_depth = 0;
                                if (s_microib_neighborhood_depth == 0) {
                                    ++s_microib_neighborhood_depth;
                                    PM4_ScanLinear(start, neigh_size);
                                    --s_microib_neighborhood_depth;
                                }
                            }
                            return size;
                        }
                    } else {
                        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB addr=%08X size=%u (opc=04) translate=null", ib_addr, ib_size);
                    }
                }
                // Give the MW05 interpreter a chance to inspect the buffer as well
                Mw05InterpretMicroIB(ib_addr, ib_size);
                // Scan the indirect buffer to surface any nested PM4 draws
                static thread_local int s_microib_depth = 0;
                if (s_microib_depth < 1) {
                    ++s_microib_depth;
                    PM4_ScanLinear(ib_addr, ib_size);
                    --s_microib_depth;
                } else {
                    if (IsPM4TracingEnabled()) {
                        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.skip recursion depth=%d addr=%08X size=%u", s_microib_depth, ib_addr, ib_size);
                    }
                }
            } else {
                // Fallback: MW05 may place the micro-IB descriptor in the System Command Buffer, not inline.
                // Look for sentinel 0xFFFAFEFD near 0x00140400 and try to recover <ea, offset, size>.
                if (ib_addr == 0 || ib_size == 0) {
                    uint32_t base = 0x00140400u;
                    uint32_t* sys = reinterpret_cast<uint32_t*>(g_memory.Translate(base));
                    if (sys) {
                        const uint32_t search_bytes = 65536; // full syscmd window
                        const uint32_t words = search_bytes / 4;
                        for (uint32_t j = 0; j + 3 < words; ++j) {
                        #if defined(_MSC_VER)
                            uint32_t s0 = _byteswap_ulong(sys[j + 0]);
                            uint32_t s1 = _byteswap_ulong(sys[j + 1]);
                            uint32_t s2 = _byteswap_ulong(sys[j + 2]);
                            uint32_t s3 = _byteswap_ulong(sys[j + 3]);
                        #else
                            uint32_t s0 = __builtin_bswap32(sys[j + 0]);
                            uint32_t s1 = __builtin_bswap32(sys[j + 1]);
                            uint32_t s2 = __builtin_bswap32(sys[j + 2]);
                            uint32_t s3 = __builtin_bswap32(sys[j + 3]);
                        #endif
                            if (s0 == 0xFFFAFEFDu) {
                                if ((s1 & 0xFFFF0000u) == 0x00140000u && s3 > 0 && s3 <= 0x00010000u) {
                                    uint32_t cand_ea = s1;
                                    uint32_t cand_size = s3;
                                    int32_t signed_off = static_cast<int32_t>(s2);
                                    uint32_t eff = cand_ea + (uint32_t)(signed_off * 4); // offset is likely in dwords
                                    // Prefer effective address if within syscmd window
                                    uint32_t target = ((eff & 0xFFFF0000u) == 0x00140000u) ? eff : cand_ea;
                                    // Peek first DWORD at target to avoid self-referential wrapper chains
                                    bool accept = false;
                                    if (uint32_t* peek_ptr = reinterpret_cast<uint32_t*>(g_memory.Translate(target))) {
                                    #if defined(_MSC_VER)
                                        uint32_t first = _byteswap_ulong(*peek_ptr);
                                    #else
                                        uint32_t first = __builtin_bswap32(*peek_ptr);
                                    #endif
                                        bool is_type3 = (((first >> 30) & 0x3u) == 3u);
                                        uint32_t opc = (first >> 8) & 0x7Fu;
                                        accept = !(is_type3 && opc == 0x04u);
                                    }
                                    if (accept) {
                                        ib_addr = target;
                                        ib_size = cand_size;
                                        if (IsPM4TracingEnabled()) {
                                            KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.descr base=%08X off=%04X ea=%08X off2=%d eff=%08X size=%u",
                                                               base, j * 4, cand_ea, signed_off, target, cand_size);
                                        }
                                        // Heuristic neighborhood scan around the recovered IB address
                                        uint32_t base_lo = 0x00140000u;
                                        uint32_t base_hi = 0x00150000u; // exclusive
                                        uint32_t start = ib_addr > 0x400u ? (ib_addr - 0x400u) : ib_addr;
                                        if (start < base_lo) start = base_lo;
                                        uint32_t end = ib_addr + ib_size + 0x2000u;
                                        if (end > base_hi) end = base_hi;
                                        if (end > start) {
                                            uint32_t neigh_size = end - start;
                                            static thread_local int s_microib_neighborhood_depth2 = 0;
                                            if (s_microib_neighborhood_depth2 == 0) {
                                                ++s_microib_neighborhood_depth2;
                                                PM4_ScanLinear(start, neigh_size);
                                                --s_microib_neighborhood_depth2;
                                            }
                                        }
                                        return size;
                                    }
                                }
                            }
                        }
                    }
                }
                if (IsPM4TracingEnabled()) {
                    // Log up to first 16 params for analysis
                    uint32_t p[16] = {};
                    uint32_t n = count < 16 ? count : 16;
                    for (uint32_t i = 0; i < n; ++i) p[i] = (i < 8 ? beParams[i] : __builtin_bswap32(params[i]));
                    KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.unrecognized opc=04 count=%u p0=%08X p1=%08X p2=%08X p3=%08X p4=%08X p5=%08X p6=%08X p7=%08X",
                                        count, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
                    if (count > 8) {
                        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.unrecognized.tail p8=%08X p9=%08X p10=%08X p11=%08X p12=%08X p13=%08X p14=%08X p15=%08X",
                                            p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
                    }
                    // If there is a plausible EA in 0x0014xxxx among the first params, dump 64 bytes from it
                    for (uint32_t i = 0; i < n; ++i) {
                        uint32_t v = p[i];
                        if ((v & 0xFFFF0000u) == 0x00140000u) {
                            uint32_t* dump_ptr = reinterpret_cast<uint32_t*>(g_memory.Translate(v));
                            if (dump_ptr) {
                                uint32_t d[16] = {};
                                for (uint32_t j = 0; j < 16; ++j) d[j] = __builtin_bswap32(dump_ptr[j]);
                                KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.peek ea=%08X d0=%08X d1=%08X d2=%08X d3=%08X d4=%08X d5=%08X d6=%08X d7=%08X",
                                                    v, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]);
                                KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.peek.tail d8=%08X d9=%08X d10=%08X d11=%08X d12=%08X d13=%08X d14=%08X d15=%08X",
                                                    d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
                            } else {
                                KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.peek ea=%08X translate=null", v);
                            }
                            break;
                        }
                    }
                }
            }
        }
        else if (IsPM4TracingEnabled()) {
            // Log other interesting commands (with extra detail for WAIT_REG_MEM)
            if (opcode == PM4_WAIT_REG_MEM) {
                uint32_t* params = ptr + 1;
                uint32_t p0 = (count >= 0 && params[0]) ? __builtin_bswap32(params[0]) : 0; // func/space/poll
                uint32_t p1 = (count >= 1 && params[1]) ? __builtin_bswap32(params[1]) : 0; // ref
                uint32_t p2 = (count >= 2 && params[2]) ? __builtin_bswap32(params[2]) : 0; // mask
                uint32_t p3 = (count >= 3 && params[3]) ? __builtin_bswap32(params[3]) : 0; // addr/reg
                // Bits (heuristic):
                // p0[0] function: 0=never, 1=less, 2=equal, 3=LE, 4=greater, 5=NE, 6=GE
                // p0[4] mem_space (0=reg,1=mem), p0[31] poll (0=wait reg/mem, 1= ??)
                uint32_t func = (p0 & 0x7u);
                uint32_t mem_space = (p0 >> 4) & 0x1u;
                KernelTraceHostOpF("HOST.PM4.WAIT_REG_MEM addr=%08X count=%u func=%u space=%s ref=%08X mask=%08X target=%08X",
                                   addr, count, func, mem_space ? "mem" : "reg", p1, p2, p3);
                // Minimal host-side nudge to satisfy early CP waits: env-guarded, non-invasive
                // Call the default VD ISR nudge periodically to bump ring write-back/sysid
                static uint32_t s_wait_seen = 0;
                ++s_wait_seen;
                if (const char* fw = std::getenv("MW05_FORCE_ACK_WAIT")) {
                    if (*fw && *fw != '0') {
                        // Aggressive: nudge on every WAIT when enabled to unlock early boot loops
                        Mw05RunHostDefaultVdIsrNudge("pm4wait");
                    }
                }
            } else {
                const char* opname = nullptr;
                switch (opcode) {
                    case PM4_SET_CONSTANT: opname = "SET_CONSTANT"; break;
                    case PM4_SET_SHADER_CONSTANTS: opname = "SET_SHADER_CONSTANTS"; break;
                    case PM4_EVENT_WRITE: opname = "EVENT_WRITE"; break;
                    case PM4_INDIRECT_BUFFER: opname = "INDIRECT_BUFFER"; break;
                    default: break;
                }
                if (opname) {
                    KernelTraceHostOpF("HOST.PM4.%s addr=%08X count=%u", opname, addr, count);
                }
            }
        }

        return size;
    }
    else if (type == PM4_TYPE0) {
        // PACKET0: register write(s). Count field = number of registers - 1
        uint32_t count = (header >> 16) & 0x3FFF;
        uint32_t start_reg = header & 0xFFFFu;
        // Debug: log raw TYPE0 header/fields to validate parsing
        // Optional: very verbose TYPE0 header logging (off by default to avoid log spam)
        static const bool s_log_type0_hdr = [](){
            if (const char* v = std::getenv("MW05_PM4_LOG_TYPE0")) return !(v[0]=='0' && v[1]=='\0');
            return false;
        }();
        if (IsPM4TracingEnabled() && s_log_type0_hdr) {
            KernelTraceHostOpF("HOST.PM4.TYPE0.HDR addr=%08X header=%08X count=%u start=%04X", addr, header, count, start_reg);
        }

        // Optional: decode interesting CP regs (RB/IB) to verify command processor setup
        auto trace_regs = [](){
            if (const char* v = std::getenv("MW05_PM4_TRACE_REGS")) return !(v[0]=='0' && v[1]=='\0');
            return false;
        }();
        if (trace_regs && count <= 0x4000) {
            uint32_t* params = ptr + 1;
            // Budgeted verbose logging of TYPE0 register writes to discover actual ranges in use
            static int s_reg_log_budget = -1;
            if (s_reg_log_budget < 0) {
                int budget = 2048; // default
                if (const char* b = std::getenv("MW05_PM4_TRACE_REG_BUDGET")) {
                    budget = std::max(0, atoi(b));
                }
                s_reg_log_budget = budget;
                KernelTraceHostOpF("HOST.PM4.TYPE0.REG.budget init=%d", s_reg_log_budget);
            }
            for (uint32_t i = 0; i <= count; ++i) {
                uint32_t reg = start_reg + i;
            #if defined(_MSC_VER)
                uint32_t val = params[i] ? _byteswap_ulong(params[i]) : 0;
            #else
                uint32_t val = params[i] ? __builtin_bswap32(params[i]) : 0;
            #endif
                // If budget remains, log every register write with its high-byte group to map ranges quickly
                if (s_reg_log_budget > 0) {
                    --s_reg_log_budget;
                    KernelTraceHostOpF("HOST.PM4.TYPE0.REG reg=%04X grp=%02X val=%08X", reg, (reg >> 8) & 0xFFu, val);
                }
            }
        }
        return (count + 2) * 4; // header + (count+1) payload dwords
    }
    else if (type == PM4_TYPE2) {
        // PACKET2: NOP-like, no payload; advance by one dword to stay aligned
        return 4;
    }

    // Unknown/unsupported type (e.g., TYPE1): advance conservatively by one DWORD
    return 4;
}

// Scan ring buffer for PM4 packets when a write is detected
void PM4_ScanRingBuffer(uint32_t writeAddr, size_t writeSize) {
    if (!IsPM4TracingEnabled()) return;

    uint32_t base = g_rbBase.load(std::memory_order_acquire);
    uint32_t size = g_rbSize.load(std::memory_order_acquire);

    if (!base || !size) return;

    // Check if write is within ring buffer
    if (writeAddr < base || writeAddr >= (base + size)) return;

    // Calculate write offset
    uint32_t writeOffset = writeAddr - base;
    uint32_t prevWrite = g_rbWritePtr.exchange(writeOffset, std::memory_order_acq_rel);

    // Only scan if we've moved forward significantly (avoid scanning every tiny write)
    uint32_t delta = (writeOffset >= prevWrite) ? (writeOffset - prevWrite) : (size - prevWrite + writeOffset);

    static const bool s_eager_scan = [](){
        if (const char* v = std::getenv("MW05_PM4_EAGER_SCAN"))
            return !(v[0]=='0' && v[1]=='\0');
        return false;
    }();
    if (delta < 16 && !s_eager_scan) return;  // Skip small writes unless eager scan is enabled

    // Parse packets between prevWrite and writeOffset
    uint32_t offset = prevWrite;
    uint32_t scanned = 0;
    const uint32_t maxScan = 2048;  // Limit scan to prevent infinite loops

    KernelTraceHostOpF("HOST.PM4.Scan.start prev=%04X cur=%04X delta=%u", prevWrite, writeOffset, delta);

    if (IsSnoopEnabled()) {
        DumpHexWindow(base + prevWrite, 16);
    }

    while (offset != writeOffset && scanned < maxScan) {
        uint32_t addr = base + offset;
        uint32_t packetSize = ParsePM4Packet(addr);

        offset = (offset + packetSize) & (size - 1);
        scanned++;
    }

    if (scanned > 0) {
        KernelTraceHostOpF("HOST.PM4.Scan.end prev=%04X cur=%04X scanned=%u draws=%llu",
                          prevWrite, writeOffset, scanned,
                          (unsigned long long)g_pm4DrawCount.load(std::memory_order_relaxed));
    }
}

// Optional: debug scan of entire ring when triggers are missing
void PM4_DebugScanAll() {
    if (!IsPM4TracingEnabled()) return;
    static const bool s_scan_all = [](){
        if (const char* v = std::getenv("MW05_PM4_SCAN_ALL"))
            return !(v[0]=='0' && v[1]=='\0');
        return false;
    }();
    if (!s_scan_all) return;

    uint32_t base = g_rbBase.load(std::memory_order_acquire);
    uint32_t size = g_rbSize.load(std::memory_order_acquire);
    if (!base || !size) return;

    KernelTraceHostOpF("HOST.PM4.ScanAll.begin base=%08X size=%u", base, size);

    // One-time memory stats to verify whether guest writes anything into the ring
    static bool s_loggedMemStats = false;
    if (!s_loggedMemStats) {
        uint32_t nonzero = 0;
        for (uint32_t off = 0; off < size; off += 4) {
            uint32_t* p = reinterpret_cast<uint32_t*>(g_memory.Translate(base + off));
            if (p && *p) nonzero++;
        }
        KernelTraceHostOpF("HOST.PM4.ScanAll.memstats nonzero_dwords=%u total_dwords=%u", nonzero, size / 4);
        // If scratch was armed, also count deviations from the pattern
        if (g_rbScratchArmed.load(std::memory_order_acquire)) {
            uint32_t pat = g_rbScratchPattern.load(std::memory_order_acquire);
            uint32_t changed = 0;
            for (uint32_t off = 0; off < size; off += 4) {
                uint32_t* p = reinterpret_cast<uint32_t*>(g_memory.Translate(base + off));
                if (!p) continue;
            #if defined(_MSC_VER)
                uint32_t le = _byteswap_ulong(*p);
            #else
                uint32_t le = __builtin_bswap32(*p);
            #endif
                if (le != pat) changed++;
            }
            KernelTraceHostOpF("HOST.PM4.RingScratch.differs dwords_changed=%u of %u", changed, size / 4);
        }
        s_loggedMemStats = true;
    // If ring scratch pattern is armed and no dword differs right now, skip scanning to avoid false-positive histograms
    if (g_rbScratchArmed.load(std::memory_order_acquire)) {
        uint32_t pat_now = g_rbScratchPattern.load(std::memory_order_acquire);
        bool any_diff = false;
        for (uint32_t off = 0; off < size; off += 4) {
            uint32_t* p = reinterpret_cast<uint32_t*>(g_memory.Translate(base + off));
            if (!p) continue;
        #if defined(_MSC_VER)
            uint32_t le = _byteswap_ulong(*p);
        #else
            uint32_t le = __builtin_bswap32(*p);
        #endif
            if (le != pat_now) { any_diff = true; break; }
        }
        if (!any_diff) {
            KernelTraceHostOpF("HOST.PM4.ScanAll.skip.scratch_unchanged base=%08X size=%u", base, size);
            return;
        }
    }

    }
    // Log packet type composition so we know if TYPE3 ever shows up
    {
        uint64_t t0 = g_typeCounts[0].load(std::memory_order_relaxed);
        uint64_t t1 = g_typeCounts[1].load(std::memory_order_relaxed);
        uint64_t t2 = g_typeCounts[2].load(std::memory_order_relaxed);
        uint64_t t3 = g_typeCounts[3].load(std::memory_order_relaxed);
        KernelTraceHostOpF("HOST.PM4.Types t0=%llu t1=%llu t2=%llu t3=%llu",
            (unsigned long long)t0, (unsigned long long)t1,
            (unsigned long long)t2, (unsigned long long)t3);
    }

    uint32_t offset = 0;
    uint32_t scanned = 0;
    const uint32_t maxScan = 8192; // cap
    // Early-out: if ring is scratch-armed and unchanged, skip this forced scan
    if (g_rbScratchArmed.load(std::memory_order_acquire)) {
        uint32_t pat_now = g_rbScratchPattern.load(std::memory_order_acquire);
        bool any_diff = false;
        for (uint32_t off = 0; off < size; off += 4) {
            uint32_t* p = reinterpret_cast<uint32_t*>(g_memory.Translate(base + off));
            if (!p) continue;
    #if defined(_MSC_VER)
            uint32_t le = _byteswap_ulong(*p);
    #else
            uint32_t le = __builtin_bswap32(*p);
    #endif
            if (le != pat_now) { any_diff = true; break; }
        }
        if (!any_diff) {
            KernelTraceHostOpF("HOST.PM4.ScanAll.skip.scratch_unchanged base=%08X size=%u (force)", base, size);
            return;
        }
    }

    while (offset < size && scanned < maxScan) {
        uint32_t addr = base + offset;
        uint32_t packetSize = ParsePM4Packet(addr);
        if (packetSize == 0) { packetSize = 4; }
        offset = (offset + packetSize) & (size - 1);
        if (offset == 0) break; // wrapped once
        scanned++;
    }
    KernelTraceHostOpF("HOST.PM4.ScanAll.end scanned=%u draws=%llu", scanned,
                       (unsigned long long)g_pm4DrawCount.load(std::memory_order_relaxed));
    // Dump any non-zero opcode histogram entries once per pass
    PM4_DumpOpcodeHistogram();
}

// Force variant used by auto-diagnosis: always performs a single pass scan
void PM4_DebugScanAll_Force() {
    uint32_t base = g_rbBase.load(std::memory_order_acquire);
    uint32_t size = g_rbSize.load(std::memory_order_acquire);
    if (!base || !size) return;
    KernelTraceHostOpF("HOST.PM4.ScanAll.begin base=%08X size=%u (force)", base, size);
    // Early-out: skip forced scan if ring scratch pattern is armed and unchanged
    if (g_rbScratchArmed.load(std::memory_order_acquire)) {
        uint32_t pat_now = g_rbScratchPattern.load(std::memory_order_acquire);
        bool any_diff = false;
        for (uint32_t off = 0; off < size; off += 4) {
            uint32_t* p = reinterpret_cast<uint32_t*>(g_memory.Translate(base + off));
            if (!p) continue;
    #if defined(_MSC_VER)
            uint32_t le = _byteswap_ulong(*p);
    #else
            uint32_t le = __builtin_bswap32(*p);
    #endif
            if (le != pat_now) { any_diff = true; break; }
        }
        if (!any_diff) {
            KernelTraceHostOpF("HOST.PM4.ScanAll.skip.scratch_unchanged base=%08X size=%u (force)", base, size);
            return;
        }
    }

    // One-time memory stats to verify whether guest writes anything into the ring
    static bool s_loggedMemStatsForce = false;
    if (!s_loggedMemStatsForce) {
        uint32_t nonzero = 0;
        for (uint32_t off = 0; off < size; off += 4) {
            uint32_t* p = reinterpret_cast<uint32_t*>(g_memory.Translate(base + off));
            if (p && *p) nonzero++;
        }
        KernelTraceHostOpF("HOST.PM4.ScanAll.memstats nonzero_dwords=%u total_dwords=%u", nonzero, size / 4);
        // If scratch was armed, also count deviations from the pattern
        if (g_rbScratchArmed.load(std::memory_order_acquire)) {
            uint32_t pat = g_rbScratchPattern.load(std::memory_order_acquire);
            uint32_t changed = 0;
            for (uint32_t off = 0; off < size; off += 4) {
                uint32_t* p = reinterpret_cast<uint32_t*>(g_memory.Translate(base + off));
                if (!p) continue;
            #if defined(_MSC_VER)
                uint32_t le = _byteswap_ulong(*p);
            #else
                uint32_t le = __builtin_bswap32(*p);
            #endif
                if (le != pat) changed++;
            }
            KernelTraceHostOpF("HOST.PM4.RingScratch.differs dwords_changed=%u of %u (force)", changed, size / 4);
        }
        s_loggedMemStatsForce = true;
    }
    // Log packet type composition to understand stream content
    {
        uint64_t t0 = g_typeCounts[0].load(std::memory_order_relaxed);
        uint64_t t1 = g_typeCounts[1].load(std::memory_order_relaxed);
        uint64_t t2 = g_typeCounts[2].load(std::memory_order_relaxed);
        uint64_t t3 = g_typeCounts[3].load(std::memory_order_relaxed);
        KernelTraceHostOpF("HOST.PM4.Types t0=%llu t1=%llu t2=%llu t3=%llu",
            (unsigned long long)t0, (unsigned long long)t1,
            (unsigned long long)t2, (unsigned long long)t3);
    }
    uint32_t offset = 0;
    uint32_t scanned = 0;
    const uint32_t maxScan = 4096; // smaller cap for forced
    for (;;) {
        uint32_t addr = base + offset;
        uint32_t packetSize = ParsePM4Packet(addr);
        if (packetSize == 0) packetSize = 4;
        offset = (offset + packetSize) & (size - 1);
        if (offset == 0) break;
        if (++scanned >= maxScan) break;
    }
    KernelTraceHostOpF("HOST.PM4.ScanAll.end scanned=%u draws=%llu (force)", scanned,
                       (unsigned long long)g_pm4DrawCount.load(std::memory_order_relaxed));
    PM4_DumpOpcodeHistogram();
}



// Hook for ring buffer write pointer updates (called from VdSwap)
void PM4_OnRingBufferWrite(uint32_t writeOffset) {
    if (!IsPM4TracingEnabled()) return;

    uint32_t base = g_rbBase.load(std::memory_order_acquire);
    if (!base) return;

    PM4_ScanRingBuffer(base + writeOffset, 4);
}

// Hook for ring buffer writes (called from TraceRbWrite)
void PM4_OnRingBufferWriteAddr(uint32_t writeAddr, size_t writeSize) {
    PM4_ScanRingBuffer(writeAddr, writeSize);
}

// Get statistics
uint64_t PM4_GetDrawCount() {
    return g_pm4DrawCount.load(std::memory_order_relaxed);
}

uint64_t PM4_GetPacketCount() {
    return g_pm4PacketCount.load(std::memory_order_relaxed);
}

void PM4_ResetStats() {
    g_pm4DrawCount.store(0, std::memory_order_relaxed);
    g_pm4PacketCount.store(0, std::memory_order_relaxed);
}

void PM4_DumpOpcodeHistogram() {
    // Log non-zero opcode counts once per call
    for (int i = 0; i < 128; ++i) {
        uint64_t c = g_opcodeCounts[i].load(std::memory_order_relaxed);
        if (!c) continue;
        KernelTraceHostOpF("HOST.PM4.OPC[%02X]=%llu", i, (unsigned long long)c);
    }
}

