// PM4 packet parser for MW05 ring buffer commands
// This intercepts ring buffer writes and logs PM4 draw commands

#include <kernel/memory.h>
#include <kernel/trace.h>
#include <cstdint>
#include <atomic>
#include <cstdlib>

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

#if defined(_MSC_VER)
    uint32_t header = _byteswap_ulong(*ptr);  // Big-endian -> host
#else
    uint32_t header = __builtin_bswap32(*ptr);  // Big-endian -> host
#endif
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
        else if (IsPM4TracingEnabled()) {
            // Log other interesting commands
            const char* opname = nullptr;
            switch (opcode) {
                case PM4_SET_CONSTANT: opname = "SET_CONSTANT"; break;
                case PM4_SET_SHADER_CONSTANTS: opname = "SET_SHADER_CONSTANTS"; break;
                case PM4_EVENT_WRITE: opname = "EVENT_WRITE"; break;
                case PM4_WAIT_REG_MEM: opname = "WAIT_REG_MEM"; break;
                case PM4_INDIRECT_BUFFER: opname = "INDIRECT_BUFFER"; break;
                default: break;
            }

            if (opname) {
                KernelTraceHostOpF("HOST.PM4.%s addr=%08X count=%u", opname, addr, count);
            }
        }

        return size;
    }
    else if (type == PM4_TYPE0) {
        // PACKET0: register write(s). Count field = number of registers - 1
        uint32_t count = (header >> 16) & 0x3FFF;
        uint32_t start_reg = header & 0xFFFFu;
        // Debug: log raw TYPE0 header/fields to validate parsing
        if (IsPM4TracingEnabled()) {
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

