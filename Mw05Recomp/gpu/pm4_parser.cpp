// PM4 packet parser for MW05 ring buffer commands
// This intercepts ring buffer writes and logs PM4 draw commands

#include <kernel/memory.h>
#include <kernel/trace.h>
#include <cstdint>
#include <atomic>
#include <cstdlib>

#include <cstring>

#include <fstream>
#include <filesystem>

extern "C"
{
    void Mw05RunHostDefaultVdIsrNudge(const char* tag);
    void Mw05DebugKickClear();
    void Mw05InterpretMicroIB(uint32_t ib_addr, uint32_t ib_size);
}

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
    PM4_MICRO_IB = 0x04,            // Micro Index Buffer (embedded small index buffers)
    PM4_ME_INIT = 0x48,
    PM4_NOP = 0x10,
    PM4_INDIRECT_BUFFER = 0x3F,
    PM4_WAIT_REG_MEM = 0x3C,
    PM4_CONTEXT_UPDATE = 0x3E,      // Update GPU context state
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

// Subset of Xenos register names from Xenia Canary (indices are dword addresses)
static inline const char* XenosRegName(uint32_t reg) {
    switch (reg) {
        // Render target / depth surface
        case 0x2000: return "RB_SURFACE_INFO";
        case 0x2001: return "RB_COLOR_INFO";
        case 0x2002: return "RB_DEPTH_INFO";
        case 0x2104: return "RB_COLOR_MASK";
        case 0x2200: return "RB_DEPTHCONTROL";
        // Scissor / window
        case 0x200E: return "PA_SC_SCREEN_SCISSOR_TL";
        case 0x200F: return "PA_SC_SCREEN_SCISSOR_BR";
        case 0x2080: return "PA_SC_WINDOW_OFFSET";
        case 0x2081: return "PA_SC_WINDOW_SCISSOR_TL";
        case 0x2082: return "PA_SC_WINDOW_SCISSOR_BR";
        // Viewport (floats)
        case 0x210F: return "PA_CL_VPORT_XSCALE";
        case 0x2110: return "PA_CL_VPORT_XOFFSET";
        case 0x2111: return "PA_CL_VPORT_YSCALE";
        case 0x2112: return "PA_CL_VPORT_YOFFSET";
        case 0x2113: return "PA_CL_VPORT_ZSCALE";
        case 0x2114: return "PA_CL_VPORT_ZOFFSET";
        // Mode control
        case 0x2205: return "PA_SU_SC_MODE_CNTL";
        default: return nullptr;
    }
}

static inline bool XenosRegIsViewportFloat(uint32_t reg) {
    return reg >= 0x210F && reg <= 0x2114;
}

static inline bool IsPM4TraceInterestingRegsEnabled() {
    if (const char* v = std::getenv("MW05_PM4_TRACE_INTERESTING")) return !(v[0]=='0' && v[1]=='\0');
    return false;
}


// Ring buffer state

// Host state application bridge (implemented in video.cpp)
extern "C" {
    void Mw05HostSetViewport(float x, float y, float width, float height, float minDepth, float maxDepth);
    void Mw05HostSetScissor(int32_t left, int32_t top, int32_t right, int32_t bottom);
    void Mw05HostApplyColorSurface(uint32_t rbSurfaceInfo, uint32_t rbColorInfo);
    void Mw05HostApplyDepthSurface(uint32_t rbSurfaceInfo, uint32_t rbDepthInfo);
    void Mw05HostDrawIndexed(uint32_t primitiveType, int32_t baseVertexIndex, uint32_t startIndex, uint32_t primCount);
}

static uint32_t s_rb_surface_info = 0;
static uint32_t s_rb_color_info = 0;
static uint32_t s_rb_depth_info = 0;
static bool s_rt_applied_once = false;
static bool s_ds_applied_once = false;
static bool s_micro_applied_vp_once = false;
static bool s_micro_applied_sc_once = false;
static bool s_micro_bound_rt_once = false;


static struct {
    bool have_xs{false}, have_xo{false}, have_ys{false}, have_yo{false}, have_zs{false}, have_zo{false};
    float xs{0.0f}, xo{0.0f}, ys{0.0f}, yo{0.0f}, zs{0.0f}, zo{0.0f};
} s_vp_accum;
static uint32_t s_sc_tl = 0, s_sc_br = 0;  // packed x/y
static inline bool IsApplyHostStateEnabled() {
    if (const char* v = std::getenv("MW05_PM4_APPLY_STATE")) return !(v[0]=='0' && v[1]=='\0');
    return false;
}

static inline bool IsPm4RegChangeLogEnabled() {
    if (const char* v = std::getenv("MW05_PM4_LOG_NONZERO")) return !(v[0]=='0' && v[1]=='\0');
    return false;
}
static inline bool IsEmitDrawsEnabled() {
    if (const char* v = std::getenv("MW05_PM4_EMIT_DRAWS")) return !(v[0]=='0' && v[1]=='\0');
    return false;
}

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

// Keep a small rolling history of recent TYPE0 register writes for correlation
struct RecentRegWrite { uint32_t reg; uint32_t val; };
static RecentRegWrite g_recentRegWrites[256];
static std::atomic<uint32_t> g_recentRegWriteIndex{0};

static inline void RecordRecentRegWrite(uint32_t reg, uint32_t val) {
    uint32_t i = g_recentRegWriteIndex.fetch_add(1, std::memory_order_relaxed);
    g_recentRegWrites[i & 255] = { reg, val };
}

static inline void DumpRecentRegWritesCompact(uint32_t max_count = 32) {
    uint32_t i = g_recentRegWriteIndex.load(std::memory_order_relaxed);
    uint32_t count = (max_count > 256u) ? 256u : max_count;
    for (uint32_t k = 0; k < count; ++k) {
        uint32_t idx = (i - 1 - k) & 255;
        auto e = g_recentRegWrites[idx];
        if (e.reg == 0 && e.val == 0) break; // uninitialized early in boot
        KernelTraceHostOpF("HOST.PM4.TYPE0.REG.recent reg=%04X grp=%02X val=%08X", e.reg, (e.reg >> 8) & 0xFFu, e.val);
    }
}

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

    // DEBUG: Log PM4 scan calls (increased limit to see more activity)
    static int s_scanLogCount = 0;
    if (s_scanLogCount < 100) {
        fprintf(stderr, "[RENDER-DEBUG] PM4_ScanLinear called: addr=%08X bytes=%u count=%d\n", addr, bytes, s_scanLogCount);
        fflush(stderr);
        s_scanLogCount++;
    }

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

    // DEBUG: Log scan results (increased limit to see more activity)
    if (s_scanLogCount <= 100) {
        uint64_t draws = g_pm4DrawCount.load(std::memory_order_relaxed);
        fprintf(stderr, "[RENDER-DEBUG] PM4_ScanLinear result: consumed=%u draws=%llu\n", consumed, (unsigned long long)draws);
        fflush(stderr);
    }

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
    if (!ptr) {
        static int s_translateFailCount = 0;
        if (s_translateFailCount < 10) {
            fprintf(stderr, "[PM4-TRANSLATE-FAIL] Address %08X failed translation (count=%d)\n", addr, s_translateFailCount);
            fflush(stderr);
            s_translateFailCount++;
        }
        return 4;
    }

    // Read raw dword from guest memory
    uint32_t raw = *ptr;
    // Normalize to a little-endian logical header so bitfield math is consistent.
    // MW05 stores PM4 words big-endian in memory, so always byte-swap.
    uint32_t header =
    #if defined(_MSC_VER)
        _byteswap_ulong(raw);
    #else
        __builtin_bswap32(raw);
    #endif

    // Decode from normalized header
    uint32_t type   = (header >> 30) & 0x3u;
    uint32_t opcode = (header >> 8)  & 0x7Fu;
    uint32_t count  = (header >> 16) & 0x3FFFu;

    g_pm4PacketCount.fetch_add(1, std::memory_order_relaxed);
    static bool s_logged_first_type3 = false;

    if (type < 4) g_typeCounts[type].fetch_add(1, std::memory_order_relaxed);

    // DEBUG: Log first 50 packets to see what types/opcodes we're getting
    static int s_packetLogCount = 0;
    if (s_packetLogCount < 50) {
        fprintf(stderr, "[PM4-DEBUG] Packet #%d: addr=%08X type=%u opcode=%02X count=%u header=%08X raw=%08X\n",
                s_packetLogCount, addr, type, opcode, count, header, raw);
        fflush(stderr);
        s_packetLogCount++;
    }

    // DEBUG: Log type distribution every 1000 packets
    static int s_typeLogTicker = 0;
    if ((++s_typeLogTicker % 1000) == 0) {
        uint64_t t0 = g_typeCounts[0].load(std::memory_order_relaxed);
        uint64_t t1 = g_typeCounts[1].load(std::memory_order_relaxed);
        uint64_t t2 = g_typeCounts[2].load(std::memory_order_relaxed);
        uint64_t t3 = g_typeCounts[3].load(std::memory_order_relaxed);
        fprintf(stderr, "[PM4-TYPE-DIST] TYPE0=%llu TYPE1=%llu TYPE2=%llu TYPE3=%llu total=%llu\n",
                (unsigned long long)t0, (unsigned long long)t1, (unsigned long long)t2, (unsigned long long)t3,
                (unsigned long long)(t0+t1+t2+t3));
        fflush(stderr);
    }

    if (type == PM4_TYPE3) {
        uint32_t opcode = (header >> 8) & 0x7F;
        uint32_t count = (header >> 16) & 0x3FFF;
        if (!s_logged_first_type3) {
            s_logged_first_type3 = true;
            if (IsPM4TracingEnabled()) {
                KernelTraceHostOpF("HOST.PM4.FirstType3 addr=%08X opc=%02X count=%u", addr, opcode, count);
            }
        }

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

        // Log draw commands (and optionally emit guarded host draws)
        // MW05 uses Micro-IB (0x04) for most draws, plus standard DRAW_INDX (0x22/0x36)
        if (opcode == PM4_MICRO_IB || opcode == PM4_DRAW_INDX || opcode == PM4_DRAW_INDX_2) {
            g_pm4DrawCount.fetch_add(1, std::memory_order_relaxed);

            // Read draw parameters (already byteswapped to host LE)
            // CRITICAL FIX: Check count bounds before accessing params array
            // count is unsigned, so we need to check if it's reasonable (not 0xFFFFFFFF)
            uint32_t* params = ptr + 1;
            uint32_t p0 = (count > 0 && count < 0x10000) ? __builtin_bswap32(params[0]) : 0;
            uint32_t p1 = (count > 1 && count < 0x10000) ? __builtin_bswap32(params[1]) : 0;
            uint32_t p2 = (count > 2 && count < 0x10000) ? __builtin_bswap32(params[2]) : 0;

            // DEBUG: Log PM4 draw commands
            static int s_pm4DrawLogCount = 0;
            if (s_pm4DrawLogCount < 5) {
                const char* opcode_name = (opcode == PM4_MICRO_IB) ? "MICRO_IB" :
                                         (opcode == PM4_DRAW_INDX) ? "DRAW_INDX" : "DRAW_INDX_2";
                fprintf(stderr, "[RENDER-DEBUG] PM4 DRAW command detected: opcode=%s count=%u total_draws=%llu emit_enabled=%d\n",
                        opcode_name,
                        count, (unsigned long long)g_pm4DrawCount.load(std::memory_order_relaxed),
                        IsEmitDrawsEnabled());
                fflush(stderr);
                s_pm4DrawLogCount++;
            }

            if (IsPM4TracingEnabled()) {
                const char* opcode_name = (opcode == PM4_MICRO_IB) ? "MICRO_IB" :
                                         (opcode == PM4_DRAW_INDX) ? "INDX" : "INDX_2";
                KernelTraceHostOpF("HOST.PM4.DRAW_%s addr=%08X count=%u p0=%08X p1=%08X p2=%08X total_draws=%llu",
                                  opcode_name,
                                  addr, count, p0, p1, p2,
                                  (unsigned long long)g_pm4DrawCount.load(std::memory_order_relaxed));
            }

            // Guarded attempt to translate PM4 draw -> host DrawIndexed.
            // Only emit when parameters look defensible; otherwise just log.
            if (IsEmitDrawsEnabled()) {
                auto indices_per_prim = [](uint32_t prim) -> uint32_t {
                    switch (prim) {
                        case 1: /*POINTLIST*/ return 1;
                        case 2: /*LINELIST*/ return 2;
                        case 3: /*LINESTRIP*/ return 2; // uses n+1 verts, but indices per prim ~2
                        case 4: /*TRIANGLELIST*/ return 3;
                        case 5: /*TRIANGLEFAN*/ return 3;
                        case 6: /*TRIANGLESTRIP*/ return 3; // uses n+2 verts, but indices per prim ~3
                        default: return 0;
                    }
                };

                // Heuristics (subject to refinement):
                // - Primitive type is commonly encoded in low 6 bits of the initiator (p0).
                // - Index count often appears in p1 or p2; prefer p2 when present.
                uint32_t prim_cand0 = (p0 & 0x3Fu);
                uint32_t prim_cand1 = (p1 & 0x3Fu);
                uint32_t prim = 0;
                if (indices_per_prim(prim_cand0)) prim = prim_cand0;
                else if (indices_per_prim(prim_cand1)) prim = prim_cand1;

                uint32_t idx_count0 = (p1 & 0xFFFFu);
                uint32_t idx_count1 = (p2 & 0xFFFFu);
                uint32_t index_count = idx_count1 ? idx_count1 : idx_count0;

                uint32_t ipp = indices_per_prim(prim);
                uint32_t prim_count = (ipp > 0 && index_count >= ipp) ? (index_count / ipp) : 0;
                bool divisible = (ipp > 0) && (prim_count * ipp == index_count);

                if (prim && prim_count > 0 && divisible) {
                    if (IsPM4TracingEnabled()) {
                        KernelTraceHostOpF("HOST.PM4.DRAW.emit prim=%u index_count=%u prim_count=%u baseVtx=%d startIdx=%u (opc=%s)",
                            prim, index_count, prim_count, 0, 0, (opcode == PM4_DRAW_INDX) ? "22" : "36");
                    }
                    // Conservative: assume startIndex=0, baseVertexIndex=0 until better mapping is confirmed.
                    Mw05HostDrawIndexed(prim, /*baseVertexIndex*/ 0, /*startIndex*/ 0, prim_count);
                } else {
                    if (IsPM4TracingEnabled()) {
                        KernelTraceHostOpF("HOST.PM4.DRAW.guarded.skip prim_cand0=%u prim_cand1=%u idx_cand0=%u idx_cand1=%u",
                            prim_cand0, prim_cand1, idx_count0, idx_count1);
                    }
                }
            }
        }
        // Heuristic: MW05 micro-IB wrapper observed as TYPE3 opc=0x04 followed by pattern
        //   0x81000001, 0xFFFAFEFD, <ea in 0x0014xxxx>, <signed>, <small size> ...
        // Try to recover an indirect buffer target from the next parameters and scan it.
        else if (opcode == 0x04) {
            // One-time conservative host state to ensure a target/viewport are bound before real draws
            if (IsApplyHostStateEnabled()) {
                if (!s_micro_bound_rt_once) {
                    KernelTraceHostOpF("HOST.PM4.MW05.bind.once (opc=04)");
                    Mw05HostApplyColorSurface(s_rb_surface_info, s_rb_color_info);
                    Mw05HostApplyDepthSurface(s_rb_surface_info, s_rb_depth_info);
                    s_micro_bound_rt_once = true;
                }
                if (!s_micro_applied_vp_once) {
                    KernelTraceHostOpF("HOST.PM4.MW05.viewport.once 1280x720");
                    Mw05HostSetViewport(0.0f, 0.0f, 1280.0f, 720.0f, 0.0f, 1.0f);
                    s_micro_applied_vp_once = true;
                }
                if (!s_micro_applied_sc_once) {
                    KernelTraceHostOpF("HOST.PM4.MW05.scissor.once 1280x720");
                    Mw05HostSetScissor(0, 0, 1280, 720);
                    s_micro_applied_sc_once = true;
                }
            }
                // Correlate recent TYPE0 writes around this micro-IB wrapper
                KernelTraceHostOpF("HOST.PM4.MW05.recent.regs (opc=04)");
                DumpRecentRegWritesCompact(24);


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
            // If we found an address but no size, use a default scan window
            if (ib_addr && !ib_size) {
                ib_size = 0x400u;  // Default 1KB scan window
                if (IsPM4TracingEnabled()) {
                    KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.default_size addr=%08X size=%u", ib_addr, ib_size);
                }
            }
            if (ib_addr) {
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

                // CRITICAL: Call the micro-IB interpreter to execute the commands
                // Even if we don't see the MW05 magic header directly, the interpreter
                // can follow pointers and find the actual rendering commands
                if (IsPM4TracingEnabled()) {
                    KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.execute addr=%08X size=%u", ib_addr, ib_size);
                }
                Mw05InterpretMicroIB(ib_addr, ib_size);
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
                    // Optional: dump syscmd and ring buffers once for offline analysis (controlled by MW05_DUMP_SYSBUF=1)
                    static bool s_dumped_buffers_once = false;
                    if (!s_dumped_buffers_once) {
                        const char* dump_env = std::getenv("MW05_DUMP_SYSBUF");
                        if (dump_env && *dump_env && *dump_env != '0') {
                            // Ensure a local traces directory exists in the current working dir
                            std::error_code ec;
                            std::filesystem::create_directories("traces", ec);
                            auto dump_region = [](const char* path, uint32_t ea_base, uint32_t ea_size) {
                                uint8_t* p = reinterpret_cast<uint8_t*>(g_memory.Translate(ea_base));
                                if (!p || ea_size == 0) return false;
                                std::ofstream f(path, std::ios::binary | std::ios::out);
                                if (!f) return false;
                                f.write(reinterpret_cast<const char*>(p), static_cast<std::streamsize>(ea_size));
                                return true;
                            };
                            // Syscmd window [0x00140000, 0x00150000)
                            dump_region("traces/syscmd_00140000_64k.bin", 0x00140000u, 0x10000u);
                            // Ring window [0x00120000, 0x00130000)
                            dump_region("traces/ring_00120000_64k.bin", 0x00120000u, 0x10000u);
                            // Also dump a 16KB neighborhood around the current micro IB address if within syscmd window
                            if (ib_addr >= 0x00140000u && ib_addr < 0x00150000u) {
                                uint32_t start = (ib_addr >= 0x2000u) ? (ib_addr - 0x2000u) : ib_addr;
                                if (start < 0x00140000u) start = 0x00140000u;
                                uint32_t end = ib_addr + 0x4000u;
                                if (end > 0x00150000u) end = 0x00150000u;
                                if (end > start) {
                                    char path[256];
                                    std::snprintf(path, sizeof(path), "traces/sys_neigh_%08X_%u.bin", start, end - start);
                                    dump_region(path, start, end - start);
                                }
                            }
                            if (IsPM4TracingEnabled()) KernelTraceHostOpF("HOST.PM4.MW05.Dump.sys_ring.once ib=%08X", ib_addr);
                            s_dumped_buffers_once = true;
                        }
                    }

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

                                        // Classify GLAC+MW05 nodes and follow their embedded pointer (d2)
                                        bool looks_glac = (d[0] == 0x43474C41u) || (d[4] == 0x43474C41u);
                                        if (looks_glac && d[1] == 0x3530574Du) {
                                            KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.node.glac_mw05 ea=%08X d0=%08X d1=%08X d2=%08X d3=%08X d4=%08X d5=%08X d6=%08X d7=%08X",
                                                               a, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]);
                                        #if defined(_MSC_VER)
                                            uint32_t follow_ea = _byteswap_ulong(d[2]);
                                        #else
                                            uint32_t follow_ea = __builtin_bswap32(d[2]);
                                        #endif
                                            if ((follow_ea & 0xFFFF0000u) == 0x00140000u) {
                                                uint32_t* fp = reinterpret_cast<uint32_t*>(g_memory.Translate(follow_ea));
                                                if (fp) {
                                                    uint32_t fd[8] = {};
                                                    for (int jj = 0; jj < 8; ++jj) {
                                                    #if defined(_MSC_VER)
                                                        fd[jj] = _byteswap_ulong(fp[jj]);
                                                    #else
                                                        fd[jj] = __builtin_bswap32(fp[jj]);
                                                    #endif
                                                    }
                                                    KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.node.follow ea=%08X -> %08X f0=%08X f1=%08X f2=%08X f3=%08X f4=%08X f5=%08X f6=%08X f7=%08X",
                                                                       a, follow_ea, fd[0], fd[1], fd[2], fd[3], fd[4], fd[5], fd[6], fd[7]);
                                                    // Find a nearby MW05 header to anchor heuristics: either at follow_ea or within +/-0x40
                                                    uint32_t header_ea = 0;
                                                    if (fd[0] == 0x3530574Du) {
                                                        header_ea = follow_ea;
                                                    } else {
                                                        uint32_t sstart = (follow_ea >= 0x40u) ? (follow_ea - 0x40u) : follow_ea;
                                                        uint32_t send = follow_ea + 0x40u;
                                                        for (uint32_t sea = sstart; sea + 4 <= send; sea += 4) {
                                                            auto* sp = reinterpret_cast<uint32_t*>(g_memory.Translate(sea));
                                                            if (!sp) break;
                                                        #if defined(_MSC_VER)
                                                            uint32_t sig = _byteswap_ulong(*sp);
                                                        #else
                                                            uint32_t sig = __builtin_bswap32(*sp);
                                                        #endif
                                                            if (sig == 0x3530574Du) { header_ea = sea; break; }
                                                        }
                                                    }
                                                    if (header_ea) {
                                                        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.header ea=%08X src_ea=%08X", header_ea, follow_ea);

                                                        // Heuristic viewport probe near this MW05 header
                                                        uint32_t scan_start = (header_ea >= 0x80u) ? (header_ea - 0x80u) : header_ea;
                                                        uint32_t scan_end = header_ea + 0x200u;
                                                        uint32_t be_w = 0x00000500u; // 1280
                                                        uint32_t be_h = 0x000002D0u; // 720
                                                        for (uint32_t sea = scan_start; sea + 8 <= scan_end; sea += 4) {
                                                            auto* sp = reinterpret_cast<uint32_t*>(g_memory.Translate(sea));
                                                            if (!sp) break;
                                                        #if defined(_MSC_VER)
                                                            uint32_t s0 = _byteswap_ulong(*sp);
                                                            uint32_t s1 = _byteswap_ulong(*(sp + 1));
                                                        #else
                                                            uint32_t s0 = __builtin_bswap32(*sp);
                                                            uint32_t s1 = __builtin_bswap32(*(sp + 1));
                                                        #endif
                        if (IsApplyHostStateEnabled()) {
                            if (!s_micro_applied_vp_once) {
                                Mw05HostSetViewport(0.0f, 0.0f, 1280.0f, 720.0f, 0.0f, 1.0f);
                                s_micro_applied_vp_once = true;
                            }
                            if (!s_micro_applied_sc_once) {
                                Mw05HostSetScissor(0, 0, 1280, 720);
                                s_micro_applied_sc_once = true;
                        if (IsApplyHostStateEnabled()) {
                            if (!s_micro_applied_vp_once) {
                                Mw05HostSetViewport(0.0f, 0.0f, 1280.0f, 720.0f, 0.0f, 1.0f);
                                s_micro_applied_vp_once = true;
                            }
                            if (!s_micro_applied_sc_once) {
                                Mw05HostSetScissor(0, 0, 1280, 720);
                                s_micro_applied_sc_once = true;
                            }
                            if (!s_micro_bound_rt_once) {
                                Mw05HostApplyColorSurface(s_rb_surface_info, s_rb_color_info);
                                Mw05HostApplyDepthSurface(s_rb_surface_info, s_rb_depth_info);
                                s_micro_bound_rt_once = true;
                            }
                        }
                            }
                            if (!s_micro_bound_rt_once) {
                                Mw05HostApplyColorSurface(s_rb_surface_info, s_rb_color_info);
                                Mw05HostApplyDepthSurface(s_rb_surface_info, s_rb_depth_info);
                                s_micro_bound_rt_once = true;
                            }
                        }
                                                            if (s0 == be_w && s1 == be_h) {
                                                                KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.viewport.candidate near=%08X w=%u h=%u src_ea=%08X hdr=%08X",
                                                                                   sea, 1280u, 720u, follow_ea, header_ea);
                                                                break;
                                                            }
                                                            // Also check for float-based viewport setup (X/Y scale/offset) for 1280x720: 640.0f, 360.0f
                                                            uint32_t f_x = 0x44200000u; // 640.0f
                                                            uint32_t f_y = 0x43B40000u; // 360.0f
                                                            if ((s0 == f_x && s1 == f_y) || (s0 == f_y && s1 == f_x)) {
                                                                KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.viewport.float.candidate near=%08X xs=%f ys=%f src_ea=%08X hdr=%08X",
                                                                                   sea, 640.0f, 360.0f, follow_ea, header_ea);
                                                                break;
                                                            }
                                                        }
                                                        // Conservative small scan to surface any nested PM4 from this MW05 header
                                                        static thread_local int s_node_follow_depth = 0;
                                                        if (s_node_follow_depth == 0) {
                                                            ++s_node_follow_depth;
                                                            PM4_ScanLinear(header_ea, 0x80u);
                                                            --s_node_follow_depth;
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        // Alternate GLAC+MW05 layout observed at 0x001403E0..
                                        if (looks_glac && d[4] == 0x43474C41u && d[5] == 0x3530574Du) {
                                            KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.node.glac_mw05 ea=%08X d0=%08X d1=%08X d2=%08X d3=%08X d4=%08X d5=%08X d6=%08X d7=%08X",
                                                               a, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]);
                                        #if defined(_MSC_VER)
                                            uint32_t follow_ea2 = _byteswap_ulong(d[6]);
                                        #else
                                            uint32_t follow_ea2 = __builtin_bswap32(d[6]);
                                        #endif
                                            if ((follow_ea2 & 0xFFFF0000u) == 0x00140000u) {
                                                uint32_t* fp2 = reinterpret_cast<uint32_t*>(g_memory.Translate(follow_ea2));
                                                if (fp2) {
                                                    uint32_t fd2[8] = {};
                                                    for (int jj = 0; jj < 8; ++jj) {
                                                    #if defined(_MSC_VER)
                                                        fd2[jj] = _byteswap_ulong(fp2[jj]);
                                                    #else
                                                        fd2[jj] = __builtin_bswap32(fp2[jj]);
                                                    #endif
                                                    }
                                                    KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.node.follow ea=%08X -> %08X f0=%08X f1=%08X f2=%08X f3=%08X f4=%08X f5=%08X f6=%08X f7=%08X",
                                                                       a, follow_ea2, fd2[0], fd2[1], fd2[2], fd2[3], fd2[4], fd2[5], fd2[6], fd2[7]);
                                                    // Find a nearby MW05 header to anchor heuristics: either at follow_ea2 or within +/-0x40
                                                    uint32_t header_ea2 = 0;
                                                    if (fd2[0] == 0x3530574Du) {
                                                        header_ea2 = follow_ea2;
                                                    } else {
                                                        uint32_t sstart2 = (follow_ea2 >= 0x40u) ? (follow_ea2 - 0x40u) : follow_ea2;
                                                        uint32_t send2 = follow_ea2 + 0x40u;
                                                        for (uint32_t sea2 = sstart2; sea2 + 4 <= send2; sea2 += 4) {
                                                            auto* sp2 = reinterpret_cast<uint32_t*>(g_memory.Translate(sea2));
                                                            if (!sp2) break;
                                                        #if defined(_MSC_VER)
                                                            uint32_t sig2 = _byteswap_ulong(*sp2);
                                                        #else
                                                            uint32_t sig2 = __builtin_bswap32(*sp2);
                                                        #endif
                                                            if (sig2 == 0x3530574Du) { header_ea2 = sea2; break; }
                                                        }
                                                    }
                                                    if (header_ea2) {
                                                        // Heuristic viewport probe near this MW05 header
                                                        uint32_t scan_start2 = (header_ea2 >= 0x80u) ? (header_ea2 - 0x80u) : header_ea2;
                                                        uint32_t scan_end2 = header_ea2 + 0x200u;
                                                        uint32_t be_w2 = 0x00000500u; // 1280
                                                        uint32_t be_h2 = 0x000002D0u; // 720
                                                        for (uint32_t sea2 = scan_start2; sea2 + 8 <= scan_end2; sea2 += 4) {
                                                            auto* sp2 = reinterpret_cast<uint32_t*>(g_memory.Translate(sea2));
                                                            if (!sp2) break;
                                                        #if defined(_MSC_VER)
                                                            uint32_t t0 = _byteswap_ulong(*sp2);
                                                            uint32_t t1 = _byteswap_ulong(*(sp2 + 1));
                                                        #else
                                                            uint32_t t0 = __builtin_bswap32(*sp2);
                                                            uint32_t t1 = __builtin_bswap32(*(sp2 + 1));

                                                        #endif
                                                            if (t0 == be_w2 && t1 == be_h2) {
                                                                KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.viewport.candidate near=%08X w=%u h=%u src_ea=%08X hdr=%08X",
                                                                                   sea2, 1280u, 720u, follow_ea2, header_ea2);
                                                                break;
                                                            }
                                                            // Float-based viewport probe (640.0f, 360.0f)
                                                            uint32_t f_x2 = 0x44200000u; // 640.0f
                                                            uint32_t f_y2 = 0x43B40000u; // 360.0f
                                                            if ((t0 == f_x2 && t1 == f_y2) || (t0 == f_y2 && t1 == f_x2)) {
                                                                KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.viewport.float.candidate near=%08X xs=%f ys=%f src_ea=%08X hdr=%08X",

                                                                                   sea2, 640.0f, 360.0f, follow_ea2, header_ea2);
                                                                break;
                                                            }
                                                        }
                                                        static thread_local int s_node_follow_depth2 = 0;
                                                        if (s_node_follow_depth2 == 0) {
                        if (IsApplyHostStateEnabled()) {
                            if (!s_micro_applied_vp_once) {
                                Mw05HostSetViewport(0.0f, 0.0f, 1280.0f, 720.0f, 0.0f, 1.0f);
                                s_micro_applied_vp_once = true;
                            }
                            if (!s_micro_applied_sc_once) {
                                Mw05HostSetScissor(0, 0, 1280, 720);
                                s_micro_applied_sc_once = true;
                            }
                            if (!s_micro_bound_rt_once) {
                                Mw05HostApplyColorSurface(s_rb_surface_info, s_rb_color_info);
                                Mw05HostApplyDepthSurface(s_rb_surface_info, s_rb_depth_info);
                                s_micro_bound_rt_once = true;
                            }
                        }
                                                            ++s_node_follow_depth2;
                                                            PM4_ScanLinear(header_ea2, 0x80u);
                                                            --s_node_follow_depth2;
                                                        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.header ea=%08X src_ea=%08X", header_ea2, follow_ea2);

                                                        }
                                                    }
                                                }
                                            }
                        if (IsApplyHostStateEnabled()) {
                            if (!s_micro_applied_vp_once) {
                                Mw05HostSetViewport(0.0f, 0.0f, 1280.0f, 720.0f, 0.0f, 1.0f);
                                s_micro_applied_vp_once = true;
                            }
                            if (!s_micro_applied_sc_once) {
                                Mw05HostSetScissor(0, 0, 1280, 720);
                                s_micro_applied_sc_once = true;
                            }
                            if (!s_micro_bound_rt_once) {
                                Mw05HostApplyColorSurface(s_rb_surface_info, s_rb_color_info);
                                Mw05HostApplyDepthSurface(s_rb_surface_info, s_rb_depth_info);
                                s_micro_bound_rt_once = true;
                            }
                        }
                                        }

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

                            KernelTraceHostOpF("HOST.PM4.MW05.Interpret.call ib=%08X size=%u (magic path)", ib_addr, ib_size);
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
                            // Always hand off to the MW05 interpreter before returning so it can follow pointers
                            KernelTraceHostOpF("HOST.PM4.MW05.Interpret.call ib=%08X size=%u (selfref path)", ib_addr, ib_size);
                            Mw05InterpretMicroIB(ib_addr, ib_size);
                            return size;
                        }
                    } else {
                        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB addr=%08X size=%u (opc=04) translate=null", ib_addr, ib_size);
                    }
                }
                // Give the MW05 interpreter a chance to inspect the buffer as well
                KernelTraceHostOpF("HOST.PM4.MW05.Interpret.call ib=%08X size=%u (post-scan path)", ib_addr, ib_size);
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
                        // As a last resort, scan the whole syscmd window for 'MW05' magic once per thread
                        static thread_local int s_sys_scan_magic_once = 0;
                        if (s_sys_scan_magic_once == 0) {
                            KernelTraceHostOpF("HOST.PM4.MW05.ScanSyscmd.begin 00140000..00150000");
                            uint32_t base_lo = 0x00140000u;
                            uint32_t base_hi = 0x00150000u;
                            for (uint32_t ea = base_lo; ea + 4 <= base_hi; ea += 4) {
                                uint32_t* hp = reinterpret_cast<uint32_t*>(g_memory.Translate(ea));
                                if (!hp) continue;
                                uint32_t be = *hp;
                            #if defined(_MSC_VER)
                                uint32_t le = _byteswap_ulong(be);
                            #else
                                uint32_t le = __builtin_bswap32(be);
                            #endif
                                if (le == 0x3530574Du) {
                                    KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.scan.hit ea=%08X", ea);
                                    // Neighborhood PM4 scan around the header to surface any nested TYPE0/TYPE3
                                    uint32_t start = (ea >= 0x200u) ? (ea - 0x200u) : ea;
                                    uint32_t end = ea + 0x400u;
                                    if (end > base_hi) end = base_hi;
                                    uint32_t size = (end > start) ? (end - start) : 0u;
                                    if (size) {
                                        static thread_local int s_sys_scan_magic_depth = 0;
                                        if (s_sys_scan_magic_depth == 0) {
                                            ++s_sys_scan_magic_depth;
                                            PM4_ScanLinear(start, size);
                                            --s_sys_scan_magic_depth;
                                        }
                                    }
                                    // Give the interpreter a chance to follow embedded pointers
                                    Mw05InterpretMicroIB(ea, 0x100u);
                                    s_sys_scan_magic_once = 1;
                                    break;
                                }
                            }
                        }
                            KernelTraceHostOpF("HOST.PM4.MW05.ScanRing.begin 00120000..00130000");
                            if (s_sys_scan_magic_once == 0) {
                                // Also scan the primary ring buffer region for safety
                                uint32_t r_lo = 0x00120000u;
                                uint32_t r_hi = 0x00130000u;
                                for (uint32_t ea = r_lo; ea + 4 <= r_hi; ea += 4) {
                                    uint32_t* hp = reinterpret_cast<uint32_t*>(g_memory.Translate(ea));
                                    if (!hp) continue;
                                    uint32_t be = *hp;
                                #if defined(_MSC_VER)
                                    uint32_t le = _byteswap_ulong(be);
                                #else
                                    uint32_t le = __builtin_bswap32(be);
                                #endif
                                    if (le == 0x3530574Du) {
                                        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.scan.hit ea=%08X (ring)", ea);
                                        uint32_t start = (ea >= 0x200u) ? (ea - 0x200u) : ea;
                                        uint32_t end = ea + 0x400u;
                                        if (end > r_hi) end = r_hi;
                                        uint32_t size = (end > start) ? (end - start) : 0u;
                                        if (size) {
                                            static thread_local int s_ring_scan_magic_depth = 0;
                                            if (s_ring_scan_magic_depth == 0) {
                                                ++s_ring_scan_magic_depth;
                                                PM4_ScanLinear(start, size);
                                // Optional much wider scan when enabled (covers 0x00100000..0x00200000 once)
                                static const bool s_scan_wider = [](){ if (const char* v = std::getenv("MW05_PM4_SCAN_WIDER")) return !(v[0]=='0' && v[1]=='\0'); return false; }();
                                if (s_scan_wider) {
                                    KernelTraceHostOpF("HOST.PM4.MW05.ScanWider.begin 00100000..00200000");
                                    uint32_t w2_lo = 0x00100000u;
                                    uint32_t w2_hi = 0x00200000u;
                                    uint32_t steps2 = 0;
                                    for (uint32_t ea2 = w2_lo; ea2 + 4 <= w2_hi && steps2 < 262144; ea2 += 4, ++steps2) {
                                        uint32_t* hp2 = (uint32_t*)g_memory.Translate(ea2);
                                        if (!hp2) continue;
                                        uint32_t le2 =
                                        #if defined(_MSC_VER)
                                            _byteswap_ulong(*hp2);
                                        #else
                                            __builtin_bswap32(*hp2);
                                        #endif
                                        if (le2 == 0x3530574Du) {
                                            KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.scan.hit ea=%08X (wider)", ea2);
                                            uint32_t s = (ea2 >= 0x200u) ? (ea2 - 0x200u) : ea2;
                                            uint32_t e = ea2 + 0x400u; if (e > w2_hi) e = w2_hi;
                                            if (e > s) PM4_ScanLinear(s, e - s);
                                            Mw05InterpretMicroIB(ea2, 0x100u);
                                            break;
                                        }
                                    }
                                }

                                                --s_ring_scan_magic_depth;
                                            }
                                        }
                                        Mw05InterpretMicroIB(ea, 0x100u);
                                        s_sys_scan_magic_once = 1;
                                        break;
                                    }
                            if (s_sys_scan_magic_once == 0) {
                                // Wider pass: scan 0x00130000..0x00190000 once, capped window
                                KernelTraceHostOpF("HOST.PM4.MW05.ScanWide.begin 00130000..00190000");
                                uint32_t w_lo = 0x00130000u;
                                uint32_t w_hi = 0x00190000u;
                                uint32_t steps = 0;
                                for (uint32_t ea = w_lo; ea + 4 <= w_hi; ea += 4) {
                                    uint32_t* hp = reinterpret_cast<uint32_t*>(g_memory.Translate(ea));
                                    if (!hp) continue;
                                    uint32_t be = *hp;
                                #if defined(_MSC_VER)
                                    uint32_t le = _byteswap_ulong(be);
                                #else
                                    uint32_t le = __builtin_bswap32(be);
                                #endif
                                    if (le == 0x3530574Du) {
                                        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.scan.hit ea=%08X (wide)", ea);
                                        uint32_t start = (ea >= 0x200u) ? (ea - 0x200u) : ea;
                                        uint32_t end = ea + 0x400u;
                                        if (end > w_hi) end = w_hi;
                                        uint32_t size = (end > start) ? (end - start) : 0u;
                                        if (size) PM4_ScanLinear(start, size);
                                        Mw05InterpretMicroIB(ea, 0x100u);
                                        s_sys_scan_magic_once = 1;
                                        break;
                                    }
                                    if (++steps > 32768) {
                                        // Cap scan work to avoid long stalls
                                        break;
                                    }
                                }
                            }

                                }
                            }


                    }
                }
            }
                // Unconditional wide scans (outside tracing gate) to find MW05 headers in memory once
                static thread_local int s_any_scan_once = 0;
                if (s_any_scan_once == 0) {
                    // Syscmd window
                    KernelTraceHostOpF("HOST.PM4.MW05.ScanSyscmd.begin 00140000..00150000");
                    for (uint32_t ea = 0x00140000u; ea + 4 <= 0x00150000u; ea += 4) {
                        uint32_t* hp = (uint32_t*)g_memory.Translate(ea);
                        if (!hp) continue;
                    #if defined(_MSC_VER)
                        uint32_t le = _byteswap_ulong(*hp);
                    #else
                        uint32_t le = __builtin_bswap32(*hp);
                    #endif
                        if (le == 0x3530574Du) {
                            KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.scan.hit ea=%08X", ea);
                            uint32_t start = (ea >= 0x200u) ? (ea - 0x200u) : ea;
                            uint32_t end = ea + 0x400u;
                            if (end > 0x00150000u) end = 0x00150000u;
                            if (end > start) PM4_ScanLinear(start, end - start);
                            Mw05InterpretMicroIB(ea, 0x100u);
                            s_any_scan_once = 1;
                            break;
                        }
                    }
                    // Ring window
                    if (s_any_scan_once == 0) {
                        KernelTraceHostOpF("HOST.PM4.MW05.ScanRing.begin 00120000..00130000");
                        for (uint32_t ea = 0x00120000u; ea + 4 <= 0x00130000u; ea += 4) {
                            uint32_t* hp = (uint32_t*)g_memory.Translate(ea);
                            if (!hp) continue;
                        #if defined(_MSC_VER)
                            uint32_t le = _byteswap_ulong(*hp);
                        #else
                            uint32_t le = __builtin_bswap32(*hp);
                        #endif
                            if (le == 0x3530574Du) {
                                KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.scan.hit ea=%08X (ring)", ea);
                                uint32_t start = (ea >= 0x200u) ? (ea - 0x200u) : ea;
                                uint32_t end = ea + 0x400u;
                                if (end > 0x00130000u) end = 0x00130000u;
                                if (end > start) PM4_ScanLinear(start, end - start);
                                Mw05InterpretMicroIB(ea, 0x100u);
                                s_any_scan_once = 1;
                                break;
                            }
                        }
                    }
                    // Wider
                    if (s_any_scan_once == 0) {
                        KernelTraceHostOpF("HOST.PM4.MW05.ScanWide.begin 00130000..00190000");
                        uint32_t steps = 0;
                        for (uint32_t ea = 0x00130000u; ea + 4 <= 0x00190000u; ea += 4) {
                            uint32_t* hp = (uint32_t*)g_memory.Translate(ea);
                            if (!hp) continue;
                        #if defined(_MSC_VER)
                            uint32_t le = _byteswap_ulong(*hp);
                        #else
                            uint32_t le = __builtin_bswap32(*hp);
                        #endif
                            if (le == 0x3530574Du) {
                                KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.scan.hit ea=%08X (wide)", ea);
                                uint32_t start = (ea >= 0x200u) ? (ea - 0x200u) : ea;
                                uint32_t end = ea + 0x400u;
                                if (end > 0x00190000u) end = 0x00190000u;
                                if (end > start) PM4_ScanLinear(start, end - start);
                                Mw05InterpretMicroIB(ea, 0x100u);
                                s_any_scan_once = 1;
                                break;
                            }
                            if (++steps > 32768) break;
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
                // Record for opc=04 correlation
                RecordRecentRegWrite(reg, val);
                // If budget remains, log every register write with its high-byte group to map ranges quickly
                if (s_reg_log_budget > 0) {
                    --s_reg_log_budget;
                    KernelTraceHostOpF("HOST.PM4.TYPE0.REG reg=%04X grp=%02X val=%08X", reg, (reg >> 8) & 0xFFu, val);
                }
                // Apply a minimal subset of render state to the host when enabled.
                if (IsApplyHostStateEnabled()) {
                    auto as_float = [](uint32_t u) {
                        float f; std::memcpy(&f, &u, sizeof(f)); return f;
                    };
                    switch (reg) {
                        case 0x210F: s_vp_accum.xs = as_float(val); s_vp_accum.have_xs = true; break;
                        case 0x2110: s_vp_accum.xo = as_float(val); s_vp_accum.have_xo = true; break;
                        case 0x2111: s_vp_accum.ys = as_float(val); s_vp_accum.have_ys = true; break;
                        case 0x2112: s_vp_accum.yo = as_float(val); s_vp_accum.have_yo = true; break;
                        case 0x2113: s_vp_accum.zs = as_float(val); s_vp_accum.have_zs = true; break;
                        case 0x2114: s_vp_accum.zo = as_float(val); s_vp_accum.have_zo = true; break;
                        case 0x200E: /* PA_SC_SCREEN_SCISSOR_TL */
                        case 0x2081: /* PA_SC_WINDOW_SCISSOR_TL */
                            s_sc_tl = val; break;
                        case 0x200F: /* PA_SC_SCREEN_SCISSOR_BR */
                        case 0x2082: /* PA_SC_WINDOW_SCISSOR_BR */
                            s_sc_br = val; break;
                        default: break;
                    }
                    // Track RB_* surface registers for first-time application
                    if (reg == 0x2000) { s_rb_surface_info = val; }
                    if (reg == 0x2001) { s_rb_color_info = val; }
                    if (reg == 0x2002) { s_rb_depth_info = val; }

                    // If we have enough to form a viewport, push it.
                    if (s_vp_accum.have_xs && s_vp_accum.have_xo && s_vp_accum.have_ys && s_vp_accum.have_yo) {
                        float xs = s_vp_accum.xs, xo = s_vp_accum.xo;
                        float ys = s_vp_accum.ys, yo = s_vp_accum.yo;
                        float width = 2.0f * std::fabs(xs);
                        float height = 2.0f * std::fabs(ys);
                        float x = xo - xs;
                        float y = yo - ys;
                        float minZ = 0.0f, maxZ = 1.0f;
                        if (s_vp_accum.have_zs && s_vp_accum.have_zo) {
                            minZ = s_vp_accum.zo - s_vp_accum.zs;
                            maxZ = s_vp_accum.zo + s_vp_accum.zs;
                            if (minZ > maxZ) std::swap(minZ, maxZ);
                            minZ = std::clamp(minZ, 0.0f, 1.0f);
                            maxZ = std::clamp(maxZ, 0.0f, 1.0f);
                        }
                        Mw05HostSetViewport(x, y, width, height, minZ, maxZ);
                    }
                    // If we have a scissor TL/BR, push it.
                    if ((s_sc_tl | s_sc_br) != 0) {
                        int32_t left  = int32_t(s_sc_tl & 0x7FFFu);
                        int32_t top   = int32_t((s_sc_tl >> 16) & 0x7FFFu);
                        int32_t right = int32_t(s_sc_br & 0x7FFFu);
                        int32_t bottom= int32_t((s_sc_br >> 16) & 0x7FFFu);
                        if (right > left && bottom > top) {
                            Mw05HostSetScissor(left, top, right, bottom);
                        }
                    }
                    // If first non-zero RB_* seen, bind targets once (gated)
                    if (!s_rt_applied_once && s_rb_color_info != 0) {
                        Mw05HostApplyColorSurface(s_rb_surface_info, s_rb_color_info);
                        s_rt_applied_once = true;
                    }
                    if (!s_ds_applied_once && s_rb_depth_info != 0) {
                        Mw05HostApplyDepthSurface(s_rb_surface_info, s_rb_depth_info);
                        s_ds_applied_once = true;
                    }

                }
                // Focused, low-noise logging of known interesting regs (names from Xenia)
                if (IsPM4TraceInterestingRegsEnabled()) {
                    if (const char* name = XenosRegName(reg)) {
                        if (XenosRegIsViewportFloat(reg)) {
                            float f;
                            static_assert(sizeof(f) == sizeof(uint32_t), "float size");
                            std::memcpy(&f, &val, sizeof(f));
                            KernelTraceHostOpF("HOST.PM4.TYPE0.REG.named reg=%04X name=%s f=%f val=%08X", reg, name, f, val);
                        } else if (reg == 0x200E || reg == 0x200F || reg == 0x2081 || reg == 0x2082) {
                            uint32_t x = val & 0x7FFFu;
                            uint32_t y = (val >> 16) & 0x7FFFu;
                            KernelTraceHostOpF("HOST.PM4.TYPE0.REG.named reg=%04X name=%s x=%u y=%u raw=%08X", reg, name, x, y, val);
                        } else {
                            KernelTraceHostOpF("HOST.PM4.TYPE0.REG.named reg=%04X name=%s val=%08X", reg, name, val);
                        }
                    }
                }
                // Optional: log first transition to non-zero for key regs (low-noise)
                if (IsPm4RegChangeLogEnabled()) {
                    static uint32_t s_last_rb_color_info = 0, s_last_rb_depth_info = 0;
                    static uint32_t s_last_vp_regs[6] = {0}; // 210F..2114
                    static uint32_t s_last_sc_tl = 0, s_last_sc_br = 0;
                    if (reg == 0x2001 && val != s_last_rb_color_info) {
                        KernelTraceHostOpF("HOST.PM4.TYPE0.REG.change RB_COLOR_INFO %08X -> %08X", s_last_rb_color_info, val);
                        s_last_rb_color_info = val;
                    }
                    if (reg == 0x2002 && val != s_last_rb_depth_info) {
                        KernelTraceHostOpF("HOST.PM4.TYPE0.REG.change RB_DEPTH_INFO %08X -> %08X", s_last_rb_depth_info, val);
                        s_last_rb_depth_info = val;
                    }
                    if (reg >= 0x210F && reg <= 0x2114) {
                        uint32_t idx = reg - 0x210F;
                        if (val != s_last_vp_regs[idx]) {
                            KernelTraceHostOpF("HOST.PM4.TYPE0.REG.change VP[%u] %08X -> %08X", idx, s_last_vp_regs[idx], val);
                            s_last_vp_regs[idx] = val;
                        }
                    }
                    if ((reg == 0x200E && val != s_last_sc_tl) || (reg == 0x200F && val != s_last_sc_br)) {
                        KernelTraceHostOpF("HOST.PM4.TYPE0.REG.change SC %08X,%08X -> %08X,%08X", s_last_sc_tl, s_last_sc_br,
                            reg == 0x200E ? val : s_last_sc_tl, reg == 0x200F ? val : s_last_sc_br);
                        if (reg == 0x200E) s_last_sc_tl = val; else s_last_sc_br = val;
                    }
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
    static int s_dumpCount = 0;
    if (++s_dumpCount % 10 != 0) return; // Only dump every 10th call to reduce spam

    fprintf(stderr, "\n[PM4-OPCODE-HISTOGRAM] Dump #%d:\n", s_dumpCount / 10);
    for (int i = 0; i < 128; ++i) {
        uint64_t c = g_opcodeCounts[i].load(std::memory_order_relaxed);
        if (!c) continue;
        fprintf(stderr, "  [PM4-OPC] 0x%02X = %llu\n", i, (unsigned long long)c);
    }
    fprintf(stderr, "[PM4-OPCODE-HISTOGRAM] End dump\n\n");
    fflush(stderr);
}

