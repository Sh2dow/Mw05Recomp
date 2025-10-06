#include "stdafx.h"
#include <atomic>
#include <cstdint>
#include "kernel/trace.h"
#include "kernel/memory.h"
#include "mw05_micro_interpreter.h"

// Forward for the existing debug clear used to force visible frames (kept disabled by default)
#include <unordered_set>
#include <vector>
#include <string>

extern "C" void Mw05DebugKickClear();

// From pm4_parser.cpp
void PM4_ScanLinear(uint32_t addr, uint32_t bytes);
// PM4 parser helpers we can invoke for broader scans / histograms
void PM4_DebugScanAll_Force();
void PM4_DumpOpcodeHistogram();

static inline bool IsFullPM4ScanEnabled() {
    if (const char* v = std::getenv("MW05_PM4_SCAN_FULL")) return !(v[0]=='0' && v[1]=='\0');
    return false;
}


extern "C" {
    // Accessors exposed by kernel/imports for ring/syscmd buffers
    uint32_t Mw05GetRingBaseEA();
    uint32_t Mw05GetRingSizeBytes();
}

// Host-side helpers to enqueue real render commands (declared in video.cpp)
extern "C" void Mw05HostSetViewport(float x, float y, float width, float height, float minDepth, float maxDepth);
extern "C" void Mw05HostSetScissor(int32_t left, int32_t top, int32_t right, int32_t bottom);
extern "C" void Mw05HostApplyColorSurface(uint32_t rbSurfaceInfo, uint32_t rbColorInfo);
extern "C" void Mw05HostApplyDepthSurface(uint32_t rbSurfaceInfo, uint32_t rbDepthInfo);

static inline bool IsApplyHostStateEnabled() {
    if (const char* v = std::getenv("MW05_PM4_APPLY_STATE")) return !(v[0]=='0' && v[1]=='\0');
    return false;
}

static thread_local bool s_bound_rt_once = false;
static thread_local bool s_applied_vp_once = false;
static thread_local bool s_applied_sc_once = false;



// Forward declarations for local helpers used by the micro tree dumper
static inline uint32_t bswap32(uint32_t v);
static inline int32_t be_low_s16_from_le(uint32_t le_word);

static inline bool IsMicroTreeDumpEnabled() {
    if (const char* v = std::getenv("MW05_MICRO_TREE")) return !(v[0]=='0' && v[1]=='\0');
    return false;
}

struct MicroNode {
    uint32_t ea;
    uint32_t d[8];
};

static void DumpMicroNode(uint32_t ea, const uint32_t d[8], int depth) {
    KernelTraceHostOpF("HOST.MW05.Micro.node depth=%d ea=%08X d0=%08X d1=%08X d2=%08X d3=%08X d4=%08X d5=%08X d6=%08X d7=%08X",
        depth, ea, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]);
}

static void WalkMicroTree(uint32_t root_ea, int max_depth = 3, int max_nodes = 128) {
    if (!IsMicroTreeDumpEnabled()) return;
    auto is_sys = [](uint32_t v){ return (v & 0xFFFF0000u) == 0x00140000u; };

    std::unordered_set<uint32_t> seen;
    std::vector<std::pair<uint32_t,int>> stack;
    stack.emplace_back(root_ea, 0);

    int nodes = 0;
    while (!stack.empty() && nodes < max_nodes) {
        auto [ea, depth] = stack.back(); stack.pop_back();
        if (!ea || !is_sys(ea) || seen.count(ea) || depth > max_depth) continue;
        seen.insert(ea);

        uint32_t* p = reinterpret_cast<uint32_t*>(g_memory.Translate(ea));
        if (!p) continue;
        uint32_t d[8]{};
        for (int i = 0; i < 8; ++i) d[i] = bswap32(p[i]);
        DumpMicroNode(ea, d, depth);
        ++nodes;

        // Follow common patterns observed: GLAC/MW05 headers and pointer slots.
        // Layout A: d0=GLAC, d1=MW05, d2=ptr
        if (d[0] == 0x43474C41u && d[1] == 0x3530574Du && is_sys(d[2]))
            stack.emplace_back(d[2], depth + 1);
        // Layout B: d4=GLAC, d5=MW05, d6=ptr
        if (d[4] == 0x43474C41u && d[5] == 0x3530574Du && is_sys(d[6]))
            stack.emplace_back(d[6], depth + 1);
        // If node is MW05 at d0, follow d1 (ptr) with d3 as signed offset (like outer header)
        if (d[0] == 0x3530574Du) {
            uint32_t follow = d[1];
            int32_t  rel    = be_low_s16_from_le(d[3]);
            uint32_t eff    = follow + rel;
            if (is_sys(eff)) stack.emplace_back(eff, depth + 1);
        }
    }
}

static inline void MaybeWalkMicroTree(uint32_t eff_root) {
    if (!IsMicroTreeDumpEnabled()) return;
    WalkMicroTree(eff_root, /*max_depth*/4, /*max_nodes*/256);
}

// Simple guard to avoid spamming anything in tight loops
static std::atomic<uint32_t> s_clearCounter{0};

static inline uint32_t bswap32(uint32_t v) {
#if defined(_MSC_VER)
    return _byteswap_ulong(v);
#else
    return __builtin_bswap32(v);
#endif
}

// Extract signed 16-bit from the BE low 16 bits of a dword that we've already byteswapped to LE.
// For a LE value x, BE low16 corresponds to the LE high16 bits.
static inline int32_t be_low_s16_from_le(uint32_t le_word) {
    uint32_t hi16 = (le_word >> 16) & 0xFFFFu;
    return static_cast<int16_t>(hi16);
}

extern "C" void Mw05InterpretMicroIB(uint32_t ib_addr, uint32_t ib_size)
{
    KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.Interpret start ea=%08X size=%u", ib_addr, ib_size);
    // Optional one-time dumps of syscmd/ring for offline analysis (MW05_DUMP_SYSBUF=1)
    static bool s_dumped_once = false;
    if (!s_dumped_once) {
        const char* dump_env = std::getenv("MW05_DUMP_SYSBUF");
        if (dump_env && *dump_env && *dump_env != '0') {
        #if __has_include(<filesystem>)
            std::error_code ec;
            std::filesystem::create_directories("traces", ec);
        #endif
            auto dump_region = [](const char* path, uint32_t ea_base, uint32_t ea_size) {
                uint8_t* pbytes = reinterpret_cast<uint8_t*>(g_memory.Translate(ea_base));
                if (!pbytes || ea_size == 0) return false;
                std::ofstream f(path, std::ios::binary | std::ios::out);
                if (!f) return false;
                f.write(reinterpret_cast<const char*>(pbytes), static_cast<std::streamsize>(ea_size));
                return true;
            };
            dump_region("traces/syscmd_00140000_64k.bin", 0x00140000u, 0x10000u);
            dump_region("traces/ring_00120000_64k.bin", 0x00120000u, 0x10000u);
            // Also dump the 0x00130000 window as some micro pairs reference 0x0013xxxx
            dump_region("traces/blk_00130000_64k.bin", 0x00130000u, 0x10000u);
            if (ib_addr >= 0x00140000u && ib_addr < 0x00150000u) {
                uint32_t start = ib_addr > 0x2000u ? (ib_addr - 0x2000u) : ib_addr;
                if (start < 0x00140000u) start = 0x00140000u;
                uint32_t end = ib_addr + 0x4000u;
                if (end > 0x00150000u) end = 0x00150000u;
                if (end > start) {
                    char path[256];
                    std::snprintf(path, sizeof(path), "traces/sys_neigh_%08X_%u.bin", start, end - start);
                    dump_region(path, start, end - start);
                }
            }
            KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.dump.once ib=%08X", ib_addr);
            s_dumped_once = true;
        }
    }


    uint32_t* p = reinterpret_cast<uint32_t*>(g_memory.Translate(ib_addr));
    if (!p) return;

    // Read a small header window and swap to host LE for analysis
    uint32_t d[16]{};
    for (int i = 0; i < 16; ++i) d[i] = bswap32(p[i]);
    KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.hdr d0=%08X d1=%08X d2=%08X d3=%08X d4=%08X d5=%08X d6=%08X d7=%08X",
                       d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]);

    // Two observed layouts:
    // A) Direct MW05 header: d0 == 'MW05' (0x3530574D BE after swap). In this case:
    //    - d1 = EA to another micro list (already swapped to LE)
    //    - d3 BE low16 = signed byte offset to apply
    //    - d5 may carry a tiny size hint
    // B) Wrapper layout (observed):
    //    - d0 = base EA inside 0x0014xxxx (e.g., 0x00140410)
    //    - d1 = signed relative offset (appears to be in dwords; e.g., 0xFFFFFFF9 = -7)
    //    - d2 = small size in bytes (e.g., 0x20)
    //    - subsequent pairs repeat (d3=-7, d4=0x20, ...)

    bool is_direct_mw = (d[0] == 0x3530574Du);

    // Conservatively bind RT/DS once so real draws (when decoded) have a target
    if (IsApplyHostStateEnabled()) {
        if (!s_bound_rt_once) {
            KernelTraceHostOpF("HOST.MW05.MicroIB.bind.once RTDS");
            Mw05HostApplyColorSurface(0, 0);
            Mw05HostApplyDepthSurface(0, 0);
            s_bound_rt_once = true;
        }
    }

    uint32_t eff = 0;
    uint32_t sz = ib_size;
    uint32_t follow_ea = 0;
    int32_t  rel_bytes = 0;

    if (is_direct_mw) {
        // Layout A
        auto fixup_ea = [](uint32_t ea) {
            if (ea >= 0x00020000u && ea < 0x00060000u) return (ea | 0x00100000u);
            return ea;
        };
        follow_ea = fixup_ea(d[1]);
        rel_bytes = be_low_s16_from_le(d[3]); // signed byte offset in bytes
        eff = follow_ea + rel_bytes;
        eff = fixup_ea(eff);
        // Optional tiny size hint via d5 high bytes
        uint32_t cand_be_low = (d[5] << 24) | ((d[5] << 8) & 0x00FF0000);
        uint32_t cand = (cand_be_low >> 24);
        if (cand > 0 && cand <= 0x4000) sz = std::min(sz ? sz : cand, 0x4000u);
        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.mode=A eff_pre=%08X follow=%08X off=%d ib=%08X", eff, follow_ea, rel_bytes, ib_addr);
    } else {
        // Layout B (wrapper): treat d0 as base EA; d1 as signed dword offset; d2 as size in bytes
        uint32_t base_ea = d[0];
        // Fixup: MW05 often stores syscmd/ring EAs without the 0x00100000 high bits (e.g., 0x00040410 for 0x00140410)
        auto fixup_ea = [](uint32_t ea) {
            if (ea >= 0x00020000u && ea < 0x00060000u) return (ea | 0x00100000u);
            return ea;
        };
        base_ea = fixup_ea(base_ea);
        int32_t rel_dw = static_cast<int32_t>(d[1]); // already LE; appears to be in dwords
        rel_bytes = rel_dw * 4; // convert to bytes
        follow_ea = base_ea;
        eff = base_ea + rel_bytes;
        eff = fixup_ea(eff);
        if (d[2] > 0 && d[2] <= 0x4000u) sz = d[2];
        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.mode=B eff_pre=%08X base=%08X off_dw=%d off_b=%d sz_hint=%u ib=%08X", eff, base_ea, rel_dw, rel_bytes, sz, ib_addr);
    }

    // Log calculation, then follow the effective target if it translates; otherwise fall back
    KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.eff.calc eff=%08X follow=%08X off=%d sz_hint=%u ib=%08X", eff, follow_ea, rel_bytes, sz, ib_addr);
    if (void* eff_ptr = g_memory.Translate(eff)) {
        if (sz == 0 || sz > 0x8000u) sz = 0x400u; // conservative cap when unknown
        // Peek at first 8 dwords of the effective target
        uint32_t* pe = reinterpret_cast<uint32_t*>(eff_ptr);
        uint32_t ed[8]{}; for (int i = 0; i < 8; ++i) ed[i] = bswap32(pe[i]);
        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.eff.hdr ea=%08X e0=%08X e1=%08X e2=%08X e3=%08X e4=%08X e5=%08X e6=%08X e7=%08X",
            eff, ed[0], ed[1], ed[2], ed[3], ed[4], ed[5], ed[6], ed[7]);
        // If target looks like a TYPE3 packet header, widen scan window and dump payload
        bool is_type3 = (((ed[0] >> 30) & 0x3u) == 3u);
        if (is_type3) {
            uint32_t hdr = ed[0];
            uint32_t count = (hdr >> 16) & 0x3FFFu;
            uint32_t opcode = (hdr >> 8) & 0xFFu;
            KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.eff.pm4 header ea=%08X op=%02X count=%u", eff, opcode, count);
            // Dump up to 32 dwords of payload for analysis (already big->host swapped)
            uint32_t dump = (count < 32u) ? count : 32u;
            for (uint32_t i = 0; i < dump; i += 8) {
                uint32_t w[8]{};
                for (uint32_t j = 0; j < 8 && (i + j) < dump; ++j) {
                    w[j] = bswap32(pe[1 + i + j]);
                }
                KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.eff.pm4.payload ea=%08X i=%u w0=%08X w1=%08X w2=%08X w3=%08X w4=%08X w5=%08X w6=%08X w7=%08X",
                    eff, i, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
            }
            // Interpret payload as pairs: (rel_dw_hi16|size_lo16, base_ea)
            for (uint32_t i = 0; (i + 1) < count; i += 2) {
                uint32_t wrel = bswap32(pe[1 + i]);
                uint32_t base_ea2 = bswap32(pe[1 + i + 1]);
                // Fixup base if MW05 stored it without high bits
                auto fixup_ea2 = [](uint32_t ea) {
                    if (ea >= 0x00020000u && ea < 0x00060000u) return (ea | 0x00100000u);
                    return ea;
                };
                base_ea2 = fixup_ea2(base_ea2);
                // Heuristic: high16 is signed dword offset, low16 is a size hint in bytes
                int16_t rel_dw_s16 = static_cast<int16_t>((wrel >> 16) & 0xFFFF);
                int32_t rel_b = static_cast<int32_t>(rel_dw_s16) * 4;
                uint16_t size_hint = static_cast<uint16_t>(wrel & 0xFFFF);
                uint32_t eff2 = base_ea2 + rel_b;
                eff2 = fixup_ea2(eff2);
                // Constrain to syscmd window to avoid host page faults
                const uint32_t win_lo = 0x00120000u; // include ring area too
                const uint32_t win_hi = 0x00150000u;
                if (eff2 < win_lo || eff2 >= win_hi) {
                    KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.chain.outside eff2=%08X base=%08X rel_dw=%d size_hint=%u", eff2, base_ea2, (int)rel_dw_s16, (unsigned)size_hint);
                    continue;
                }
                void* p2 = g_memory.Translate(eff2);
                if (!p2) {
                    KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.chain.translate.null eff2=%08X base=%08X rel_dw=%d size_hint=%u", eff2, base_ea2, (int)rel_dw_s16, (unsigned)size_hint);
                    continue;
                }
                uint32_t* p32 = reinterpret_cast<uint32_t*>(p2);
                // Safely read up to 8 dwords within the window
                uint32_t avail_bytes = (win_hi - eff2);
                uint32_t avail_words = avail_bytes / 4;
                uint32_t to_read = (avail_words < 8u) ? avail_words : 8u;
                uint32_t eh[8]{};
                for (uint32_t k = 0; k < to_read; ++k) eh[k] = bswap32(p32[k]);
                // Dump a small window (up to 16 dwords) around eff2 for forensics
                {
                    uint32_t dump_n = (to_read < 16u) ? to_read : 16u;
                    for (uint32_t di = 0; di < dump_n; di += 8) {
                        uint32_t w[8]{};
                        for (uint32_t dj = 0; dj < 8 && (di + dj) < dump_n; ++dj) w[dj] = eh[di + dj];
                        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.chain.dump eff2=%08X i=%u w0=%08X w1=%08X w2=%08X w3=%08X w4=%08X w5=%08X w6=%08X w7=%08X",
                            eff2, di, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
                    }
                }

                KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.chain.hdr eff2=%08X base=%08X rel_dw=%d size_hint=%u e0=%08X e1=%08X e2=%08X e3=%08X",
                    eff2, base_ea2, (int)rel_dw_s16, (unsigned)size_hint, eh[0], eh[1], eh[2], eh[3]);

                // Look for inline TYPE3 headers within the first 8 dwords and follow them too
                for (uint32_t hk = 0; hk < to_read; ++hk) {
                    uint32_t hdr3 = eh[hk];
                    bool is_t3 = (((hdr3 >> 30) & 0x3u) == 3u);
                    if (!is_t3) continue;
                    uint32_t opcode3 = (hdr3 >> 8) & 0xFFu;
                    uint32_t count3 = (hdr3 >> 16) & 0x3FFFu;
                    // Sanity: avoid misclassifying arbitrary 0xFFFFxxxx as TYPE3
                    if (count3 == 0 || count3 > 0x100u) continue;
                    if ((hk + 1 + count3) > to_read) continue; // payload must fit in our window
                    uint32_t eff3 = eff2 + hk * 4;
                    KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.chain.inline.pm4 header ea=%08X op=%02X count=%u", eff3, opcode3, count3);
                    // Dump a few payload dwords
                    uint32_t dump3 = (count3 < 16u) ? count3 : 16u;
                    for (uint32_t i3 = 0; i3 < dump3; i3 += 8) {
                        uint32_t w[8]{};
                        for (uint32_t j3 = 0; j3 < 8 && (i3 + j3) < dump3; ++j3) w[j3] = bswap32(p32[hk + 1 + i3 + j3]);
                        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.chain.inline.pm4.payload ea=%08X i=%u w0=%08X w1=%08X w2=%08X w3=%08X w4=%08X w5=%08X w6=%08X w7=%08X",
                            eff3, i3, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
                    }
                    if (opcode3 == 0x04) {
                        // Interpret as pairs and follow
                        for (uint32_t i3 = 0; (i3 + 1) < count3; i3 += 2) {
                            uint32_t wrel3 = bswap32(p32[hk + 1 + i3]);
                            uint32_t base3 = bswap32(p32[hk + 1 + i3 + 1]);
                            int16_t rel_dw3 = static_cast<int16_t>((wrel3 >> 16) & 0xFFFF);
                            uint16_t sz3 = static_cast<uint16_t>(wrel3 & 0xFFFF);
                            int32_t rel_b3 = static_cast<int32_t>(rel_dw3) * 4;
                            uint32_t eff4 = base3 + rel_b3;
                            const uint32_t win_lo2 = 0x00120000u, win_hi2 = 0x00150000u;
                            if (eff4 < win_lo2 || eff4 >= win_hi2) {
                                KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.chain.inline.outside eff=%08X base=%08X rel_dw=%d size_hint=%u", eff4, base3, (int)rel_dw3, (unsigned)sz3);
                                continue;
                            }
                            KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.chain.inline.follow eff=%08X base=%08X rel_dw=%d size_hint=%u", eff4, base3, (int)rel_dw3, (unsigned)sz3);
                            uint32_t scan_sz2 = sz3 ? ((sz3 + 3u) & ~3u) : 0x200u;
                            uint32_t scan_end2 = eff4 + scan_sz2; if (scan_end2 > win_hi2) scan_end2 = win_hi2;
                            if (scan_end2 > eff4) PM4_ScanLinear(eff4, scan_end2 - eff4);
                        }
                    } else {
                        // Log presence of any non-0x04 TYPE3 opcodes inline for later mapping
                        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.chain.inline.pm4.non04 ea=%08X op=%02X count=%u", eff3, opcode3, count3);
                    }
                    // Note: do not break; scan across the small inline window to surface multiple headers
                }

                // Light scan around each nested target within bounds (prefer size_hint when present)
                uint32_t scan_sz = size_hint ? ((size_hint + 3u) & ~3u) : 0x200u;
                uint32_t scan_end = eff2 + scan_sz; if (scan_end > win_hi) scan_end = win_hi;
                if (scan_end > eff2) PM4_ScanLinear(eff2, scan_end - eff2);

            }
            sz = std::max<uint32_t>(sz, 0x400u);
        }
        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.eff ea=%08X follow=%08X off=%d size=%u", eff, follow_ea, rel_bytes, sz);
        PM4_ScanLinear(eff, sz);
        MaybeWalkMicroTree(eff);
    } else {
        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.eff.translate.null eff=%08X follow=%08X off=%d sz_hint=%u", eff, follow_ea, rel_bytes, sz);
        // Fallback: neighborhood scan around the IB within the syscmd window
        uint32_t base_lo = 0x00140000u, base_hi = 0x00150000u;
        uint32_t start = ib_addr > 0x100u ? (ib_addr - 0x100u) : ib_addr;
        if (start < base_lo) start = base_lo;
        uint32_t end = ib_addr + (sz ? sz : 0x400u);
        if (end > base_hi) end = base_hi;
        if (end > start) {
            KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.neigh start=%08X size=%u", start, end - start);
            PM4_ScanLinear(start, end - start);
    // Optional full-window PM4 scan for diagnostics
    if (IsFullPM4ScanEnabled()) {
        KernelTraceHostOpF("HOST.PM4.FullScan.begin");
        // Scan full ring (force variant handles wrap)
        PM4_DebugScanAll_Force();
        // Also scan raw linear windows for ring and syscmd
        PM4_ScanLinear(0x00120000u, 0x10000u);
        PM4_ScanLinear(0x00140000u, 0x10000u);
        PM4_DumpOpcodeHistogram();
        KernelTraceHostOpF("HOST.PM4.FullScan.end");
    }

        }
    }

    // Opportunistic: also scan a slice of the ring to surface any standard draws
    const uint32_t rb_base = Mw05GetRingBaseEA();
    const uint32_t rb_size = Mw05GetRingSizeBytes();
    if (rb_base && rb_size) {
        const uint32_t rb_scan = (rb_size > 0x8000u) ? 0x8000u : rb_size;
        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.scan_ring base=%08X size=%u", rb_base, rb_scan);
        PM4_ScanLinear(rb_base, rb_scan);
    }

    // Focused sweep + micro-list walker over 0x00140200..0x00140480.
    // Goal: detect GLAC/MW05 descriptor nodes and follow their embedded pointers.
    {
        uint32_t base_lo = 0x00140010u, base_hi = 0x00150000u; // exclusive
        auto is_sys_ea = [](uint32_t v){ return (v & 0xFFFF0000u) == 0x00140000u; };
        for (uint32_t a = base_lo; a < base_hi; a += 0x20u) {
            uint32_t* w = reinterpret_cast<uint32_t*>(g_memory.Translate(a));
            if (!w) continue;
            uint32_t d0 = bswap32(w[0]);
            uint32_t d1 = bswap32(w[1]);
            uint32_t d2 = bswap32(w[2]);
            uint32_t d3 = bswap32(w[3]);
            uint32_t d4 = bswap32(w[4]);
            uint32_t d5 = bswap32(w[5]);
            uint32_t d6 = bswap32(w[6]);
            uint32_t d7 = bswap32(w[7]);

            bool looks_mw05 = (d0 == 0x3530574Du) || (d1 == 0x3530574Du) || (d4 == 0x3530574Du);
            bool looks_glac = (d0 == 0x43474C41u) || (d4 == 0x43474C41u);
            if (looks_glac && d1 == 0x3530574Du) {
                // GLAC + MW05 node detected at 'a'. d2 commonly encodes a BE pointer to another micro node.
                KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.node.glac_mw05 ea=%08X d0=%08X d1=%08X d2=%08X d3=%08X d4=%08X d5=%08X d6=%08X d7=%08X",
                    a, d0, d1, d2, d3, d4, d5, d6, d7);
                uint32_t follow_ea2 = d2; // d* are already swapped to host LE
                if (is_sys_ea(follow_ea2)) {
                    uint32_t* fp = reinterpret_cast<uint32_t*>(g_memory.Translate(follow_ea2));
                    if (fp) {
                        uint32_t fd[8]{};
                        for (int j = 0; j < 8; ++j) fd[j] = bswap32(fp[j]);
                        KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.node.follow ea=%08X -> %08X f0=%08X f1=%08X f2=%08X f3=%08X f4=%08X f5=%08X f6=%08X f7=%08X",
                            a, follow_ea2, fd[0], fd[1], fd[2], fd[3], fd[4], fd[5], fd[6], fd[7]);
                        // If the follow target is an MW05 header, scan a conservative window for nested PM4
                        if (fd[0] == 0x3530574Du) {
                            uint32_t scan_sz = 0x400u;
                            PM4_ScanLinear(follow_ea2, scan_sz);
                        }
                    }
                }
            }

            // If we see likely viewport constants around here, apply once
            if (IsApplyHostStateEnabled() && !s_applied_vp_once) {
                // Float-based viewport probe (640.0f, 360.0f) swapped to LE immediate values from BE source
                const uint32_t f_x = 0x44200000u; // 640.0f
                const uint32_t f_y = 0x43B40000u; // 360.0f
                if ((d0 == f_x && d1 == f_y) || (d0 == f_y && d1 == f_x) ||
                    (d2 == f_x && d3 == f_y) || (d2 == f_y && d3 == f_x) ||
                    (d4 == f_x && d5 == f_y) || (d4 == f_y && d5 == f_x)) {
                    KernelTraceHostOpF("HOST.MW05.MicroIB.viewport.apply 1280x720 ea=%08X", a);
                    Mw05HostSetViewport(0.0f, 0.0f, 1280.0f, 720.0f, 0.0f, 1.0f);
                    s_applied_vp_once = true;
                }
            }
            if (IsApplyHostStateEnabled() && !s_applied_sc_once && s_applied_vp_once) {
                KernelTraceHostOpF("HOST.MW05.MicroIB.scissor.apply 1280x720 ea=%08X", a);
                Mw05HostSetScissor(0, 0, 1280, 720);
                s_applied_sc_once = true;
            }

            // Emit context lines for other interesting cells (EA-like fields)
            if (looks_mw05 || looks_glac || is_sys_ea(d0) || is_sys_ea(d1) || is_sys_ea(d2) || is_sys_ea(d3)) {
                KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.focus ea=%08X d0=%08X d1=%08X d2=%08X d3=%08X d4=%08X d5=%08X d6=%08X d7=%08X",
                    a, d0, d1, d2, d3, d4, d5, d6, d7);
                uint32_t cand_eas[4] = { d0, d1, d2, d3 };
                for (uint32_t v : cand_eas) {
                    if (is_sys_ea(v)) {
                        uint32_t* hp = reinterpret_cast<uint32_t*>(g_memory.Translate(v));
                        if (hp) {
                            uint32_t dd[8]{};
                            for (int j = 0; j < 8; ++j) dd[j] = bswap32(hp[j]);
                            KernelTraceHostOpF("HOST.PM4.MW05.MicroIB.focus.peek ea=%08X d0=%08X d1=%08X d2=%08X d3=%08X d4=%08X d5=%08X d6=%08X d7=%08X",
                                v, dd[0], dd[1], dd[2], dd[3], dd[4], dd[5], dd[6], dd[7]);
                        }
                    }
                }
            }
        }
    }
}
