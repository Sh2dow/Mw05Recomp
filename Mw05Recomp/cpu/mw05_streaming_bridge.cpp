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

#include <string>
#include <vector>

#include <kernel/io/file_system.h>

// Global watch slot (shared with trace helpers)
extern std::atomic<uint32_t> g_watchEA;

namespace {
    inline bool GuestRangeValid(uint32_t ea, size_t bytes = 4) {
        if (!ea) return false;
        const uint64_t end = static_cast<uint64_t>(ea) + static_cast<uint64_t>(bytes);
        return end <= PPC_MEMORY_SIZE;
    }


    inline bool PlausibleEA(uint32_t ea) {
        // MW05 guest addresses typically live in 0x8000_0000..0x8FFF_FFFF
        return ea >= 0x80000000u && ea < 0x90000000u;
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
            if (!PlausibleEA(ea) || !GuestRangeValid(ea, 64)) return;
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
        // Extra hexdumps to fingerprint MW05 loader structs
        auto dump_hex = [&](const char* tag, uint32_t ea, size_t bytes){
            if (!PlausibleEA(ea) || !GuestRangeValid(ea, (uint32_t)bytes)) return;
            const uint8_t* p = static_cast<const uint8_t*>(g_memory.Translate(ea)); if (!p) return;
            char line[128];
            for (size_t i=0;i<bytes;i+=16){
                int n=0; n += std::snprintf(line+n,sizeof(line)-n,"%s+%02X:",tag,(int)i);
                for (size_t j=0;j<16 && i+j<bytes;j++){ n += std::snprintf(line+n,sizeof(line)-n," %02X", p[i+j]); }
                n += std::snprintf(line+n,sizeof(line)-n,"  |");
                for (size_t j=0;j<16 && i+j<bytes;j++){ unsigned c=p[i+j]; line[n++]= (c>=32&&c<=126)?(char)c:'.'; }
                line[n++]='|'; line[n]=0; KernelTraceHostOpF("HOST.StreamBridge.hex %s ea=%08X %s", tag, ea, line);
            }
        };

        if (w2 && GuestRangeValid(w2, 4)) {
            dump_hex("w2", w2, 64);
            uint32_t p2 = LoadU32_BE(w2 + 0);
            if (PlausibleEA(p2)) dump_hex("w2.p0", p2, 128);
        }


        // Deep scan of w0/w1 regions for pointer-like fields that may be strings/paths
        auto deep_scan = [&](const char* tag, uint32_t baseEA){
            if (!PlausibleEA(baseEA) || !GuestRangeValid(baseEA, 0x100)) return;
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
                if (!PlausibleEA(be) || !GuestRangeValid(be, 128)) continue;
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

        if (w0 && PlausibleEA(w0)) deep_scan("w0", w0);
        if (w1 && PlausibleEA(w1)) deep_scan("w1", w1);

        if (w2 && PlausibleEA(w2)) deep_scan("w2", w2);

        // Follow first pointer-sized fields in w0/w1 as candidates
        if (w0 && GuestRangeValid(w0, 4)) {
            uint32_t p0 = LoadU32_BE(w0 + 0);
            if (PlausibleEA(p0) && GuestRangeValid(p0, 16) && g_memory.Translate(p0)) {
                KernelTraceHostOpF("HOST.StreamBridge.w0.ptr0=%08X", p0);
                probe_ptr("w0.ptr0", p0);
                deep_scan("w0.ptr0", p0);
            }
        }
        if (w1 && GuestRangeValid(w1, 8)) {
            uint32_t p1_1 = LoadU32_BE(w1 + 4);
            if (PlausibleEA(p1_1) && GuestRangeValid(p1_1, 16) && g_memory.Translate(p1_1)) {
                KernelTraceHostOpF("HOST.StreamBridge.w1.ptr1=%08X", p1_1);
                probe_ptr("w1.ptr1", p1_1);
                deep_scan("w1.ptr1", p1_1);
                }
            }
        }

    // Attempt a minimal decode of the loader block and perform synchronous
    // host file I/O into a guest buffer if we can confidently extract
    // (path, bufferEA, size). Returns true if an attempt was made.
    static bool TryPerformIOForBlock(uint32_t blockEA) {
        if (!GuestRangeValid(blockEA, 20) || !g_memory.Translate(blockEA)) return false;
        auto rd = [&](uint32_t ea){ return LoadU32_BE(ea); };
        const uint32_t w0 = rd(blockEA + 0);
        const uint32_t w1 = rd(blockEA + 4);
        const uint32_t w2 = rd(blockEA + 8);
        const uint32_t w3 = rd(blockEA + 12);
        const uint32_t w4 = rd(blockEA + 16);

        auto looks_size = [](uint32_t v){ return v > 0 && v <= 0x2000000; };

        auto likely_mw_path = [](const char* s){
            if (!s) return false;
            // Accept FS service tokens too; some early init probes use "FS\\ZDIR" forms
            // and we'll try to translate them later.
            // Allow classic MW roots (case-insensitive) starting at beginning
            const char* roots_ci[] = {"GLOBAL","FRONTEND","TRACKS","CARS","SOUND","LANGUAGES","FX","MOVIES","NIS","SUBTITLES","CREDITS","FS","NFS"};
            if (s[0]=='\\' || s[0]=='/') {
                const char* t = s + 1; // after leading slash
                for (const char* r : roots_ci) { size_t n=std::strlen(r); if (_strnicmp(t, r, n)==0) return true; }
            }
            // Also allow relative forms like "GLOBAL\\..." (case-insensitive)
            for (const char* r : roots_ci) { size_t n=std::strlen(r); if (_strnicmp(s, r, n)==0 && (s[n]=='\\' || s[n]=='/')) return true; }
            // Accept Xbox-style device roots: game:\\, D:\\, HDD:\\, etc. Also accept bare "D:".
            if (_strnicmp(s, "game:\\", 6)==0) return true;
            if (std::isalpha((unsigned char)s[0]) && s[1]==':') {
                if (s[2]=='\\' || s[2]=='/' || s[2]==0) return true;
            }
            // Accept dvd-like aliases sometimes seen in logs
            if (_strnicmp(s, "dvd:\\", 5)==0 || _strnicmp(s, "cdrom:\\", 7)==0) return true;
            // Finally, accept bare file-like tokens commonly used by MW when the folder is implicit
            // (e.g., "GLOBALB.BIN", "ZDIR", "ZDIR.BIN", etc.).
            // Be conservative: require at least one dot and an expected extension, or known names.
            auto ends_with_ci = [](const char* str, const char* suf){
                size_t ls = std::strlen(str), lr = std::strlen(suf); if (lr>ls) return false; return _strnicmp(str+ls-lr, suf, lr)==0; };
            if (_stricmp(s, "ZDIR")==0 || _stricmp(s, "ZDIR.BIN")==0) return true;
            if (std::strchr(s, '.') != nullptr) {
                if (ends_with_ci(s, ".BIN") || ends_with_ci(s, ".BUN") || ends_with_ci(s, ".BND") || ends_with_ci(s, ".RWS") || ends_with_ci(s, ".FSH") || ends_with_ci(s, ".TPL")) {
                    return true;
                }
            }
            return false;
        };

        // Collect candidate string EAs by scanning w0 / w1 regions for pointer-like fields to ASCII/UTF-16LE
        struct PathCand { uint32_t strEA; char ascii[256]; uint32_t containerEA; int offsetInContainer; };
        PathCand best{}; best.strEA = 0; best.containerEA = 0; best.offsetInContainer = -1; best.ascii[0] = 0;
        auto scan_paths = [&](uint32_t baseEA){
            if (!GuestRangeValid(baseEA, 0x100)) return;
            auto* p = static_cast<const uint8_t*>(g_memory.Translate(baseEA)); if (!p) return;
            for (int i=0;i<0x80;i+=4){
                uint32_t v = 0; std::memcpy(&v, p+i, 4);
    #if defined(_MSC_VER)
                const uint32_t be = _byteswap_ulong(v);
    #else
                const uint32_t be = __builtin_bswap32(v);
    #endif
                if (!GuestRangeValid(be, 4)) continue;
                const char* s = reinterpret_cast<const char*>(g_memory.Translate(be));
                if (!s) continue;
                // ASCII
                int len=0; bool ok=false; for (; len<200 && s[len]; ++len){ char c=s[len]; if (c<0x20||c>0x7E){ ok=false; break; } ok=true; }
                if (ok && len>=5) {
                    int has_sep=0, has_dot=0; for (int k=0;k<len;k++){ char c=s[k]; has_sep|=(c=='/'||c=='\\'||c==':'); has_dot|=(c=='.'); }
                    if ((has_sep || has_dot) && likely_mw_path(s)) {
                        std::memset(best.ascii, 0, sizeof(best.ascii));
                        const int n = std::min(len, (int)sizeof(best.ascii)-1);
                        std::memcpy(best.ascii, s, n);
                        best.strEA = be; best.containerEA = baseEA; best.offsetInContainer = i;
                        KernelTraceHostOpF("HOST.StreamBridge.io.path ascii ea=%08X '%s'", be, best.ascii);
                        return;
                    }
                }
                // UTF-16LE
                const uint16_t* w = reinterpret_cast<const uint16_t*>(s);
                char a[256]{}; int n=0; bool ok16=false; for (; n<255 && w[n]; ++n){ uint16_t ch=w[n]; if (ch<0x20||ch>0x7E){ ok16=false; break; } a[n]=char(ch); ok16=true; }
                if (ok16 && n>=5) {
                    int has_sep=0, has_dot=0; for (int k=0;k<n;k++){ char c=a[k]; has_sep|=(c=='/'||c=='\\'||c==':'); has_dot|=(c=='.'); }
                    if ((has_sep || has_dot) && likely_mw_path(a)) {
                        std::memset(best.ascii, 0, sizeof(best.ascii));
                        std::memcpy(best.ascii, a, n);
                        best.strEA = be; best.containerEA = baseEA; best.offsetInContainer = i;
                        KernelTraceHostOpF("HOST.StreamBridge.io.path utf16 ea=%08X '%s'", be, best.ascii);
                        return;
                    }
                }
            }
        };
        if (w0) scan_paths(w0);
        if (!best.strEA && w1) scan_paths(w1);

        // Fallback: scan raw bytes of candidate structs for path-like ASCII
        auto scan_region_for_paths = [&](const char* tag, uint32_t baseEA, size_t bytes){
            if (best.strEA || !GuestRangeValid(baseEA, (uint32_t)bytes)) return;
            const uint8_t* p = static_cast<const uint8_t*>(g_memory.Translate(baseEA)); if (!p) return;
            for (size_t i=0; !best.strEA && i+8<bytes; ++i) {
                // Look for minimal pattern like "game:\\" or any \\ or / and a dot later
                size_t j=i; int len=0; int has_sep=0, has_dot=0; char buf[128]{};
                while (j<bytes && len<120) {
                    char c = (char)p[j];
                    if (c==0) break;
                    if (c<0x20 || c>0x7E) { len=0; has_sep=0; has_dot=0; break; }
                    buf[len++] = c; has_sep |= (c=='/'||c=='\\'||c==':'); has_dot |= (c=='.');
                    // Accept directory-looking tokens too (e.g., "\\GLOBAL", "\\CARS\\...")
                    // Be more permissive: if it starts with a slash and is at least 3 chars, capture it;
                    // we'll validate with likely_mw_path() which now includes FS too.
                    if ((has_sep && len>=5) || ((buf[0]=='\\' || buf[0]=='/') && len>=3)) {
                        if (!likely_mw_path(buf)) break; // skip non-MW-looking paths
                        std::memset(best.ascii, 0, sizeof(best.ascii));
                        std::memcpy(best.ascii, buf, len);
                        best.strEA = baseEA + (uint32_t)i; best.containerEA = baseEA; best.offsetInContainer = (int)i;
                        KernelTraceHostOpF("HOST.StreamBridge.io.path.fallback %s ea=%08X '%s'", tag, best.strEA, best.ascii);
                        return;
                    }
                    ++j;
                }
            }
        };
        if (!best.strEA) {
            // Common container patterns observed in snapshots
            auto looks_guest_addr_local = [](uint32_t v){ return v >= 0x80000000u && (v & 0x3u) == 0; };
            uint32_t p0 = (GuestRangeValid(w0, 4) ? LoadU32_BE(w0 + 0) : 0);
            uint32_t p1 = (GuestRangeValid(w1, 8) ? LoadU32_BE(w1 + 4) : 0);
            if (p0) scan_region_for_paths("w0.p0", p0, 0x1000);
            if (!best.strEA && p1) scan_region_for_paths("w1.p1", p1, 0x1000);
            // Also follow w2 -> first pointer
            if (!best.strEA && GuestRangeValid(w2, 4)) {
                uint32_t p2_0 = LoadU32_BE(w2 + 0);
                if (p2_0) scan_region_for_paths("w2.p0", p2_0, 0x1000);
            }

            if (!best.strEA && looks_guest_addr_local(w4) && GuestRangeValid(w4, 4) && g_memory.Translate(w4)) scan_region_for_paths("w4", w4, 0x800);
            if (!best.strEA && looks_guest_addr_local(w0)) scan_region_for_paths("w0", w0, 0x800);
            if (!best.strEA && looks_guest_addr_local(w1)) scan_region_for_paths("w1", w1, 0x800);
            if (!best.strEA && looks_guest_addr_local(w2)) scan_region_for_paths("w2", w2, 0x800);
            if (!best.strEA && looks_guest_addr_local(w3)) scan_region_for_paths("w3", w3, 0x800);
            if (!best.strEA) scan_region_for_paths("block", blockEA, 0x100);
        }

        if (!best.strEA) {
            // Try to deduce (bufEA,size) even without a clear path, then attempt
            // a conservative fallback read of well-known boot bundles to push
            // the dispatcher forward. This is gated by MW05_STREAM_FALLBACK_BOOT.
            const bool allow_fallback = ReadEnvBool("MW05_STREAM_FALLBACK_BOOT", true);

            auto looks_guest_addr = [&](uint32_t v){ return v >= 0x80000000u && (v & 0x3u) == 0; };
            auto looks_size_be = [&](uint32_t v){ return v > 0 && v <= 0x2000000; };

            uint32_t fbBufEA = 0, fbSize = 0;
            auto scan_for_buf = [&](uint32_t baseEA, size_t bytes){
                if (fbBufEA && fbSize) return; // already found
                if (!GuestRangeValid(baseEA, (uint32_t)bytes)) return;
                const uint8_t* p = static_cast<const uint8_t*>(g_memory.Translate(baseEA)); if (!p) return;
                for (size_t off=0; off+8<=bytes; off+=4) {
                    uint32_t a=0,b=0; std::memcpy(&a,p+off,4); std::memcpy(&b,p+off+4,4);
    #if defined(_MSC_VER)
                    a=_byteswap_ulong(a); b=_byteswap_ulong(b);
    #else
                    a=__builtin_bswap32(a); b=__builtin_bswap32(b);
    #endif
                    if (!fbBufEA && looks_guest_addr(a) && GuestRangeValid(a, 16) && g_memory.Translate(a)) fbBufEA = a;
                    if (!fbSize && looks_size_be(b)) fbSize = b;
                    if (fbBufEA && fbSize) break;
                }
            };

            // Follow immediate pointers around the block to locate (bufEA,size)
            if (w0 && GuestRangeValid(w0, 0x80)) scan_for_buf(w0, 0x80);
            if (!fbBufEA || !fbSize) {
                if (w1 && GuestRangeValid(w1, 0x80)) scan_for_buf(w1, 0x80);
                if (w2 && GuestRangeValid(w2, 4)) {
                    uint32_t p2_0 = LoadU32_BE(w2 + 0);
                    if (p2_0) scan_for_buf(p2_0, 0x200);
                }
            }

            if (allow_fallback && fbBufEA) {
                // If size unknown, use a conservative default (1 MiB), and shrink
                // until it fits the mapped guest region.
                if (!fbSize) fbSize = 0x100000;
                while (fbSize >= 0x10000 && (!GuestRangeValid(fbBufEA, fbSize) || g_memory.Translate(fbBufEA) == nullptr)) {
                    fbSize >>= 1;
                }
                if (fbSize >= 0x10000) {
                    // Cap to 4 MiB to avoid long stalls if the size is large/unknown.
                    fbSize = std::min<uint32_t>(fbSize, 0x400000);
                    uint8_t* dst = static_cast<uint8_t*>(g_memory.Translate(fbBufEA));
                    if (dst) {
                        const char* boots[] = {
                            // Prefer memory files first; these are consumed early to seed pools
                            "game:\\GLOBAL\\GLOBALMEMORYFILE.BIN",
                            "game:\\GLOBAL\\PERMANENTMEMORYFILE.BIN",
                            "game:\\GLOBAL\\FRONTENDMEMORYFILE.BIN",
                            // Then try known bundles if memory files aren’t referenced yet
                            "game:\\GLOBAL\\GLOBALB.BUN",
                            "game:\\GLOBAL\\GLOBALA.BUN",
                            "game:\\GLOBAL\\INGAMEB.BUN",
                            // Compressed variants (raw copy won’t help if decompression is expected)
                            "game:\\GLOBAL\\GLOBALB.LZC",
                            "game:\\GLOBAL\\INGAMEB.LZC",
                            "game:\\GLOBAL\\WIDESCREEN_GLOBAL.BUN"
                        };
                        for (const char* cand : boots) {
                            // If we can resolve to a host path, clamp by actual file size.
                            std::filesystem::path resolved = FileSystem::ResolvePath(cand, /*mods=*/true);
                            uint32_t toRead = fbSize;
                            std::error_code ec{};
                            auto fsz = std::filesystem::file_size(resolved, ec);
                            if (!ec) {
                                if (fsz == 0) continue;
                                if (fsz < toRead) toRead = (uint32_t)std::min<uint64_t>(fsz, 0x400000ull);
                            }
                            KernelTraceHostOpF("HOST.StreamBridge.io.try.fallback cand='%s' buf=%08X size=%u", cand, fbBufEA, (unsigned)toRead);
                            FileHandle* fh = XCreateFileA(cand, /*GENERIC_READ*/ 0x80000000u | 0x00000001u, /*share read*/ 0x1u, nullptr, /*OPEN_EXISTING*/ 3u, 0u);
                            if (!fh) continue;
                            be<uint32_t> bytesRead{0};
                            uint32_t ok = XReadFile(fh, dst, toRead, &bytesRead, nullptr);
                            KernelTraceHostOpF("HOST.StreamBridge.io.read.fallback ok=%u bytes=%u", (unsigned)ok, (unsigned)bytesRead.get());
                            if (ok != 0 && bytesRead.get() > 0) {
                                // Treat as handled; upstream will clear the block.
                                return true;
                            }
                        }
                    }
                }
            }

            // No reliable path and no fallback read; keep logging for diagnostics.
            auto preview_ascii = [&](uint32_t ea){
                if (!PlausibleEA(ea)) return;
                char buf[96]{}; int n=0; const char* s=(const char*)g_memory.Translate(ea);
                if (!s) return; for (; n<95 && s[n]; ++n){ char c=s[n]; if (c<0x20||c>0x7E) break; buf[n]=c; }
                buf[n]=0; KernelTraceHostOpF("HOST.StreamBridge.io.no_path.ascii ea=%08X \"%s\"", ea, buf);
            };
            auto preview_utf16 = [&](uint32_t ea){
                if (!PlausibleEA(ea)) return;
                char buf[96]{}; int n=0; const uint16_t* w=(const uint16_t*)g_memory.Translate(ea);
                if (!w) return; for (; n<95 && w[n]; ++n){ uint16_t ch=w[n]; if (ch<0x20||ch>0x7E) break; buf[n]=(char)ch; }
                buf[n]=0; KernelTraceHostOpF("HOST.StreamBridge.io.no_path.utf16 ea=%08X \"%s\"", ea, buf);
            };
            preview_ascii(w0); preview_ascii(w1); preview_ascii(w2); preview_ascii(w3);
            preview_utf16(w0); preview_utf16(w1); preview_utf16(w2); preview_utf16(w3);
            KernelTraceHostOpF("HOST.StreamBridge.io.no_path w0=%08X w1=%08X w2=%08X w3=%08X w4=%08X", w0, w1, w2, w3, w4);
            return false; // No reliable path/fallback yet
        }

        // Heuristic: find buffer EA and size near the path pointer occurrence inside its container region
        uint32_t bufEA = 0; uint32_t size = 0;
        if (best.containerEA) {
            auto* p = static_cast<const uint8_t*>(g_memory.Translate(best.containerEA));
            if (p) {
                // Look at the two words after the path pointer slot
                for (int j=1; j<=3; ++j) {
                    const int off = best.offsetInContainer + j*4;
                    if (!GuestRangeValid(best.containerEA + off, 4)) break;
                    uint32_t v=0; std::memcpy(&v, p+off, 4);
    #if defined(_MSC_VER)
                    const uint32_t be = _byteswap_ulong(v);
    #else
                    const uint32_t be = __builtin_bswap32(v);
    #endif
                    auto looks_guest_addr = [](uint32_t v){ return v >= 0x80000000u && (v & 0x3u) == 0; };
                    if (!bufEA && looks_guest_addr(be)) bufEA = be;
                    if (!size && looks_size(be)) size = be;
                }
            }
        }
        // Fall back to w2..w4 interpretation if needed
        auto looks_guest_addr = [&](uint32_t v){ return v >= 0x80000000u && (v & 0x3u) == 0; };
        auto maybe_ptr = [&](uint32_t v){ return looks_guest_addr(v); };
        if (!bufEA) {
            if (maybe_ptr(w2)) bufEA = w2; else if (maybe_ptr(w3)) bufEA = w3; /*do not use w4 as buf*/
        }
        if (!size) {
            // If w4 points to a struct, first dword often looks like a size
            if (maybe_ptr(w4)) {
                uint32_t s = LoadU32_BE(w4 + 0);
                if (looks_size(s)) size = s;
            }
            if (!size) {
                if (looks_size(w2) && !maybe_ptr(w2)) size = w2;
                else if (looks_size(w3) && !maybe_ptr(w3)) size = w3;
                else if (looks_size(w4) && !maybe_ptr(w4)) size = w4;
            }
        }

        if (!bufEA || !size) {
            KernelTraceHostOpF("HOST.StreamBridge.io.no_args path='%s' buf=%08X size=%08X", best.ascii, bufEA, size);
            return false;
        }

        // Clamp read size to mapped memory region if necessary
        if (!GuestRangeValid(bufEA, size) || g_memory.Translate(bufEA) == nullptr) {
            // reduce to a safe window (up to 1 MiB)
            size = std::min<uint32_t>(size, 0x100000);
            if (!GuestRangeValid(bufEA, size) || g_memory.Translate(bufEA) == nullptr) {
                KernelTraceHostOpF("HOST.StreamBridge.io.bad_buf path='%s' buf=%08X size=%08X", best.ascii, bufEA, size);
                return false;
            }
        }

        // Build path variants to maximize chances of opening the right file
        std::vector<std::string> variants;
        auto add_variant = [&](std::string s){ variants.emplace_back(std::move(s)); };
        const char* s0 = best.ascii;
        bool has_root = (std::strchr(s0, ':') != nullptr);
        bool has_dot  = (std::strchr(s0, '.') != nullptr);
        std::string base = s0;
        if (!has_root) {
            add_variant(std::string("game:\\") + base);
        }
        add_variant(base);
        if (!has_dot || (!base.empty() && base.back()=='.')) {
            add_variant(base + "BIN");
            add_variant(base + "bin");
            if (!has_root) {
                add_variant(std::string("game:\\") + base + "BIN");
                add_variant(std::string("game:\\") + base + "bin");
            }
        }

        be<uint32_t> bytesRead{0};
        uint8_t* dst = static_cast<uint8_t*>(g_memory.Translate(bufEA));
        for (const auto& cand : variants) {
            KernelTraceHostOpF("HOST.StreamBridge.io.try guest='%s' cand='%s' buf=%08X size=%u", best.ascii, cand.c_str(), bufEA, (unsigned)size);
            FileHandle* fh = XCreateFileA(cand.c_str(), /*GENERIC_READ|FILE_READ_DATA*/ 0x80000000u | 0x00000001u, /*share read*/ 0x1u, nullptr, /*OPEN_EXISTING*/ 3u, /*normal*/ 0u);
            if (!fh) continue;
            bytesRead = 0;
            uint32_t ok = XReadFile(fh, dst, size, &bytesRead, nullptr);
            KernelTraceHostOpF("HOST.StreamBridge.io.read ok=%u bytes=%u", (unsigned)ok, (unsigned)bytesRead.get());
            if (ok != 0 && bytesRead.get() > 0) return true;
        }
        KernelTraceHostOpF("HOST.StreamBridge.io.open_fail guest='%s' buf=%08X size=%u", best.ascii, bufEA, (unsigned)size);
        return false;
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

    // Optional: when no path is decoded, still ACK the block to keep the
    // dispatcher moving. Default OFF.
    static const bool s_ack_no_path = ReadEnvBool("MW05_STREAM_ACK_NO_PATH", false);

    // Only claim loader/asset dispatcher sentinels here; kernel fast-delay
    // watchdogs are handled in dedicated shims. Allow opt-in bypass if the
    // loader dispatcher lives outside the expected range.
    if (!LRInLoaderDispatcher(lr)) {
        static const bool s_any_lr = ReadEnvBool("MW05_STREAM_ANY_LR", false);
        if (!s_any_lr) {
            return false;
        }
        KernelTraceHostOpF("HOST.StreamBridge.any_lr slot=%08X lr=%08llX", slotEA, (unsigned long long)lr);
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

    // Attempt real I/O if possible before deciding whether to consume the sentinel
    const bool did_io = TryPerformIOForBlock(blockEA);

    // Arm watch for the slot to attribute any follow-up writes.
    if (g_watchEA.load(std::memory_order_relaxed) != slotEA) {
        g_watchEA.store(slotEA, std::memory_order_relaxed);
        KernelTraceHostOpF("HOST.StreamBridge.watch arm=%08X", slotEA);
    }

    if (did_io) {
        // Clear the entire scheduler block so the producer sees a completed entry.
        ClearSchedulerBlock(blockEA);
        // Store handled: suppress the sentinel write.
        return true;
    }

    if (s_ack_no_path) {
        KernelTraceHostOpF("HOST.StreamBridge.ack.no_path block=%08X", blockEA);
        ClearSchedulerBlock(blockEA);
        return true;
    }

    // No I/O attempted/confident path not found: let the game write the sentinel and
    // handle the block via its native path (this enables proper fallback logic).
    return false;
}
