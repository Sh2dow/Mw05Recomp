// Loader/asset system shims and diagnostics.
// Wraps hot functions in the 0x8215BDxx–0x8215C1xx range to log
// arguments and nearby memory so we can identify job descriptors
// and file path pointers.

#include <cpu/ppc_context.h>
#include <kernel/memory.h>
#include <kernel/trace.h>
#include <ppc/ppc_config.h>
#include <cstdint>
#include <cctype>
#include <cstring>

#include <cpu/guest_stack_var.h> // TraceGuestArgs lives here (gated)

#define TRACE_LOADER_ARGS(TAG, CTX) \
    do { if (IsTraceLoaderArgsEnabled()) \
        TraceGuestArgs((TAG), (CTX).r3.u32, (CTX).r4.u32, (CTX).r5.u32, (CTX).r6.u32); } while (0)

#define TRACE_LOADER_VERBOSE(CTX) \
    do { if (!IsTraceLoaderArgsEnabled()) { \
        KernelTraceHostOpF("HOST.Loader.args r3=%08X r4=%08X r5=%08X r6=%08X", \
                           (CTX).r3.u32, (CTX).r4.u32, (CTX).r5.u32, (CTX).r6.u32); \
        DumpWordWindow("HOST.Loader.r3", (CTX).r3.u32, 8); \
        DumpWordWindow("HOST.Loader.r4", (CTX).r4.u32, 8); \
        DumpWordWindow("HOST.Loader.r5", (CTX).r5.u32, 8); \
        DumpWordWindow("HOST.Loader.r6", (CTX).r6.u32, 8); \
        ProbeForPath("r3", (CTX).r3.u32); \
        ProbeForPath("r4", (CTX).r4.u32); \
        ProbeForPath("r5", (CTX).r5.u32); \
        ProbeForPath("r6", (CTX).r6.u32); \
        DeepProbeObjectPaths("r3", (CTX).r3.u32); \
        DeepProbeObjectPaths("r4", (CTX).r4.u32); \
        DeepProbeObjectPaths("r5", (CTX).r5.u32); \
        DeepProbeObjectPaths("r6", (CTX).r6.u32); \
    }} while (0)

extern "C" {
    void __imp__sub_8215BDD8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8215C080(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8215C0F0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8215C168(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8215BC08(PPCContext& ctx, uint8_t* base);
    void __imp__sub_826BE660(PPCContext& ctx, uint8_t* base);
}

namespace {
    inline bool GuestRangeValid(uint32_t ea, size_t bytes = 4) {
        if (!ea) return false;
        const uint64_t end = static_cast<uint64_t>(ea) + static_cast<uint64_t>(bytes);
        return end <= PPC_MEMORY_SIZE;
    }

    inline bool IsLikelyAscii(const uint8_t* p, size_t len) {
        size_t printable = 0;
        for (size_t i = 0; i < len; ++i) {
            const uint8_t c = p[i];
            if (c == 0) break;
            if (c < 0x20 || c > 0x7E) return false;
            ++printable;
        }
        return printable >= 4;
    }

    inline void DumpWordWindow(const char* tag, uint32_t ea, int words = 8) {
        if (!GuestRangeValid(ea, static_cast<size_t>(words) * 4)) {
            KernelTraceHostOpF("%s ea=%08X (oor)", tag, ea);
            return;
        }
        auto* p = static_cast<const uint8_t*>(g_memory.Translate(ea));
        if (!p) {
            KernelTraceHostOpF("%s ea=%08X (unmapped)", tag, ea);
            return;
        }
        uint32_t w[16]{};
        for (int i = 0; i < words && i < 16; ++i) {
            uint32_t v = 0; std::memcpy(&v, p + i * 4, 4);
#if defined(_MSC_VER)
            w[i] = _byteswap_ulong(v);
#else
            w[i] = __builtin_bswap32(v);
#endif
        }
        KernelTraceHostOpF("%s ea=%08X w[0..%d]= %08X %08X %08X %08X  %08X %08X %08X %08X",
                           tag, ea, words-1,
                           w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
    }

    inline bool LooksPathLike(const char* s) {
        if (!s) return false;
        bool has_sep=false, has_dot=false;
        int len=0; for (; s[len] && len<200; ++len) {
            const char c = s[len];
            if (c < 0x20 || c > 0x7E) return false;
            has_sep = has_sep || (c=='/' || c=='\\' || c==':');
            has_dot = has_dot || (c=='.');
        }
        return len >= 5 && (has_sep || has_dot);
    }

    inline bool TryDecodeUTF16LEToAscii(const uint16_t* s16, size_t max_chars, char* out, size_t out_cap) {
        size_t n=0; for (; n<max_chars && n+1<out_cap; ++n) {
            uint16_t w = s16[n];
            if (w == 0) { out[n] = 0; break; }
            if (w < 0x20 || w > 0x7E) return false;
            out[n] = char(w);
        }
        if (n == 0) return false;
        out[n] = 0;
        // Path-like heuristic
        bool sep=false, dot=false; for (size_t i=0;i<n;i++){ sep|=(out[i]=='/'||out[i]=='\\'||out[i]==':'); dot|=(out[i]=='.'); }
        return sep || dot;
    }

    inline void ProbeForPath(const char* origin, uint32_t ea) {
        if (!GuestRangeValid(ea, 4)) return;
        if (auto* p = static_cast<const uint8_t*>(g_memory.Translate(ea))) {
            // Inspect a larger window of potential pointers and inline strings.
            for (int off = 0; off < 0x200; off += 4) {
                uint32_t v = 0; std::memcpy(&v, p + off, 4);
#if defined(_MSC_VER)
                const uint32_t be = _byteswap_ulong(v);
#else
                const uint32_t be = __builtin_bswap32(v);
#endif
                if (!GuestRangeValid(be, 128)) continue;
                const char* s = reinterpret_cast<const char*>(g_memory.Translate(be));
                if (!s) continue;
                if (LooksPathLike(s)) {
                    char buf[160]{}; size_t i=0; for (; i<sizeof(buf)-1 && s[i]; ++i) buf[i]=s[i]; buf[i]=0;
                    KernelTraceHostOpF("HOST.Loader.Path %s+0x%X -> %08X '%s'", origin, off, be, buf);
                    continue;
                }
                // Try UTF-16LE
                const uint16_t* w = reinterpret_cast<const uint16_t*>(s);
                char a[160]{};
                if (TryDecodeUTF16LEToAscii(w, 128/2, a, sizeof(a))) {
                    KernelTraceHostOpF("HOST.Loader.Path16 %s+0x%X -> %08X '%s'", origin, off, be, a);
                }
            }
        }
    }

    inline void DeepProbeObjectPaths(const char* tag, uint32_t objEA) {
        if (!GuestRangeValid(objEA, 0x80)) return;
        auto* p = static_cast<const uint8_t*>(g_memory.Translate(objEA));
        if (!p) return;
        int hits = 0;
        for (int i = 0; i < 0x80 && hits < 4; i += 4) {
            uint32_t v = 0; std::memcpy(&v, p + i, 4);
#if defined(_MSC_VER)
            const uint32_t be = _byteswap_ulong(v);
#else
            const uint32_t be = __builtin_bswap32(v);
#endif
            if (!GuestRangeValid(be, 128)) continue;
            const char* s = reinterpret_cast<const char*>(g_memory.Translate(be));
            if (!s) continue;
            if (LooksPathLike(s)) {
                char buf[160]{}; size_t k=0; for (; k<sizeof(buf)-1 && s[k]; ++k) buf[k]=s[k]; buf[k]=0;
                KernelTraceHostOpF("HOST.Loader.DeepPath %s+0x%X -> %08X '%s'", tag, i, be, buf);
                ++hits;
                continue;
            }
            const uint16_t* w = reinterpret_cast<const uint16_t*>(s);
            char a[160]{};
            if (TryDecodeUTF16LEToAscii(w, 64, a, sizeof(a))) {
                KernelTraceHostOpF("HOST.Loader.DeepPath16 %s+0x%X -> %08X '%s'", tag, i, be, a);
                ++hits;
            }
        }
    }
}

#define LOADER_SHIM(NAME) \
  void NAME(PPCContext& ctx, uint8_t* base) { \
    SetPPCContext(ctx); \
    KernelTraceHostOp("HOST.Loader." #NAME ".enter"); \
    TRACE_LOADER_ARGS("ldr." #NAME ".pre", ctx); \
    TRACE_LOADER_VERBOSE(ctx); \
    __imp__##NAME(ctx, base); \
    TRACE_LOADER_ARGS("ldr." #NAME ".post", ctx); \
    KernelTraceHostOp("HOST.Loader." #NAME ".exit"); \
  }

LOADER_SHIM(sub_8215BDD8)
LOADER_SHIM(sub_8215C080)
LOADER_SHIM(sub_8215C0F0)
LOADER_SHIM(sub_8215C168)
LOADER_SHIM(sub_8215BC08)
LOADER_SHIM(sub_826BE660)
