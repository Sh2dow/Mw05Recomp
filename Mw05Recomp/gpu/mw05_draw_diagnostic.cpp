// MW05 Draw Function Diagnostic Hooks
// Purpose: Identify which MW05 functions are the actual draw calls
// by hooking a wide range of candidates and logging their activity.

#include <kernel/trace.h>
#include <cpu/ppc_context.h>
#include <ppc/ppc_recomp_shared.h>
#include "mw05_micro_interpreter.h"

// Forward declarations of recompiled originals
extern "C" {
    // Candidates from 0x8259 range (video/render related based on trace patterns)
    void __imp__sub_82598068(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825981A0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825981E8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_82598230(PPCContext& ctx, uint8_t* base);  // CreateDevice
    // Note: sub_825986F8, sub_825987E0, sub_825988B0 are already hooked in video.cpp as MW05Shim_*
    void __imp__sub_82598A20(PPCContext& ctx, uint8_t* base);  // Present wrapper

    // Candidates from 0x8259A-0x8259F range
    void __imp__sub_8259A0E0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8259A320(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8259A498(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8259AF50(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8259B0D8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8259B210(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8259B5C0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8259B618(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8259B700(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8259B750(PPCContext& ctx, uint8_t* base);

    // Candidates from 0x825A0-0x825A5 range
    void __imp__sub_825A0090(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A0160(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A02F8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A0610(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A07C8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A0858(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A0900(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A09A0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A0B98(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A0C00(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A1030(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A1120(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A1268(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A12F8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A1388(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A1418(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A14A8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A1538(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A15C8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A16A0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A1718(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A1788(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A17F8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A1838(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A18F8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A1988(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A1A08(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A1AE8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A1CC0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A1E30(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A1EA0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A1F58(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A1FB8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A2150(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A21A0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A22E8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A23C8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A24B8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A2508(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A2570(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A25E8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A28B0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A2910(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A2980(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A2A30(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A2AE8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A2BA8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A2CA0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A2DC8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A3000(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A35E0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A3670(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A36F0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A3820(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A3940(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A39B0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A3AA0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A3B38(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A4108(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A4328(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A4558(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A4580(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A4670(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A4780(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A47F0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A4D68(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A4DD8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A5008(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A5108(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A52D0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A53B0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A5408(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A5460(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A54F0(PPCContext& ctx, uint8_t* base);  // Already shimmed
    void __imp__sub_825A5580(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A55D0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A5880(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A58C0(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A5928(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A59A8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A5A58(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A5BC8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A5CC8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A5D60(PPCContext& ctx, uint8_t* base);
    void __imp__sub_825A5EB0(PPCContext& ctx, uint8_t* base);
}

// Environment variable to enable draw diagnostic tracing
static bool IsDrawDiagnosticEnabled() {


    static int cached = -1;
    if (cached < 0) {
        const char* env = std::getenv("MW05_DRAW_DIAGNOSTIC");
        cached = (env && env[0] == '1') ? 1 : 0;
    }
    return cached != 0;
}

// Macro to create diagnostic shims that log parameters
#define DRAW_DIAG_SHIM(name) \
    void name(PPCContext& ctx, uint8_t* base) { \
        if (IsDrawDiagnosticEnabled()) { \
            KernelTraceHostOpF("HOST.DrawDiag." #name " lr=%08llX r3=%08X r4=%08X r5=%08X r6=%08X r7=%08X", \
                               (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32, ctx.r7.u32); \
        } \
        __imp__##name(ctx, base); \
    }

// Create diagnostic shims for all candidates
DRAW_DIAG_SHIM(sub_82598068)
DRAW_DIAG_SHIM(sub_825981A0)
DRAW_DIAG_SHIM(sub_825981E8)
// sub_82598230 is CreateDevice, already hooked
// sub_825986F8, sub_825987E0, sub_825988B0 are already hooked in video.cpp as MW05Shim_*
// sub_82598A20 is Present, already hooked

DRAW_DIAG_SHIM(sub_8259A0E0)
DRAW_DIAG_SHIM(sub_8259A320)
DRAW_DIAG_SHIM(sub_8259A498)
DRAW_DIAG_SHIM(sub_8259AF50)
DRAW_DIAG_SHIM(sub_8259B0D8)
DRAW_DIAG_SHIM(sub_8259B210)
DRAW_DIAG_SHIM(sub_8259B5C0)
DRAW_DIAG_SHIM(sub_8259B618)

// Lightweight device struct dumper for MW05 draw-diag
static void DumpEAU32Window(const char* tag, uint32_t ea, uint32_t dwords)
{
    if (!ea || ea >= PPC_MEMORY_SIZE) {
        KernelTraceHostOpF("HOST.DrawDiag.dump %s ea=%08X invalid", tag, ea);
        return;
    }
    auto* p = reinterpret_cast<be<uint32_t>*>(g_memory.Translate(ea));
    if (!p) {
        KernelTraceHostOpF("HOST.DrawDiag.dump %s ea=%08X xlat=null", tag, ea);
        return;
    }
    // Print up to 8 dwords to stay concise
    const uint32_t n = dwords > 8 ? 8 : dwords;
    uint32_t v0 = (n > 0) ? (uint32_t)p[0] : 0u;
    uint32_t v1 = (n > 1) ? (uint32_t)p[1] : 0u;
    uint32_t v2 = (n > 2) ? (uint32_t)p[2] : 0u;
    uint32_t v3 = (n > 3) ? (uint32_t)p[3] : 0u;
    uint32_t v4 = (n > 4) ? (uint32_t)p[4] : 0u;
    uint32_t v5 = (n > 5) ? (uint32_t)p[5] : 0u;
    uint32_t v6 = (n > 6) ? (uint32_t)p[6] : 0u;
    uint32_t v7 = (n > 7) ? (uint32_t)p[7] : 0u;
    KernelTraceHostOpF("HOST.DrawDiag.dump %s ea=%08X d0=%08X d1=%08X d2=%08X d3=%08X d4=%08X d5=%08X d6=%08X d7=%08X",
                       tag, ea, v0, v1, v2, v3, v4, v5, v6, v7);
}

DRAW_DIAG_SHIM(sub_8259B700)
DRAW_DIAG_SHIM(sub_8259B750)

DRAW_DIAG_SHIM(sub_825A0090)
DRAW_DIAG_SHIM(sub_825A0160)
DRAW_DIAG_SHIM(sub_825A02F8)
DRAW_DIAG_SHIM(sub_825A0610)
DRAW_DIAG_SHIM(sub_825A07C8)
DRAW_DIAG_SHIM(sub_825A0858)
DRAW_DIAG_SHIM(sub_825A0900)
DRAW_DIAG_SHIM(sub_825A09A0)
DRAW_DIAG_SHIM(sub_825A0B98)
DRAW_DIAG_SHIM(sub_825A0C00)
DRAW_DIAG_SHIM(sub_825A1030)
DRAW_DIAG_SHIM(sub_825A1120)
DRAW_DIAG_SHIM(sub_825A1268)
DRAW_DIAG_SHIM(sub_825A12F8)
DRAW_DIAG_SHIM(sub_825A1388)
DRAW_DIAG_SHIM(sub_825A1418)
DRAW_DIAG_SHIM(sub_825A14A8)
DRAW_DIAG_SHIM(sub_825A1538)
DRAW_DIAG_SHIM(sub_825A15C8)
DRAW_DIAG_SHIM(sub_825A16A0)
DRAW_DIAG_SHIM(sub_825A1718)
DRAW_DIAG_SHIM(sub_825A1788)
DRAW_DIAG_SHIM(sub_825A17F8)
DRAW_DIAG_SHIM(sub_825A1838)
DRAW_DIAG_SHIM(sub_825A18F8)
DRAW_DIAG_SHIM(sub_825A1988)
DRAW_DIAG_SHIM(sub_825A1A08)
DRAW_DIAG_SHIM(sub_825A1AE8)
DRAW_DIAG_SHIM(sub_825A1CC0)
DRAW_DIAG_SHIM(sub_825A1E30)
DRAW_DIAG_SHIM(sub_825A1EA0)
DRAW_DIAG_SHIM(sub_825A1F58)
DRAW_DIAG_SHIM(sub_825A1FB8)
DRAW_DIAG_SHIM(sub_825A2150)
DRAW_DIAG_SHIM(sub_825A21A0)
DRAW_DIAG_SHIM(sub_825A22E8)
DRAW_DIAG_SHIM(sub_825A23C8)
DRAW_DIAG_SHIM(sub_825A24B8)
DRAW_DIAG_SHIM(sub_825A2508)
DRAW_DIAG_SHIM(sub_825A2570)
// Custom override: deeper dump and potential handoff to host interpreter later
extern "C" void Mw05DebugKickClear();
void sub_825A25E8(PPCContext& ctx, uint8_t* base) {
    if (IsDrawDiagnosticEnabled()) {
        KernelTraceHostOpF("HOST.DrawDiag.sub_825A25E8 lr=%08llX r3=%08X r4=%08X r5=%08X r6=%08X r7=%08X",
                           (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32, ctx.r7.u32);
        // Dump neighborhoods around pointers passed in registers to understand layout
        DumpEAU32Window("r3", ctx.r3.u32 & ~0x1Fu, 8);
        DumpEAU32Window("r4", ctx.r4.u32 & ~0x1Fu, 8);
        DumpEAU32Window("r7", ctx.r7.u32 & ~0x1Fu, 8);
    }

    // Opportunistic: if r7 points into System Command Buffer and the header 0x1C bytes before it is 'MW05',
    // invoke the micro-IB interpreter to surface real draws/state.
    uint32_t r7ea = ctx.r7.u32;
    if ((r7ea & 0xFFFF0000u) == 0x00140000u && r7ea >= 0x0014001Cu) {
        auto* hdrp = reinterpret_cast<be<uint32_t>*>(g_memory.Translate(r7ea - 0x1C));
        if (hdrp) {
        #if defined(_MSC_VER)
            uint32_t hdr = _byteswap_ulong((uint32_t)*hdrp);
        #else
            uint32_t hdr = __builtin_bswap32((uint32_t)*hdrp);
        #endif
            if (hdr == 0x3530574Du) {
                // Prefer using the known 32-byte prelude; if r5 looks sane, pass it too
                uint32_t size_hint = (ctx.r5.u32 > 0 && ctx.r5.u32 <= 0x1000u) ? ctx.r5.u32 : 32u;
                Mw05InterpretMicroIB(r7ea - 0x1C, size_hint);
            }
        }
    }
    // If no exact -0x1C header, scan a small window backwards for 'MW05' magic and hand off
    if ((r7ea & 0xFFFF0000u) == 0x00140000u) {
        uint32_t scan_start = (r7ea > 0x80u) ? (r7ea - 0x80u) : 0u;
        uint32_t scan_end = r7ea;
        for (uint32_t a = scan_start; a + 4 <= scan_end; a += 4) {
            auto* wp = reinterpret_cast<be<uint32_t>*>(g_memory.Translate(a));
            if (!wp) continue;
        #if defined(_MSC_VER)
            uint32_t w = _byteswap_ulong((uint32_t)*wp);
        #else
            uint32_t w = __builtin_bswap32((uint32_t)*wp);
        #endif
            if (w == 0x3530574Du) {
                uint32_t size_hint2 = (ctx.r5.u32 > 0 && ctx.r5.u32 <= 0x2000u) ? ctx.r5.u32 : 32u;
                KernelTraceHostOpF("HOST.DrawDiag.sub_825A25E8.magic_scan hit ea=%08X size_hint=%u", a, size_hint2);
                Mw05InterpretMicroIB(a, size_hint2);
                break;
            }
        }
    }

    // Wider net: scan the entire System Command Buffer payload for 'MW05' and hand off the first hit.
    // Also kick a periodic debug clear so we get visible frames during bring-up.
    {
        const uint32_t sysEA = Mw05GetSysBufBaseEA();
        if (sysEA) {
            uint8_t* sysHostBytes = reinterpret_cast<uint8_t*>(g_memory.Translate(sysEA));
            if (sysHostBytes) {
                const uint32_t head = 0x10u;
                const uint32_t total = 0x00010000u;
                const uint32_t payload = total - head;
                uint32_t firstMagic = 0;
                for (uint32_t off = 0; off + 4 <= payload; off += 4) {
                    uint32_t be = (uint32_t)sysHostBytes[head + off + 0] << 24 |
                                  (uint32_t)sysHostBytes[head + off + 1] << 16 |
                                  (uint32_t)sysHostBytes[head + off + 2] << 8  |
                                  (uint32_t)sysHostBytes[head + off + 3] << 0;
                    if (be == 0x3530574Du) { firstMagic = sysEA + head + off; break; }
                }
                if (firstMagic) {
                    KernelTraceHostOpF("HOST.DrawDiag.sys_scan.magic first=%08X", firstMagic);
                    Mw05InterpretMicroIB(firstMagic, 32u);
                }
            }
        }
    }

    __imp__sub_825A25E8(ctx, base);
}
DRAW_DIAG_SHIM(sub_825A28B0)
DRAW_DIAG_SHIM(sub_825A2910)
DRAW_DIAG_SHIM(sub_825A2980)
DRAW_DIAG_SHIM(sub_825A2A30)
DRAW_DIAG_SHIM(sub_825A2AE8)
DRAW_DIAG_SHIM(sub_825A2BA8)
DRAW_DIAG_SHIM(sub_825A2CA0)
DRAW_DIAG_SHIM(sub_825A2DC8)
DRAW_DIAG_SHIM(sub_825A3000)
DRAW_DIAG_SHIM(sub_825A35E0)
DRAW_DIAG_SHIM(sub_825A3670)
DRAW_DIAG_SHIM(sub_825A36F0)
DRAW_DIAG_SHIM(sub_825A3820)
DRAW_DIAG_SHIM(sub_825A3940)
DRAW_DIAG_SHIM(sub_825A39B0)
DRAW_DIAG_SHIM(sub_825A3AA0)
DRAW_DIAG_SHIM(sub_825A3B38)
DRAW_DIAG_SHIM(sub_825A4108)
DRAW_DIAG_SHIM(sub_825A4328)
DRAW_DIAG_SHIM(sub_825A4558)
DRAW_DIAG_SHIM(sub_825A4580)
DRAW_DIAG_SHIM(sub_825A4670)
DRAW_DIAG_SHIM(sub_825A4780)
DRAW_DIAG_SHIM(sub_825A47F0)
DRAW_DIAG_SHIM(sub_825A4D68)
DRAW_DIAG_SHIM(sub_825A4DD8)
DRAW_DIAG_SHIM(sub_825A5008)
DRAW_DIAG_SHIM(sub_825A5108)
DRAW_DIAG_SHIM(sub_825A52D0)
DRAW_DIAG_SHIM(sub_825A53B0)
DRAW_DIAG_SHIM(sub_825A5408)
DRAW_DIAG_SHIM(sub_825A5460)
// sub_825A54F0 already shimmed in mw05_trace_shims.cpp
DRAW_DIAG_SHIM(sub_825A5580)
DRAW_DIAG_SHIM(sub_825A55D0)
DRAW_DIAG_SHIM(sub_825A5880)
DRAW_DIAG_SHIM(sub_825A58C0)
DRAW_DIAG_SHIM(sub_825A5928)
DRAW_DIAG_SHIM(sub_825A59A8)
DRAW_DIAG_SHIM(sub_825A5A58)
DRAW_DIAG_SHIM(sub_825A5BC8)
DRAW_DIAG_SHIM(sub_825A5CC8)
// Custom shim for sub_825A5D60 to also dump device/scheduler headers occasionally
void sub_825A5D60(PPCContext& ctx, uint8_t* base) {
    if (IsDrawDiagnosticEnabled()) {
        KernelTraceHostOpF("HOST.DrawDiag.sub_825A5D60 lr=%08llX r3=%08X r4=%08X r5=%08X r6=%08X r7=%08X",
                           (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32, ctx.r7.u32);
        static uint32_t s_count = 0;
        if ((++s_count <= 8) || ((s_count & 0x3Fu) == 1u)) {
            // Dump device header more aggressively early on, then every 64 calls
            DumpEAU32Window("dev.hdr", ctx.r3.u32, 8);
            // Also try dumping the scheduler/context header pointed by device[0]
            uint32_t dev_ea = ctx.r3.u32;
            if (dev_ea >= 0x1000 && dev_ea < PPC_MEMORY_SIZE) {
                auto* p = reinterpret_cast<be<uint32_t>*>(g_memory.Translate(dev_ea));
                if (p) {
                    uint32_t sched_ea = (uint32_t)p[0];
                    if (sched_ea >= 0x1000 && sched_ea < PPC_MEMORY_SIZE) {
                        DumpEAU32Window("sched.hdr", sched_ea, 8);
                        // Build PM4 with proper r3=scheduler; unconditionally run deep chain
                        extern void MW05Shim_sub_82595FC8(PPCContext&, uint8_t*);
                        extern void MW05Shim_sub_825972B0(PPCContext&, uint8_t*);
                        extern void MW05Shim_sub_82597650(PPCContext&, uint8_t*);
                        extern void MW05Shim_sub_825976D8(PPCContext&, uint8_t*);
                        extern void MW05Shim_sub_825968B0(PPCContext&, uint8_t*);
                        extern void MW05Shim_sub_82596E40(PPCContext&, uint8_t*);
                        extern void MW05Shim_sub_825A54F0(PPCContext&, uint8_t*);
                        uint32_t saved_r3 = ctx.r3.u32;
                        ctx.r3.u32 = sched_ea;
                        KernelTraceHostOpF("HOST.DrawDiag.sub_825A5D60.try_alloc r3=%08X", ctx.r3.u32);
                        MW05Shim_sub_825968B0(ctx, base);
                        // Ensure r3 stays as scheduler for subsequent calls
                        ctx.r3.u32 = sched_ea;
                        KernelTraceHostOpF("HOST.DrawDiag.sub_825A5D60.try_pre r3=%08X", ctx.r3.u32);
                        MW05Shim_sub_82595FC8(ctx, base);
                        ctx.r3.u32 = sched_ea;
                        // Run tail helpers BEFORE main, in case main long-jumps out
                        KernelTraceHostOpF("HOST.DrawDiag.sub_825A5D60.try_tail_pre r3=%08X", ctx.r3.u32);
                        MW05Shim_sub_82597650(ctx, base);
                        ctx.r3.u32 = sched_ea;
                        MW05Shim_sub_825976D8(ctx, base);
                        ctx.r3.u32 = sched_ea;
                        MW05Shim_sub_82596E40(ctx, base);
                        ctx.r3.u32 = sched_ea;
                        // Try present-manager once before main builder to advance swap state
                        KernelTraceHostOpF("HOST.DrawDiag.sub_825A5D60.try_present_pre r3=%08X", ctx.r3.u32);
                        MW05Shim_sub_825A54F0(ctx, base);
                        ctx.r3.u32 = sched_ea;
                        // Now attempt main builder
                        KernelTraceHostOpF("HOST.DrawDiag.sub_825A5D60.try_main r3=%08X", ctx.r3.u32);
                        MW05Shim_sub_825972B0(ctx, base);
                        // Post helpers may not execute if main long-jumps; still try
                        ctx.r3.u32 = sched_ea;
                        KernelTraceHostOpF("HOST.DrawDiag.sub_825A5D60.try_post r3=%08X", ctx.r3.u32);
                        MW05Shim_sub_825A54F0(ctx, base);
                        ctx.r3.u32 = saved_r3;
                    }
                }
            }
        }
    }
    __imp__sub_825A5D60(ctx, base);
}

DRAW_DIAG_SHIM(sub_825A5EB0)

