// MW05 Draw Function Diagnostic Hooks
// Purpose: Identify which MW05 functions are the actual draw calls
// by hooking a wide range of candidates and logging their activity.

#include <kernel/trace.h>
#include <cpu/ppc_context.h>
#include <ppc/ppc_recomp_shared.h>

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
DRAW_DIAG_SHIM(sub_825A25E8)
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
DRAW_DIAG_SHIM(sub_825A5D60)
DRAW_DIAG_SHIM(sub_825A5EB0)

