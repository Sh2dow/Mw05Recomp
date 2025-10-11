// Initialization chain tracing for MW05
// This file wraps key initialization functions to trace why threads aren't being created

#include "stdafx.h"

// Wrapper for sub_82216398 - initialization gate that calls sub_82440220
extern "C" void __imp__sub_82216398(PPCContext&, uint8_t*);
static void MW05Trace_sub_82216398(PPCContext& ctx, uint8_t* base) {
    fprintf(stderr, "[INIT-TRACE] sub_82216398 INIT_GATE ENTER lr=%08llX\n", (unsigned long long)ctx.lr);
    fflush(stderr);
    KernelTraceHostOpF("HOST.sub_82216398 INIT_GATE ENTER lr=%08llX", (unsigned long long)ctx.lr);
    __imp__sub_82216398(ctx, base);
    fprintf(stderr, "[INIT-TRACE] sub_82216398 INIT_GATE EXIT\n");
    fflush(stderr);
    KernelTraceHostOpF("HOST.sub_82216398 INIT_GATE EXIT");
}

// Wrapper for sub_82440220 - main initialization that calls sub_825A16A0
extern "C" void __imp__sub_82440220(PPCContext&, uint8_t*);
static void MW05Trace_sub_82440220(PPCContext& ctx, uint8_t* base) {
    fprintf(stderr, "[INIT-TRACE] sub_82440220 MAIN_INIT ENTER lr=%08llX\n", (unsigned long long)ctx.lr);
    fflush(stderr);
    KernelTraceHostOpF("HOST.sub_82440220 MAIN_INIT ENTER lr=%08llX", (unsigned long long)ctx.lr);
    __imp__sub_82440220(ctx, base);
    fprintf(stderr, "[INIT-TRACE] sub_82440220 MAIN_INIT EXIT\n");
    fflush(stderr);
    KernelTraceHostOpF("HOST.sub_82440220 MAIN_INIT EXIT");
}

// Wrapper for sub_825A16A0 - graphics initialization that calls CreateDevice
extern "C" void __imp__sub_825A16A0(PPCContext&, uint8_t*);
static void MW05Trace_sub_825A16A0(PPCContext& ctx, uint8_t* base) {
    fprintf(stderr, "[INIT-TRACE] sub_825A16A0 GFX_INIT ENTER lr=%08llX r3=%08X r4=%08X\n",
            (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32);
    fflush(stderr);
    KernelTraceHostOpF("HOST.sub_825A16A0 GFX_INIT ENTER lr=%08llX r3=%08X r4=%08X",
                       (unsigned long long)ctx.lr, ctx.r3.u32, ctx.r4.u32);
    __imp__sub_825A16A0(ctx, base);
    fprintf(stderr, "[INIT-TRACE] sub_825A16A0 GFX_INIT EXIT r3=%08X\n", ctx.r3.u32);
    fflush(stderr);
    KernelTraceHostOpF("HOST.sub_825A16A0 GFX_INIT EXIT r3=%08X", ctx.r3.u32);
}

// Wrapper for sub_824BF440 - function that calls sub_82216398
extern "C" void __imp__sub_824BF440(PPCContext&, uint8_t*);
static void MW05Trace_sub_824BF440(PPCContext& ctx, uint8_t* base) {
    fprintf(stderr, "[INIT-TRACE] sub_824BF440 CALLER ENTER lr=%08llX\n", (unsigned long long)ctx.lr);
    fflush(stderr);
    KernelTraceHostOpF("HOST.sub_824BF440 CALLER ENTER lr=%08llX", (unsigned long long)ctx.lr);
    __imp__sub_824BF440(ctx, base);
    fprintf(stderr, "[INIT-TRACE] sub_824BF440 CALLER EXIT\n");
    fflush(stderr);
    KernelTraceHostOpF("HOST.sub_824BF440 CALLER EXIT");
}

// Wrapper for _xstart - C runtime startup (entry point at 0x8262E9A8)
extern "C" void __imp___xstart(PPCContext&, uint8_t*);
static void MW05Trace__xstart(PPCContext& ctx, uint8_t* base) {
    fprintf(stderr, "[INIT-TRACE] _xstart ENTRY_POINT ENTER lr=%08llX\n", (unsigned long long)ctx.lr);
    fflush(stderr);
    KernelTraceHostOpF("HOST._xstart ENTRY_POINT ENTER lr=%08llX", (unsigned long long)ctx.lr);
    __imp___xstart(ctx, base);
    fprintf(stderr, "[INIT-TRACE] _xstart ENTRY_POINT EXIT\n");
    fflush(stderr);
    KernelTraceHostOpF("HOST._xstart ENTRY_POINT EXIT");
}

// Register the wrappers
GUEST_FUNCTION_HOOK(sub_82216398, MW05Trace_sub_82216398);
GUEST_FUNCTION_HOOK(sub_82440220, MW05Trace_sub_82440220);
GUEST_FUNCTION_HOOK(sub_825A16A0, MW05Trace_sub_825A16A0);
GUEST_FUNCTION_HOOK(sub_824BF440, MW05Trace_sub_824BF440);
GUEST_FUNCTION_HOOK(_xstart, MW05Trace__xstart);

// Ensure hooks are registered
static void RegisterMw05InitTraceHooks() {
    fprintf(stderr, "[INIT-TRACE] Registering initialization trace hooks\n");
    fflush(stderr);
    g_memory.InsertFunction(0x82216398, sub_82216398);
    g_memory.InsertFunction(0x82440220, sub_82440220);
    g_memory.InsertFunction(0x825A16A0, sub_825A16A0);
    g_memory.InsertFunction(0x824BF440, sub_824BF440);
    g_memory.InsertFunction(0x8262E9A8, _xstart);
}

// Auto-register on module load
static struct AutoRegister {
    AutoRegister() { RegisterMw05InitTraceHooks(); }
} s_autoReg;

