// Runtime patch hooks for problematic recompiled functions that are called directly
// (bypassing g_memory InsertFunction redirection). We patch the prologue of the
// __imp__ functions to jump to our safe stubs.

#include <cstdint>
#include <windows.h>
#include <kernel/trace.h>
#include <cpu/ppc_context.h>

extern "C" 
{
    void __imp__sub_82625D60(PPCContext& ctx, uint8_t* base);
    void __imp__sub_8261E320(PPCContext& ctx, uint8_t* base);
    void __imp__sub_82855308(PPCContext& ctx, uint8_t* base);
}

static void LogBytes(const char* tag, const void* p, size_t n) {
    const uint8_t* b = reinterpret_cast<const uint8_t*>(p);
    uint64_t v0 = 0, v1 = 0;
    memcpy(&v0, b + 0, (n >= 8 ? 8 : n));
    if (n > 8) memcpy(&v1, b + 8, (n - 8 >= 8 ? 8 : n - 8));
    KernelTraceHostOpF("HOST.Patch.%s at=%p b0=%016llX b1=%016llX", tag, p, (unsigned long long)v0, (unsigned long long)v1);
}

static void PatchFunctionJump(void* target, void* replacement)
{
    LogBytes("pre", target, 16);
    DWORD oldProt = 0;
    if (!VirtualProtect(target, 16, PAGE_EXECUTE_READWRITE, &oldProt)) {
        KernelTraceHostOpF("HOST.Patch.fail vp target=%p err=%lu", target, GetLastError());
        return;
    }
    // mov rax, imm64 ; jmp rax
    uint8_t stub[12];
    stub[0] = 0x48; stub[1] = 0xB8; // MOV RAX, imm64
    *reinterpret_cast<uint64_t*>(&stub[2]) = reinterpret_cast<uint64_t>(replacement);
    stub[10] = 0xFF; stub[11] = 0xE0; // JMP RAX

    memcpy(target, stub, sizeof(stub));
    FlushInstructionCache(GetCurrentProcess(), target, sizeof(stub));
    DWORD tmp; VirtualProtect(target, 16, oldProt, &tmp);
    LogBytes("post", target, 16);
}

extern "C" void __imp__sub_82625D60_stub(PPCContext& ctx, uint8_t* /*base*/)
{
    KernelTraceHostOpF("HOST.RuntimeHook.__imp__sub_82625D60 STUB r3=%08X r4=%08X r5=%08X r6=%08X",
                       ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32);
    ctx.r3.u32 = 0; // conservative success
}
extern "C" void __imp__sub_8261E320_stub(PPCContext& ctx, uint8_t* /*base*/)
{
    KernelTraceHostOpF("HOST.RuntimeHook.__imp__sub_8261E320 STUB r3=%08X r4=%08X r5=%08X r6=%08X",
                       ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32);
    ctx.r3.u32 = 0;
}
extern "C" void __imp__sub_82855308_stub(PPCContext& ctx, uint8_t* /*base*/)
{
    KernelTraceHostOpF("HOST.RuntimeHook.__imp__sub_82855308 STUB r3=%08X r4=%08X r5=%08X r6=%08X",
                       ctx.r3.u32, ctx.r4.u32, ctx.r5.u32, ctx.r6.u32);
    ctx.r3.u32 = 0;
}

static void InstallRuntimePatches()
{
    PatchFunctionJump(reinterpret_cast<void*>(&__imp__sub_82625D60),
                      reinterpret_cast<void*>(&__imp__sub_82625D60_stub));
    PatchFunctionJump(reinterpret_cast<void*>(&__imp__sub_8261E320),
                      reinterpret_cast<void*>(&__imp__sub_8261E320_stub));
    PatchFunctionJump(reinterpret_cast<void*>(&__imp__sub_82855308),
                      reinterpret_cast<void*>(&__imp__sub_82855308_stub));
}

static bool RuntimePatchesEnabled()
{
    if (const char* v = std::getenv("MW05_RUNTIME_PATCHES")) {
        return v[0] && v[0] != '0';
    }
    return false; // default: disabled to allow real code paths
}

#if defined(_MSC_VER)
#  pragma section(".CRT$XCU",read)
    static void __cdecl ppc_runtime_patch_hooks_ctor();
    __declspec(allocate(".CRT$XCU")) void (*ppc_runtime_patch_hooks_ctor_)(void) = ppc_runtime_patch_hooks_ctor;
    static void __cdecl ppc_runtime_patch_hooks_ctor() { if (RuntimePatchesEnabled()) InstallRuntimePatches(); else KernelTraceHostOp("HOST.Patch.skip"); }
#else
    __attribute__((constructor)) static void ppc_runtime_patch_hooks_ctor() { if (RuntimePatchesEnabled()) InstallRuntimePatches(); else KernelTraceHostOp("HOST.Patch.skip"); }
#endif

