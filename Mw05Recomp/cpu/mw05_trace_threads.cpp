// Trace MW05 thread entries and optionally kick minimal video init.

#include <cpu/ppc_context.h>
#include <kernel/trace.h>
#include <kernel/memory.h>
#include <kernel/heap.h>
#include <cstdlib>

extern "C" {
    void __imp__sub_828508A8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_82812ED0(PPCContext& ctx, uint8_t* base);
}

static inline bool KickVideoInitEnabled() {
    if (const char* v = std::getenv("MW05_KICK_VIDEO")) {
        return !(v[0] == '0' && v[1] == '\0');
    }
    return false;
}

// Minimal host-side kick (idempotent) to initialize system command buffer.
// Host Vd helper forward-decl (defined in kernel/imports.cpp)
extern uint32_t VdGetSystemCommandBuffer(be<uint32_t>* outCmdBufPtr, be<uint32_t>* outValue);
// Host Vd helpers we can invoke to seed minimal video state
extern void VdInitializeEngines();
extern void VdInitializeRingBuffer(uint32_t base, uint32_t len_log2);
extern void VdEnableRingBufferRPtrWriteBack(uint32_t base);
extern void VdSetSystemCommandBufferGpuIdentifierAddress(uint32_t addr);

static void KickMinimalVideo()
{
    static bool s_done = false;
    if (s_done) return;
    s_done = true;

    // 1) Ensure the system command buffer exists
    VdGetSystemCommandBuffer(nullptr, nullptr);

    // 2) Create a small ring buffer and write-back pointer in guest memory
    const uint32_t len_log2 = 12; // 4 KiB ring (small, dev-only)
    const uint32_t size_bytes = 1u << len_log2;
    void* ring_host = g_userHeap.Alloc(size_bytes, 0x100);
    if (!ring_host) return;
    const uint32_t ring_guest = g_memory.MapVirtual(ring_host);

    void* wb_host = g_userHeap.Alloc(64, 4);
    if (!wb_host) return;
    const uint32_t wb_guest = g_memory.MapVirtual(wb_host);

    // 3) Seed ring buffer state via host helpers
    VdInitializeRingBuffer(ring_guest, len_log2);
    VdEnableRingBufferRPtrWriteBack(wb_guest);
    VdSetSystemCommandBufferGpuIdentifierAddress(wb_guest + 8); // arbitrary within wb area
    VdInitializeEngines();
}

void sub_828508A8(PPCContext& ctx, uint8_t* base)
{
    KernelTraceHostOp("HOST.ThreadEntry.828508A8");
    if (KickVideoInitEnabled()) KickMinimalVideo();
    __imp__sub_828508A8(ctx, base);
}

void sub_82812ED0(PPCContext& ctx, uint8_t* base)
{
    KernelTraceHostOp("HOST.ThreadEntry.82812ED0");
    if (KickVideoInitEnabled()) KickMinimalVideo();
    __imp__sub_82812ED0(ctx, base);
}
