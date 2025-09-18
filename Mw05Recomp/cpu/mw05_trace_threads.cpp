// Trace MW05 thread entries and optionally kick minimal video init.

#include <cpu/ppc_context.h>
#include <kernel/trace.h>
#include <kernel/memory.h>
#include <kernel/heap.h>
#include "xbox.h"
#include <cstdlib>

extern "C" {
    void __imp__sub_828508A8(PPCContext& ctx, uint8_t* base);
    void __imp__sub_82812ED0(PPCContext& ctx, uint8_t* base);
}

extern void Mw05RegisterVdInterruptEvent(uint32_t eventEA, bool manualReset);

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

    const uint32_t block_ptr = ctx.r3.u32;
    KernelTraceHostOpF("HOST.ThreadEntry.82812ED0.block ptr=%08X", block_ptr);
    if (block_ptr) {
        uint8_t* raw = static_cast<uint8_t*>(g_memory.Translate(block_ptr));
        if (raw) {
            struct ThreadStartBlock {
                be<uint32_t> state;
                be<uint32_t> entry;
                be<uint32_t> context;
                be<uint32_t> event;
                be<uint32_t> work_item_a;
                be<uint32_t> work_item_b;
            };
            const auto* block = reinterpret_cast<const ThreadStartBlock*>(raw);
            KernelTraceHostOpF("HOST.ThreadEntry.82812ED0.block fields state=%08X entry=%08X ctx=%08X evt=%08X w0=%08X w1=%08X",
                               static_cast<uint32_t>(block->state),
                               static_cast<uint32_t>(block->entry),
                               static_cast<uint32_t>(block->context),
                               static_cast<uint32_t>(block->event),
                               static_cast<uint32_t>(block->work_item_a),
                               static_cast<uint32_t>(block->work_item_b));
            KernelTraceHostOpF("HOST.ThreadEntry.82812ED0.block raw %02X %02X %02X %02X  %02X %02X %02X %02X  %02X %02X %02X %02X  %02X %02X %02X %02X",
                               raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                               raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]);
            const uint32_t eventEA = static_cast<uint32_t>(block->event);
            if (eventEA) {
                bool manualReset = false;
                if (auto* hdr = reinterpret_cast<XDISPATCHER_HEADER*>(g_memory.Translate(eventEA))) {
                    manualReset = (hdr->Type == 0);
                }
                Mw05RegisterVdInterruptEvent(eventEA, manualReset);
                KernelTraceHostOpF("HOST.ThreadEntry.82812ED0.event ea=%08X manual=%u", eventEA, manualReset ? 1u : 0u);
            }
        }
    }

    if (KickVideoInitEnabled()) KickMinimalVideo();
    __imp__sub_82812ED0(ctx, base);
}
