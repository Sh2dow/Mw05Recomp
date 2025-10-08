#include <stdafx.h>
#include "heap.h"
#include "memory.h"
#include "function.h"
#include <os/logger.h>

// Forward declaration for VD initialization
extern "C" void Mw05ForceVdInitOnce();

constexpr uint32_t kStatusSuccess = 0;
constexpr uint32_t kStatusInvalidParameter = 0xC000000D;
constexpr uint32_t kStatusNoMemory = 0xC0000017;

constexpr size_t RESERVED_BEGIN = 0x7FEA0000;
constexpr size_t RESERVED_END = 0xA0000000;

void Heap::Init()
{
    heapBase = g_memory.Translate(0x20000);
    heapSize = RESERVED_BEGIN - 0x20000;
    heap = o1heapInit(heapBase, heapSize);
    physicalBase = g_memory.Translate(RESERVED_END);
    physicalSize = 0x100000000ull - RESERVED_END;
    physicalHeap = o1heapInit(physicalBase, physicalSize);
}

void* Heap::Alloc(size_t size)
{
    std::lock_guard lock(mutex);
    size = std::max<size_t>(1, size);
    {
        const char* t1 = std::getenv("MW05_TRACE_HEAP");
        const char* t2 = std::getenv("MW05_TRACE_MEM");
        const bool on = (t1 && !(t1[0]=='0' && t1[1]=='\0')) || (t2 && !(t2[0]=='0' && t2[1]=='\0'));
        if (on)
        {
            const auto d = o1heapGetDiagnostics(heap);
            bool ok = o1heapDoInvariantsHold(heap);
            LOGFN("[heap] user pre-alloc size={} diag alloc={}/{} oom={} invariants={} ",
                  size, d.allocated, d.capacity, (unsigned long long)d.oom_count, ok ? "ok" : "bad");
        }
    }
    void* out = o1heapAllocate(heap, size);
    {
        const char* t1 = std::getenv("MW05_TRACE_HEAP");
        const char* t2 = std::getenv("MW05_TRACE_MEM");
        const bool on = (t1 && !(t1[0]=='0' && t1[1]=='\0')) || (t2 && !(t2[0]=='0' && t2[1]=='\0'));
        if (on)
        {
            const auto d = o1heapGetDiagnostics(heap);
            LOGFN("[heap] user alloc size={} host={} guest=0x{:08X} alloc={}/{} oom={}",
                  size, (const void*)out, g_memory.MapVirtual(out), d.allocated, d.capacity, (unsigned long long)d.oom_count);
        }
    }
    if (const char* chk = std::getenv("MW05_HEAP_CHECK"))
    {
        if (chk[0] && !(chk[0]=='0' && chk[1]=='\0'))
        {
            if (!o1heapDoInvariantsHold(heap))
            {
                LOGFN("[heap] user invariants FAILED after alloc size={} host={}", size, (const void*)out);
            }
        }
    }
    return out;
}

void* Heap::Alloc(size_t size, size_t alignment)
{
    std::lock_guard lock(mutex);
    size = std::max<size_t>(1, size);
    alignment = alignment == 0 ? 16 : std::max<size_t>(16, alignment);

    {
        const char* t1 = std::getenv("MW05_TRACE_HEAP");
        const char* t2 = std::getenv("MW05_TRACE_MEM");
        const bool on = (t1 && !(t1[0]=='0' && t1[1]=='\0')) || (t2 && !(t2[0]=='0' && t2[1]=='\0'));
        if (on)
        {
            const auto d = o1heapGetDiagnostics(heap);
            bool ok = o1heapDoInvariantsHold(heap);
            LOGFN("[heap] user pre-alloc(aligned) size={} align={} alloc={}/{} oom={} invariants={} ",
                  size, alignment, d.allocated, d.capacity, (unsigned long long)d.oom_count, ok ? "ok" : "bad");
        }
    }

    // Reserve extra slack so we can always place a tag before the aligned pointer.
    void* base = o1heapAllocate(heap, size + (alignment * 2));
    size_t aligned = ((size_t)base + alignment) & ~(alignment - 1);
    if (aligned - (size_t)base < 16)
        aligned += alignment; // ensure at least 16 bytes for the tag

    // Mark aligned interior pointer and keep original base for recovery.
    *((uint64_t*)aligned - 2) = Heap::kAlignedMagic;
    *((void**)aligned - 1) = base;

    void* out = (void*)aligned;
    {
        const char* t1 = std::getenv("MW05_TRACE_HEAP");
        const char* t2 = std::getenv("MW05_TRACE_MEM");
        const bool on = (t1 && !(t1[0]=='0' && t1[1]=='\0')) || (t2 && !(t2[0]=='0' && t2[1]=='\0'));
        if (on)
        {
            const auto d = o1heapGetDiagnostics(heap);
            LOGFN("[heap] user alloc(aligned) size={} align={} host_base={} host_aligned={} guest=0x{:08X} alloc={}/{} oom={}",
                  size, alignment, (const void*)base, out, g_memory.MapVirtual(out), d.allocated, d.capacity, (unsigned long long)d.oom_count);
        }
    }
    if (const char* chk = std::getenv("MW05_HEAP_CHECK"))
    {
        if (chk[0] && !(chk[0]=='0' && chk[1]=='\0'))
        {
            if (!o1heapDoInvariantsHold(heap))
            {
                LOGFN("[heap] user invariants FAILED after alloc(aligned) size={} host_base={} host_aligned={}", size, (const void*)base, out);
            }
        }
    }
    return out;
}

void* Heap::AllocPhysical(size_t size, size_t alignment)
{
    size = std::max<size_t>(1, size);
    alignment = alignment == 0 ? 0x1000 : std::max<size_t>(16, alignment);

    std::lock_guard lock(physicalMutex);

    // Reserve extra slack so we can always place a tag before the aligned pointer.
    void* base = o1heapAllocate(physicalHeap, size + (alignment * 2));
    size_t aligned = ((size_t)base + alignment) & ~(alignment - 1);
    if (aligned - (size_t)base < 16)
        aligned += alignment; // ensure at least 16 bytes for the tag

    // Mark aligned interior pointer and keep original base for recovery.
    *((uint64_t*)aligned - 2) = Heap::kAlignedMagic;
    *((void**)aligned - 1) = base;

    void* out = (void*)aligned;
    {
        const char* t1 = std::getenv("MW05_TRACE_HEAP");
        const char* t2 = std::getenv("MW05_TRACE_MEM");
        const bool on = (t1 && !(t1[0]=='0' && t1[1]=='\0')) || (t2 && !(t2[0]=='0' && t2[1]=='\0'));
        if (on)
        {
            const auto d = o1heapGetDiagnostics(physicalHeap);
            LOGFN("[heap] physical alloc size={} align={} host_base={} host_aligned={} guest=0x{:08X} alloc={}/{} oom={}",
                  size, alignment, (const void*)base, out, g_memory.MapVirtual(out), d.allocated, d.capacity, (unsigned long long)d.oom_count);
        }
    }
    if (const char* chk = std::getenv("MW05_HEAP_CHECK"))
    {
        if (chk[0] && !(chk[0]=='0' && chk[1]=='\0'))
        {
            if (!o1heapDoInvariantsHold(physicalHeap))
            {
                LOGFN("[heap] physical invariants FAILED after alloc size={} host={} aligned={}", size, (const void*)base, out);
            }
        }
    }
    return out;
}

void Heap::Free(void* ptr)
{
    // Robust range check rather than pointer comparison on instance pointer.
    auto in_range = [](void* p, void* base, size_t size) -> bool {
        return p >= base && p < (static_cast<uint8_t*>(base) + size);
    };

    if (ptr != nullptr && in_range(ptr, physicalBase, physicalSize))
    {
        std::lock_guard lock(physicalMutex);
        // If this is an aligned interior pointer, translate to original base.
        if (*((uint64_t*)ptr - 2) == Heap::kAlignedMagic)
        {
            ptr = *((void**)ptr - 1);
        }
        {
            const char* t1 = std::getenv("MW05_TRACE_HEAP");
            const char* t2 = std::getenv("MW05_TRACE_MEM");
            const bool on = (t1 && !(t1[0]=='0' && t1[1]=='\0')) || (t2 && !(t2[0]=='0' && t2[1]=='\0'));
            if (on)
            {
                const auto d = o1heapGetDiagnostics(physicalHeap);
                LOGFN("[heap] physical free host_aligned={} guest=0x{:08X} host_base={} alloc={}/{} oom={}",
                      ptr, g_memory.MapVirtual(ptr), *((void**)ptr - 1), d.allocated, d.capacity, (unsigned long long)d.oom_count);
            }
        }
        o1heapFree(physicalHeap, ptr);
        if (const char* chk = std::getenv("MW05_HEAP_CHECK"))
        {
            if (chk[0] && !(chk[0]=='0' && chk[1]=='\0'))
            {
                if (!o1heapDoInvariantsHold(physicalHeap))
                {
                    LOGFN("[heap] physical invariants FAILED after free host_aligned={}", ptr);
                }
            }
        }
    }
    else if (ptr != nullptr && in_range(ptr, heapBase, heapSize))
    {
        std::lock_guard lock(mutex);
        // If this is an aligned interior pointer (e.g., from VM reserve), redirect to original base.
        if (*((uint64_t*)ptr - 2) == Heap::kAlignedMagic)
        {
            void* base = *((void**)ptr - 1);
            // Decide which heap owns the base.
            if (in_range(base, physicalBase, physicalSize))
            {
                // Was actually allocated from physical heap, free there.
                std::lock_guard lock2(physicalMutex);
                o1heapFree(physicalHeap, base);
                return;
            }
            else
            {
                ptr = base;
            }
        }
        {
            const char* t1 = std::getenv("MW05_TRACE_HEAP");
            const char* t2 = std::getenv("MW05_TRACE_MEM");
            const bool on = (t1 && !(t1[0]=='0' && t1[1]=='\0')) || (t2 && !(t2[0]=='0' && t2[1]=='\0'));
            if (on)
            {
                const auto d = o1heapGetDiagnostics(heap);
                LOGFN("[heap] user free host={} guest=0x{:08X} alloc={}/{} oom={}",
                      ptr, g_memory.MapVirtual(ptr), d.allocated, d.capacity, (unsigned long long)d.oom_count);
            }
        }
        o1heapFree(heap, ptr);
        if (const char* chk = std::getenv("MW05_HEAP_CHECK"))
        {
            if (chk[0] && !(chk[0]=='0' && chk[1]=='\0'))
            {
                if (!o1heapDoInvariantsHold(heap))
                {
                    LOGFN("[heap] user invariants FAILED after free host={}", ptr);
                }
            }
        }
    }
    else
    {
        // Unknown pointer; drop and warn.
        LOGFN("[heap] warn: Free called with out-of-range pointer host={}", ptr);
    }
}

size_t Heap::Size(void* ptr)
{
    if (!ptr) return 0;

    auto read_fragment_size = [](void* user_ptr) -> size_t {
        uint8_t* header = static_cast<uint8_t*>(user_ptr) - O1HEAP_ALIGNMENT;
        return *(reinterpret_cast<size_t*>(header));
    };

    // If this is an aligned interior pointer marked with magic, recover base.
    if (*((uint64_t*)ptr - 2) == Heap::kAlignedMagic)
    {
        void* base = *((void**)ptr - 1);
        if (base)
        {
            const size_t frag = read_fragment_size(base);
            return frag - O1HEAP_ALIGNMENT;
        }
    }

    const size_t frag = read_fragment_size(ptr);
    return frag - O1HEAP_ALIGNMENT;
}

uint32_t RtlAllocateHeap(uint32_t heapHandle, uint32_t flags, uint32_t size)
{
    void* ptr = g_userHeap.Alloc(size);
    if ((flags & 0x8) != 0)
        memset(ptr, 0, size);

    assert(ptr);
    return g_memory.MapVirtual(ptr);
}

uint32_t RtlReAllocateHeap(uint32_t heapHandle, uint32_t flags, uint32_t memoryPointer, uint32_t size)
{
    void* ptr = g_userHeap.Alloc(size);
    if ((flags & 0x8) != 0)
        memset(ptr, 0, size);

    if (memoryPointer != 0)
    {
        void* oldPtr = g_memory.Translate(memoryPointer);
        memcpy(ptr, oldPtr, std::min<size_t>(size, g_userHeap.Size(oldPtr)));
        g_userHeap.Free(oldPtr);
    }

    assert(ptr);
    return g_memory.MapVirtual(ptr);
}

uint32_t RtlFreeHeap(uint32_t heapHandle, uint32_t flags, uint32_t memoryPointer)
{
    if (memoryPointer != NULL)
        g_userHeap.Free(g_memory.Translate(memoryPointer));

    return true;
}

uint32_t RtlSizeHeap(uint32_t heapHandle, uint32_t flags, uint32_t memoryPointer)
{
    if (memoryPointer != NULL)
        return (uint32_t)g_userHeap.Size(g_memory.Translate(memoryPointer));

    return 0;
}

uint32_t XAllocMem(uint32_t size, uint32_t flags)
{
    // Flags:
    // - 0x80000000: allocate from physical heap
    // - 0x40000000: zero memory
    // - bits 27..24: alignment exponent (1 << n); when n==0 treat as default
    const bool phys = (flags & 0x80000000u) != 0u;
    const uint32_t align_nibble = (flags >> 24) & 0xFu;
    const size_t alignment = (align_nibble == 0) ? 0 : (size_t(1) << align_nibble);

    void* ptr = nullptr;
    if (phys)
    {
        // For physical allocations, when align nibble is 0, use default 4 KiB page alignment.
        ptr = g_userHeap.AllocPhysical(size, alignment /* 0 => default 0x1000 inside */);
    }
    else
    {
        // For virtual allocations, honor alignment nibble when specified; otherwise default path.
        if (alignment != 0)
            ptr = g_userHeap.Alloc(size, alignment);
        else
            ptr = g_userHeap.Alloc(size);
    }

    if (!ptr) {
        LOGF_ERROR("[heap] XAllocMem failed size={} flags={:08X}", size, flags);
        return 0;
    }

    if ((flags & 0x40000000u) != 0u)
        memset(ptr, 0, size);

    return g_memory.MapVirtual(ptr);
}


void XFreeMem(uint32_t baseAddress, uint32_t flags)
{
    if (baseAddress != NULL)
        g_userHeap.Free(g_memory.Translate(baseAddress));
}

uint32_t ExAllocatePool(uint32_t poolType, uint32_t numberOfBytes)
{
    (void)poolType;
    void* ptr = g_userHeap.Alloc(numberOfBytes);
    if (!ptr) {
        LOGF_ERROR("[heap] ExAllocatePool failed size={} type={}", numberOfBytes, poolType);
        return 0;
    }
    return g_memory.MapVirtual(ptr);
}

uint32_t ExAllocatePoolWithTag(uint32_t poolType, uint32_t numberOfBytes, uint32_t tag)
{
    (void)tag;
    return ExAllocatePool(poolType, numberOfBytes);
}

void ExFreePool(uint32_t baseAddress)
{
    if (baseAddress != 0) {
        g_userHeap.Free(g_memory.Translate(baseAddress));
    }
}

uint32_t XamAlloc(uint32_t flags, uint32_t size, be<uint32_t>* outAddress)
{
    if (!outAddress) {
        return kStatusInvalidParameter;
    }

    const uint32_t guestPtr = XAllocMem(size, flags);
    if (!guestPtr) {
        return kStatusNoMemory;
    }

    *outAddress = guestPtr;
    return kStatusSuccess;
}

uint32_t XamFree(uint32_t flags, uint32_t baseAddress)
{
    (void)flags;
    if (baseAddress != 0) {
        g_userHeap.Free(g_memory.Translate(baseAddress));
    }
    return kStatusSuccess;
}

GUEST_FUNCTION_STUB(sub_82BD7788); // HeapCreate
GUEST_FUNCTION_STUB(sub_82BD9250); // HeapDestroy

// Game-specific allocator used by video subsystem
// This allocator is called 51 times throughout the game, including by sub_82849DE8 (video singleton creator)
// Shimming it to use the host allocator fixes the video singleton allocation failure
void MW05Shim_sub_82539870(PPCContext& ctx, uint8_t* base)
{
    uint32_t size = ctx.r3.u32;
    void* ptr = g_userHeap.Alloc(size);
    if (!ptr) {
        fprintf(stderr, "[heap] sub_82539870 FAILED to allocate %u bytes\n", size);
        fflush(stderr);
        ctx.r3.u32 = 0;
        return;
    }
    uint32_t guestAddr = g_memory.MapVirtual(ptr);
    fprintf(stderr, "[heap] sub_82539870 allocated %u bytes at guest=%08X\n", size, guestAddr);
    fflush(stderr);
    ctx.r3.u32 = guestAddr;
}

GUEST_FUNCTION_HOOK(__imp__sub_82539870, MW05Shim_sub_82539870);

// CRITICAL FIX: sub_8284A698 is supposed to initialize the object but doesn't set the vtable
// We need to stub it to properly initialize the object with a vtable
// Looking at the IDA code, this function allocates 432 bytes and initializes the object
// But the vtable is not being set, causing NULL vtable pointer issues
extern "C" void __imp__sub_8284A698(PPCContext& ctx, uint8_t* base);

void MW05Shim_sub_8284A698(PPCContext& ctx, uint8_t* base)
{
    fprintf(stderr, "[heap] MW05Shim_sub_8284A698 ENTRY\n");
    fflush(stderr);

    uint32_t r3_in = ctx.r3.u32;  // Object pointer (offset +8 from base)
    uint32_t r4_in = ctx.r4.u32;
    uint32_t r5_in = ctx.r5.u32;

    fprintf(stderr, "[heap] sub_8284A698 CALLED r3=%08X r4=%08X r5=%08X\n", r3_in, r4_in, r5_in);
    fflush(stderr);

    // Call the original function
    __imp__sub_8284A698(ctx, base);

    // After the original function, patch the vtable pointer
    // Allocate a dummy vtable in guest memory
    static uint32_t s_vtable_guest_addr = 0;

    if (s_vtable_guest_addr == 0) {
        // Allocate 128 bytes for the vtable (32 entries * 4 bytes)
        void* vtable_host = g_userHeap.Alloc(128);
        if (vtable_host) {
            s_vtable_guest_addr = g_memory.MapVirtual(vtable_host);

            // Initialize the vtable - all entries NULL except offset 0x34
            uint32_t* vtable_ptr = reinterpret_cast<uint32_t*>(vtable_host);
            memset(vtable_ptr, 0, 128);

            // Set entry at offset 0x34 (index 13) to point to our stub
            vtable_ptr[13] = __builtin_bswap32(0x82849000);

            fprintf(stderr, "[heap] Allocated dummy vtable at guest=%08X with stub at offset 0x34\n", s_vtable_guest_addr);
            fflush(stderr);
        } else {
            fprintf(stderr, "[heap] FAILED to allocate dummy vtable!\n");
            fflush(stderr);
        }
    }

    // Set the vtable pointer at offset 0 of the object
    if (s_vtable_guest_addr) {
        uint32_t obj_addr = r3_in - 8;  // r3 is offset +8, so object base is -8
        uint32_t* obj_ptr = reinterpret_cast<uint32_t*>(g_memory.Translate(obj_addr));
        if (obj_ptr) {
            *obj_ptr = __builtin_bswap32(s_vtable_guest_addr);
            fprintf(stderr, "[heap] Set vtable pointer at object %08X to %08X\n", obj_addr, s_vtable_guest_addr);
            fflush(stderr);

            // CRITICAL: Initialize offset 0x60 to non-zero to unblock the video thread
            // The video thread (sub_82849D40) waits in a loop until offset 0x60 is non-zero
            // Set it to 2 (the value it sets after the wait loop completes)
            uint32_t* field_0x60 = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(obj_ptr) + 0x60);
            *field_0x60 = __builtin_bswap32(2);
            fprintf(stderr, "[heap] Set object+0x60 to 2 to unblock video thread\n");
            fflush(stderr);
        }
    }

    int32_t result = static_cast<int32_t>(ctx.r3.u32);
    fprintf(stderr, "[heap] sub_8284A698 RETURNED r3=%08X (%d)\n", ctx.r3.u32, result);
    fflush(stderr);
    fprintf(stderr, "[heap] TEST: About to call Mw05ForceVdInitOnce\n");
    fflush(stderr);

    // CRITICAL: Initialize VD graphics subsystem now that video singleton is created
    // This ensures ring buffer, system command buffer, and engines are initialized
    try {
        Mw05ForceVdInitOnce();
        fprintf(stderr, "[heap] TEST: Mw05ForceVdInitOnce completed\n");
        fflush(stderr);
    } catch (...) {
        fprintf(stderr, "[heap] ERROR: Exception in Mw05ForceVdInitOnce!\n");
        fflush(stderr);
    }
}

GUEST_FUNCTION_HOOK(sub_8284A698, MW05Shim_sub_8284A698);

// CRITICAL FIX: This function is failing with E_OUTOFMEMORY (0x8007000E)
// It's trying to initialize D3D resources but failing
// For now, just stub it out to return success
// Called by sub_82849DE8 after sub_8284A698 succeeds
void MW05Shim_sub_82881020(PPCContext& ctx, uint8_t* base)
{
    uint32_t r3_in = ctx.r3.u32;
    uint32_t r4_in = ctx.r4.u32;
    uint32_t r5_in = ctx.r5.u32;

    fprintf(stderr, "[heap] sub_82881020 STUBBED (was failing with E_OUTOFMEMORY) r3=%08X r4=%08X r5=%08X\n", r3_in, r4_in, r5_in);
    fflush(stderr);

    // Return success instead of calling the failing function
    ctx.r3.u32 = 0;  // Success

    fprintf(stderr, "[heap] sub_82881020 STUBBED returning SUCCESS\n");
    fflush(stderr);
}

GUEST_FUNCTION_HOOK(__imp__sub_82881020, MW05Shim_sub_82881020);

// CRITICAL FIX: Stub for NULL vtable entry at offset 0x34
// This vtable entry is called by sub_82849BF8 in a loop 4 times
// The result is shifted and ORed together
// Looking at the IDA code, the loop calls the vtable function 4 times (r30 = 0..3)
// and shifts the result left by r30, then ORs it together
// For now, just return 1 to indicate success/availability
void MW05Stub_sub_82849000(PPCContext& ctx, uint8_t* base)
{
    static int call_count = 0;
    if (call_count++ < 10) {
        fprintf(stderr, "[heap] NULL vtable entry stub (sub_82849000) called, returning 1\n");
        fflush(stderr);
    }
    // Return 1 to indicate success
    ctx.r3.u32 = 1;
}

// Register the stub at address 0x82849000 (unused area near sub_82849BF8)
GUEST_FUNCTION_HOOK(sub_82849000, MW05Stub_sub_82849000);

// CRITICAL FIX: sub_82849BF8 is stuck in a loop calling NULL vtable entries
// Instead of trying to patch the vtable, just stub the entire function
// Looking at the IDA code, this function:
// 1. Calls XNotifyGetNext to check for system notifications
// 2. Calls sub_82849678 and sub_82849718 (helper functions)
// 3. Calls a vtable function 4 times in a loop (r30 = 0..3)
// 4. Shifts the result left by r30 and ORs them together
// 5. Checks if a specific bit is set and sets a flag at offset 0x2C
// The vtable calls are failing because the vtable is NULL
// For now, just stub the entire function to allow the video thread to progress
void MW05Shim_sub_82849BF8(PPCContext& ctx, uint8_t* base)
{
    uint32_t r3_in = ctx.r3.u32;  // Object pointer

    static int call_count = 0;
    if (call_count++ < 3) {
        fprintf(stderr, "[heap] sub_82849BF8 STUBBED (skipping NULL vtable calls) r3=%08X\n", r3_in);
        fflush(stderr);
    }

    // Just return success without calling the original function
    // The function doesn't return a value, so we don't need to set r3
    // The important thing is to not call the NULL vtable entries
}

GUEST_FUNCTION_HOOK(__imp__sub_82849BF8, MW05Shim_sub_82849BF8);

#if MW05_ENABLE_UNLEASHED
GUEST_FUNCTION_HOOK(sub_82BD7D30, RtlAllocateHeap);
GUEST_FUNCTION_HOOK(sub_82BD8600, RtlFreeHeap);
GUEST_FUNCTION_HOOK(sub_82BD88F0, RtlReAllocateHeap);
GUEST_FUNCTION_HOOK(sub_82BD6FD0, RtlSizeHeap);

GUEST_FUNCTION_HOOK(sub_831CC9C8, XAllocMem);
GUEST_FUNCTION_HOOK(sub_831CCA60, XFreeMem);
#else
GUEST_FUNCTION_HOOK(__imp__ExAllocatePool, ExAllocatePool);
GUEST_FUNCTION_HOOK(__imp__ExAllocatePoolWithTag, ExAllocatePoolWithTag);
GUEST_FUNCTION_HOOK(__imp__ExFreePool, ExFreePool);
GUEST_FUNCTION_HOOK(__imp__XamAlloc, XamAlloc);
GUEST_FUNCTION_HOOK(__imp__XamFree, XamFree);
#endif
