#include <stdafx.h>
#include "heap.h"
#include "memory.h"
#include "function.h"
#include <os/logger.h>

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
    void* ptr = (flags & 0x80000000) != 0 ?
        g_userHeap.AllocPhysical(size, (1ull << ((flags >> 24) & 0xF))) :
        g_userHeap.Alloc(size);

    if (!ptr) {
        LOGF_ERROR("[heap] XAllocMem failed size={} flags={:08X}", size, flags);
        return 0;
    }

    if ((flags & 0x40000000) != 0)
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
