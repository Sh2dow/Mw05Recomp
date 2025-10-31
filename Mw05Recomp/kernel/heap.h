#pragma once

#include "mutex.h"
#include <atomic>

// Forward declare BaseHeap to avoid circular dependency
namespace mw05 {
    class BaseHeap;
}

struct Heap
{
    // Uses Xenia's BaseHeap allocator (page-based with metadata in host memory)
    // BaseHeap stores page table in HOST memory (std::vector), NOT in guest heap
    // This prevents the game from corrupting heap metadata by writing to guest addresses

    Mutex* mutex{nullptr};
    void* heap;  // mw05::BaseHeap* - page-based heap allocator from Xenia
    void* heapBase{};
    size_t heapSize{};

    Mutex* physicalMutex{nullptr};
    void* physicalHeap{nullptr};  // NOT USED - physical heap uses bump allocator
    void* physicalBase{};
    size_t physicalSize{};
    size_t physicalAllocated{};  // Track allocated bytes for bump allocator
    size_t nextPhysicalAddr{};   // Bump allocator pointer

    // Flag to disable heap operations during shutdown
    std::atomic<bool> shutdownInProgress{false};

    // Flag to disable logging during global construction (before main() is called)
    bool inGlobalConstruction{true};

    // Default constructor - does nothing
    // Init() will be called manually in main() after C runtime is fully initialized
    Heap() = default;

    void Init();

    void* Alloc(size_t size);
    void* AllocPhysical(size_t size, size_t alignment);
    void Free(void* ptr);

    size_t Size(void* ptr);

    // Get heap statistics for debugging
    void GetStats(uint32_t* out_allocated, uint32_t* out_capacity);

    // Dump heap map to log
    void DumpMap();

    template<typename T, typename... Args>
    T* Alloc(Args&&... args)
    {
        T* obj = (T*)Alloc(sizeof(T));
        new (obj) T(std::forward<Args>(args)...);
        return obj;
    }

    template<typename T, typename... Args>
    T* AllocPhysical(Args&&... args)
    {
        T* obj = (T*)AllocPhysical(sizeof(T), alignof(T));
        new (obj) T(std::forward<Args>(args)...);
        return obj;
    }
};

extern Heap g_userHeap;
