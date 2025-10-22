#pragma once

#include "mutex.h"
#include <atomic>

struct Heap
{
    // EXACT COPY from UnleashedRecomp (with base/size fields for diagnostics)
    // CRITICAL FIX: Use pointers to Mutex instead of direct members to avoid
    // calling InitializeCriticalSection during global construction (before main())
    Mutex* mutex{nullptr};
    O1HeapInstance* heap;
    void* heapBase{};
    size_t heapSize{};

    Mutex* physicalMutex{nullptr};
    O1HeapInstance* physicalHeap;  // NOT USED - physical heap uses bump allocator
    void* physicalBase{};
    size_t physicalSize{};
    size_t physicalAllocated{};  // Track allocated bytes for bump allocator
    size_t nextPhysicalAddr{};   // Bump allocator pointer

    // Flag to disable heap operations during shutdown to prevent o1heap assertions
    std::atomic<bool> shutdownInProgress{false};

    // Flag to disable logging during global construction (before main() is called)
    // This prevents fprintf() from being called before the C runtime is fully initialized
    bool inGlobalConstruction{true};

    // Store initial diagnostics to detect heap corruption
    O1HeapDiagnostics initialDiagnostics{};

    // Memory guards (canaries) to detect heap corruption
    static constexpr uint64_t CANARY_MAGIC = 0xDEADBEEFCAFEBABEull;
    uint64_t* canaryBefore{nullptr};  // Canary placed before o1heap instance
    uint64_t* canaryAfter{nullptr};   // Canary placed after o1heap instance
    size_t canaryCheckCount{0};       // Number of times canaries have been checked

    // Default constructor - does nothing
    // Init() will be called manually in main() after C runtime is fully initialized
    Heap() = default;

    void Init();

    void* Alloc(size_t size);
    void* AllocPhysical(size_t size, size_t alignment);
    void Free(void* ptr);

    size_t Size(void* ptr);

    // Get heap diagnostics for debugging
    O1HeapDiagnostics GetDiagnostics();

    // Check if memory guards (canaries) are intact
    bool CheckCanaries(const char* caller);

    // Validate heap integrity (checks canaries + diagnostics)
    bool ValidateHeapIntegrity(const char* caller);

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
