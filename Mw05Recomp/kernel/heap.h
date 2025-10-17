#pragma once

#include "mutex.h"

struct Heap
{
    // EXACT COPY from UnleashedRecomp (with base/size fields for diagnostics)
    Mutex mutex;
    O1HeapInstance* heap;
    void* heapBase{};
    size_t heapSize{};

    Mutex physicalMutex;
    O1HeapInstance* physicalHeap;
    void* physicalBase{};
    size_t physicalSize{};

    void Init();

    void* Alloc(size_t size);
    void* AllocPhysical(size_t size, size_t alignment);
    void Free(void* ptr);

    size_t Size(void* ptr);

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
