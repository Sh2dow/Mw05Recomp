#include <stdafx.h>
#include "xdm.h"
#include "freelist.h"

#include <mutex>
#include <unordered_set>

Mutex g_kernelLock;

namespace
{
    Mutex g_kernelRegistryLock;
    std::unordered_set<KernelObject*> g_liveKernelObjects;
}

void RegisterKernelObject(KernelObject* obj)
{
    if (!obj || obj == GetInvalidKernelObject<KernelObject>())
    {
        return;
    }

    std::lock_guard guard{ g_kernelRegistryLock };
    const bool inserted = g_liveKernelObjects.insert(obj).second;
    assert(inserted && "kernel object registered twice");
}

void UnregisterKernelObject(KernelObject* obj)
{
    if (!obj || obj == GetInvalidKernelObject<KernelObject>())
    {
        return;
    }

    std::lock_guard guard{ g_kernelRegistryLock };
    g_liveKernelObjects.erase(obj);
}

bool IsKernelObjectAlive(const KernelObject* obj)
{
    if (!obj || obj == GetInvalidKernelObject<const KernelObject>())
    {
        return false;
    }

    std::lock_guard guard{ g_kernelRegistryLock };
    return g_liveKernelObjects.find(const_cast<KernelObject*>(obj)) != g_liveKernelObjects.end();
}

void DestroyKernelObject(KernelObject* obj)
{
    if (!obj || obj == GetInvalidKernelObject<KernelObject>())
    {
        return;
    }

    UnregisterKernelObject(obj);
    obj->~KernelObject();
    g_userHeap.Free(obj);
}

uint32_t GetKernelHandle(KernelObject* obj)
{
    assert(obj != GetInvalidKernelObject());
    return g_memory.MapVirtual(obj);
}

void DestroyKernelObject(uint32_t handle)
{
    if (!IsKernelObject(handle))
    {
        return;
    }

    DestroyKernelObject(GetKernelObject(handle));
}

bool IsKernelObject(uint32_t handle)
{
    return (handle & 0x80000000) != 0;
}

bool IsKernelObject(void* obj)
{
    return IsKernelObject(g_memory.MapVirtual(obj));
}

bool IsInvalidKernelObject(void* obj)
{
    return obj == GetInvalidKernelObject();
}
