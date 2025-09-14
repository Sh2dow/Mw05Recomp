#include <stdafx.h>
#include "memory.h"
#include <ppc/ppc_context.h>

Memory::Memory()
{
#ifdef _WIN32
    base = (uint8_t*)VirtualAlloc((void*)0x100000000ull, PPC_MEMORY_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (base == nullptr)
        base = (uint8_t*)VirtualAlloc(nullptr, PPC_MEMORY_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (base == nullptr)
        return;

    // Historically we marked the first page as PAGE_NOACCESS to catch bad
    // guest pointer use early. During bring-up this causes host AVs inside
    // recompiled guest code before imports can sanitize. Leave it RW so
    // stray reads yield zeros instead of crashing.
    //DWORD oldProtect;
    //VirtualProtect(base, 4096, PAGE_NOACCESS, &oldProtect);
#else
    base = (uint8_t*)mmap((void*)0x100000000ull, PPC_MEMORY_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

    if (base == (uint8_t*)MAP_FAILED)
        base = (uint8_t*)mmap(NULL, PPC_MEMORY_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

    if (base == nullptr)
        return;

    // See Windows comment above; avoid guard page during early bring-up.
    //mprotect(base, 4096, PROT_NONE);
#endif

    // Populate recompiled guest->host function mappings if available.
    // Do not gate on SWA/UNLEASHED; MW05 uses its own generated mappings too.
    extern PPCFuncMapping PPCFuncMappings[];
    for (size_t i = 0; PPCFuncMappings[i].guest != 0; i++)
    {
        if (PPCFuncMappings[i].host != nullptr)
            InsertFunction(PPCFuncMappings[i].guest, PPCFuncMappings[i].host);
    }
}

void* MmGetHostAddress(uint32_t ptr)
{
    return g_memory.Translate(ptr);
}

extern "C" uint8_t* MmGetGuestBase()
{
    return g_memory.base;
}

extern "C" uint64_t MmGetGuestLimit()
{
    return PPC_MEMORY_SIZE;
}
