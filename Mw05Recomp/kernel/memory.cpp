#include <stdafx.h>
#include "memory.h"
#include <ppc/ppc_context.h>

Memory::Memory()
{
#ifdef _WIN32
    base = (uint8_t*)VirtualAlloc((void*)0x100000000ull, PPC_MEMORY_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (base == nullptr)
        base = (uint8_t*)VirtualAlloc(nullptr, PPC_MEMORY_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (base == nullptr) {
        fprintf(stderr, "[MEMORY-INIT] ERROR: VirtualAlloc FAILED! Cannot allocate %llu bytes\n", PPC_MEMORY_SIZE);
        fflush(stderr);
        return;
    }

    // Write to a log file since stderr might not be set up yet
    FILE* log = fopen("memory_init.log", "w");
    if (log) {
        fprintf(log, "[MEMORY-INIT] VirtualAlloc succeeded: base=%p size=0x%llX (%.2f GB)\n",
                base, PPC_MEMORY_SIZE, PPC_MEMORY_SIZE / (1024.0 * 1024.0 * 1024.0));
        fflush(log);
    }

    fprintf(stderr, "[MEMORY-INIT] VirtualAlloc succeeded: base=%p size=0x%llX (%.2f GB)\n",
            base, PPC_MEMORY_SIZE, PPC_MEMORY_SIZE / (1024.0 * 1024.0 * 1024.0));
    fflush(stderr);

    // CRITICAL CHECK: Verify that VirtualAlloc actually zeroed the memory
    // Check a few key locations that will become heap metadata
    fprintf(stderr, "[MEMORY-INIT] Checking if memory is zero-initialized...\n");

    // Check user heap start (0x00020000)
    uint8_t* user_heap_start = base + 0x00020000;
    bool user_heap_zeroed = true;
    for (int i = 0; i < 128; i++) {
        if (user_heap_start[i] != 0) {
            user_heap_zeroed = false;
            break;
        }
    }

    // Check physical heap start (0xA0000000)
    uint8_t* phys_heap_start = base + 0xA0000000;
    bool phys_heap_zeroed = true;
    for (int i = 0; i < 128; i++) {
        if (phys_heap_start[i] != 0) {
            phys_heap_zeroed = false;
            break;
        }
    }

    if (log) {
        fprintf(log, "[MEMORY-INIT] User heap (0x00020000): %s\n", user_heap_zeroed ? "ZEROED" : "NOT ZEROED!");
        fprintf(log, "[MEMORY-INIT] Physical heap (0xA0000000): %s\n", phys_heap_zeroed ? "ZEROED" : "NOT ZEROED!");

        if (!user_heap_zeroed || !phys_heap_zeroed) {
            fprintf(log, "[MEMORY-INIT] WARNING: Memory NOT zero-initialized by VirtualAlloc!\n");
            fprintf(log, "[MEMORY-INIT] Dumping first 128 bytes of physical heap:\n");
            for (int i = 0; i < 128; i += 16) {
                fprintf(log, "  [%+4d]: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
                        i, phys_heap_start[i+0], phys_heap_start[i+1], phys_heap_start[i+2], phys_heap_start[i+3],
                        phys_heap_start[i+4], phys_heap_start[i+5], phys_heap_start[i+6], phys_heap_start[i+7],
                        phys_heap_start[i+8], phys_heap_start[i+9], phys_heap_start[i+10], phys_heap_start[i+11],
                        phys_heap_start[i+12], phys_heap_start[i+13], phys_heap_start[i+14], phys_heap_start[i+15]);
            }
        }
        fclose(log);
    }

    fprintf(stderr, "[MEMORY-INIT] User heap (0x00020000): %s\n", user_heap_zeroed ? "ZEROED" : "NOT ZEROED!");
    fprintf(stderr, "[MEMORY-INIT] Physical heap (0xA0000000): %s\n", phys_heap_zeroed ? "ZEROED" : "NOT ZEROED!");

    if (!user_heap_zeroed || !phys_heap_zeroed) {
        fprintf(stderr, "[MEMORY-INIT] WARNING: Memory NOT zero-initialized by VirtualAlloc!\n");
        fprintf(stderr, "[MEMORY-INIT] Dumping first 128 bytes of physical heap:\n");
        for (int i = 0; i < 128; i += 16) {
            fprintf(stderr, "  [%+4d]: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
                    i, phys_heap_start[i+0], phys_heap_start[i+1], phys_heap_start[i+2], phys_heap_start[i+3],
                    phys_heap_start[i+4], phys_heap_start[i+5], phys_heap_start[i+6], phys_heap_start[i+7],
                    phys_heap_start[i+8], phys_heap_start[i+9], phys_heap_start[i+10], phys_heap_start[i+11],
                    phys_heap_start[i+12], phys_heap_start[i+13], phys_heap_start[i+14], phys_heap_start[i+15]);
        }
    }
    fflush(stderr);

    // NOTE: UnleashedRecomp protects the first 4KB to catch NULL pointer dereferences:
    //   VirtualProtect(base, 4096, PAGE_NOACCESS, &oldProtect);
    // However, MW05 legitimately accesses low memory addresses (e.g., when scanning
    // for paths in loader shims), so we DON'T protect the first 4KB.
    // This means NULL pointer dereferences won't be caught by the OS, but the game
    // will run correctly.
#else
    base = (uint8_t*)mmap((void*)0x100000000ull, PPC_MEMORY_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

    if (base == (uint8_t*)MAP_FAILED)
        base = (uint8_t*)mmap(NULL, PPC_MEMORY_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

    if (base == nullptr)
        return;

    // NOTE: Same as Windows - don't protect the first 4KB for MW05
    // mprotect(base, 4096, PROT_NONE);
#endif

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
