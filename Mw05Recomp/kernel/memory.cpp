#include <stdafx.h>
#include "memory.h"
#include <ppc/ppc_context.h>

Memory::Memory()
{
#ifdef _WIN32
    // CRITICAL FIX: Allocate extra space for function pointer table!
    // The function table is stored AFTER the guest memory at base + PPC_MEMORY_SIZE.
    // Function table size: PPC_CODE_SIZE * sizeof(PPCFunc*) = 16 MB * 8 = 128 MB
    // Total allocation: 4 GB (guest memory) + 128 MB (function table) = 4.125 GB
    const uint64_t function_table_size = PPC_CODE_SIZE * sizeof(PPCFunc*);
    const uint64_t total_allocation_size = PPC_MEMORY_SIZE + function_table_size;

    base = (uint8_t*)VirtualAlloc((void*)0x100000000ull, total_allocation_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (base == nullptr)
        base = (uint8_t*)VirtualAlloc(nullptr, total_allocation_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (base == nullptr) {
        fprintf(stderr, "[MEMORY-INIT] ERROR: VirtualAlloc FAILED! Cannot allocate %llu bytes (guest: %llu + function table: %llu)\n",
                total_allocation_size, PPC_MEMORY_SIZE, function_table_size);
        fflush(stderr);
        return;
    }

    // Write to a log file since stderr might not be set up yet
    FILE* log = fopen("memory_init.log", "w");
    if (log) {
        fprintf(log, "[MEMORY-INIT] VirtualAlloc succeeded: base=%p total_size=0x%llX (%.2f GB) [guest: %.2f GB + function table: %.2f MB]\n",
                base, total_allocation_size, total_allocation_size / (1024.0 * 1024.0 * 1024.0),
                PPC_MEMORY_SIZE / (1024.0 * 1024.0 * 1024.0), function_table_size / (1024.0 * 1024.0));
        fflush(log);
    }

    fprintf(stderr, "[MEMORY-INIT] VirtualAlloc succeeded: base=%p total_size=0x%llX (%.2f GB) [guest: %.2f GB + function table: %.2f MB]\n",
            base, total_allocation_size, total_allocation_size / (1024.0 * 1024.0 * 1024.0),
            PPC_MEMORY_SIZE / (1024.0 * 1024.0 * 1024.0), function_table_size / (1024.0 * 1024.0));
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
    // However, MW05 DOES access low memory addresses (confirmed by crash when protection enabled),
    // so we DON'T protect the first 4KB. This means NULL pointer dereferences won't be caught
    // by the OS, but the game will run correctly.
#else
    base = (uint8_t*)mmap((void*)0x100000000ull, PPC_MEMORY_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

    if (base == (uint8_t*)MAP_FAILED)
        base = (uint8_t*)mmap(NULL, PPC_MEMORY_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

    if (base == nullptr)
        return;

    // NOTE: Same as Windows - don't protect the first 4KB for MW05
    // mprotect(base, 4096, PROT_NONE);
#endif

    size_t total_funcs = 0;
    size_t null_funcs = 0;
    for (size_t i = 0; PPCFuncMappings[i].guest != 0; i++)
    {
        total_funcs++;
        if (PPCFuncMappings[i].host != nullptr)
        {
            InsertFunction(PPCFuncMappings[i].guest, PPCFuncMappings[i].host);

            // DEBUG: Log the entry point function specifically
            if (PPCFuncMappings[i].guest == 0x8262E9A8)
            {
                fprintf(stderr, "[FUNC-TABLE-INIT] Entry point function found in mapping:\n");
                fprintf(stderr, "[FUNC-TABLE-INIT]   guest=0x%08X host=%p\n",
                        PPCFuncMappings[i].guest, PPCFuncMappings[i].host);

                // Verify it was inserted correctly
                PPCFunc* inserted = FindFunction(0x8262E9A8);
                fprintf(stderr, "[FUNC-TABLE-INIT]   Verification: FindFunction(0x8262E9A8) = %p\n", inserted);
                fflush(stderr);
            }
        }
        else
        {
            null_funcs++;
        }
    }

    fprintf(stderr, "[FUNC-TABLE-INIT] Populated function table: %zu total, %zu null\n", total_funcs, null_funcs);
    fflush(stderr);

    fprintf(stderr, "[MEMORY-INIT] Memory::Memory() constructor COMPLETED successfully!\n");
    fprintf(stderr, "[MEMORY-INIT] Returning from constructor...\n");
    fflush(stderr);
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
