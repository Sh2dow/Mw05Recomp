#include <stdafx.h>
#include "memory.h"
#include <ppc/ppc_context.h>
#include <atomic>

// Forward declaration for VEH handler
static LONG WINAPI PageFaultHandler(EXCEPTION_POINTERS* exceptionInfo);

// Global pointer to Memory instance for VEH handler
static Memory* g_memory_instance = nullptr;

// Track total committed memory
static std::atomic<size_t> g_total_committed{0};

Memory::Memory()
{
#ifdef _WIN32
    // Use VirtualAlloc with MEM_RESERVE only (like Xenia)
    // Pages will be committed on-demand to reduce memory usage
    // Function table will be committed upfront since it's accessed during initialization

    // Function table size: PPC_CODE_SIZE * sizeof(PPCFunc*) = 16 MB * 8 = 128 MB
    // Total allocation: 4 GB (guest memory) + 128 MB (function table) = 4.125 GB
    const uint64_t function_table_size = PPC_CODE_SIZE * sizeof(PPCFunc*);
    const uint64_t total_allocation_size = PPC_MEMORY_SIZE + function_table_size;

    // CRITICAL: Use FILE MAPPING instead of VirtualAlloc (like Xenia)!
    // File mapping allows the OS to commit pages on-demand automatically
    // without needing VEH or manual commitment!
    //
    // CreateFileMapping with INVALID_HANDLE_VALUE creates a page file-backed mapping
    // MapViewOfFileEx maps it to a specific address
    // The OS commits pages automatically when they're accessed!

    HANDLE file_mapping = CreateFileMappingA(
        INVALID_HANDLE_VALUE,  // Use page file
        nullptr,               // Default security
        PAGE_READWRITE,        // Read/write access
        static_cast<DWORD>(total_allocation_size >> 32),  // High 32 bits of size
        static_cast<DWORD>(total_allocation_size & 0xFFFFFFFF),  // Low 32 bits
        nullptr);              // No name

    if (file_mapping == nullptr) {
        fprintf(stderr, "[MEMORY-INIT] ERROR: CreateFileMapping failed! Error: %lu\n", GetLastError());
        fflush(stderr);
        std::abort();
    }

    base = (uint8_t*)MapViewOfFileEx(
        file_mapping,
        FILE_MAP_ALL_ACCESS,
        0,  // High 32 bits of offset
        0,  // Low 32 bits of offset
        total_allocation_size,
        (void*)0x100000000ull);  // Desired base address

    CloseHandle(file_mapping);  // Can close handle after mapping

    if (base == nullptr) {
        fprintf(stderr, "[MEMORY-INIT] ERROR: MapViewOfFileEx FAILED! Error: %lu\n", GetLastError());
        fprintf(stderr, "[MEMORY-INIT] ERROR: Requested size: 0x%llX (%.2f GB)\n",
                total_allocation_size,
                total_allocation_size / (1024.0 * 1024.0 * 1024.0));
        fflush(stderr);
        std::abort();  // CRITICAL: Cannot continue without memory
    }

    fprintf(stderr, "[MEMORY-INIT] File mapping succeeded: base=%p total_size=0x%llX (%.2f GB)\n",
            base, total_allocation_size,
            total_allocation_size / (1024.0 * 1024.0 * 1024.0));
    fprintf(stderr, "[MEMORY-INIT] Using FILE MAPPING - OS commits pages on-demand automatically!\n");
    fprintf(stderr, "[MEMORY-INIT] Expected commit: ~512 MB (like Xbox 360 and Xenia)\n");
    fflush(stderr);

    // NOTE: With file mapping, pages are committed automatically by the OS when accessed
    // No need to manually commit function table or any other memory!

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

    // DO NOT USE VEH! It commits pages on EVERY ACCESS (884,678 pages = 3.45 GB)!
    // Xenia commits pages only when ALLOCATED through heap functions.
    // We do the same:
    // - BaseHeap commits user heap pages when game calls malloc/new
    // - Physical heap commits pages when game calls MmAllocatePhysicalMemory
    // - XEX loader commits code section when loading executable
    // - Thread stacks committed when threads are created

    fprintf(stderr, "[MEMORY-INIT] Memory::Memory() constructor COMPLETED successfully!\n");
    fprintf(stderr, "[MEMORY-INIT] Pages committed ONLY on allocation (NO VEH - like Xenia)\n");
    fflush(stderr);
}

// Commit a page on-demand when it's first accessed (like Xenia)
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

// Vectored Exception Handler for on-demand page commitment
// This catches ACCESS_VIOLATION exceptions and commits pages as needed
static LONG WINAPI PageFaultHandler(EXCEPTION_POINTERS* exceptionInfo)
{
    // Only handle ACCESS_VIOLATION (0xC0000005)
    if (exceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Get the faulting address
    ULONG_PTR faultAddress = exceptionInfo->ExceptionRecord->ExceptionInformation[1];

    // Check if the fault is within our guest memory range
    if (g_memory_instance == nullptr || g_memory_instance->base == nullptr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    uint8_t* base = g_memory_instance->base;
    uint64_t base_addr = reinterpret_cast<uint64_t>(base);
    uint64_t end_addr = base_addr + PPC_MEMORY_SIZE;

    // Check if fault is in guest memory range (not function table)
    if (faultAddress < base_addr || faultAddress >= end_addr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // CRITICAL FIX: Use 4KB pages instead of 64KB pages!
    // Xbox 360 uses 64KB PHYSICAL pages, but for VIRTUAL memory we can use 4KB pages
    // This reduces waste: if game touches 1 byte, we commit 4KB instead of 64KB (16x reduction!)
    // Expected result: 3.4 GB / 16 = 212 MB committed (much closer to Xbox 360's 512 MB limit)
    const size_t kPageSize = 4 * 1024;  // 4KB pages (Windows native page size)
    uint64_t offset = faultAddress - base_addr;
    size_t page_start = (offset / kPageSize) * kPageSize;

    // Commit the page
    void* page_addr = base + page_start;
    void* committed = VirtualAlloc(page_addr, kPageSize, MEM_COMMIT, PAGE_READWRITE);

    if (committed == nullptr) {
        fprintf(stderr, "[VEH] ERROR: Failed to commit page at 0x%p! Error: %lu\n",
                page_addr, GetLastError());
        fflush(stderr);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Track total committed memory (no logging - too slow!)
    g_total_committed.fetch_add(kPageSize);

    // Continue execution - the faulting instruction will be retried
    return EXCEPTION_CONTINUE_EXECUTION;
}


