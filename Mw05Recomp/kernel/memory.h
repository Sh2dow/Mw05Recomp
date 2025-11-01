#pragma once
#include <cassert>

#ifndef _WIN32
#define MEM_COMMIT  0x00001000  
#define MEM_RESERVE 0x00002000  
#endif

struct Memory
{
    uint8_t* base{};

    Memory();

    // Lazy initialization - ensures memory is allocated before any operations
    // This is thread-safe in C++11+ (guaranteed by the standard)
    bool EnsureInitialized() noexcept
    {
        if (base == nullptr) {
            fprintf(stderr, "[MEMORY] ERROR: Memory not initialized! Call from global constructor?\n");
            fflush(stderr);
            return false;
        }
        return true;
    }

    bool IsInMemoryRange(const void* host) const noexcept
    {
        return host >= base && host < (base + PPC_MEMORY_SIZE);
    }

    void* Translate(size_t offset) const noexcept
    {
        if (offset)
            assert(offset < PPC_MEMORY_SIZE);

        return base + offset;
    }

    uint32_t MapVirtual(const void* host) const noexcept
    {
        if (host)
            assert(IsInMemoryRange(host));

        return static_cast<uint32_t>(static_cast<const uint8_t*>(host) - base);
    }

    PPCFunc* FindFunction(uint32_t guest) const noexcept
    {
        // Bounds check: guest address must be within code range
        if (guest < PPC_CODE_BASE || guest >= (PPC_CODE_BASE + PPC_CODE_SIZE))
        {
            fprintf(stderr, "[FindFunction] ERROR: Guest address 0x%08X is outside code range [0x%08X, 0x%08X)\n",
                    guest, PPC_CODE_BASE, PPC_CODE_BASE + PPC_CODE_SIZE);
            fflush(stderr);
            return nullptr;
        }

        return PPC_LOOKUP_FUNC(base, guest);
    }

    // Safe version of InsertFunction that checks if memory is initialized
    bool InsertFunction(uint32_t guest, PPCFunc* host)
    {
        // CRITICAL: Check if memory is initialized before accessing function table
        if (!EnsureInitialized()) {
            fprintf(stderr, "[INSERT-FUNC] ERROR: Cannot insert function 0x%08X - memory not initialized!\n", guest);
            fflush(stderr);
            return false;
        }

        // CRITICAL DEBUG: Log the function table write operation
        uint64_t code_offset = uint64_t(uint32_t(guest) - uint32_t(PPC_CODE_BASE));
        uint64_t table_offset = PPC_MEMORY_SIZE + (code_offset * sizeof(PPCFunc*));
        PPCFunc** funcPtrAddr = reinterpret_cast<PPCFunc**>(base + table_offset);

        // Log BEFORE write
        PPCFunc* old_value = *funcPtrAddr;

        // Write the function pointer
        PPC_LOOKUP_FUNC(base, guest) = host;

        // Log AFTER write
        PPCFunc* new_value = *funcPtrAddr;

        // Log for graphics callback AND worker thread entry point
        if (guest == 0x825979A8 || guest == 0x828508A8) {
            fprintf(stderr, "[INSERT-FUNC] guest=0x%08X host=%p\n", guest, (void*)host);
            fprintf(stderr, "[INSERT-FUNC]   code_offset=0x%llX table_offset=0x%llX\n",
                    (unsigned long long)code_offset, (unsigned long long)table_offset);
            fprintf(stderr, "[INSERT-FUNC]   funcPtrAddr=%p old=%p new=%p\n",
                    (void*)funcPtrAddr, (void*)old_value, (void*)new_value);
            fprintf(stderr, "[INSERT-FUNC]   Verification: read back = %p\n",
                    (void*)PPC_LOOKUP_FUNC(base, guest));
            fflush(stderr);
        }

        return true;
    }
};

extern "C" void* MmGetHostAddress(uint32_t ptr);
extern Memory g_memory;
