/**
 ******************************************************************************
 * MW05 Recomp - BaseHeap Implementation                                      *
 ******************************************************************************
 * Adapted from Xenia's page-based heap allocator                             *
 * Original: Copyright 2020 Ben Vanik (Xenia Project)                         *
 * Adapted: 2025-10-31 for MW05 Recompilation Project                         *
 ******************************************************************************
 */

#pragma once

#include <cstdint>
#include <vector>
#include <mutex>

namespace mw05 {

// Memory allocation flags (similar to VirtualAlloc)
enum MemoryAllocationFlag : uint32_t {
    kMemoryAllocationReserve = 1 << 0,
    kMemoryAllocationCommit = 1 << 1,
};

// Memory protection flags
enum MemoryProtectFlag : uint32_t {
    kMemoryProtectRead = 1 << 0,
    kMemoryProtectWrite = 1 << 1,
    kMemoryProtectNoAccess = 0,
    kMemoryProtectReadWrite = kMemoryProtectRead | kMemoryProtectWrite,
};

// Heap allocation information (similar to MEMORY_BASIC_INFORMATION)
struct HeapAllocationInfo {
    uint32_t base_address;
    uint32_t allocation_base;
    uint32_t allocation_protect;
    uint32_t allocation_size;
    uint32_t region_size;
    uint32_t state;
    uint32_t protect;
};

// Page table entry (stored in HOST memory, NOT guest heap!)
union PageEntry {
    uint64_t qword;
    struct {
        // Base address of the allocated region in pages
        uint32_t base_address : 20;
        // Total number of pages in the allocated region
        uint32_t region_page_count : 20;
        // Protection bits specified during region allocation
        uint32_t allocation_protect : 4;
        // Current protection bits as of the last Protect
        uint32_t current_protect : 4;
        // Allocation state (reserve/commit)
        uint32_t state : 2;
        uint32_t reserved : 14;
    };
};

/**
 * Page-based heap allocator
 * 
 * CRITICAL: Page table is stored in HOST memory (std::vector), NOT in guest heap!
 * This prevents the game from corrupting heap metadata.
 * 
 * Based on Xenia's BaseHeap design, simplified for MW05's needs.
 */
class BaseHeap {
public:
    BaseHeap();
    virtual ~BaseHeap();

    // Initialize the heap
    void Initialize(uint8_t* membase, uint32_t heap_base, uint32_t heap_size, 
                   uint32_t page_size);

    // Dispose and decommit all memory
    virtual void Dispose();

    // Getters
    uint32_t heap_base() const { return heap_base_; }
    uint32_t heap_size() const { return heap_size_; }
    uint32_t page_size() const { return page_size_; }
    uint32_t total_page_count() const { return static_cast<uint32_t>(page_table_.size()); }
    uint32_t unreserved_page_count() const { return unreserved_page_count_; }
    uint32_t reserved_page_count() const { return total_page_count() - unreserved_page_count(); }

    // Translate guest address to host pointer
    template <typename T = uint8_t*>
    inline T TranslateRelative(size_t relative_address) const {
        return reinterpret_cast<T>(membase_ + heap_base_ + relative_address);
    }

    // Allocate memory with given properties
    // Returns true on success, sets *out_address to allocated guest address
    virtual bool Alloc(uint32_t size, uint32_t alignment,
                      uint32_t allocation_type, uint32_t protect,
                      bool top_down, uint32_t* out_address);

    // Allocate at a specific address
    virtual bool AllocFixed(uint32_t base_address, uint32_t size,
                           uint32_t alignment, uint32_t allocation_type,
                           uint32_t protect);

    // Decommit pages
    virtual bool Decommit(uint32_t address, uint32_t size);

    // Release pages
    virtual bool Release(uint32_t address, uint32_t* out_region_size = nullptr);

    // Change protection
    virtual bool Protect(uint32_t address, uint32_t size, uint32_t protect,
                        uint32_t* old_protect = nullptr);

    // Query region information
    bool QueryRegionInfo(uint32_t base_address, HeapAllocationInfo* out_info);
    bool QuerySize(uint32_t address, uint32_t* out_size);
    bool QueryProtect(uint32_t address, uint32_t* out_protect);

    // Dump heap map to log
    void DumpMap();

    // Get heap statistics
    void GetStats(uint32_t* out_allocated, uint32_t* out_capacity);

protected:
    // Helper: Get page count for a size
    uint32_t GetPageCount(uint32_t size) const {
        return (size + page_size_ - 1) >> page_size_shift_;
    }

    // Helper: Round up to page boundary
    uint32_t RoundUpToPage(uint32_t value) const {
        return (value + page_size_ - 1) & ~(page_size_ - 1);
    }

    // Helper: Get page index from address
    uint32_t GetPageIndex(uint32_t address) const {
        return (address - heap_base_) >> page_size_shift_;
    }

    // Helper: Get address from page index
    uint32_t GetPageAddress(uint32_t page_index) const {
        return heap_base_ + (page_index << page_size_shift_);
    }

    // Find free pages
    bool FindFreePage(uint32_t page_count, uint32_t alignment_pages,
                     bool top_down, uint32_t* out_page_index);

    // Commit host memory for pages
    bool CommitPages(uint32_t page_index, uint32_t page_count, uint32_t protect);

    // Decommit host memory for pages
    bool DecommitPages(uint32_t page_index, uint32_t page_count);

    // Protect host memory for pages
    bool ProtectPages(uint32_t page_index, uint32_t page_count, uint32_t protect);

    // Convert protection flags to Windows PAGE_* constants
    uint32_t ToWin32Protect(uint32_t protect);

protected:
    uint8_t* membase_;                      // Host base address
    uint32_t heap_base_;                    // Guest base address
    uint32_t heap_size_;                    // Total heap size
    uint32_t page_size_;                    // Page size (4KB or 64KB)
    uint32_t page_size_shift_;              // log2(page_size)
    uint32_t unreserved_page_count_;        // Number of free pages

    // CRITICAL: Page table stored in HOST memory (std::vector)
    // This is NOT in the guest heap, so the game cannot corrupt it!
    std::vector<PageEntry> page_table_;

    // Mutex for thread safety
    std::mutex mutex_;
};

} // namespace mw05

