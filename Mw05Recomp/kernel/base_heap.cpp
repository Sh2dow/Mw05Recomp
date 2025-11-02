/**
 ******************************************************************************
 * MW05 Recomp - BaseHeap Implementation                                      *
 ******************************************************************************
 * Adapted from Xenia's page-based heap allocator                             *
 * Original: Copyright 2020 Ben Vanik (Xenia Project)                         *
 * Adapted: 2025-10-31 for MW05 Recompilation Project                         *
 ******************************************************************************
 */

#include "base_heap.h"
#include <Windows.h>
#include <cstdio>
#include <algorithm>

namespace mw05 {

BaseHeap::BaseHeap()
    : membase_(nullptr),
      heap_base_(0),
      heap_size_(0),
      page_size_(0),
      page_size_shift_(0),
      unreserved_page_count_(0) {
}

BaseHeap::~BaseHeap() {
    Dispose();
}

void BaseHeap::Initialize(uint8_t* membase, uint32_t heap_base, 
                         uint32_t heap_size, uint32_t page_size) {
    membase_ = membase;
    heap_base_ = heap_base;
    heap_size_ = heap_size;
    page_size_ = page_size;

    // Calculate page_size_shift (log2 of page_size)
    page_size_shift_ = 0;
    uint32_t temp = page_size;
    while (temp > 1) {
        temp >>= 1;
        page_size_shift_++;
    }

    // Initialize page table (stored in HOST memory!)
    uint32_t page_count = heap_size >> page_size_shift_;
    page_table_.resize(page_count);
    
    // Mark all pages as unreserved
    for (auto& entry : page_table_) {
        entry.qword = 0;
    }
    unreserved_page_count_ = page_count;

    fprintf(stderr, "[BASEHEAP] Initialized: base=0x%08X size=%u MB pages=%u page_size=%u KB\n",
            heap_base_, heap_size_ / (1024 * 1024), page_count, page_size_ / 1024);
    fprintf(stderr, "[BASEHEAP] Page table stored in HOST memory at %p (NOT in guest heap!)\n",
            page_table_.data());
    fflush(stderr);
}

void BaseHeap::Dispose() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Decommit all committed pages
    for (size_t i = 0; i < page_table_.size(); ++i) {
        if (page_table_[i].state & kMemoryAllocationCommit) {
            DecommitPages(static_cast<uint32_t>(i), 1);
        }
    }

    // Clear page table
    page_table_.clear();
    unreserved_page_count_ = 0;
}

bool BaseHeap::Alloc(uint32_t size, uint32_t alignment,
                    uint32_t allocation_type, uint32_t protect,
                    bool top_down, uint32_t* out_address) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (size == 0) {
        return false;
    }

    // Round up to page boundary
    size = RoundUpToPage(size);
    uint32_t page_count = GetPageCount(size);

    // Calculate alignment in pages
    uint32_t alignment_pages = std::max(1u, alignment >> page_size_shift_);

    // Find free pages
    uint32_t page_index;
    if (!FindFreePage(page_count, alignment_pages, top_down, &page_index)) {
        fprintf(stderr, "[BASEHEAP] Alloc FAILED: size=%u pages=%u (no free pages)\n",
                size, page_count);
        fflush(stderr);
        return false;
    }

    // Mark pages as reserved
    for (uint32_t i = 0; i < page_count; ++i) {
        page_table_[page_index + i].base_address = page_index;
        page_table_[page_index + i].region_page_count = page_count;
        page_table_[page_index + i].allocation_protect = protect;
        page_table_[page_index + i].current_protect = protect;
        page_table_[page_index + i].state = kMemoryAllocationReserve;
    }
    unreserved_page_count_ -= page_count;

    // Commit if requested
    if (allocation_type & kMemoryAllocationCommit) {
        if (!CommitPages(page_index, page_count, protect)) {
            // Rollback reservation
            for (uint32_t i = 0; i < page_count; ++i) {
                page_table_[page_index + i].qword = 0;
            }
            unreserved_page_count_ += page_count;
            return false;
        }
    }

    *out_address = GetPageAddress(page_index);
    
    fprintf(stderr, "[BASEHEAP] Alloc: addr=0x%08X size=%u pages=%u %s\n",
            *out_address, size, page_count,
            (allocation_type & kMemoryAllocationCommit) ? "COMMIT" : "RESERVE");
    fflush(stderr);

    return true;
}

bool BaseHeap::AllocFixed(uint32_t base_address, uint32_t size,
                         uint32_t alignment, uint32_t allocation_type,
                         uint32_t protect) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (base_address < heap_base_ || base_address >= heap_base_ + heap_size_) {
        return false;
    }

    size = RoundUpToPage(size);
    uint32_t page_index = GetPageIndex(base_address);
    uint32_t page_count = GetPageCount(size);

    // Check if pages are free
    for (uint32_t i = 0; i < page_count; ++i) {
        if (page_table_[page_index + i].state != 0) {
            fprintf(stderr, "[BASEHEAP] AllocFixed FAILED: addr=0x%08X already allocated\n",
                    base_address);
            fflush(stderr);
            return false;
        }
    }

    // Mark pages as reserved
    for (uint32_t i = 0; i < page_count; ++i) {
        page_table_[page_index + i].base_address = page_index;
        page_table_[page_index + i].region_page_count = page_count;
        page_table_[page_index + i].allocation_protect = protect;
        page_table_[page_index + i].current_protect = protect;
        page_table_[page_index + i].state = kMemoryAllocationReserve;
    }
    unreserved_page_count_ -= page_count;

    // Commit if requested
    if (allocation_type & kMemoryAllocationCommit) {
        if (!CommitPages(page_index, page_count, protect)) {
            // Rollback
            for (uint32_t i = 0; i < page_count; ++i) {
                page_table_[page_index + i].qword = 0;
            }
            unreserved_page_count_ += page_count;
            return false;
        }
    }

    fprintf(stderr, "[BASEHEAP] AllocFixed: addr=0x%08X size=%u pages=%u\n",
            base_address, size, page_count);
    fflush(stderr);

    return true;
}

bool BaseHeap::Decommit(uint32_t address, uint32_t size) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (address < heap_base_ || address >= heap_base_ + heap_size_) {
        return false;
    }

    uint32_t page_index = GetPageIndex(address);
    uint32_t page_count = GetPageCount(size);

    return DecommitPages(page_index, page_count);
}

bool BaseHeap::Release(uint32_t address, uint32_t* out_region_size) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (address < heap_base_ || address >= heap_base_ + heap_size_) {
        return false;
    }

    uint32_t page_index = GetPageIndex(address);
    if (page_table_[page_index].state == 0) {
        return false;  // Not allocated
    }

    // Get region info
    uint32_t region_base = page_table_[page_index].base_address;
    uint32_t region_count = page_table_[page_index].region_page_count;

    if (out_region_size) {
        *out_region_size = region_count << page_size_shift_;
    }

    // Decommit and release all pages in region
    for (uint32_t i = 0; i < region_count; ++i) {
        if (page_table_[region_base + i].state & kMemoryAllocationCommit) {
            DecommitPages(region_base + i, 1);
        }
        page_table_[region_base + i].qword = 0;
    }
    unreserved_page_count_ += region_count;

    fprintf(stderr, "[BASEHEAP] Release: addr=0x%08X pages=%u\n",
            GetPageAddress(region_base), region_count);
    fflush(stderr);

    return true;
}

bool BaseHeap::Protect(uint32_t address, uint32_t size, uint32_t protect,
                      uint32_t* old_protect) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (address < heap_base_ || address >= heap_base_ + heap_size_) {
        return false;
    }

    uint32_t page_index = GetPageIndex(address);
    uint32_t page_count = GetPageCount(size);

    if (old_protect) {
        *old_protect = page_table_[page_index].current_protect;
    }

    // Update protection
    for (uint32_t i = 0; i < page_count; ++i) {
        page_table_[page_index + i].current_protect = protect;
    }

    return ProtectPages(page_index, page_count, protect);
}

bool BaseHeap::QueryRegionInfo(uint32_t base_address, HeapAllocationInfo* out_info) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (base_address < heap_base_ || base_address >= heap_base_ + heap_size_) {
        return false;
    }

    uint32_t page_index = GetPageIndex(base_address);
    const auto& entry = page_table_[page_index];

    if (entry.state == 0) {
        // Free page
        out_info->base_address = base_address;
        out_info->allocation_base = 0;
        out_info->allocation_protect = 0;
        out_info->allocation_size = 0;
        out_info->region_size = page_size_;
        out_info->state = 0;
        out_info->protect = 0;
        return true;
    }

    // Allocated page
    uint32_t region_base = GetPageAddress(entry.base_address);
    uint32_t region_size = entry.region_page_count << page_size_shift_;

    out_info->base_address = base_address;
    out_info->allocation_base = region_base;
    out_info->allocation_protect = entry.allocation_protect;
    out_info->allocation_size = region_size;
    out_info->region_size = region_size;
    out_info->state = entry.state;
    out_info->protect = entry.current_protect;

    return true;
}

bool BaseHeap::QuerySize(uint32_t address, uint32_t* out_size) {
    HeapAllocationInfo info;
    if (!QueryRegionInfo(address, &info)) {
        return false;
    }
    *out_size = info.region_size;
    return true;
}

bool BaseHeap::QueryProtect(uint32_t address, uint32_t* out_protect) {
    HeapAllocationInfo info;
    if (!QueryRegionInfo(address, &info)) {
        return false;
    }
    *out_protect = info.protect;
    return true;
}

void BaseHeap::GetStats(uint32_t* out_allocated, uint32_t* out_capacity) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint32_t allocated = (total_page_count() - unreserved_page_count_) << page_size_shift_;
    uint32_t capacity = heap_size_;

    if (out_allocated) *out_allocated = allocated;
    if (out_capacity) *out_capacity = capacity;
}

void BaseHeap::DumpMap() {
    std::lock_guard<std::mutex> lock(mutex_);

    fprintf(stderr, "\n[BASEHEAP] Memory Map Dump:\n");
    fprintf(stderr, "  Base: 0x%08X  Size: %u MB  Pages: %u\n",
            heap_base_, heap_size_ / (1024 * 1024), total_page_count());
    fprintf(stderr, "  Reserved: %u pages  Free: %u pages\n",
            reserved_page_count(), unreserved_page_count_);
    fprintf(stderr, "  Page table at: %p (HOST memory)\n\n", page_table_.data());

    // Dump allocated regions
    for (size_t i = 0; i < page_table_.size(); ++i) {
        if (page_table_[i].state != 0 && page_table_[i].base_address == i) {
            uint32_t addr = GetPageAddress(static_cast<uint32_t>(i));
            uint32_t size = page_table_[i].region_page_count << page_size_shift_;
            const char* state = (page_table_[i].state & kMemoryAllocationCommit) ? "COMMIT" : "RESERVE";
            fprintf(stderr, "  0x%08X - 0x%08X (%6u KB) %s\n",
                    addr, addr + size - 1, size / 1024, state);
        }
    }
    fprintf(stderr, "\n");
    fflush(stderr);
}

// Helper: Find free pages
bool BaseHeap::FindFreePage(uint32_t page_count, uint32_t alignment_pages,
                           bool top_down, uint32_t* out_page_index) {
    if (top_down) {
        // Search from top
        for (int32_t i = static_cast<int32_t>(page_table_.size()) - page_count; i >= 0; --i) {
            if ((i % alignment_pages) != 0) continue;

            bool all_free = true;
            for (uint32_t j = 0; j < page_count; ++j) {
                if (page_table_[i + j].state != 0) {
                    all_free = false;
                    break;
                }
            }

            if (all_free) {
                *out_page_index = static_cast<uint32_t>(i);
                return true;
            }
        }
    } else {
        // Search from bottom
        for (uint32_t i = 0; i <= page_table_.size() - page_count; ++i) {
            if ((i % alignment_pages) != 0) continue;

            bool all_free = true;
            for (uint32_t j = 0; j < page_count; ++j) {
                if (page_table_[i + j].state != 0) {
                    all_free = false;
                    break;
                }
            }

            if (all_free) {
                *out_page_index = i;
                return true;
            }
        }
    }

    return false;
}

// Helper: Commit pages
bool BaseHeap::CommitPages(uint32_t page_index, uint32_t page_count, uint32_t protect) {
    // CRITICAL: Memory class now uses MEM_RESERVE only (like Xbox 360)
    // We MUST commit pages explicitly using VirtualAlloc!

    void* host_addr = TranslateRelative(page_index << page_size_shift_);
    size_t size = static_cast<size_t>(page_count) << page_size_shift_;

    // Commit the pages
    void* result = VirtualAlloc(host_addr, size, MEM_COMMIT, PAGE_READWRITE);
    if (result == nullptr) {
        fprintf(stderr, "[BASEHEAP] VirtualAlloc MEM_COMMIT FAILED: addr=%p size=%zu error=%lu\n",
                host_addr, size, GetLastError());
        fflush(stderr);
        return false;
    }

    // Track total committed memory
    static std::atomic<size_t> total_committed{0};
    size_t committed = total_committed.fetch_add(size) + size;

    fprintf(stderr, "[BASEHEAP] Committed %u pages (%zu KB) at 0x%p - Total committed: %.2f MB\n",
            page_count, size / 1024, host_addr, committed / (1024.0 * 1024.0));
    fflush(stderr);

    // Apply protection if needed
    if (protect != (kMemoryProtectRead | kMemoryProtectWrite)) {
        DWORD win32_protect = ToWin32Protect(protect);
        DWORD old_protect;
        if (!VirtualProtect(host_addr, size, win32_protect, &old_protect)) {
            fprintf(stderr, "[BASEHEAP] VirtualProtect FAILED: addr=%p size=%zu error=%lu\n",
                    host_addr, size, GetLastError());
            fflush(stderr);
            return false;
        }
    }

    // Update page table
    for (uint32_t i = 0; i < page_count; ++i) {
        page_table_[page_index + i].state |= kMemoryAllocationCommit;
    }

    return true;
}

// Helper: Decommit pages
bool BaseHeap::DecommitPages(uint32_t page_index, uint32_t page_count) {
    // NOTE: In MW05Recomp, we don't actually decommit memory since it's all pre-committed
    // Just update the page table to mark pages as decommitted (for tracking purposes)
    // The memory remains accessible but we treat it as "free"

    // Update page table
    for (uint32_t i = 0; i < page_count; ++i) {
        page_table_[page_index + i].state &= ~kMemoryAllocationCommit;
    }

    return true;
}

// Helper: Protect pages
bool BaseHeap::ProtectPages(uint32_t page_index, uint32_t page_count, uint32_t protect) {
    void* host_addr = TranslateRelative(page_index << page_size_shift_);
    size_t size = static_cast<size_t>(page_count) << page_size_shift_;

    DWORD win32_protect = ToWin32Protect(protect);
    DWORD old_protect;

    if (!VirtualProtect(host_addr, size, win32_protect, &old_protect)) {
        fprintf(stderr, "[BASEHEAP] ProtectPages FAILED: addr=%p size=%zu error=%lu\n",
                host_addr, size, GetLastError());
        fflush(stderr);
        return false;
    }

    return true;
}

// Helper: Convert protection flags to Windows PAGE_* constants
uint32_t BaseHeap::ToWin32Protect(uint32_t protect) {
    if (protect & kMemoryProtectWrite) {
        return PAGE_READWRITE;
    } else if (protect & kMemoryProtectRead) {
        return PAGE_READONLY;
    } else {
        return PAGE_NOACCESS;
    }
}

} // namespace mw05

