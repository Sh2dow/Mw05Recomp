#pragma once

#include <cstdint>
#include <vector>
#include <mutex>
#include <algorithm>

#include "memory.h"

// Simple 64 KiB-granular VM arena for guest allocations.
// Keeps VM away from the heap allocator (o1heap) to avoid corruption.
class VmArena
{
public:
    void Init(uint32_t guestBase, uint32_t sizeBytes)
    {
        std::lock_guard<std::mutex> lk(mutex);
        base = guestBase;
        size = sizeBytes;
        freeList.clear();
        reserved.clear();
        freeList.push_back({ base, size });
    }

    // Reserve a 64 KiB-aligned region. If hint != 0, attempts fixed-address reserve.
    // Returns 0 on failure.
    uint32_t Reserve(uint32_t hint, uint32_t size64k)
    {
        std::lock_guard<std::mutex> lk(mutex);
        const uint32_t gran = 0x10000u;
        size64k = AlignUp(size64k, gran);

        if (hint)
        {
            hint = AlignDown(hint, gran);
            if (!IsFreeRange(hint, size64k))
                return 0; // conflicting addresses
            CarveFree(hint, size64k);
            reserved.push_back({ hint, size64k });
            return hint;
        }

        for (auto& f : freeList)
        {
            const uint32_t cand = AlignUp(f.base, gran);
            const uint64_t end = uint64_t(cand) + size64k;
            if (cand >= f.base && end <= uint64_t(f.base) + f.size)
            {
                CarveFree(cand, size64k);
                reserved.push_back({ cand, size64k });
                return cand;
            }
        }
        return 0;
    }

    // Commit within a reserved region. Returns false if the range is not reserved.
    bool Commit(uint32_t guest, uint32_t sizeBytes)
    {
        std::lock_guard<std::mutex> lk(mutex);
        return OverlapsReserved(guest, sizeBytes);
    }

    // Release a range (merges into free list). Returns false if not reserved.
    bool Release(uint32_t guest, uint32_t sizeBytes)
    {
        std::lock_guard<std::mutex> lk(mutex);
        if (sizeBytes == 0)
        {
            // Find the exact reserved region at this base.
            for (size_t i = 0; i < reserved.size(); ++i)
            {
                if (reserved[i].base == guest)
                {
                    const uint32_t sz = reserved[i].size;
                    reserved.erase(reserved.begin() + i);
                    InsertFree(guest, sz);
                    return true;
                }
            }
            return false;
        }
        // Partial release: split reserved entries as needed.
        for (size_t i = 0; i < reserved.size(); ++i)
        {
            auto r = reserved[i];
            const uint64_t rend = uint64_t(r.base) + r.size;
            const uint64_t aend = uint64_t(guest) + sizeBytes;
            if (guest >= r.base && aend <= rend)
            {
                // Remove the portion [guest, aend)
                reserved.erase(reserved.begin() + i);
                if (guest > r.base) reserved.push_back({ r.base, guest - r.base });
                if (aend < rend) reserved.push_back({ uint32_t(aend), uint32_t(rend - aend) });
                InsertFree(guest, sizeBytes);
                return true;
            }
        }
        return false;
    }

private:
    struct Range { uint32_t base; uint32_t size; };
    uint32_t base{};
    uint32_t size{};
    std::vector<Range> freeList;
    std::vector<Range> reserved;
    std::mutex mutex;

    static uint32_t AlignUp(uint32_t v, uint32_t a) { return (v + (a - 1u)) & ~(a - 1u); }
    static uint32_t AlignDown(uint32_t v, uint32_t a) { return v & ~(a - 1u); }

    bool IsFreeRange(uint32_t b, uint32_t sz)
    {
        for (auto& f : freeList)
        {
            const uint64_t fend = uint64_t(f.base) + f.size;
            const uint64_t aend = uint64_t(b) + sz;
            if (b >= f.base && aend <= fend) return true;
        }
        return false;
    }

    void CarveFree(uint32_t b, uint32_t sz)
    {
        for (size_t i = 0; i < freeList.size(); ++i)
        {
            auto f = freeList[i];
            const uint64_t fend = uint64_t(f.base) + f.size;
            const uint64_t aend = uint64_t(b) + sz;
            if (b >= f.base && aend <= fend)
            {
                freeList.erase(freeList.begin() + i);
                if (b > f.base) freeList.push_back({ f.base, b - f.base });
                if (aend < fend) freeList.push_back({ uint32_t(aend), uint32_t(fend - aend) });
                NormalizeFree();
                return;
            }
        }
    }

    void InsertFree(uint32_t b, uint32_t sz)
    {
        freeList.push_back({ b, sz });
        NormalizeFree();
    }

    void NormalizeFree()
    {
        std::sort(freeList.begin(), freeList.end(), [](auto& a, auto& b){ return a.base < b.base; });
        std::vector<Range> merged;
        merged.reserve(freeList.size()); // Pre-allocate to avoid reallocation during iteration
        for (auto& r : freeList)
        {
            if (!merged.empty() && uint64_t(merged.back().base) + merged.back().size == r.base)
            {
                merged.back().size += r.size;
            }
            else
            {
                merged.push_back(r);
            }
        }
        freeList.swap(merged);
    }

    bool OverlapsReserved(uint32_t b, uint32_t sz)
    {
        const uint64_t aend = uint64_t(b) + sz;
        for (auto& r : reserved)
        {
            const uint64_t rend = uint64_t(r.base) + r.size;
            if (b >= r.base && aend <= rend) return true;
        }
        return false;
    }
};

