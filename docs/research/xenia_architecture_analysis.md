# Xenia Architecture Analysis & Recommendations for MW05 Recomp

**Date**: 2025-10-31  
**Purpose**: Analyze Xenia's architecture to solve MW05's heap corruption and memory management issues

---

## 🔍 Key Findings from Xenia's Third-Party Libraries

### Memory Management & Concurrency

Xenia uses a **completely different approach** than MW05Recomp:

1. **NO o1heap** - Xenia does NOT use o1heap for guest memory allocation
2. **Custom Page-Based Heap** - Xenia implements `BaseHeap` with page table management
3. **disruptorplus** - Lock-free ring buffer for high-performance producer/consumer communication
4. **VirtualAlloc/mmap** - Direct OS memory management with page-level control

### Critical Libraries Xenia Uses

| Library | Purpose | Relevance to MW05 |
|---------|---------|-------------------|
| **disruptorplus** | Lock-free ring buffer for thread communication | ✅ **HIGH** - Could replace PM4 buffer management |
| **xbyak** | JIT code generation (x86/x64 assembler) | ⚠️ Already have similar (PPC recompiler) |
| **fmt** | Fast string formatting | ✅ Already using |
| **imgui** | Debug UI | ✅ Already using |
| **xxhash** | Fast hashing | ⚠️ Low priority |
| **snappy/zstd** | Compression | ❌ Not needed |
| **FFmpeg** | Video/audio decoding | ❌ Not needed (MW05 uses Bink) |

---

## 🚨 Root Cause: o1heap Design Incompatibility

### The Problem

**o1heap REQUIRES its instance structure at the BEGINNING of the heap arena**:

```c
// From o1heap.c line 246
O1HeapInstance* o1heapInit(void* const base, const size_t size)
{
    // Allocate the core heap metadata structure in the beginning of the arena.
    out = (O1HeapInstance*)base;  // ❌ CRITICAL: Instance stored AT base!
    // ...
    out->diagnostics.capacity = capacity;  // At base + 520 (0x208)
}
```

**The game writes to guest address 0x00100208**, which is:
- `heapBase (0x00100000) + 0x208 (520 bytes)`
- **Exactly where o1heap stores `diagnostics.capacity`**

### Why VirtualProtect Failed

```cpp
// Attempted fix (FAILED):
VirtualProtect(heapBase, 4096, PAGE_READONLY, &oldProtect);
```

**Result**: 10 access violation crashes in 1 second

**Reason**: o1heap needs to **WRITE** to its instance during allocations:
- Updating bin masks
- Modifying free lists
- Tracking diagnostics

---

## ✅ Recommended Solutions (Priority Order)

### **Option 1: Switch to Xenia's Page-Based Heap (RECOMMENDED)**

**Advantages**:
- ✅ Proven in production (Xenia runs thousands of Xbox 360 games)
- ✅ No metadata stored in guest-accessible memory
- ✅ Page table stored in host memory (separate from guest heap)
- ✅ Supports Xbox 360 memory model (virtual + physical heaps)
- ✅ Built-in protection and debugging features

**Implementation**:
1. Copy `BaseHeap` from Xenia (`xenia/memory.h`)
2. Adapt for MW05's memory layout (0x00100000-0x7FEA0000)
3. Keep physical heap as-is (bump allocator works fine)
4. Remove o1heap dependency

**Estimated Effort**: 2-3 days

---

### **Option 2: Use disruptorplus for PM4 Buffer Management**

**Current Problem**: PM4 buffer system is complex and error-prone

**disruptorplus Benefits**:
- ✅ Lock-free ring buffer (perfect for PM4 command buffers)
- ✅ Single producer (game) / single consumer (GPU emulator)
- ✅ Batched operations (game writes multiple PM4 commands at once)
- ✅ No locks or CAS operations (just atomic reads/writes)
- ✅ Header-only library (easy integration)

**Use Case**:
```cpp
// Replace current PM4 buffer management with:
ring_buffer<PM4Command> pm4_buffer(1024 * 1024);  // 1MB ring buffer
single_threaded_claim_strategy<spin_wait_strategy> claim_strategy(...);
sequence_barrier<spin_wait_strategy> consumed(...);

// Game thread (producer):
sequence_t seq = claim_strategy.claim_one();
pm4_buffer[seq] = {opcode, args...};
claim_strategy.publish(seq);

// GPU thread (consumer):
sequence_t available = claim_strategy.wait_until_published(nextToRead);
while (nextToRead <= available) {
    ProcessPM4Command(pm4_buffer[nextToRead++]);
}
consumed.publish(available);
```

**Estimated Effort**: 1-2 days

---

### **Option 3: Move o1heap Instance to Host Memory (WORKAROUND)**

**Concept**: Separate o1heap instance from guest heap arena

**Problem**: o1heap's API doesn't support this:
```c
// o1heap REQUIRES instance at base:
O1HeapInstance* o1heapInit(void* const base, const size_t size);
```

**Would require**:
- Forking o1heap
- Modifying internal structure
- Maintaining custom fork

**Verdict**: ❌ **NOT RECOMMENDED** (too much maintenance burden)

---

### **Option 4: Intercept Game Writes to 0x00100208 (HACK)**

**Concept**: Use memory protection + exception handler

```cpp
// Protect o1heap instance page
VirtualProtect(heapBase, 4096, PAGE_NOACCESS, &oldProtect);

// Add vectored exception handler
AddVectoredExceptionHandler(1, [](EXCEPTION_POINTERS* ex) {
    if (ex->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        void* addr = (void*)ex->ExceptionRecord->ExceptionInformation[1];
        if (addr == heapBase + 0x208) {
            // Redirect write to safe location
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
});
```

**Verdict**: ❌ **NOT RECOMMENDED** (performance overhead, complexity)

---

## 📊 Comparison: o1heap vs Xenia's BaseHeap

| Feature | o1heap | Xenia BaseHeap |
|---------|--------|----------------|
| **Metadata Location** | ❌ In guest heap (corrupted by game) | ✅ In host memory (safe) |
| **Fragmentation** | ✅ Good (buddy allocator) | ✅ Good (page-based) |
| **Performance** | ✅ Fast (O(1) for power-of-2) | ✅ Fast (page table lookup) |
| **Xbox 360 Compatibility** | ⚠️ Generic allocator | ✅ Designed for Xbox 360 |
| **Debugging** | ⚠️ Limited | ✅ Built-in (DumpMap, page tracking) |
| **Production Use** | ⚠️ Embedded systems | ✅ Xenia (thousands of games) |

---

## 🎯 Recommended Action Plan

### Phase 1: Immediate Fix (1-2 days)
1. **Implement Xenia's BaseHeap** for user heap (0x00100000-0x7FEA0000)
2. Keep physical heap as bump allocator (it works fine)
3. Remove o1heap dependency

### Phase 2: PM4 Buffer Optimization (1-2 days)
1. **Integrate disruptorplus** for PM4 command buffer management
2. Replace current PM4 buffer system with lock-free ring buffer
3. Simplify producer/consumer synchronization

### Phase 3: Testing & Validation (1 day)
1. Run 5-minute stress tests
2. Verify no memory leaks
3. Confirm heap corruption is fixed
4. Benchmark performance vs current implementation

---

## 📚 Reference Files from Xenia

### Core Memory Management
- `src/xenia/memory.h` - BaseHeap interface
- `src/xenia/memory.cc` - BaseHeap implementation
- `src/xenia/base/memory.h` - Low-level memory utilities

### disruptorplus Integration
- `third_party/disruptorplus/include/disruptorplus/ring_buffer.hpp`
- `third_party/disruptorplus/include/disruptorplus/single_threaded_claim_strategy.hpp`
- `third_party/disruptorplus/include/disruptorplus/spin_wait_strategy.hpp`

---

## 🔧 Implementation Notes

### BaseHeap Key Features to Port

1. **Page Table** (host memory):
```cpp
std::vector<PageEntry> page_table_;  // NOT in guest memory!
```

2. **Translation**:
```cpp
template <typename T = uint8_t*>
inline T TranslateRelative(size_t relative_address) const {
    return reinterpret_cast<T>(membase_ + heap_base_ + 
                               host_address_offset_ + relative_address);
}
```

3. **Allocation**:
```cpp
bool Alloc(uint32_t size, uint32_t alignment, uint32_t allocation_type,
           uint32_t protect, bool top_down, uint32_t* out_address);
```

4. **Protection**:
```cpp
bool Protect(uint32_t address, uint32_t size, uint32_t protect,
             uint32_t* old_protect = nullptr);
```

---

## 💡 Why This Will Work

1. **Metadata Separation**: Page table in host memory → game can't corrupt it
2. **Proven Design**: Xenia successfully emulates Xbox 360 memory model
3. **Better Debugging**: Built-in heap dump and tracking features
4. **Performance**: Page-based allocation is fast for game-sized allocations
5. **Compatibility**: Designed specifically for Xbox 360 guest memory layout

---

## ⚠️ Migration Risks

### Low Risk
- ✅ BaseHeap API is similar to current heap interface
- ✅ Can migrate incrementally (user heap first, keep physical heap)
- ✅ Xenia code is well-tested and documented

### Medium Risk
- ⚠️ Need to adapt Xenia's code to MW05's build system
- ⚠️ May need to adjust page size (Xenia uses 4KB, Xbox 360 uses 64KB pages)

### Mitigation
- Start with user heap only
- Keep physical heap as-is (bump allocator works)
- Add extensive logging during migration
- Run parallel tests with old/new heap

---

## 📈 Expected Outcomes

### After BaseHeap Migration
- ✅ **Zero heap corruption** (metadata in host memory)
- ✅ **Stable 30+ minute runs** (no memory leaks)
- ✅ **Better debugging** (heap dump, page tracking)
- ✅ **Xbox 360 compatibility** (proper memory model)

### After disruptorplus Integration
- ✅ **Simpler PM4 buffer code** (lock-free ring buffer)
- ✅ **Better performance** (no locks, batched operations)
- ✅ **Easier debugging** (clear producer/consumer model)

---

## 🎓 Lessons Learned

1. **Don't fight the architecture** - o1heap wasn't designed for this use case
2. **Learn from production systems** - Xenia has solved these problems
3. **Metadata placement matters** - Keep it out of guest-accessible memory
4. **Use the right tool** - Page-based heap for OS-level memory, ring buffers for IPC

---

## 📞 Next Steps

**Immediate**: Review this analysis with user  
**Short-term**: Implement BaseHeap migration  
**Medium-term**: Integrate disruptorplus for PM4 buffers  
**Long-term**: Consider other Xenia optimizations (JIT improvements, etc.)

