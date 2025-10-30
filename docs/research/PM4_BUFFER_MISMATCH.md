# PM4 Buffer Mismatch - System Command Buffer vs Ring Buffer

**Date**: 2025-10-30
**Status**: PARTIALLY FIXED - System buffer scanner implemented, but buffer is empty ⚠️

## Summary
The game is NOT issuing draw commands because we're reading PM4 commands from the **wrong buffer**!

## The Problem
- **Symptom**: All PM4 packets have `header=DEADBEEF` and `opcode=0x3E` (context updates only)
- **Expected**: Draw commands (opcode 0x04, 0x22, 0x36) should be present
- **Result**: `draws=0` despite VdSwap being called 46 times

## Root Cause Analysis

### Two Separate Buffers
Xbox 360 has **TWO different PM4 command buffers**:

1. **System Command Buffer** (where game writes PM4 commands)
   - Address: `0x00F00000` (15 MB, fixed address)
   - Size: 64 KB (`kSysCmdBufSize = 64 * 1024`)
   - Allocated by: `VdGetSystemCommandBuffer()` in `Mw05Recomp/kernel/imports.cpp:6404`
   - Initialized: Zeroed out with `memset(g_SysCmdBufHost, 0, kSysCmdBufSize)`
   - **This is where the game writes PM4 commands!**

2. **PM4 Ring Buffer** (for GPU command processing)
   - Address: `0x001002E0` (allocated by `Mw05AutoVideoInitIfNeeded()`)
   - Size: 64 KB (2^16 bytes, `len_log2=16`)
   - Allocated by: `VdInitializeRingBuffer()` in `Mw05Recomp/kernel/imports.cpp:6473`
   - Initialized: Filled with `0xDEADBEEF` pattern when `MW05_PM4_ARM_RING_SCRATCH=1`
   - **This is where we're INCORRECTLY reading PM4 commands!**

### The Mismatch
```
Game writes PM4 commands → System Command Buffer (0x00F00000)
                                    ↓
                                    ❌ MISMATCH!
                                    ↓
PM4 parser reads commands ← Ring Buffer (0x001002E0) ← DEADBEEF pattern!
```

### Evidence from Code

**System Command Buffer Allocation** (`Mw05Recomp/kernel/imports.cpp:6388-6402`):
```cpp
static constexpr uint32_t kSysCmdBufFixedAddr = 0x00F00000;  // 15 MB
static constexpr uint32_t kSysCmdBufSize = 64 * 1024;

static void EnsureSystemCommandBuffer()
{
    if (g_SysCmdBufGuest == 0)
    {
        g_SysCmdBufGuest = kSysCmdBufFixedAddr;  // 0x00F00000
        g_SysCmdBufHost = g_memory.Translate(g_SysCmdBufGuest);
        g_VdSystemCommandBuffer.store(g_SysCmdBufGuest);

        if (g_SysCmdBufHost) {
            memset(g_SysCmdBufHost, 0, kSysCmdBufSize);  // Zero the buffer!
        }
    }
}
```

**Ring Buffer Initialization** (`Mw05Recomp/gpu/pm4_parser.cpp:221-247`):
```cpp
void PM4_SetRingBuffer(uint32_t base, uint32_t size_log2) {
    fprintf(stderr, "[PM4-RINGBUF] PM4_SetRingBuffer: base=%08X size_log2=%u\n",
            base, size_log2);
    
    g_rbBase.store(base, std::memory_order_release);
    const uint32_t size = (size_log2 < 32) ? (1u << size_log2) : 0;
    g_rbSize.store(size, std::memory_order_release);
    
    // Optional: Arm ring scratch pattern (MW05_PM4_ARM_RING_SCRATCH=1)
    if (s_arm_scratch && base && size) {
        uint32_t* p = reinterpret_cast<uint32_t*>(g_memory.Translate(base));
        if (p) {
            const uint32_t pat = 0xDEADBEEFu;  // ← This is what we're reading!
            g_rbScratchPattern.store(pat, std::memory_order_release);
            for (uint32_t i = 0; i < size / 4; ++i) {
                p[i] = pat;  // Fill entire ring buffer with DEADBEEF
            }
        }
    }
}
```

**PM4 Scanner Reading Wrong Buffer** (`Mw05Recomp/gpu/pm4_parser.cpp:1659-1683`):
```cpp
void PM4_ScanRingBuffer(uint32_t writeAddr, size_t writeSize) {
    uint32_t base = g_rbBase.load(std::memory_order_acquire);  // 0x001002E0
    uint32_t size = g_rbSize.load(std::memory_order_acquire);  // 65536
    
    // Check if write is within ring buffer
    if (writeAddr < base || writeAddr >= (base + size)) return;
    
    // ❌ WRONG! This scans the ring buffer (0x001002E0) filled with DEADBEEF
    // Should scan system command buffer (0x00F00000) instead!
}
```

### Evidence from Logs

**System Command Buffer Calls** (`traces/auto_test_stderr.txt`):
```
[VD-INIT] Calling VdGetSystemCommandBuffer
[SYSTEM-THREAD] GPU Commands will process PM4 ring buffer and signal event at 0x40009D4C
```

**PM4 Packets Read** (`traces/auto_test_stderr.txt`):
```
[PM4-DEBUG] Packet #0: addr=001002E0 type=3 opcode=3E count=7853 header=DEADBEEF
[PM4-DEBUG] Packet #1: addr=00107D9C type=3 opcode=3E count=7853 header=DEADBEEF
[PM4-DEBUG] Packet #2: addr=0010F858 type=3 opcode=3E count=7853 header=DEADBEEF
```

All packets:
- `addr=001002E0` (ring buffer address!)
- `header=DEADBEEF` (scratch pattern!)
- `opcode=3E` (garbage data interpreted as opcode)
- `count=7853` (0x1EAD = part of DEADBEEF pattern)

## The Fix

### Natural Solution
Update PM4 scanner to read from **system command buffer** (0x00F00000) instead of ring buffer (0x001002E0).

### Implementation Plan
1. **Add system command buffer scanning** to `Mw05Recomp/gpu/pm4_parser.cpp`
2. **Scan on VdSwap calls** - when game calls VdSwap, scan system command buffer for PM4 commands
3. **Keep ring buffer scanning** as fallback for games that use ring buffer directly

### Code Changes Required

**File**: `Mw05Recomp/gpu/pm4_parser.cpp`

Add new function:
```cpp
void PM4_ScanSystemCommandBuffer() {
    // Get system command buffer address from kernel
    extern std::atomic<uint32_t> g_VdSystemCommandBuffer;
    uint32_t sysBufAddr = g_VdSystemCommandBuffer.load(std::memory_order_acquire);
    
    if (!sysBufAddr) return;
    
    // Scan system command buffer for PM4 commands
    constexpr uint32_t kSysCmdBufSize = 64 * 1024;
    PM4_ScanLinear(sysBufAddr, kSysCmdBufSize);
}
```

Update VdSwap to trigger system buffer scan:
```cpp
// In VdSwap implementation (Mw05Recomp/kernel/imports.cpp)
void VdSwap(...) {
    // ... existing VdSwap code ...
    
    // Scan system command buffer for PM4 commands
    PM4_ScanSystemCommandBuffer();
    
    // ... rest of VdSwap ...
}
```

## Expected Results After Fix
- PM4 packets should have **valid headers** (not DEADBEEF)
- Should see **draw commands**: opcode 0x04 (Micro-IB), 0x22 (DRAW_INDX), 0x36 (DRAW_INDX_2)
- `draws` counter should increase from 0 to actual draw count
- Game should progress from initialization to rendering stage

## Related Files
- `Mw05Recomp/kernel/imports.cpp` - System command buffer allocation (lines 6384-6415)
- `Mw05Recomp/gpu/pm4_parser.cpp` - PM4 packet parser (lines 221-247, 1659-1683)
- `docs/research/archive/MICROIB_FORMAT_DISCOVERY.md` - PM4 opcode reference

## Related Issues
- ✅ VdSwap Fixed - Signature Mismatch (2025-10-28)
- ✅ PM4 Buffer System FIXED (2025-10-28)
- ✅ Memory Leak in Buffer Initialization FIXED (2025-10-28)
- ❌ **PM4 Ring Buffer Corruption** (CURRENT ISSUE - ROOT CAUSE IDENTIFIED)

## Next Steps
1. Implement `PM4_ScanSystemCommandBuffer()` function
2. Call it from VdSwap
3. Test and verify draw commands are detected
4. Remove `MW05_PM4_ARM_RING_SCRATCH` environment variable (no longer needed)


## Fix Applied (2025-10-30)

### Implementation
1. ? **Added PM4_ScanSystemCommandBuffer() function** in Mw05Recomp/gpu/pm4_parser.cpp
   - Scans system command buffer at 0x00F00000 (64 KB)
   - Uses existing PM4_ScanLinear() function for packet parsing
   - Logs scan results for debugging

2. ? **Called from VdSwap()** in Mw05Recomp/kernel/imports.cpp
   - Scans system buffer every time game presents a frame
   - Natural integration point - game calls VdSwap when ready to present

3. ? **Added function declaration** in Mw05Recomp/gpu/pm4_parser.h
   - Properly exported for cross-compilation unit usage

### Test Results
- ? Build successful, no linker errors
- ? Function properly scans buffer at 0x00F00000 (64 KB)
- ? VdSwap called 32 times in 30 seconds
- ? PM4 scanner executed 114 times
- ? **System command buffer is EMPTY** (all zeros: header=00000000 raw=00000000)
- ? **Game is NOT writing PM4 commands to the system command buffer**
- ? Still draws=0 - no draw commands detected

## Current Issue - System Buffer Empty

**The system command buffer at 0x00F00000 is completely empty (all zeros).**

This means the game is either:
1. Not using the system command buffer for PM4 commands
2. Writing PM4 commands to a different location
3. Not yet initialized to the rendering stage (still in initialization)

## Next Investigation Steps

1. **Investigate game PM4 command buffer usage**
   - Check if game calls VdGetSystemCommandBuffer to allocate buffer space
   - Trace where game writes PM4 commands
   - Verify game rendering initialization sequence

2. **Check alternative PM4 command locations**
   - Game may use its own PM4 buffer management (like sub_82595FC8)
   - May write commands to a different address than system buffer
   - Need to find where game actually writes PM4 packets

3. **Verify rendering initialization**
   - Game may still be in initialization phase (only writing context updates)
   - Need to check if game has progressed to rendering stage
   - May need to wait longer or trigger specific game events
