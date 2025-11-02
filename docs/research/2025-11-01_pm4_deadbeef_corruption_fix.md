# PM4 DEADBEEF "Corruption" - Root Cause Analysis and Fix

**Date**: 2025-11-01  
**Status**: ✅ FIXED - Not corruption, intentional scratch pattern!

## Summary

The PM4 packets showing `header=DEADBEEF raw=EFBEADDE` are **NOT corrupted**. This is an **intentional scratch pattern** used to detect if the game writes to the ring buffer. The real issue is that we're scanning the **wrong buffer** - the ring buffer filled with DEADBEEF instead of the buffer where the game actually writes PM4 commands.

## The "Corruption" Pattern

**User's Observation**:
```
[PM4-DEBUG] Packet #0: addr=00102000 type=3 opcode=3E count=7853 header=DEADBEEF raw=EFBEADDE
[PM4-DEBUG] Packet #1: addr=00109ABC type=3 opcode=3E count=7853 header=DEADBEEF raw=EFBEADDE
[PM4-DEBUG] Packet #2: addr=00111578 type=3 opcode=3E count=7853 header=DEADBEEF raw=EFBEADDE
```

**Analysis**:
- `raw = 0xEFBEADDE` (big-endian in guest memory)
- `header = 0xDEADBEEF` (little-endian after byte-swap)
- `count = 7853` (0x1EAD = part of DEADBEEF pattern)
- `opcode = 0x3E` (garbage data interpreted as opcode)

## Root Cause

### The Scratch Pattern

**File**: `Mw05Recomp/gpu/pm4_parser.cpp` (lines 242-262)

```cpp
static const bool s_arm_scratch = [](){
    if (const char* v = std::getenv("MW05_PM4_ARM_RING_SCRATCH"))
        return !(v[0]=='0' && v[1]=='\0');
    return false;
}();
if (s_arm_scratch && base && size) {
    uint32_t* p = reinterpret_cast<uint32_t*>(g_memory.Translate(base));
    if (p) {
        const uint32_t pat = 0xDEADBEEFu;
        g_rbScratchPattern.store(pat, std::memory_order_release);
        for (uint32_t off = 0; off < size; off += 4) {
            p[off / 4] = __builtin_bswap32(pat);  // Stores 0xEFBEADDE in memory
        }
        g_rbScratchArmed.store(true, std::memory_order_release);
    }
}
```

**Purpose**: Fill the ring buffer with a known pattern (DEADBEEF) to detect if the game writes to it.

### Multiple PM4 Scanners

There are **THREE** PM4 scanning functions:

1. **PM4_ScanSystemCommandBuffer()** (lines 345-382)
   - Scans system command buffer at 0x00F00000
   - Enabled by `MW05_PM4_SYSBUF_SCAN=1`
   - **Result**: Buffer is EMPTY (all zeros)

2. **PM4_ScanRingBuffer()** (lines 1716-1765)
   - Scans ring buffer when writes are detected
   - Enabled by `MW05_PM4_TRACE=1`
   - **Result**: Finds DEADBEEF pattern (not real PM4 commands)

3. **PM4_DebugScanAll()** (lines 1768-1800+)
   - Debug scan of entire ring buffer
   - Enabled by `MW05_PM4_SCAN_ALL=1`
   - **Result**: Scans DEADBEEF-filled ring buffer

### Environment Variable Configuration

**File**: `Mw05Recomp/main.cpp` (lines 111-139)

**BEFORE FIX**:
```cpp
MwSetEnvDefault("MW05_PM4_SCAN_ALL",                 "1");  // ← Scans DEADBEEF ring buffer!
MwSetEnvDefault("MW05_PM4_ARM_RING_SCRATCH",         "1");  // ← Fills ring with DEADBEEF!
MwSetEnvDefault("MW05_PM4_SYSBUF_SCAN",              "1");  // ← Scans empty system buffer
MwSetEnvDefault("MW05_PM4_EAGER_SCAN",               "1");  // ← Aggressive ring buffer scan
```

**Result**: Both ring buffer (DEADBEEF) and system buffer (empty) are scanned, but the DEADBEEF packets are logged first, making it look like corruption.

## The Fix

### Disable Ring Buffer Scanning

**File**: `Mw05Recomp/main.cpp` (lines 107-150)

```cpp
// CRITICAL FIX (2025-11-01): PM4 Ring Buffer Corruption Fix
// The ring buffer is filled with DEADBEEF pattern (MW05_PM4_ARM_RING_SCRATCH=1)
// and scanned (MW05_PM4_SCAN_ALL=1), which causes all packets to show as corrupted.
// The game writes PM4 commands to a DIFFERENT buffer (not the ring buffer or system buffer).
// We need to find WHERE the game writes PM4 commands and scan that buffer instead.
//
// DISABLE ring buffer scanning to avoid DEADBEEF false positives:
MwSetEnvDefault("MW05_PM4_SCAN_ALL",                 "0");  // DISABLED - scans DEADBEEF ring buffer
MwSetEnvDefault("MW05_PM4_ARM_RING_SCRATCH",         "0");  // DISABLED - fills ring with DEADBEEF
MwSetEnvDefault("MW05_PM4_EAGER_SCAN",               "0");  // DISABLED - aggressive ring buffer scan

// ENABLE system buffer scanning (though it's currently empty):
MwSetEnvDefault("MW05_PM4_SYSBUF_SCAN",              "1");  // Scan system command buffer
```

### Expected Results After Fix

1. ✅ No more DEADBEEF headers in logs
2. ✅ PM4 scanner will only scan system command buffer (0x00F00000)
3. ❌ Still `draws=0` because system buffer is empty

## The Real Issue

The fix eliminates the DEADBEEF false positives, but **the real issue remains**:

**The game is NOT writing PM4 commands to either buffer!**

### Evidence

1. **System command buffer** (0x00F00000): EMPTY (all zeros)
2. **Ring buffer** (0x00102000): Filled with DEADBEEF pattern (no game writes)
3. **Game is running**: VdSwap called 24 times, Present called 97 times, GPU Commands signaled 1680 times
4. **No draw commands**: `draws=0` despite active rendering loop

### Possible Explanations

1. **Game uses a third buffer** - The game may have its own PM4 buffer management (sub_82595FC8) and write to a different address
2. **Still in initialization** - The game may not have progressed to the rendering stage yet (only writing context updates)
3. **Different rendering path** - MW05 may use a different rendering architecture than expected

## Next Steps

1. **Find where game writes PM4 commands**
   - Trace game's PM4 buffer allocation (sub_82595FC8)
   - Monitor memory writes to find PM4 command buffer
   - Check if game uses indirect buffers or micro-IBs

2. **Investigate game rendering state**
   - Check if game has progressed to rendering stage
   - Monitor file I/O to see if assets are being loaded
   - Compare with Xenia to see when it starts issuing draw commands

3. **Add memory write tracking**
   - Hook memory writes to detect PM4 command buffer writes
   - Log addresses where game writes PM4-like patterns
   - Scan those addresses for draw commands

## Related Files

- `Mw05Recomp/main.cpp` - Environment variable configuration (lines 107-150)
- `Mw05Recomp/gpu/pm4_parser.cpp` - PM4 packet parser (lines 242-262, 345-382, 1716-1765)
- `docs/research/PM4_BUFFER_MISMATCH.md` - Previous investigation of buffer mismatch
- `docs/research/2025-10-27_TYPE3_packets_discovered.md` - TYPE3 packet discovery

## Conclusion

The DEADBEEF "corruption" was a **red herring** - it's an intentional scratch pattern used to detect ring buffer writes. The real issue is that the game is not writing PM4 commands to any of the buffers we're scanning. We need to find WHERE the game actually writes PM4 commands and scan that buffer instead.

**Status**: DEADBEEF false positives eliminated, but `draws=0` issue remains. Need to find game's actual PM4 command buffer.

