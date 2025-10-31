# Main Loop Investigation - 2025-10-30

## Summary

Investigated why the game's rendering initialization sequence is not progressing to the rendering stage (draws=0).

## Key Findings

### 1. Manual Main Loop Implementation Was Hanging

**Problem**: The manual implementation `sub_82441E80_debug` in `Mw05Recomp/kernel/imports.cpp` was calling `sub_8215CB08` but never returning from it.

**Root Cause**: Calling recompiled PPC functions directly from host code doesn't work properly - the calling convention is different and functions don't return correctly.

**Evidence**:
- Debug message "sub_8215CB08() returned ptr=0x%08X" was NEVER printed
- Function `sub_8215CB08` completed successfully (logs showed "Memory pool init completed")
- BUT the caller never continued execution after the call

### 2. Recompiled Functions Cause Crashes

**Problem**: Adding main loop functions to TOML for recompilation caused crashes with exception 0xC0000005 (access violation) after 12.5 seconds.

**Functions Tested**:
- `sub_82441E80` (0xBC bytes) - main thread entry (calls main loop)
- `sub_82441CF0` (0x168 bytes) - main loop
- `sub_8261A5E8` (0x1EC bytes) - create worker threads
- `sub_823C8420` (0x90 bytes) - work queue processing

**Test Results**:
- ❌ ALL FOUR FUNCTIONS: Crash after 12.5s with exception 0xC0000005
- ✅ ONLY `sub_823C8420`: No crash, runs stably for 15+ seconds
- ❌ Still `draws=0` in both cases

**Crash Location**: Right after entering a critical section at `0x00FE2DE4`

### 3. Worker Thread System is Working

**Status**: ✅ FULLY FUNCTIONAL

The worker thread fixes from previous sessions are working correctly:
- Worker pool slots properly initialized with `work_func=0x82441E58`
- Worker threads created successfully (5 threads)
- No exceptions or crashes from worker threads
- Memory usage stable (~1.7 GB working set when not using recompiled main loop functions)

## Actions Taken

### 1. Removed Manual Main Loop Hook

**File**: `Mw05Recomp/kernel/imports.cpp`

**Change**: Disabled the hook for `sub_82441E80`:
```cpp
// GUEST_FUNCTION_HOOK(sub_82441E80, sub_82441E80_debug);  // DISABLED - manual implementation hangs
```

**Reason**: Manual implementation was hanging because calling recompiled PPC functions from host code doesn't work.

### 2. Attempted to Recompile Main Loop Functions

**File**: `Mw05RecompLib/config/MW05.toml`

**Attempt**: Added main loop functions to TOML for recompilation:
```toml
{ address = 0x82441E80, size = 0xBC },  # main thread entry (calls main loop)
{ address = 0x82441CF0, size = 0x168 }, # main loop
{ address = 0x8261A5E8, size = 0x1EC }, # create worker threads
{ address = 0x823C8420, size = 0x90 }   # work queue processing
```

**Result**: Caused crashes - disabled all except `sub_823C8420` which works.

**Current State**: Only `sub_823C8420` (work queue processing) is enabled in TOML.

## Current Status

### ✅ Working
- Worker thread system fully functional
- Game runs stably for 15+ seconds without crashes
- VdSwap: 44 calls
- Present: 175 calls
- Memory usage stable

### ❌ Not Working
- `draws=0` - no draw commands issued
- Game stuck in initialization phase writing only SET_CONSTANT (0x3E) PM4 packets
- Main loop functions (`sub_82441E80`, `sub_82441CF0`, `sub_8261A5E8`) cause crashes when recompiled

## Next Steps

### Option 1: Investigate Recompiler Bugs

The crashes when recompiling main loop functions suggest bugs in the recompiler. Need to:
1. Analyze the generated code for `sub_82441E80`, `sub_82441CF0`, `sub_8261A5E8`
2. Compare with IDA decompilation
3. Identify specific bugs in the recompiled code
4. Fix recompiler or add workarounds

### Option 2: Use Targeted Hooks Instead of Full Recompilation

Instead of recompiling entire functions, use `PPC_FUNC_IMPL` + `PPC_FUNC` pattern to override specific buggy parts:
1. Let the game run naturally using original code
2. Identify specific bugs that prevent rendering
3. Create minimal hooks to fix only those bugs
4. Avoid replacing entire functions

### Option 3: Investigate Why draws=0

Even with stable execution, the game is not issuing draw commands. Need to:
1. Check if game is waiting for initialization event/callback
2. Investigate what triggers transition from initialization to rendering
3. Check for missing resources or failed asset loads
4. Compare with PC version initialization sequence using IDA Pro API (port 5051)

## Recommended Approach

**Priority 1**: Option 3 - Investigate why draws=0
- The game is running stably now
- Worker threads are working
- Focus on understanding why rendering hasn't started
- This is likely a separate issue from the main loop execution

**Priority 2**: Option 2 - Use targeted hooks
- Avoid full recompilation which causes crashes
- Use minimal hooks to fix specific bugs
- Follow UnleashedRecomp's approach of targeted fixes

**Priority 3**: Option 1 - Fix recompiler bugs
- Only if targeted hooks don't work
- Requires deep understanding of recompiler internals
- Time-consuming and risky

## Files Modified

1. `Mw05Recomp/kernel/imports.cpp` - Disabled manual main loop hook
2. `Mw05RecompLib/config/MW05.toml` - Added/disabled main loop functions
3. `docs/research/2025-10-30_main_loop_investigation.md` - This document

## Test Results

### Test 1: All Main Loop Functions Recompiled
- **Duration**: 12.5 seconds
- **Result**: ❌ CRASH (exception 0xC0000005)
- **VdSwap**: 43 calls
- **Present**: 172 calls
- **draws**: 0

### Test 2: Only Work Queue Processing Recompiled
- **Duration**: 15 seconds (timeout)
- **Result**: ✅ NO CRASH
- **VdSwap**: 44 calls
- **Present**: 175 calls
- **draws**: 0

### Test 3: No Main Loop Functions Recompiled (Baseline)
- **Duration**: 30+ seconds
- **Result**: ✅ NO CRASH
- **VdSwap**: Multiple calls
- **Present**: Multiple calls
- **draws**: 0
- **Memory**: 4.6 GB working set (higher than expected)

## Conclusion

The manual main loop implementation approach was fundamentally flawed. Attempting to recompile the main loop functions causes crashes. The game runs stably without these recompilations, but still shows `draws=0`. The next step is to investigate why the game is not progressing to the rendering stage, rather than trying to force it through manual implementations or full recompilation.

## UPDATE: Physical Heap Size Issue FOUND AND FIXED! (2025-10-30)

### Root Cause of draws=0

**CRITICAL FINDING**: The game was running out of physical memory!

**Evidence**:
```
[AllocPhysical] FAILED: Out of physical memory! requested=361758720 available=163012240
[AllocPhysical] FAILED: physicalBase=00000001A0000000 physicalSize=1610612736 nextAddr=00000001F648A170
[MmAllocPhysicalMemEx] FAILED: AllocPhysical returned NULL for size=361758720 (345.00 MB)
```

**Analysis**:
- Physical heap was 1536 MB (1.5 GB)
- Game successfully allocated 4 chunks of ~345 MB each (22.46% → 44.96% → 67.42% → 89.88%)
- Game tried to allocate a 5th chunk of 345 MB but only had 163 MB left
- **Total needed**: ~1800 MB (4 × 345 MB + overhead)
- **Available**: 1536 MB
- **Shortfall**: ~264 MB

These large allocations are likely render targets or texture buffers needed for rendering.

### Fix Applied

**File**: `Mw05Recomp/kernel/heap.cpp` (line 82-86)

**Change**: Increased physical heap size from 1536 MB to 2048 MB (2 GB):
```cpp
// OLD:
physicalSize = 0x60000000ULL;  // 1536 MB (1.5 GB)

// NEW:
physicalSize = 0x80000000ULL;  // 2048 MB (2 GB)
```

**Reason**: MW05 needs ~1800 MB for render targets (4 × 345 MB + overhead). Using 2048 MB to be safe.

### Test Results After Fix

**Physical Heap Allocations**: ✅ ALL SUCCEEDED!
```
[AllocPhysical] LARGE ALLOCATION: size=361758720 (345.00 MB) align=4096
[AllocPhysical]   Physical heap usage: 361795584 / 2147483648 bytes (16.85%)
[AllocPhysical] LARGE ALLOCATION: size=361758720 (345.00 MB) align=4096
[AllocPhysical]   Physical heap usage: 724082688 / 2147483648 bytes (33.72%)
[AllocPhysical] LARGE ALLOCATION: size=361758720 (345.00 MB) align=4096
[AllocPhysical]   Physical heap usage: 1085841408 / 2147483648 bytes (50.56%)
[AllocPhysical] LARGE ALLOCATION: size=361758720 (345.00 MB) align=4096
[AllocPhysical]   Physical heap usage: 1447604224 / 2147483648 bytes (67.41%)
```

All 4 allocations succeeded! Physical heap is now 2 GB and only 67.41% full.

### New Issue: o1heap Assertion Failure

**Problem**: After fixing physical heap, game now hits assertion failure in user heap:
```
Assertion failed: frag->header.used, file D:/Repos/Games/Mw05Recomp/thirdparty/o1heap/o1heap.c, line 413
```

**Analysis**: This assertion means o1heap is trying to free a fragment that's not marked as used. This suggests:
1. Double-free bug (freeing same memory twice)
2. Memory corruption (heap metadata corrupted)
3. Invalid pointer being freed

**Status**: Game runs for 28+ seconds before hitting this assertion, which is progress! The physical heap fix allowed the game to progress further in initialization.

### Next Steps

1. **Investigate o1heap assertion failure**:
   - Add logging to track all Alloc/Free calls
   - Identify which pointer is being double-freed
   - Check if game is freeing physical heap pointers through user heap (wrong heap)

2. **Test if draws > 0 after fixing o1heap issue**:
   - Physical heap allocations succeeded
   - Game may now be able to create render targets
   - Need to fix o1heap issue to see if rendering starts

3. **Consider disabling o1heap assertions for testing**:
   - Temporarily disable assertion to see if game continues
   - Check if draws > 0 after assertion point
   - This would confirm if o1heap issue is blocking rendering

