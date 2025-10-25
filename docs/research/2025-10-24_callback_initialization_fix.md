# Callback Initialization Fix - Complete Investigation Summary

**Date**: 2025-10-24  
**Status**: Fix implemented, testing required  
**Issue**: Main render thread 0x825AA970 never created, draws=0  
**Root Cause**: Callback pointer at offset +88 in structure returned by sub_826BE3E8 was NULL

## Executive Summary

We've identified and fixed the root cause of why the game is not rendering (draws=0). The problem was that a critical callback pointer was NULL, preventing the entire game initialization chain from executing. The fix initializes this callback pointer in the correct structure, which should trigger the complete initialization sequence including render thread creation.

## The Problem

### Symptoms
1. **Heap allocation dropped from 7 MB to 6 MB** - Missing 20608-byte allocation
2. **Main render thread 0x825AA970 NEVER created** - No thread to issue draw commands
3. **CreateDevice (sub_82598230) NEVER called** - Graphics device not initialized
4. **draws=0** - No rendering happening despite all systems running

### Investigation Timeline

#### 1. Heap Allocation Mystery
User noticed heap allocation dropped from 7 MB to 6 MB between test runs. The missing allocation was 20608 bytes that should have been allocated by `sub_825A16A0`. This led to the question: **Why is sub_825A16A0 not being called?**

#### 2. Call Chain Mapping (Using IDA API)
We traced backwards from `sub_825A16A0` to find the complete initialization chain:

```
sub_82850820 (Thread #1 worker loop)
  ↓ reads callback from offset +88 of structure returned by sub_826BE3E8()
  ↓ calls callback 0x8261A558
    ↓ callback reads work_func from offset +16 and calls it
    ↓ work_func 0x82441E58 calls sub_823B0190 (main game init)
      ↓ sub_823B0190 calls sub_823AF590 (massive initialization)
        ↓ sub_823AF590 calls sub_82216088
          ↓ sub_82216088 calls sub_82440530
            ↓ sub_82440530 calls sub_82440448
              ↓ sub_82440448 calls sub_825A16A0 (allocates 20608 bytes!)
                ↓ sub_825A16A0 calls sub_825A8698
                  ↓ sub_825A8698 calls CreateDevice and sub_825AAE58
                    ↓ sub_825AAE58 creates thread 0x825AA970 (MAIN RENDER THREAD!)
```

#### 3. Root Cause Identification

**Decompiled sub_82850820** (using IDA API):
```c
int sub_82850820() {
  v0 = sub_826BE3E8();
  v1 = *(_DWORD *)(v0 + 88);  // <-- Reads callback from offset +88!
  v2 = v1(*(_DWORD *)(v0 + 88));
  return sub_8284DEA0(v2);
}
```

**Traced execution**:
- sub_82850820 is called but returns immediately
- sub_826BE3E8 returns structure at 0x00227560
- Callback should be at: 0x00227560 + 88 = 0x002275B8
- **Actual value at 0x002275B8: 0x00000000 (NULL)**

**Conclusion**: sub_82850820 cannot call NULL pointer → entire initialization chain blocked!

#### 4. Structure Allocation Investigation

**Decompiled sub_826BE348** (the function that allocates the structure):
```c
_DWORD *sub_826BE348() {
  v2 = (_DWORD *)v1(dword_828E14E0);  // <-- Looks up in global table!
  if (!v2) {
    v2 = (_DWORD *)sub_826C52B0(1, 204);  // <-- Allocates 204 bytes ONCE!
    if (v2) {
      v3(dword_828E14E0, v2);  // <-- Stores in global table!
      v2[5] = 1;
      v2[23] = &unk_828E1AF0;
      *v2 = sub_8262EC60();
      v2[1] = -1;
    }
  }
  return v2;  // <-- Returns SAME structure every time!
}
```

**Key Discovery**: 
- Structure is allocated ONCE and stored in global table at `dword_828E14E0`
- sub_826BE3E8 returns this REAL structure from the global table
- We were creating a NEW context structure, but that's not what sub_82850820 uses!

## Previous Fix Attempts (What Didn't Work)

### Attempt 1: Initialize callback in manually-created context at offset +84
**Problem**: Off-by-4 error (should be +88, not +84)  
**Result**: Failed - callback still NULL

### Attempt 2: Fix offset to +88 in manually-created context
**Problem**: sub_826BE3E8 returns a DIFFERENT structure (0x00227560 vs 0x00227480)  
**Result**: Failed - initializing wrong structure

### Attempt 3: Calculate correct offset (+0x138) accounting for structure offset
**Problem**: Still initializing wrong structure (manually-created vs real structure)  
**Result**: Failed - callback still NULL in the real structure

## The Final Fix (What Should Work)

Instead of creating a new context, we initialize the callback in the REAL structure returned by sub_826BE3E8.

**File**: `Mw05Recomp/cpu/mw05_trace_threads.cpp` lines 1087-1112

```cpp
PPC_FUNC_IMPL(__imp__sub_826BE3E8) {
    // Call original function
    sub_826BE3E8(ctx, base);
    
    // CRITICAL FIX: Initialize callback in REAL structure returned by sub_826BE3E8
    if (ctx.r3.u32 != 0) {
        extern Memory g_memory;
        void* struct_ptr = g_memory.Translate(ctx.r3.u32);
        if (struct_ptr) {
            be<uint32_t>* struct_u32 = reinterpret_cast<be<uint32_t>*>(struct_ptr);
            uint32_t callback_ptr = struct_u32[88/4];  // +0x58 (88) - callback pointer
            
            fprintf(stderr, "[826BE3E8] Callback pointer at +88: 0x%08X\n", callback_ptr);
            fflush(stderr);
            
            // If callback is NULL, initialize it now!
            if (callback_ptr == 0 || callback_ptr == 0xFFFFFFFF) {
                fprintf(stderr, "[826BE3E8] FIXING: Initializing callback pointer at +88 to 0x8261A558!\n");
                fflush(stderr);
                
                struct_u32[88/4] = be<uint32_t>(0x8261A558);  // +0x58 (88) - callback function
                struct_u32[92/4] = be<uint32_t>(0x82A2B318);  // +0x5C (92) - callback parameter
                
                fprintf(stderr, "[826BE3E8] FIXED: Callback pointers initialized in REAL structure at 0x%08X!\n", ctx.r3.u32);
                fflush(stderr);
            }
        }
    }
}
```

## Expected Outcome

### Immediate Effects
1. sub_82850820 reads callback from offset +88 → gets **0x8261A558** (not NULL!)
2. Calls callback 0x8261A558 → callback executes successfully
3. Callback reads work_func from offset +16 → gets **0x82441E58**
4. Calls work_func 0x82441E58 → **main game initialization starts!**

### Initialization Chain Execution
5. sub_82441E58 calls sub_823B0190 (main game init)
6. sub_823B0190 calls sub_823AF590 (massive initialization)
7. sub_823AF590 calls sub_82216088
8. sub_82216088 calls sub_82440530
9. sub_82440530 calls sub_82440448
10. sub_82440448 calls sub_825A16A0 → **allocates 20608 bytes!**
11. **Heap increases from 6 MB to 7 MB** ✅

### Graphics Initialization
12. sub_825A16A0 initializes offset+20576 to 0x04000001
13. sub_825A16A0 calls sub_825A8698
14. sub_825A8698 calls **CreateDevice (sub_82598230)** → graphics device initialized! ✅
15. sub_825A8698 calls sub_825AAE58
16. sub_825AAE58 creates **thread 0x825AA970** (MAIN RENDER THREAD!) ✅

### Final Result
17. Render thread 0x825AA970 starts executing
18. Render thread issues draw commands
19. **draws > 0** → **RENDERING BEGINS!** 🎉

## Testing Instructions

### Run the Test
```powershell
python scripts/auto_handle_messageboxes.py --duration 60
```

### Check for Success Indicators

**1. Callback Initialization Messages**:
```bash
grep "826BE3E8.*FIXING\|826BE3E8.*FIXED" traces/auto_test_stderr.txt
```
Expected: Should see initialization messages

**2. Callback Execution**:
```bash
grep "8261A558" traces/auto_test_stderr.txt | head -20
```
Expected: Should see callback being called

**3. Heap Allocation Increase**:
```bash
grep "User heap\|Physical heap" traces/auto_test_stderr.txt | tail -5
```
Expected: User heap should show ~7 MB allocated (was 6 MB)

**4. Initialization Chain**:
```bash
grep "823B0190\|823AF590\|82216088\|825A16A0" traces/auto_test_stderr.txt | head -20
```
Expected: Should see these functions being called

**5. CreateDevice Called**:
```bash
grep "CreateDevice\|82598230" traces/auto_test_stderr.txt
```
Expected: Should see CreateDevice being called

**6. Render Thread Created**:
```bash
grep "825AA970" traces/auto_test_stderr.txt | grep -i "created\|thread"
```
Expected: Should see thread creation message

**7. DRAWS > 0** (Ultimate Success):
```bash
grep "draws\|DRAW" traces/auto_test_stderr.txt | tail -10
```
Expected: draws should be > 0

## If Fix Doesn't Work

### Scenario 1: Callback initialization messages appear but callback not called
**Possible Cause**: sub_826BE348 returns a different structure than we're initializing  
**Action**: 
1. Find global table at `dword_828E14E0`
2. Inspect structure stored in global table
3. Initialize callback in that structure directly

### Scenario 2: No callback initialization messages at all
**Possible Cause**: sub_826BE3E8 wrapper not being executed  
**Action**:
1. Verify wrapper is registered correctly
2. Add more logging to confirm wrapper is called
3. Check if sub_826BE3E8 is being called at all

### Scenario 3: Callback called but initialization chain doesn't execute
**Possible Cause**: Callback parameter structure at 0x82A2B318 not initialized  
**Action**:
1. Check work_func pointer at offset +16 in callback parameter structure
2. Verify it's set to 0x82441E58
3. Initialize callback parameter structure if needed

## Related Documents

- `docs/research/2025-10-23_CRITICAL_FINDINGS_RenderThreads.md` - Analysis of render thread creation blocking
- `docs/research/2025-10-22_no_draws_investigation.md` - Investigation of why draws=0
- `AGENTS.md` - Complete instructions for next AI agent

## Key Technical Concepts

- **Worker Thread 0x828508A8**: Critical worker thread that should execute initialization
- **Callback 0x8261A558**: Function that reads work_func and calls it
- **Work Function 0x82441E58**: Main game initialization function
- **sub_826BE3E8**: Returns structure containing callback pointer at offset +88
- **sub_826BE348**: Allocates 204-byte structure ONCE and stores in global table
- **Global Table dword_828E14E0**: Stores pointer to the real structure
- **Big-endian format**: PowerPC uses big-endian, requiring `be<uint32_t>` wrapper

