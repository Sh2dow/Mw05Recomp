# Context Address Investigation - 0x00120E10 vs 0x828F1F98

## Executive Summary

**CRITICAL FINDING**: The game is using **TWO DIFFERENT context structures** for Thread #2:
1. **0x00120E10** - Actually being used at runtime (WRONG!)
2. **0x828F1F98** - Expected static global from .data section (CORRECT!)

## Runtime Evidence

From test run output:
```
[STATIC-CONTEXT-OK] ✅ qword_828F1F98 at 0x828F1F98 is mapped to host 00000001828F1F98
[STATIC-CONTEXT-OK] Current value: 0x0000000000000000
[STATIC-CONTEXT-OK] ✅ dword_828F1F90 at 0x828F1F90 is mapped to host 00000001828F1F90
[STATIC-CONTEXT-OK] Current value: 0xFFFFFFFF
[THREAD2-TRACE] Thread #2 being created with ctx=00120E10  ❌ WRONG ADDRESS!
```

## Memory Layout Analysis

### Address 0x828F1F98 (Expected - Static Global)
- **Location**: XEX .data section (high memory)
- **Range**: 0x82000000 - 0x83000000 (XEX image)
- **Type**: Static global variable `qword_828F1F98`
- **Status**: ✅ Properly mapped and accessible
- **IDA Definition**:
  ```
  .data:828F1F90 dword_828F1F90: .long 0xFFFFFFFF
  .data:828F1F94                 .align 3
  .data:828F1F98 qword_828F1F98: .quad 0
  ```

### Address 0x00120E10 (Actually Used - WRONG!)
- **Location**: Low memory (< 0x40000000)
- **Range**: 0x00000000 - 0x3FFFFFFF (System/User memory)
- **Type**: Unknown - NOT in XEX .data section!
- **Status**: ❌ Wrong memory region entirely!
- **IDA Definition**: Found in .data section but at DIFFERENT location
  ```
  .data:00120E10 qword_120E10: .quad 0
  ```

## PPC Assembly Analysis

### Expected Code Path (sub_82813418)
From IDA analysis, the correct address calculation should be:
```asm
.text:82850A00 lis r11, -32113      # r11 = 0x82850000
.text:82850A04 addi r31, r11, 8080  # r31 = 0x828F1F90
.text:82850A08 addi r3, r31, 8      # r3 = 0x828F1F98 (context address)
.text:82850A0C bl sub_82813418      # Call thread creation with r3=context
```

This calculates: `(-32113 << 16) + 8080 + 8 = 0x828F1F98` ✅

### Actual Code Path (Unknown)
Something is passing 0x00120E10 instead. This address is NOT calculated from PPC instructions - it's likely:
1. Loaded from a different structure
2. Hardcoded in a different code path
3. Coming from a heap allocation that's being misidentified

## Root Cause Hypothesis

Looking at sub_82850820 (called from sub_828508A8):
```cpp
// bl 0x826be3e8
ctx.lr = 0x82850838;
sub_826BE3E8(ctx, base);  // Returns some structure
// mr r11,r3
ctx.r11.u64 = ctx.r3.u64;
// lwz r3,88(r11)  // Load context from offset 88
ctx.r3.u64 = PPC_LOAD_U32(ctx.r11.u32 + 88);
// lwz r11,84(r11)  // Load function pointer from offset 84
ctx.r11.u64 = PPC_LOAD_U32(ctx.r11.u32 + 84);
```

**The context address 0x00120E10 is being loaded from a structure returned by sub_826BE3E8!**

This means:
1. sub_826BE3E8 returns a pointer to some structure
2. That structure has a context pointer at offset +88
3. That context pointer is 0x00120E10 (WRONG!)
4. It SHOULD be 0x828F1F98 (the static global)

## Next Steps

### Priority 1: Find Where 0x00120E10 is Initialized
Need to search for code that writes to address 0x00120E10 or stores it in the structure at offset +88.

### Priority 2: Understand sub_826BE3E8
This function returns the structure that contains the wrong context address. Need to:
1. Examine what sub_826BE3E8 does
2. Find where it initializes the structure
3. Determine why it's using 0x00120E10 instead of 0x828F1F98

### Priority 3: Check for Multiple Thread Contexts
The game might have:
- **Thread #1 context**: 0x828F1F98 (static global, correctly initialized)
- **Thread #2 context**: 0x00120E10 (different location, incorrectly initialized)

Need to verify if these are intentionally different or if one is a bug.

## Possible Solutions

### Solution A: Fix the Structure Initialization
Find where the structure (returned by sub_826BE3E8) is initialized and change:
```cpp
structure->context_ptr = 0x00120E10;  // WRONG
```
to:
```cpp
structure->context_ptr = 0x828F1F98;  // CORRECT
```

### Solution B: Redirect 0x00120E10 to 0x828F1F98
Add a memory alias/redirect so that accesses to 0x00120E10 actually use 0x828F1F98.

### Solution C: Initialize Both Contexts
If the game intentionally uses two different contexts, ensure BOTH are properly initialized:
- 0x828F1F98 (already working)
- 0x00120E10 (needs initialization)

## Technical Details

### Memory Regions
- **0x00000000 - 0x3FFFFFFF**: System/User memory (where 0x00120E10 is)
- **0x40000000 - 0x7FFFFFFF**: User heap memory
- **0x70000000 - 0x7FFFFFFF**: Xenia's heap/stack region
- **0x80000000 - 0x9FFFFFFF**: XEX image (code + data)
- **0x828F0000 - 0x82FFFFFF**: .data section (where 0x828F1F98 is)

### Context Structure
```c
struct ThreadContext {
    uint32_t state;        // +0x00 - set to 1 before calling
    uint32_t function_ptr; // +0x04 - function to call
    uint32_t context;      // +0x08 - parameter to pass
};
```

## Runtime Verification Results

From test run with added logging:
```
[sub_826BE3E8] Returning structure at 0x7FEA17B0
[THREAD2-TRACE] Thread #2 being created with ctx=00120E10
```

**CRITICAL FINDINGS**:
1. sub_826BE3E8 returns a structure at **0x7FEA17B0** (heap memory, VmArena region)
2. That structure contains **0x00120E10** at offset +88 (context pointer)
3. The structure is heap-allocated, but contains a WRONG static address

**Memory Region Analysis**:
- 0x7FEA17B0: Heap memory (VmArena: 0x7FEA0000-0xA0000000) ✅ Correct for structure
- 0x00120E10: Low memory (< 0x40000000) ❌ WRONG for context!
- 0x828F1F98: XEX .data section (0x82000000-0x83000000) ✅ Should be this!

## Conclusion

The static global approach is CORRECT, but the game code is using the WRONG address (0x00120E10) instead of the correct static global (0x828F1F98). This is NOT a recompiler bug - it's either:
1. A bug in the original game code
2. A misunderstanding of how the game initializes multiple thread contexts
3. An issue with how the structure returned by sub_826BE3E8 is initialized

**ROOT CAUSE**: The heap-allocated structure at 0x7FEA17B0 is being initialized with context pointer 0x00120E10 instead of 0x828F1F98. Need to find WHERE this initialization happens and WHY it uses the wrong address.

**Action Required**:
1. Find where the structure at 0x7FEA17B0 is allocated and initialized
2. Trace back to see where 0x00120E10 comes from
3. Determine if 0x00120E10 is a valid address that needs initialization, or if it should be 0x828F1F98

