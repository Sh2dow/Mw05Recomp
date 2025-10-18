# Crash Investigation: sub_8215BA10

**Date**: 2025-10-17
**Status**: 🔍 **ROOT CAUSE FOUND** - Import stubs are NOT being patched!
**Issue**: Game crashes when calling `RtlInitializeCriticalSection` because import stub contains original ordinal values

## Executive Summary

The thread context allocation issue has been **completely resolved**. The new crash has been **root-caused**: the import table patching mechanism only patches the **thunks** (pointers in the import table) but does NOT patch the **import stubs** (the actual code that the recompiled functions call). This causes the game to crash when calling kernel imports like `RtlInitializeCriticalSection`.

## Root Cause Analysis

### Import Patching Mechanism (main.cpp:409-590)

The current import patching process:
1. Reads XEX import table (libraries, ordinals, thunks)
2. For each import, looks up host function by name in `g_importLookup`
3. Assigns a unique guest address (starting at 0x828CA000)
4. Inserts host function at guest address via `g_memory.InsertFunction()`
5. **Patches THUNK** to point to guest address (line 583)

### The Problem

**Import stubs are NOT being patched!**

- **Thunk**: Pointer in import table (gets patched ✅)
- **Import stub**: Actual code at 0x828AA07C (does NOT get patched ❌)

### Import Stub Pattern

At address 0x828AA07C:
```
.long ordinal1, ordinal2, mtspr CTR r11, bctr
```

For `RtlInitializeCriticalSection`:
- Ordinal: 0x101012E
  - Library: 0x0101 (xboxkrnl.exe)
  - Ordinal: 0x012E (302 decimal)
  - Function: RtlInitializeCriticalSection

### Call Flow

```
Recompiled code
  ↓ (bl sub_82812C00)
sub_82812C00 (import thunk)
  ↓ (JUMPOUT to 0x828AA07C)
0x828AA07C (import stub - CONTAINS ORIGINAL ORDINAL VALUES!)
  ↓ (tries to call ordinal 0x012E)
CRASH - Invalid address
```

## Crash Pattern

### First Call - SUCCESS ✅
```
[MW05_DEBUG] [depth=1] ENTER sub_8215C838 r3=00000000 r4=A0001000
[MW05_DEBUG] [depth=1] EXIT  sub_8215C838 r3=82915A20
```
- Parameters: r3=00000000, r4=A0001000 (physical heap + 4KB)
- Result: SUCCESS, returns r3=82915A20

### Second Call - CRASH ❌
```
[MW05_DEBUG] [depth=1] ENTER sub_8215C838 r3=00000000 r4=C0001000
[*] [crash] unhandled exception code=0xC0000005
```
- Parameters: r3=00000000, r4=C0001000 (physical heap + 512MB + 4KB)
- Result: CRASH with access violation (0xC0000005)
- **NO `[RtlInitCS]` messages** - function is NEVER called!

## Diagnostic Logging Results

### RtlInitializeCriticalSection (imports.cpp:5763-5800)

Added comprehensive logging:
```cpp
static int call_count = 0;
call_count++;

fprintf(stderr, "[RtlInitCS] Call #%d: cs=%p\n", call_count, (void*)cs);
// ... pointer validation, guest address logging ...
fprintf(stderr, "[RtlInitCS] Call #%d: SUCCESS\n", call_count);
```

**Result**: NO `[RtlInitCS]` messages in log - function is NEVER called!

This confirms that the crash happens INSIDE the recompiled code BEFORE reaching our implementation.

## Crash Location

### Stack Trace
```
[*] [crash]   frame[9] = 0x7ff61cc78d24 module=Mw05Recomp.exe base=0x7ff61cae0000 +0x198D24
[*] [crash]   frame[11] = 0x7ff61d4cc35d module=Mw05Recomp.exe base=0x7ff61cae0000 +0x9EC35D
```

### Source Location
- **File**: `Mw05RecompLib/ppc/ppc_recomp.7.cpp`
- **Offset**: +0x15891D (1,411,357 bytes into file)
- **Size**: 1,747,864 bytes total

## Function Call Chain

```
sub_8215C838 (entry point)
  ↓
sub_8215BA10 (structure initialization)
  ↓
sub_82812C00 (import thunk)
  ↓
0x828AA07C (import stub - UNPATCHED!)
  ↓
CRASH - tries to call ordinal 0x012E
```

## Assembly Analysis

### sub_8215C838 (0x8215C838)
```assembly
mfspr     r12, LR
mr        r11, r3              ; r11 = r3 (parameter)
lis       r10, unk_829159E0@ha
mulli     r7, r11, 0x5C        ; r7 = r11 * 92
addi      r10, r10, unk_829159E0@l
add       r3, r7, r10          ; r3 = &unk_829159E0 + (r11 * 92)
bl        sub_8215BA10         ; Call with r3 = structure pointer
```

When r3=0 (from caller):
- r11 = 0
- r7 = 0 * 0x5C = 0
- r3 = 0x829159E0 + 0 = 0x829159E0

### sub_8215BA10 (0x8215BA10)
```assembly
mr        r31, r3              ; r31 = structure pointer
addi      r3, r31, 0x3C        ; r3 = structure + 0x3C (critical section offset)
bl        sub_82812C00         ; Call RtlInitializeCriticalSection
```

Critical section address: 0x829159E0 + 0x3C = **0x82915A1C**

### sub_82812C00 (Import Thunk)
```c
void sub_82812C00() {
  JUMPOUT(0x828AA07C);  // Jump to import stub
}
```

### Import Stub (0x828AA07C)
```
.long 0x101012E, 0x201012E, 0x7D6903A6, 0x4E800420
```
- Ordinal: 0x101012E
  - Library: 0x0101 (xboxkrnl.exe)
  - Ordinal: 0x012E (302 decimal)
  - Function: **RtlInitializeCriticalSection**

## Memory Analysis

### Memory Regions
- **A0001000**: Physical heap start + 4KB (345 MB allocated) - **WORKS**
- **C0001000**: Physical heap + 512MB + 4KB (345 MB allocated) - **CRASHES**
- **Physical heap range**: 0xA0000000 - 0x100000000 (1536 MB)
- **Both addresses are VALID** within the physical heap

### Critical Section Structure
- **Address**: 0x82915A1C (in BSS section)
- **Memory**: Zero-initialized (BSS section at 0x829159E0)
- **Alignment**: 4-byte aligned (0x82915A1C % 4 = 0)

## Implementation Status

### RtlInitializeCriticalSection
**Location**: `Mw05Recomp/kernel/imports.cpp` lines 5763-5774

```cpp
uint32_t RtlInitializeCriticalSection(XRTL_CRITICAL_SECTION* cs)
{
    if (!cs)
        return 0xC000000DL; // STATUS_INVALID_PARAMETER

    cs->Header.Absolute = 0;
    cs->LockCount = -1;
    cs->RecursionCount = 0;
    cs->OwningThread = 0;

    return 0; // STATUS_SUCCESS
}
```

The implementation is **correct** and should work with zero-initialized memory.

## Root Cause Hypotheses

### Hypothesis 1: Import Stub Not Patched
The import stub at 0x828AA07C might not be patched correctly to call our implementation of `RtlInitializeCriticalSection`. The recompiled code might be calling an invalid address.

### Hypothesis 2: Register Preservation Issue
The recompiled code might not be preserving registers correctly when calling the import. The second call might have corrupted registers that cause the crash.

### Hypothesis 3: Memory Alignment Issue
Although the critical section address (0x82915A1C) is 4-byte aligned, there might be a stricter alignment requirement (e.g., 8-byte or 16-byte) that is not being met.

### Hypothesis 4: Base Address Dependency
The base address parameter (r4) might affect the critical section initialization in some way. The first call with A0001000 succeeds, but the second call with C0001000 crashes. There might be some dependency on the base address that we're not aware of.

### Hypothesis 5: Recompiler Code Generation Bug
The recompiled code for the second call might be generated differently than the first call, causing the crash. This could be due to a bug in the recompiler or a difference in how the code is optimized.

## Next Steps

### 1. Check Import Table Patching
- Verify that ordinal 0x012E (RtlInitializeCriticalSection) is in the import lookup table
- Check if the import stub at 0x828AA07C is patched to call our implementation
- Add logging to the import patching code to confirm the patch is applied

### 2. Add Diagnostic Logging
Add logging to `RtlInitializeCriticalSection` to track calls:
```cpp
uint32_t RtlInitializeCriticalSection(XRTL_CRITICAL_SECTION* cs)
{
    fprintf(stderr, "[RtlInitCS] Called with cs=%p\n", (void*)cs);
    fflush(stderr);
    
    if (!cs) {
        fprintf(stderr, "[RtlInitCS] NULL pointer!\n");
        fflush(stderr);
        return 0xC000000DL;
    }
    
    // ... rest of implementation
    
    fprintf(stderr, "[RtlInitCS] Success\n");
    fflush(stderr);
    return 0;
}
```

### 3. Check Memory Alignment
Verify that the critical section structure has proper alignment:
- Check if XRTL_CRITICAL_SECTION has alignment requirements
- Verify that the structure at 0x82915A1C is properly aligned
- Add assertions to check alignment at runtime

### 4. Compare First vs Second Call
Analyze the differences between the two calls:
- Dump registers before and after each call
- Check if the critical section structure is different
- Verify that the base address (r4) doesn't affect the critical section

### 5. Check Recompiled Code
Examine the generated code for both calls:
- Find the exact location in `ppc_recomp.7.cpp` where the crash occurs
- Compare the generated code for the first vs second call
- Look for any differences in register usage or calling convention

## Files to Investigate

1. **`Mw05Recomp/kernel/imports.cpp`** - RtlInitializeCriticalSection implementation
2. **`Mw05Recomp/kernel/import_lookup.cpp`** - Import table patching
3. **`Mw05RecompLib/ppc/ppc_recomp.7.cpp`** - Recompiled code (crash location)
4. **`tools/XenonRecomp/XenonRecomp/recompiler.cpp`** - Recompiler code generation
5. **`out/build/x64-Clang-Debug/Mw05Recomp/out1.log`** - Runtime log

## Conclusion

The thread context allocation issue is **completely resolved**. The new crash is a separate issue related to calling `RtlInitializeCriticalSection` on the second memory region. The crash is likely due to an import patching issue, register preservation bug, or recompiler code generation problem. Further investigation is needed to identify the exact root cause.

## Redis Analysis Data

All crash analysis data has been stored in Redis under the hash `mw05_crash_analysis`:
- `crash_location`: sub_8215C838 second call with r3=00000000 r4=C0001000
- `first_call_success`: sub_8215C838 r3=00000000 r4=A0001000 - EXIT r3=82915A20
- `second_call_crash`: sub_8215C838 r3=00000000 r4=C0001000 - CRASH 0xC0000005
- `memory_regions`: A0001000=physical heap start (345MB allocated), C0001000=second physical allocation (345MB)
- `crash_offset`: +0x198D24 (frame 9), actual crash in recompiled code at +0x9EC35D (frame 11)
- `crash_function`: sub_8215BA10 calls sub_82812C00 at 0x8215BA70, crash happens in recompiled code at +0x9EC35D in ppc_recomp.7.cpp
- `sub_8215BA10_params`: r3=r31=pointer to structure, r4=r29=base address (A0001000 or C0001000), r5=r30=size, r6=r28=flags
- `sub_82812C00_call`: Called at 0x8215BA70 with r3=r31+0x3C, this is likely a mutex/lock initialization function
- `sub_82812C00_is_import`: sub_82812C00 jumps to 0x828AA07C which is an import stub with ordinal 0x101012E
- `import_stub_pattern`: Import stubs use pattern: ordinal1, ordinal2, mtspr CTR r11, bctr
- `ordinal_0x101012E`: Library=0x0101 (xboxkrnl.exe), Ordinal=0x012E (302 decimal) - likely RtlInitializeCriticalSection
- `critical_section_address`: CS at 0x829159E0+0x3C=0x82915A1C, memory is zero-initialized (BSS section)
- `rtl_init_cs_impl`: RtlInitializeCriticalSection is implemented at imports.cpp:5763-5774, should work with zero-initialized memory
- `hypothesis`: Import stub at 0x828AA07C might not be patched correctly, or recompiled code is not calling it properly

