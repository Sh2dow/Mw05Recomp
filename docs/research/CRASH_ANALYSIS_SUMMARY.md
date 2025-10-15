# Crash Analysis Summary - MW05 Recompilation

## Current Status: Partial Fix Applied, Root Cause Identified

### What Was Fixed
✅ **Game allocator is now being called**: Changed `sub_8215CB08_debug` to call the original game allocator instead of bypassing it
- File: `Mw05Recomp/kernel/imports.cpp` lines 9317-9336
- The game's initialization code (`sub_8215FDC0`) is now being executed
- Memory allocations are working correctly (addresses like 0xB56A1C00, 0xB56A0F60)

### What's Still Broken
❌ **Crash still occurs with NULL pointer dereferences**
- Crash location: offset +0x4C69450 from base (in recompiled PPC code)
- NULL-CALL messages show addresses like 0x60, 0xC0, 0x120, 0x180, etc.
- These addresses increment by 0x60 (96 bytes)
- Pattern suggests these are **OFFSETS**, not absolute addresses

## Root Cause Analysis

### The Problem
The game is passing **offsets** (0x60, 0xC0, 0x120, etc.) to functions that expect **absolute addresses**.

### Evidence
1. **Addresses are too small**: 0x60, 0xC0, 0x120 are all < 0x1000
2. **Regular increment pattern**: Each address is 0x60 (96 bytes) larger than the previous
3. **NULL vtable pointers**: When dereferenced, these addresses contain 0x00000000 or 0xFFFAFEFD
4. **Crash location**: `sub_8211E3E0` tries to dereference `*a2` where `a2` contains these invalid addresses

### IDA Decompilation Analysis

**Function `sub_8211E470`** (the caller):
```c
int __fastcall sub_8211E470(int result, unsigned int a2)
{
  _DWORD *v3 = (_DWORD *)result;
  _DWORD *v6 = (_DWORD *)v3[1];  // Load pointer from offset +4
  
  if ( v7 > 0 )
  {
    v10 = v6;
    do
    {
      result = sub_8211E3E0((int)v3, v10);  // Call with pointer
      --v7;
      ++v10;  // Increment pointer
    }
    while ( v7 );
  }
}
```

**Function `sub_8211E3E0`** (the crash site):
```c
int __fastcall sub_8211E3E0(int result, _DWORD *a2)
{
  v6 = (_DWORD *)(*(_DWORD *)(v3 + 4) + 4 * *(_DWORD *)(v3 + 12));
  if ( v6 )
    *v6 = *a2;  // CRASH HERE: dereferencing invalid pointer
}
```

### The Missing Piece
The structure at `v3` has a pointer at offset +4 (`v3[1]`), but this pointer contains **offsets** instead of **absolute addresses**. This suggests:

1. **Option A**: The structure needs to be initialized with a base address
2. **Option B**: The offsets need to be added to a base address before use
3. **Option C**: The structure is being allocated in the wrong memory region

## What Needs to Be Done Next

### Investigation Steps

1. **Find where the structure is allocated**:
   - Search for calls to `sub_8211E470` to find where the structure is created
   - Check if the structure is allocated on the stack, heap, or in static memory
   - Verify that the structure is being initialized correctly

2. **Check for missing base address**:
   - Look for code that should set a base address in the structure
   - Check if there's a missing initialization step
   - Compare with Xenia's behavior to see how it handles this

3. **Verify memory layout**:
   - Check if the XEX data section is properly loaded
   - Verify that static globals are at the correct addresses
   - Ensure that the memory mapping is correct

### Potential Fixes

**Fix Option 1: Initialize the structure correctly**
- Find the initialization code that sets the base address
- Ensure it's being called before the structure is used
- Add logging to verify the base address is set

**Fix Option 2: Add base address calculation**
- Modify `sub_8211E470` to add a base address to the offsets
- Find where the base address should come from
- Update the pointer arithmetic to use absolute addresses

**Fix Option 3: Fix memory allocation**
- Ensure the structure is allocated in the correct memory region
- Verify that the allocator is returning the right type of memory
- Check if there's a flag or parameter that controls allocation type

## Debug Commands

### Check for structure allocation
```powershell
Get-Content test_output.txt | Select-String 'sub_8211E470|sub_8211E3E0'
```

### Check for base address initialization
```powershell
Get-Content test_output.txt | Select-String 'MW05_DEBUG.*ENTER sub_8215CB08'
```

### Check crash pattern
```powershell
Get-Content test_output.txt | Select-String 'NULL-CALL' | Select-Object -First 30
```

## Files Modified

1. **Mw05Recomp/kernel/imports.cpp** (lines 9317-9336)
   - Changed `sub_8215CB08_debug` to call original game allocator
   - Removed bypass that was preventing initialization

## Next Agent Instructions

1. **DO NOT** revert the fix in `imports.cpp` - the game allocator MUST be called
2. **DO** investigate why the structure contains offsets instead of absolute addresses
3. **DO** check if there's missing initialization code
4. **DO** compare with Xenia to see how it handles this structure
5. **DO** add more logging to track structure allocation and initialization

## Key Insight

The user's hint was correct: "Earlier we implemented putting context onto heap (like Xenia does) instead of using static/global stack, so maybe not all stuff still using those addresses and that leads to uninitialized memory issues."

The problem is NOT that we're using heap vs static - the problem is that **some code is still using offsets as if they were absolute addresses**. This suggests there's a missing step where offsets should be converted to absolute addresses by adding a base address.

## Success Criteria

You'll know the fix is working when:
1. ✅ No more NULL-CALL messages in the log
2. ✅ Game progresses past the crash point
3. ✅ Structures are properly initialized with valid pointers
4. ✅ No crashes due to NULL pointer dereferences

