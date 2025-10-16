# Root Cause Analysis: Static Initializer Table Corruption

**Date**: 2025-10-16  
**Status**: CRITICAL BUG FOUND - Static initializer table contains invalid function pointers

## Executive Summary

The game is **NOT progressing to rendering** because it's crashing during C++ static initialization. The function `sub_8262FC50` iterates through a table of static initializer function pointers, but many of these pointers are **INVALID** (0x00001973, 0x00010000, 0x00001964, etc.), causing NULL-CALL errors.

## Evidence

### NULL-CALL Errors
```
[NULL-CALL] lr=8262FD08 target=00001973 r3=00000000 r31=00000004 r4=00000000
[NULL-CALL] lr=8262FD08 target=00010000 r3=00000000 r31=00000008 r4=00000000
[NULL-CALL] lr=8262FD08 target=00001964 r3=00000000 r31=0000000C r4=00000000
[NULL-CALL] lr=8262FD08 target=00000001 r3=00000000 r31=00000010 r4=00000000
[NULL-CALL] lr=8262FD08 target=00001973 r3=00000000 r31=00000014 r4=00000000
```

### Function Analysis (sub_8262FC50)

**Purpose**: C++ static initializer/destructor dispatcher  
**Location**: 0x8262FC50  
**Call site**: 0x8262FD08 (inside the loop)

**Decompiled Code**:
```c
int sub_8262FC50()
{
  void (*v0)(void); // ctr
  _DWORD *v1; // r31
  int result; // r3
  _DWORD *v3; // r31

  __asm { mfspr     r12, LR }
  if ( off_828E14F8 )
  {
    __asm { mtspr     CTR, r11 }
    v0();
  }
  v1 = &unk_828DF0FC;
  result = 0;
  if ( &unk_828DF0FC >= (_UNKNOWN *)dword_828DF108 )
  {
LABEL_9:
    v3 = &unk_828D0010;
    if ( &unk_828D0010 < (_UNKNOWN *)&dword_828DF0F8 )
    {
      do
      {
        if ( *v3 && *v3 != -1 )
        {
          __asm { mtspr     CTR, r11 }
          result = ((int (__fastcall *)(int))v0)(result);
        }
        ++v3;
      }
      while ( v3 < &dword_828DF0F8 );
    }
    result = 0;
  }
  else
  {
    while ( !result )
    {
      if ( *v1 )
      {
        __asm { mtspr     CTR, r11 }
        result = ((int (*)(void))v0)();
      }
      if ( ++v1 >= dword_828DF108 )
      {
        if ( result )
          break;
        goto LABEL_9;
      }
    }
  }
  __asm { mtspr     LR, r12 }
  return result;
}
```

**What it does**:
1. Iterates through two arrays of function pointers:
   - Array 1: `unk_828DF0FC` to `dword_828DF108`
   - Array 2: `unk_828D0010` to `dword_828DF0F8`
2. For each non-null, non-(-1) pointer, calls the function via CTR register
3. This is the standard C++ static initialization mechanism

## Root Cause

The static initializer table contains **GARBAGE VALUES** instead of valid function pointers:
- Expected: Pointers in range 0x82000000-0x82CD0000 (XEX code section)
- Actual: 0x00001973, 0x00010000, 0x00001964, 0x00000001, etc. (INVALID!)

### Possible Causes

1. **XEX Loading Bug** - The static initializer table section is not being loaded correctly
2. **Relocation Bug** - Function pointers in the table are not being relocated
3. **Byte-Swapping Bug** - Pointers are being read with wrong endianness
4. **Memory Corruption** - Something is overwriting the table after it's loaded

## Impact

- ✅ Game boots successfully
- ✅ Import table patched
- ✅ Graphics callbacks registered
- ✅ PM4 scanning happening
- ❌ **Static initializers fail** - Game crashes before reaching main loop
- ❌ **No file I/O** - Game never gets to asset loading
- ❌ **No draws** - Game never progresses to rendering

## Investigation Steps

### 1. Check XEX Loading
- Verify that all sections are loaded correctly
- Check if the `.CRT$XI*` sections (static initializers) are present
- Verify memory layout matches expected XEX structure

### 2. Check Relocation
- Verify that function pointers in the static initializer table are relocated
- Check if the XEX relocation table includes these addresses
- Compare with Xenia's relocation behavior

### 3. Check Byte-Swapping
- Verify that function pointers are byte-swapped correctly (big-endian to little-endian)
- Check if the table is being read with correct endianness

### 4. Dump the Table
- Use IDA to dump the static initializer table contents
- Compare with what's in memory at runtime
- Identify where the corruption occurs

## ROOT CAUSE CONFIRMED

**CRITICAL FINDING**: The XEX file has **NO BASE REFERENCE HEADER**!

From the trace:
```
[XEX] No base reference header found
[XEX] loadAddress=0x82000000 imageSize=0x00CD0000 entry=0x8262E9A8 compressionType=1
```

This means:
1. The XEX loader is NOT applying any relocations
2. Function pointers in the static initializer table are stored as **OFFSETS** in the XEX file
3. These offsets are never converted to **ABSOLUTE ADDRESSES**
4. When the game tries to call them, it's calling garbage addresses

### Evidence

**IDA shows** (from static initializer table at 0x828D0010):
```
00000000 826CDE30 826CDE30 828A7AE8 828A7B20 828A7BC0 828A7BF8 828A7C20
```

**Runtime shows** (from NULL-CALL errors):
```
0x00001973, 0x00010000, 0x00001964, 0x00000001, 0x00001973
```

The IDA values (0x826CDE30, etc.) are **ABSOLUTE ADDRESSES** because IDA has already applied the base address (0x82000000).

The runtime values (0x00001973, etc.) are **GARBAGE** because they're reading the raw XEX data which contains **RELATIVE OFFSETS**, not absolute addresses.

### The Fix

The XEX file doesn't have a base reference header, so we need to **FORCE relocation** by assuming the XEX was originally linked at address 0x00000000 and needs to be relocated to 0x82000000.

**Solution**: Modify `Mw05Recomp/main.cpp` to apply relocations even when there's no base reference header.

## Next Steps

### Immediate Fix

1. **Modify XEX loader to force relocation**
   - File: `Mw05Recomp/main.cpp` lines 648-721
   - Change: Apply relocations even when `baseRefPtr == nullptr`
   - Assume: `baseRef = 0x00000000` (XEX linked at 0)
   - Apply: `delta = loadAddress - 0 = 0x82000000`

2. **Test the fix**
   - Rebuild application
   - Run for 10 seconds
   - Check if NULL-CALL errors disappear
   - Check if game progresses to rendering

3. **Verify static initializer table**
   - Add logging to dump table contents after relocation
   - Compare with IDA values
   - Ensure all pointers are valid

### Long-term Validation

1. Compare with Xenia's XEX loader
2. Check if other XEX files have the same issue
3. Add validation to detect missing base reference headers
4. Document the fix for future reference

## Related Files

- `Mw05Recomp/kernel/xex_loader.cpp` - XEX loading logic
- `Mw05Recomp/kernel/imports.cpp` - Import table processing
- `Mw05RecompLib/ppc/ppc_context.h` - PPC context and function lookup
- `tools/XenonRecomp/XenonUtils/ppc_context.h` - Function table macros

## References

- AGENTS.md - Previous debugging history
- docs/research/FINAL_STATUS_RENDERING_BLOCKED.md - Previous status
- docs/research/INVESTIGATION_DRAWS.md - Draw command investigation

