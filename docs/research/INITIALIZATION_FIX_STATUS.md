# Initialization Fix Status

## Date: 2025-10-16

## Summary
Successfully implemented initialization for `dword_828E14E0` global variable to fix thread crash. The variable is now initialized to `0` during boot, after XEX load but before thread creation.

## Changes Made

### 1. Modified `Mw05Recomp/main.cpp` (lines 1034-1054)
- Added initialization code for `dword_828E14E0` at address `0x828E14E0`
- Initialization happens AFTER `LdrLoadModule()` returns but BEFORE `GuestThread::Start()`
- Uses `KernelTraceHostOpF()` for logging (appears in traces)
- Replaced `fprintf(stderr, ...)` with `KernelTraceHostOpF()` for better trace visibility

### 2. Regenerated PPC Sources
- Cleaned and regenerated all PPC sources with `build_cmd.ps1 -Clean -Stage codegen`
- Functions `sub_826BE2B0` and `sub_826BE2C0` are now properly generated
- Total of 106 PPC source files generated

### 3. Rebuilt Application
- Successfully compiled with all changes
- No build errors

## Verification
The initialization code IS running correctly:
```
[*] [TRACE] import=HOST.Init.dword_828E14E0 BEFORE = FFFFFFFF
[*] [TRACE] import=HOST.Init.dword_828E14E0 AFTER = 00000000 (expected 00000000)
```

## Current Problem
The crash still occurs at the same offset `+0x4C21A90` even after initialization. This suggests the problem is NOT with `dword_828E14E0` being uninitialized.

## Root Cause Analysis
The function pointer table at `0x828EE5E8` contains OFFSETS, not absolute function pointers:
```
00080017 00002918 00002920 00000004
00000542 00340000 005a0000 00120000
006e0000 00002937
```

These are small values (0x80017, 0x2918, etc.) that look like offsets, not absolute addresses (which should be in the range 0x82000000-0x82CD0000).

## Next Steps
1. **Investigate how the function pointer table is used**
   - Check if the generated code for `sub_826BE2B0` is correct
   - Verify if it's adding a base address to the offset before calling
   - Compare with Xenia's behavior

2. **Check the generated code**
   - Search for `sub_826BE2B0` in the regenerated PPC sources
   - Verify the implementation matches the expected behavior
   - Check if `PPC_CALL_INDIRECT_FUNC` macro is being used correctly

3. **Test the fix**
   - Run `scripts/run_clean_test.ps1` to verify the crash is fixed
   - Check if the thread runs correctly
   - Monitor for new crashes or errors

## Files Modified
- `Mw05Recomp/main.cpp` (lines 1034-1054)
- All PPC sources regenerated (106 files)

## Build Status
✅ Build successful
✅ Initialization code running
❌ Crash still occurs (different root cause)

## Trace Messages
The following trace messages confirm initialization is working:
- `HOST.Init.dword_828E14E0 BEFORE = FFFFFFFF` - Original value from XEX
- `HOST.Init.dword_828E14E0 AFTER = 00000000` - Successfully initialized to 0
- `HOST.ExCreateThread entry=828508A8 ctx=7FEA15A0 flags=00000001` - Thread created
- `HOST.NtResumeThread tid=00009500` - Thread resumed
- Crash at offset `+0x4C21A90` - Still occurring

## Hypothesis
The function pointer table at `0x828EE5E8` contains relative offsets that need to be added to a base address (likely `0x82000000` or `PPC_CODE_BASE`) before being used as function pointers. The generated code for `sub_826BE2B0` might not be doing this correctly.

