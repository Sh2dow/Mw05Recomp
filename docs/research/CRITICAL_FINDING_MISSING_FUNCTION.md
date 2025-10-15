# CRITICAL FINDING: NULL Vtable Pointer in Structure

## Summary
**ROOT CAUSE IDENTIFIED**: The structure being passed to `sub_8211E470` has a **NULL vtable pointer** at offset +0!

## Update: NO Recompiler Bug - Function Was Always Generated
**IMPORTANT DISCOVERY**: I was editing the WRONG TOML file!
- The build system uses `Mw05RecompLib/config/MW05.toml` (the CORRECT file)
- I was editing `tools/XenonRecomp/resources/mw05_recomp.toml` (WRONG file, not used by build)
- The correct TOML file has BOTH entries:
  - Line 931: `{ address = 0x8211E1D0, size = 0x514 }` (large function)
  - Line 934: `{ address = 0x8211E470, size = 0xC8 }` (specific sub-function)
- The function `sub_8211E470` was ALWAYS correctly generated in `ppc_recomp.3.cpp` at line 29113
- There was NO recompiler bug - the recompiler is working correctly!

The crash occurs because the structure has an uninitialized vtable pointer.

## Evidence

1. **Function exists in symbol mapping**:
   ```
   Mw05RecompLib\ppc\ppc_func_mapping.cpp:944: { 0x8211E470, sub_8211E470 },
   ```

2. **Function does NOT exist in generated code**:
   - Searched all `ppc_recomp.*.cpp` files - NO MATCH for `void sub_8211E470`
   - Searched for `__imp__sub_8211E470` - NO MATCH
   - Function is declared in `ppc_recomp_shared.h` but never defined
   - Build succeeds because the function is declared as `extern` (weak symbol)

3. **NULL-CALL pattern matches missing function**:
   ```
   [NULL-CALL] lr=8211E4A0 target=00000000 r3=00000060 r31=00000060
   ```
   - lr=8211E4A0 is INSIDE function 0x8211E470 (at offset +0x30)
   - target=00000000 means the function pointer is NULL
   - This happens because the function implementation doesn't exist!

4. **Recompiler ran successfully**:
   - Ran `./build_cmd.ps1 -Clean -Stage codegen`
   - Recompiler completed without errors
   - Generated 106 PPC source files
   - But `sub_8211E470` is still missing from all of them!

## Why This Causes the Crash

1. Game calls `sub_8211E470` (vector resize function)
2. Function lookup in `g_memory` returns NULL (function not recompiled)
3. Code tries to execute at address 0x00000000
4. NULL-CALL logging catches it and logs the error
5. Crash occurs

## The Real Problem

The values 0x60, 0xC0, 0x120, 0x180 are NOT the problem - they're just the parameters being passed to the function. The problem is that the function itself is MISSING from the recompiled code!

## Why Is the Function Missing?

**CONFIRMED**: This is a **RECOMPILER BUG**. The function is in the .pdata section (otherwise it wouldn't be in the mapping table), but the recompiler is failing to generate the implementation.

Possible causes:
1. **Function is inside another function's range**: The TOML file has `{ address = 0x8211E1D0, size = 0x514 }`, which covers the range 0x8211E1D0 to 0x8211E6E4. Function 0x8211E470 is INSIDE this range!
2. **Recompiler treats it as a label, not a function**: The recompiler might be trying to recompile the entire range as a single function, treating 0x8211E470 as an internal label
3. **Recompiler fails silently**: The recompiler adds the function to the mapping table but fails to generate code, without reporting an error

## How to Fix

### RECOMMENDED: Split the Large Function in TOML

The problem is that the TOML file has:
```toml
{ address = 0x8211E1D0, size = 0x514 },
```

This tells the recompiler to treat the entire range 0x8211E1D0 to 0x8211E6E4 as a single function. But the .pdata section has multiple functions in this range:
- 0x8211E1D0 (parent function)
- 0x8211E320 (sub-function)
- 0x8211E3E0 (sub-function)
- 0x8211E470 (sub-function) **<-- THIS IS THE ONE THAT'S CRASHING**
- 0x8211E538 (sub-function)
- 0x8211E678 (sub-function)
- 0x8211E738 (sub-function)

**Solution**: Remove the large function entry from the TOML file and let the recompiler use the .pdata entries instead.

1. Edit `tools/XenonRecomp/resources/mw05_recomp.toml`
2. Find line 72: `{ address = 0x8211E1D0, size = 0x514 },`
3. Delete this line (or comment it out)
4. Regenerate: `./build_cmd.ps1 -Clean -Stage codegen`
5. Rebuild: `./build_cmd.ps1 -Stage lib`
6. Test: `./build_cmd.ps1 -Stage app` and run the game

### Alternative: Implement as Manual Override

If removing the TOML entry doesn't work, create a manual implementation:
1. Create `PPC_FUNC(sub_8211E470)` in `Mw05Recomp/cpu/` or similar
2. Implement the function based on IDA decompilation
3. Register it with `GUEST_FUNCTION_HOOK` or `g_memory.InsertFunction`

## Next Steps

1. **Determine function size**: Use IDA to find the size of function at 0x8211E470
2. **Check .pdata**: Verify if the function is in the XEX's .pdata section
3. **Add to TOML**: Add the function to the manual functions list with correct size
4. **Regenerate**: Run the recompiler to generate the function
5. **Rebuild**: Build the project and test

## Related Functions

These functions are also likely missing (they're called from sub_8211E470):
- `sub_8211E3E0` (called at lr=8211E4A0)
- `sub_8211E3E8` (likely nearby)
- `sub_8211E538` (initialization function)
- `sub_8211F4A0` (cleanup function)

All of these should be checked and added to the manual functions list if missing.

## IDA Server Note

The user mentioned adding a `/disasm` endpoint to the IDA server. Once that's available, we can use it to:
1. Get the exact assembly code for sub_8211E470
2. Determine the function size
3. Check for any problematic instructions
4. Verify the function boundaries

Command to use once endpoint is available:
```powershell
(Invoke-WebRequest -Uri 'http://127.0.0.1:5050/disasm?ea=0x8211E470&count=100').Content
```

