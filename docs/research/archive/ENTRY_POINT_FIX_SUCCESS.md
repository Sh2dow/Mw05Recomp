# Entry Point Fix - Major Breakthrough!

**Date**: 2025-10-14

## Summary
Fixed critical bug where XEX entry point 0x8262E9A8 was missing from MW05.toml, preventing the game from starting correctly.

## The Problem
Game was crashing immediately after load with:
```
[boot][error] Guest function 0x8262E9A8 not found
```

The XEX entry point was NOT in the TOML configuration file, so the recompiler didn't generate code for it.

## The Investigation
1. Checked XEX header - entry point is 0x8262E9A8
2. Searched MW05.toml for 0x8262E9A8 - NOT FOUND
3. Checked generated PPC sources - function missing
4. Conclusion: TOML was incomplete

## The Fix
**File**: `Mw05RecompLib/config/MW05.toml`

Added missing entry point to functions list:

```toml
[[functions]]
address = 0x8262E9A8
size = 0x...  # Determined from IDA
```

Then regenerated PPC sources:
```powershell
./build_cmd.ps1 -Clean -Stage codegen
./build_cmd.ps1 -Stage lib
./build_cmd.ps1 -Stage app
```

## The Result
✅ Entry point 0x8262E9A8 is now being called!
✅ Game starts executing naturally
✅ No more "Guest function not found" errors
✅ Main thread progresses through initialization

## Impact
This fix unlocked:
- Natural game execution (no workarounds needed)
- Thread creation working correctly
- VdSwap being called
- PM4 command buffer processing
- File I/O starting to work

## Lesson Learned
**ALWAYS check TOML completeness** when adding new functions or investigating crashes. The TOML file is the source of truth for what gets recompiled.

## Related Commits
- `c8ee8dc` - Entry point 0x8262E9A8 is being called!
- `b9ee7c4` - Game startup fixes

## Related Files
- `Mw05RecompLib/config/MW05.toml` - Configuration file
- `tools/XenonRecomp/` - Recompiler that reads TOML
- `Mw05RecompLib/ppc/` - Generated PPC sources

