# Bug #40 Test Results - CLRLWI Fix

**Date**: 2025-10-15
**Status**: ✅ FIX APPLIED - But NOT the root cause of sleep loop
**Test Duration**: 15 seconds

## Summary

The `clrlwi` instruction bug was successfully fixed in the recompiler, but testing shows this was **NOT the cause of the infinite sleep loop**. The game exhibits identical behavior before and after the fix.

## Fix Applied

**File**: `tools/XenonRecomp/XenonRecomp/recompiler.cpp` line 839
**Instruction**: `clrlwi` (Clear Left Word Immediate)

**Before**:
```cpp
println("\t{}.u64 = {}.u32 & 0x{:X};", r(insn.operands[0]), r(insn.operands[1]), (1ull << (32 - insn.operands[2])) - 1);
```

**After**:
```cpp
println("\t{}.u32 = {}.u32 & 0x{:X};", r(insn.operands[0]), r(insn.operands[1]), (1ull << (32 - insn.operands[2])) - 1);
```

## Test Results

### Before Fix
- Sleep loop count: 5800+ calls in 15 seconds
- VdSwap calls: ~264
- Draw commands: 0
- Game stuck at `lr=0x82441D4C` calling `sub_8262D9D0`

### After Fix
- Sleep loop count: 5274-5287 calls in 15 seconds (SAME PATTERN)
- VdSwap calls: 272 (SAME)
- Draw commands: 0 (SAME)
- Game stuck at `lr=0x82441D4C` calling `sub_8262D9D0` (SAME)

## Conclusion

The `clrlwi` bug was a legitimate recompiler bug (using `.u64` instead of `.u32` for a 32-bit PowerPC instruction), but it was **NOT the cause of the sleep loop**. The game's behavior is unchanged after the fix.

This means:
1. ✅ Bug #40 is fixed (correct code generation for `clrlwi`)
2. ❌ The sleep loop is caused by a different issue
3. ❌ The game is still not progressing to rendering code
4. ❌ No draw commands are appearing

## Next Steps

The sleep loop issue requires further investigation:

1. **Investigate the sleep loop logic** - Why does the game keep calling `KeDelayExecutionThread` with `Alertable=FALSE`?
2. **Check for missing initialization** - Is there a flag or state that needs to be set before the game progresses?
3. **Compare with Xenia** - What does Xenia do differently that allows the game to progress?
4. **Check for missing threads** - Xenia creates 9 threads, we only create 3
5. **Check for missing file I/O** - Game hasn't called NtCreateFile/NtOpenFile/NtReadFile even once

## Trace Evidence

```
[TRACE] import=HOST.Wait.observe.KeDelayExecutionThread tid=00004154 lr=0x82441D4C r3=00000000 r4=00000000
[TRACE] import=HOST.FastDelay.KeDelayExecutionThread tid=00004154 lr=0x82441D4C r3=00000000 r4=00000000
[TRACE] import=HOST.sub_8262D9D0.called lr=82441D4C count=5274 r3=00000000 tid=00004154
[TRACE] import=sub_8262F2A0 tid=00004154 lr=0x82441D4C r3=00000000 r4=00000000
[TRACE] import=sub_8262F2A0.lr=82441D4C r3=00000000 r4=00000000 r5=8208F518 tid=00004154
```

The pattern repeats indefinitely with incrementing count (5274, 5275, 5276, ...).

## Related Documents

- [RECOMPILER_BUG_40_FOUND.md](RECOMPILER_BUG_40_FOUND.md) - Original bug analysis
- [AGENTS.md](../../AGENTS.md) - All 40 recompiler bugs fixed
- [FINAL_DIAGNOSIS.md](../../Traces/FINAL_DIAGNOSIS.md) - Sleep loop analysis
- [CURRENT_STATUS.md](CURRENT_STATUS.md) - Overall project status

