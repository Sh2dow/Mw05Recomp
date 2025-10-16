# Rendering Crash Analysis - Memory Allocation Failure

## Date: 2025-10-16

## Summary
✅ **GAME RUNS FOR 5+ SECONDS** - Main loop executing, graphics callbacks invoked
❌ **CRASH: Memory allocation failure** - o1heap assertion at line 332
❌ **NO DRAWS YET** - All PM4 scans show `draws=0`

## Crash Details

### Error Message
```
Assertion failed: frag != ((void*)0), file D:/Repos/Games/Mw05Recomp/thirdparty/o1heap/o1heap.c, line 332
```

### When It Happens
- After ~5 seconds of execution
- During memory allocation for game resources
- After many NULL-CALL errors

### Memory Status Before Crash
```
[AllocPhysical] BEFORE: size=368 (0.00 MB) align=16 heap_alloc=536871808/1610612160 (512.00/1536.00 MB) oom=0
[AllocPhysical] SUCCESS: size=368 (0.00 MB) align=16 guest=0xC00005F0 heap_alloc=536872320/1610612160 (512.00/1536.00 MB) oom=0
```

- Heap using: 512 MB
- Heap available: 1536 MB
- Should have plenty of space!

## Root Cause Analysis

### NULL-CALL Errors Pattern
The crash is preceded by many NULL-CALL errors:
```
[NULL-CALL] lr=8211E4A0 target=00001973 r3=00000060 r31=00000060 r4=00000014
[NULL-CALL] lr=8211E4C8 target=00001973 r3=00000060 r31=00000060 r4=00000014
[NULL-CALL] lr=8211E4A0 target=00001973 r3=000000C0 r31=000000C0 r4=00000014
...
```

**Pattern**: r3 values are offsets (0x60, 0xC0, 0x120, etc.) not pointers!
- These are multiples of 0x60 (96 bytes)
- Suggests array iteration with invalid base pointer
- Same issue we fixed before with recompiler bugs!

### Hypothesis
1. Game is iterating over an array of 96-byte structures
2. Recompiler is passing offsets instead of pointers
3. Functions try to dereference invalid pointers
4. This corrupts memory or causes allocation failures
5. Eventually o1heap runs out of valid memory

## Current Status

### ✅ Working
- Game boots and runs
- Main loop executes
- Graphics callbacks invoked
- PM4 commands processed
- File I/O hooks registered
- Import table patched (388/719 imports)

### ⚠️ Issues
- **NO DRAWS** - All PM4 scans show `draws=0`
- **NULL-CALL ERRORS** - Invalid function pointers
- **MEMORY CRASH** - o1heap allocation failure
- **MISSING IMPORTS** - 331 imports not implemented

## Next Steps

### Immediate (Critical)
1. **Fix NULL-CALL errors** - These are causing memory corruption
   - Check if recompiler fixes were applied correctly
   - Verify PPC sources were regenerated
   - Look for remaining 32-bit vs 64-bit issues

2. **Increase heap size** - Temporary workaround
   - May allow game to progress further
   - Won't fix the root cause

3. **Debug memory corruption** - Add memory guards
   - Detect which allocations are failing
   - Trace back to the NULL-CALL that caused it

### Medium Term
1. **Implement missing imports** - 331 imports still needed
2. **Create missing threads** - Xenia creates 9, we create 3
3. **Fix file I/O** - Verify files can be loaded

### Long Term
1. **Full rendering pipeline** - Get first draw command
2. **Graphics debugging** - Verify PM4 commands are correct
3. **Performance optimization** - Reduce memory usage

## Files Involved
- `Mw05Recomp/kernel/memory.cpp` - Memory allocation
- `thirdparty/o1heap/o1heap.c` - Heap allocator
- `Mw05RecompLib/ppc/ppc_recomp.*.cpp` - Generated code with NULL-CALL errors
- `tools/XenonRecomp/XenonRecomp/recompiler.cpp` - Recompiler (may have bugs)

## Related Documentation
- `docs/research/FILE_IO_HOOKS_REGISTERED.md` - File I/O setup
- `docs/research/RENDERING_STATUS.md` - Previous rendering status
- `docs/research/THREAD_CRASH_FINAL_STATUS.md` - Thread crash fixes

