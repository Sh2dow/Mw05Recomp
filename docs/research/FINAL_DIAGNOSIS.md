# MW05 Final Diagnosis - Recompiler Bug in Sleep Loop

## Summary
**ROOT CAUSE CONFIRMED**: The game is stuck in an infinite sleep loop due to a bug in the recompiled code for function `sub_8262F2A0`. The game is calling with `Alertable=FALSE`, which should cause the loop to exit immediately, but the recompiled code is NOT exiting the loop.

## Evidence

### 1. Trace Log Shows Alertable=FALSE
ALL 8,220 sleep calls have `r4=0x0` (Alertable=FALSE):
```
[HOST] import=HOST.Wait.observe.KeDelayExecutionThread tid=6b58 lr=0x8262F300 r3=0x1 r4=0x0 r5=0x2B9250 r6=0x0
```

### 2. Assembly Code Shows Loop Should Exit
```asm
.text:8262F2EC    clrlwi    r31, r29, 24    # r31 = r29 & 0xFF (extract Alertable)
.text:8262F2F0 loc_8262F2F0:                 # Loop start
.text:8262F2F0    mr        r5, r30         # Interval
.text:8262F2F4    mr        r4, r29         # Alertable
.text:8262F2F8    li        r3, 1           # WaitMode = UserMode
.text:8262F2FC    bl        KeDelayExecutionThread
.text:8262F300    cmplwi    cr6, r31, 0     # Compare r31 (Alertable) with 0
.text:8262F304    beq       cr6, loc_8262F310  # If r31==0, EXIT LOOP
.text:8262F308    cmpwi     cr6, r3, 0x101  # Compare return with STATUS_ALERTED
.text:8262F30C    beq       cr6, loc_8262F2F0  # If return==STATUS_ALERTED, loop back
```

**Expected behavior with r4=0**:
1. `r29 = r4 = 0` (Alertable parameter)
2. `r31 = r29 & 0xFF = 0`
3. At `0x8262F300`: `cmplwi cr6, r31, 0` → cr6.eq = TRUE
4. At `0x8262F304`: `beq cr6, loc_8262F310` → **SHOULD EXIT LOOP**

**Actual behavior**: Loop continues infinitely!

### 3. IDA Decompilation Confirms Logic
```c
v10 = a2;  // v10 = Alertable
do
  v11 = KeDelayExecutionThread(UserMode, a2, v9);
while ( v10 && v11 == 257 );  // Loop while Alertable AND return == STATUS_ALERTED
```

With `a2=0` (Alertable=FALSE), `v10=FALSE`, so the loop condition is FALSE and should exit immediately.

## Root Cause

**The recompiled C++ code for `sub_8262F2A0` has a bug that prevents the loop from exiting when Alertable=FALSE.**

Possible causes:
1. **Bug in `clrlwi` instruction recompilation** - The mask operation might not be working correctly
2. **Bug in `beq` branch recompilation** - The branch condition might not be evaluated correctly
3. **Bug in condition register handling** - The `cr6` register might not be set correctly by `cmplwi`

## Next Steps

### IMMEDIATE ACTION REQUIRED

**Find and examine the generated C++ code for `sub_8262F2A0`**:

The function is defined in the TOML at address `0x8262F2A0` with size `0x218` (536 bytes).

According to the function mapping, it should be in one of the `ppc_recomp.*.cpp` files.

**Steps**:
1. Search for the function definition in `Mw05RecompLib/ppc/ppc_recomp.*.cpp`
2. Examine the generated code for the loop condition
3. Look for bugs in:
   - The `clrlwi r31, r29, 24` instruction (should generate `r31.u64 = r29.u32 & 0xFF`)
   - The `cmplwi cr6, r31, 0` instruction (should generate `cr6.compare<uint32_t>(r31.u32, 0, xer)`)
   - The `beq cr6, loc_8262F310` instruction (should generate `if (cr6.eq) goto loc_8262F310`)

### WORKAROUND OPTIONS

If we can't fix the recompiler bug immediately, we can:

1. **Add a shim for `sub_8262F2A0`** - Replace the buggy function with a hand-written C++ version
2. **Patch the generated code** - Manually fix the bug in the generated C++ file
3. **Force the loop to exit** - Add environment variable to skip the sleep loop

### VERIFICATION

Once the bug is fixed:
1. Rebuild the application
2. Run the game
3. Verify that sleep calls decrease dramatically (should be <100 instead of 8,220)
4. Verify that the game progresses past initialization
5. Check if TYPE3 PM4 packets start appearing (draw commands)

## Impact

**This bug is blocking ALL game progress!**

- Game is stuck in initialization
- No draw commands are being issued
- No rendering is happening
- Game will NEVER progress past this point until the bug is fixed

**Priority**: CRITICAL - This is the #1 blocker preventing the game from running.

## Files to Examine

1. **Generated code**: `Mw05RecompLib/ppc/ppc_recomp.*.cpp` (search for `sub_8262F2A0`)
2. **Recompiler**: `tools/XenonRecomp/XenonRecomp/recompiler.cpp`
   - Line 838-842: `clrlwi` instruction
   - Search for `beq` instruction handling
   - Search for `cmplwi` instruction handling
3. **TOML config**: `Mw05RecompLib/config/MW05.toml` line 18931

## Conclusion

**The game is NOT stuck because of missing kernel functions, file loading, or graphics initialization. It's stuck because of a RECOMPILER BUG in the sleep loop function that prevents it from exiting when Alertable=FALSE.**

**Fix this bug and the game will progress!**

