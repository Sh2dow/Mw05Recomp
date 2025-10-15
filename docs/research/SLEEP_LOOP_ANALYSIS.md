# Sleep Loop Analysis - Render Thread Not Waking Up

**Date**: 2025-10-15
**Status**: 🔍 ROOT CAUSE IDENTIFIED - Event signaling works, but thread doesn't wake up
**Thread**: tid=00004154 (Render thread)
**Location**: `lr=0x82441D4C` calling `sub_8262F2A0` (KeDelayExecutionThread wrapper)

## Summary

The render thread is stuck in an infinite sleep loop, calling `KeDelayExecutionThread` with `Alertable=FALSE` thousands of times. The event at `0x40009D4C` IS being signaled by the GPU Commands system thread, but the render thread is NOT waking up.

## Evidence

### Event IS Being Signaled
```
[*] [ke.set] obj=0x40009D4C type=0 state=1
```

This message appears in the trace, confirming that `KeSetEvent` is being called on the event at `0x40009D4C`.

### Thread Is NOT Waking Up
```
[TRACE] import=HOST.Wait.observe.KeDelayExecutionThread tid=00004154 lr=0x82441D4C r3=00000000 r4=00000000
[TRACE] import=HOST.FastDelay.KeDelayExecutionThread tid=00004154 lr=0x82441D4C r3=00000000 r4=00000000
[TRACE] import=HOST.sub_8262D9D0.called lr=82441D4C count=5274 r3=00000000 tid=00004154
[TRACE] import=sub_8262F2A0 tid=00004154 lr=0x82441D4C r3=00000000 r4=00000000
```

The thread keeps calling `KeDelayExecutionThread` in a loop (count increments: 5274, 5275, 5276, ...).

## Root Cause

The render thread is calling `KeDelayExecutionThread` with `Alertable=FALSE` (r4=0), which means it's NOT waiting on an event - it's just sleeping for a fixed time interval.

Looking at the assembly for `sub_8262F2A0`:
```asm
.text:8262F2EC    clrlwi    r31, r29, 24    # r31 = r29 & 0xFF (Alertable flag)
.text:8262F2F0 loc_8262F2F0:                 # Loop start
.text:8262F2F0    mr        r5, r30         # Interval
.text:8262F2F4    mr        r4, r29         # Alertable
.text:8262F2F8    li        r3, 1           # WaitMode = UserMode
.text:8262F2FC    bl        KeDelayExecutionThread
.text:8262F300    cmplwi    cr6, r31, 0     # Compare r31 with 0
.text:8262F304    beq       cr6, loc_8262F310  # If r31==0, EXIT LOOP
.text:8262F308    cmpwi     cr6, r3, 0x101  # Compare return with STATUS_ALERTED
.text:8262F30C    beq       cr6, loc_8262F2F0  # If return==STATUS_ALERTED, loop back
```

The function is designed to:
1. Sleep with `KeDelayExecutionThread(WaitMode=1, Alertable=r29, Interval=r30)`
2. If `Alertable==0` (r31==0), exit the loop immediately
3. If `Alertable!=0` and return==STATUS_ALERTED (0x101), loop back and sleep again

**The problem**: The function is being called with `r4=0` (Alertable=FALSE), so r29=0, r31=0. The loop should exit immediately at line 0x8262F304 (`beq cr6, loc_8262F310`), but it doesn't!

## Why The Loop Doesn't Exit

The condition `r31 == 0` should be TRUE (since r31 = r29 & 0xFF = 0 & 0xFF = 0), so the branch should be taken and the loop should exit.

But the trace shows the loop keeps running. This means either:
1. **r31 is NOT 0** (the `clrlwi` instruction is not working correctly)
2. **The comparison is not working correctly** (the `cmplwi` instruction is buggy)
3. **The branch is not being taken** (the `beq` instruction is buggy)

## Hypothesis: r29 Is Not 0

Looking at the trace more carefully:
```
[TRACE] import=sub_8262F2A0 tid=00004154 lr=0x82441D4C r3=00000000 r4=00000000
[TRACE] import=sub_8262F2A0.lr=82441D4C r3=00000000 r4=00000000 r5=8208F518 tid=00004154
```

The function is called with `r4=0`, which should be copied to `r29`. But what if `r29` is NOT being set correctly?

Let me check the generated code for the function entry:

## Next Steps

1. **Check the generated code** for `sub_8262F2A0` to see if r29 is being set correctly from r4
2. **Add logging** to the generated code to trace r29, r31, and cr6.eq values
3. **Compare with Xenia** to see how Xenia handles this function
4. **Check for recompiler bugs** in the `mr` (move register) instruction that copies r4 to r29

## Related Files

- `Mw05RecompLib/ppc/ppc_recomp.80.cpp` - Generated code for `sub_8262F2A0`
- `tools/XenonRecomp/XenonRecomp/recompiler.cpp` - Recompiler source
- `Mw05Recomp/kernel/imports.cpp` - KeDelayExecutionThread implementation
- `Mw05Recomp/kernel/system_threads.cpp` - GPU Commands thread that signals the event

## Trace Pattern

The sleep loop repeats with this pattern:
```
[TRACE] import=HOST.Wait.observe.KeDelayExecutionThread tid=00004154 lr=0x82441D4C r3=00000000 r4=00000000
[TRACE] import=HOST.FastDelay.KeDelayExecutionThread tid=00004154 lr=0x82441D4C r3=00000000 r4=00000000
[TRACE] import=HOST.sub_8262D9D0.called lr=82441D4C count=5274 r3=00000000 tid=00004154
[TRACE] import=sub_8262F2A0 tid=00004154 lr=0x82441D4C r3=00000000 r4=00000000
[TRACE] import=sub_8262F2A0.lr=82441D4C r3=00000000 r4=00000000 r5=8208F518 tid=00004154
```

The count increments on each iteration (5274, 5275, 5276, ...), showing the loop is running continuously.

## Conclusion

The `clrlwi` bug fix (Bug #40) was correct, but it was NOT the cause of the sleep loop. The real issue is that the loop exit condition is not working, even though `r31` should be 0.

This suggests there's another recompiler bug affecting the loop logic, possibly in:
- The `mr` instruction that copies r4 to r29
- The `cmplwi` instruction that compares r31 with 0
- The `beq` instruction that branches when cr6.eq is true
- The condition register (cr6) handling

All of these instructions were supposedly fixed in the previous 40 bug fixes, so this is a NEW bug or a different manifestation of the same class of bugs.

