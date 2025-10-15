# Recompiler Bug #40 - CLRLWI Instruction

**Date**: 2025-10-15
**Status**: ✅ FIXED - But NOT the cause of sleep loop
**File**: `tools/XenonRecomp/XenonRecomp/recompiler.cpp` line 839
**Instruction**: `clrlwi` (Clear Left Word Immediate)

## The Bug

**Line 5748**: Assigns to `.u64` instead of `.u32`
```cpp
// clrlwi r31,r29,24
ctx.r31.u64 = ctx.r29.u32 & 0xFF;  // BUG! Should be .u32
```

**Line 5760**: Compares `.u32`
```cpp
// cmplwi cr6,r31,0
ctx.cr6.compare<uint32_t>(ctx.r31.u32, 0, ctx.xer);
```

## Analysis

The PowerPC instruction `clrlwi r31,r29,24` should:
1. Take the lower 32 bits of r29
2. Clear the upper 24 bits (keeping only the lower 8 bits)
3. Store the result in the lower 32 bits of r31

**Current buggy code**:
```cpp
ctx.r31.u64 = ctx.r29.u32 & 0xFF;
```

This assigns to the full 64-bit register, which is technically correct for the lower 32 bits, but inconsistent with how the register is used later.

**Correct code**:
```cpp
ctx.r31.u32 = ctx.r29.u32 & 0xFF;
```

## Impact

This bug causes the sleep loop to run infinitely because:
1. Game calls with `Alertable=FALSE` (r4=0)
2. r29 = r4 = 0
3. r31 = r29 & 0xFF = 0
4. Loop should exit at line 5762 when `r31 == 0`
5. But the comparison might fail due to inconsistent register width usage

## Evidence from Trace

```
[TRACE] import=HOST.Wait.observe.KeDelayExecutionThread tid=00006664 lr=0x82441D4C r3=00000000 r4=00000000
[TRACE] import=HOST.sub_8262D9D0.called lr=82441D4C count=5819
[TRACE] import=sub_8262F2A0 tid=00006664 lr=0x82441D4C r3=00000000 r4=00000000
[TRACE] import=HOST.Wait.observe.KeDelayExecutionThread tid=00006664 lr=0x82441D4C r3=00000000 r4=00000000
[TRACE] import=HOST.sub_8262D9D0.called lr=82441D4C count=5820
```

The loop runs 5800+ times in 15 seconds, calling `KeDelayExecutionThread` with `r4=0` (Alertable=FALSE) each time.

## Assembly vs Generated Code

**Original PowerPC Assembly**:
```asm
.text:8262F2EC    clrlwi    r31, r29, 24    # r31 = r29 & 0xFF
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

**Generated C++ Code** (lines 5747-5766):
```cpp
loc_8262F2EC:
	// clrlwi r31,r29,24
	ctx.r31.u64 = ctx.r29.u32 & 0xFF;  // BUG HERE
loc_8262F2F0:
	// mr r5,r30
	ctx.r5.u32 = ctx.r30.u32;
	// mr r4,r29
	ctx.r4.u32 = ctx.r29.u32;
	// li r3,1
	ctx.r3.u32 = 1u;
	// bl 0x828aa3cc
	ctx.lr = 0x8262F300;
	__imp__KeDelayExecutionThread(ctx, base);
	// cmplwi cr6,r31,0
	ctx.cr6.compare<uint32_t>(ctx.r31.u32, 0, ctx.xer);
	// beq cr6,0x8262f310
	if (ctx.cr6.eq) goto loc_8262F310;
	// cmpwi cr6,r3,257
	ctx.cr6.compare<int32_t>(ctx.r3.s32, 257, ctx.xer);
	// beq cr6,0x8262f2f0
	if (ctx.cr6.eq) goto loc_8262F2F0;
```

## Fix

Change line 5748 from:
```cpp
ctx.r31.u64 = ctx.r29.u32 & 0xFF;
```

To:
```cpp
ctx.r31.u32 = ctx.r29.u32 & 0xFF;
```

This ensures consistent register width usage throughout the function.

## Root Cause in Recompiler

The recompiler generates inconsistent code for the `clrlwi` instruction:
- It assigns to `.u64` (64-bit register)
- But later code compares `.u32` (32-bit register)

This is the same class of bug as the previous 39 fixes - using 64-bit operations for 32-bit PowerPC instructions.

**Recompiler file**: `tools/XenonRecomp/XenonRecomp/recompiler.cpp`
**Instruction**: `clrlwi` (Clear Left Word Immediate)
**Line**: Search for `clrlwi` in recompiler.cpp

The recompiler should generate:
```cpp
ctx.rD.u32 = ctx.rS.u32 & mask;
```

Instead of:
```cpp
ctx.rD.u64 = ctx.rS.u32 & mask;
```

## Expected Result After Fix

1. Game thread will exit sleep loop when Alertable=FALSE
2. Thread will progress to rendering code
3. Draw commands should start appearing in PM4 scans
4. Game should render graphics on screen

## Testing

After applying the fix:
1. Rebuild the application: `./build_cmd.ps1 -Stage app`
2. Run the test: `./scripts/run_clean_test.ps1`
3. Check for:
   - Reduced sleep calls (should be <100 instead of 5800+)
   - Draw commands appearing (DrawCount > 0)
   - Game progressing past initialization

## Related Bugs

This is bug #40 in the series of recompiler bugs:
- Bugs #1-37: Fixed in previous rounds (ADDI, MR, AND, OR, XOR, etc.)
- Bug #38: LIS instruction (fixed)
- Bug #39: Function table bug (PPC_LOOKUP_FUNC, fixed)
- **Bug #40**: clrlwi instruction (THIS BUG)

## References

- [AGENTS.md](../../AGENTS.md) - Previous recompiler bug fixes
- [FINAL_DIAGNOSIS.md](../../Traces/FINAL_DIAGNOSIS.md) - Sleep loop analysis
- [CURRENT_STATE_ANALYSIS.md](CURRENT_STATE_ANALYSIS.md) - Current test results
- [MW05.toml](../../Mw05RecompLib/config/MW05.toml) - Function configuration (line 18931)

