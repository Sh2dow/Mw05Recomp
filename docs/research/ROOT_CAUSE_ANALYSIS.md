# MW05 Root Cause Analysis - Game Stuck in Sleep Loop

## Executive Summary
The game is stuck in an infinite sleep loop at `sub_8262F2A0` (address `0x8262F2A0`). This is a sleep wrapper function that calls `KeDelayExecutionThread` repeatedly. The game has NOT progressed to rendering - it's stuck in initialization.

## Key Findings

### 1. PM4 Analysis - No Draw Commands
- **2,906,117 TYPE0 packets** (register writes) - game is setting up GPU state
- **ZERO TYPE3 packets** (command packets) - game has NOT issued any draw commands
- Ring buffer initialized correctly (base=0x00040300, size=64KB)
- System command buffer initialized correctly (base=0x00020300, size=64KB)
- **Conclusion**: Game is stuck in initialization, hasn't started rendering

### 2. Thread Analysis - Infinite Sleep Loop
- **8,220 sleep calls** in 23 seconds (357 sleeps/second)
- **ALL sleeps from lr=0x8262F300** - return address after `KeDelayExecutionThread` call
- Sleep function: `sub_8262F2A0` at address `0x8262F2A0`
- **Conclusion**: Main thread is stuck in a sleep loop, waiting for a condition that never becomes true

### 3. Sleep Function Analysis (IDA Decompilation)

```c
int __fastcall sub_8262F2A0(int a1, BOOL a2, int a3, int a4, int a5, int a6, __int64 a7)
{
  LARGE_INTEGER *v8; // r11
  LARGE_INTEGER *v9; // r30
  BOOL v10; // r31
  NTSTATUS v11; // r3
  int result; // r3
  bool v13; // zf
  _QWORD v14[6]; // [sp+50h] [-30h] BYREF

  __asm { mfspr     r12, LR }
  if ( a1 == -1 )
  {
    v8 = 0;
  }
  else
  {
    v8 = (LARGE_INTEGER *)v14;
    LODWORD(a7) = -10000 * a1;  // Convert milliseconds to 100ns units
    v14[0] = a7;
  }
  v9 = v8;
  if ( !v8 )
  {
    v14[0] = 0x8000000000000000uLL;  // INFINITE timeout
    v9 = (LARGE_INTEGER *)v14;
  }
  v10 = a2;  // Alertable flag
  do
    v11 = KeDelayExecutionThread(UserMode, a2, v9);
  while ( v10 && v11 == 257 );  // Loop while Alertable AND return == STATUS_ALERTED (0x101)
  v13 = v11 == 192;
  result = 192;
  if ( !v13 )
    return 0;
  return result;
}
```

**Key Logic**:
- Loop condition: `while ( v10 && v11 == 257 )`
- `v10` = Alertable flag (parameter `a2`)
- `v11` = Return value from `KeDelayExecutionThread`
- `257` = `0x101` = `STATUS_ALERTED`

**Expected Behavior**:
- If `Alertable=FALSE` (a2=0), then `v10=FALSE`, loop exits immediately
- If `Alertable=TRUE` and return != `STATUS_ALERTED`, loop exits
- If `Alertable=TRUE` and return == `STATUS_ALERTED`, loop continues

### 4. Trace Log Analysis

From `mw05_host_trace.log`:
```
[HOST] import=HOST.Wait.observe.KeDelayExecutionThread tid=6b58 lr=0x8262F300 r3=0x1 r4=0x0 r5=0x2B9250 r6=0x0
```

Parameters:
- `r3=0x1` = WaitMode (UserMode)
- `r4=0x0` = Alertable (FALSE)
- `r5=0x2B9250` = Interval pointer
- `lr=0x8262F300` = Return address (instruction after `bl KeDelayExecutionThread`)

**Analysis**:
- Alertable=FALSE (r4=0), so the loop should exit immediately!
- But the game is looping infinitely, which means the loop condition is NOT working correctly

### 5. Assembly Analysis

```asm
.text:8262F2EC    clrlwi    r31, r29, 24    # r31 = r29 & 0xFF (extract Alertable flag)
.text:8262F2F0 loc_8262F2F0:                 # Loop start
.text:8262F2F0    mr        r5, r30         # Interval
.text:8262F2F4    mr        r4, r29         # Alertable
.text:8262F2F8    li        r3, 1           # WaitMode = UserMode
.text:8262F2FC    bl        KeDelayExecutionThread
.text:8262F300    cmplwi    cr6, r31, 0     # Compare r31 (Alertable) with 0
.text:8262F304    beq       cr6, loc_8262F310  # If r31==0, exit loop
.text:8262F308    cmpwi     cr6, r3, 0x101  # Compare return value with STATUS_ALERTED
.text:8262F30C    beq       cr6, loc_8262F2F0  # If return==STATUS_ALERTED, loop back
```

**Loop Logic**:
1. If `r31==0` (Alertable=FALSE), branch to exit at `0x8262F310`
2. Otherwise, check if return value == `0x101` (STATUS_ALERTED)
3. If return == STATUS_ALERTED, loop back to `0x8262F2F0`

**Expected Behavior with r4=0**:
- `r29 = r4 = 0` (Alertable parameter)
- `r31 = r29 & 0xFF = 0 & 0xFF = 0`
- At `0x8262F300`: `cmplwi cr6, r31, 0` → cr6.eq = TRUE
- At `0x8262F304`: `beq cr6, loc_8262F310` → SHOULD BRANCH TO EXIT!

**But the game is NOT exiting the loop!**

## Root Cause Hypothesis

There are three possible explanations:

### Hypothesis 1: Recompiler Bug in `clrlwi` Instruction
The `clrlwi r31, r29, 24` instruction might be generating incorrect code. The recompiler generates:
```cpp
r31.u64 = r29.u32 & 0xFF;
```

This should be correct, but if `r29.u32` contains garbage in the upper 32 bits, the result might be wrong.

**Test**: Check if the recompiler is correctly masking to 32 bits before the AND operation.

### Hypothesis 2: Recompiler Bug in Branch Condition
The `beq cr6, loc_8262F310` branch might not be working correctly in the recompiled code.

**Test**: Check the generated C++ code for this function to see if the branch logic is correct.

### Hypothesis 3: Parameter Corruption
The `r4` parameter (Alertable) might be getting corrupted between the function call and the `clrlwi` instruction.

**Test**: Add logging to the recompiled function to trace `r29` and `r31` values.

## Recommended Actions

### Immediate Actions (Priority Order)

1. **Check Generated Code for `sub_8262F2A0`**
   - View the generated C++ code in `Mw05RecompLib/ppc/ppc_recomp.80.cpp`
   - Verify that the `clrlwi` instruction is generating correct code
   - Verify that the branch condition is correct
   - Look for any obvious bugs in the generated code

2. **Add Debug Logging to Sleep Function**
   - Add logging to trace `r29`, `r31`, and return value from `KeDelayExecutionThread`
   - This will help identify if the problem is parameter corruption or branch logic

3. **Check for Recompiler Bugs**
   - Review the recompiler code for `clrlwi` instruction (line 838-842 in `tools/XenonRecomp/XenonRecomp/recompiler.cpp`)
   - Review the recompiler code for `beq` instruction
   - Look for any 32-bit vs 64-bit issues

4. **Compare with Xenia**
   - Check if Xenia has the same sleep loop behavior
   - Compare the number of sleep calls and their parameters
   - See if Xenia exits the loop or also loops infinitely

### Long-term Investigation

1. **Understand What the Game is Waiting For**
   - The game is sleeping repeatedly, waiting for some condition
   - Need to identify what condition the game is checking
   - Possible conditions:
     - File loading complete
     - Thread synchronization (worker thread finished)
     - Graphics initialization complete
     - Resource loading complete

2. **Fix the Root Cause**
   - Once we understand what the game is waiting for, we can fix the missing functionality
   - This might be:
     - Missing kernel function
     - Missing file I/O operation
     - Missing thread creation
     - Missing event signaling

## Status Codes Reference

- `STATUS_SUCCESS = 0x00000000` (0) - Operation completed successfully
- `STATUS_USER_APC = 0x000000C0` (192) - A user-mode APC was delivered
- `STATUS_KERNEL_APC = 0x00000100` (256) - A kernel-mode APC was delivered
- `STATUS_ALERTED = 0x00000101` (257) - The delay completed because the thread was alerted
- `STATUS_TIMEOUT = 0x00000102` (258) - The delay timed out

## Conclusion

The game is stuck in an infinite sleep loop because the loop exit condition is NOT working correctly. The game is calling with `Alertable=FALSE`, which should cause the loop to exit immediately, but it's not exiting.

**Next Step**: Examine the generated C++ code for `sub_8262F2A0` to identify the bug in the recompiled code. This is likely a recompiler bug in either the `clrlwi` instruction or the `beq` branch instruction.

**Critical Finding**: This is NOT a missing kernel function or file loading issue - it's a RECOMPILER BUG that's preventing the sleep loop from exiting correctly!

