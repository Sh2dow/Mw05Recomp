# CRITICAL FINDINGS: VdInitializeEngines Not Being Called

## Summary
The game never calls the graphics initialization function `sub_825A85E0`, which is responsible for calling `VdInitializeEngines` with the correct callback (`0x825A85C8`). This prevents the graphics system from being initialized, resulting in a black screen.

## Evidence

### 1. Xenia (Working) Shows Correct Call
```
VdInitializeEngines unk0=0x08570000 cb=0x825A85C8 arg=0x00000000 pfp_ptr=0x00000000 me_ptr=0x00000000 lr=0x825A8610
```

### 2. Our Implementation Shows Wrong Parameters
```
[HOST] import=HOST.VdInitializeEngines.CALL#1 cb=00000000 arg1=00000000 arg2=00000000 arg3=00000000 arg4=00000000 tid=1a64 lr=0x8262F300
```

The call from `lr=0x8262F300` is NOT the graphics initialization call. The REAL call should come from `lr=0x825A8610`.

### 3. Address Space Analysis
- `0x7FEA17B0` is NOT in MW05 XEX address space (starts at `0x82000600`)
- The correct callback address is `0x825A85C8` (confirmed by IDA disassembly)
- Our trace was showing wrong parameters because we were capturing a DIFFERENT call

### 4. Call Chain Analysis (from IDA + recompiled code)

**Expected Call Chain:**
```
sub_825A16A0 (0x825A16A0)
  └─> sub_825A8698 (0x825A8698) @ line 31445 in ppc_recomp.72.cpp
      └─> sub_825A85E0 (0x825A85E0) @ line 54666 in ppc_recomp.72.cpp
          └─> VdInitializeEngines @ line 54489 in ppc_recomp.72.cpp
              Parameters set up:
              - r3 = 0x08570000 (unk0) @ line 54486
              - r4 = 0x825A85C8 (callback) @ line 54484
              - r5 = 0 (arg) @ line 54482
              - r6 = 0 (pfp_ptr) @ line 54480
              - r7 = 0 (me_ptr) @ line 54478
```

**Actual Execution:**
- `sub_825A16A0`: NEVER CALLED (not in trace log)
- `sub_825A8698`: NEVER CALLED (not in trace log)
- `sub_825A85E0`: NEVER CALLED (not in trace log)
- `VdInitializeEngines`: Called ONCE from `lr=0x8262F300` with all parameters = 0

### 5. IDA Disassembly of sub_825A85E0
```asm
.text:825A85E0 sub_825A85E0:
.text:825A85E0                 mflr      r12
.text:825A85E4                 stw       r12, var_8(r1)
.text:825A85E8                 std       r31, var_10(r1)
.text:825A85EC                 stwu      r1, back_chain(r1)
.text:825A85F0                 lis       r11, loc_825A85C8@ha
.text:825A85F4                 mr        r31, r3
.text:825A85F8                 li        r7, 0
.text:825A85FC                 li        r6, 0
.text:825A8600                 li        r5, 0
.text:825A8604                 addi      r4, r11, loc_825A85C8@l    # r4 = callback = 0x825A85C8
.text:825A8608                 lis       r3, 0x857                  # r3 = 0x08570000
.text:825A860C                 bl        VdInitializeEngines
.text:825A8610                 bl        KeGetCurrentProcessType
.text:825A8614                 lis       r11, sub_825979A8@ha
.text:825A8618                 mr        r4, r31
.text:825A861C                 addi      r3, r11, sub_825979A8@l
.text:825A8620                 bl        VdSetGraphicsInterruptCallback
```

## Root Cause

**The game is stuck in an earlier phase and never reaches the graphics initialization code.**

The function `sub_825A16A0` is never being called, which means the entire graphics initialization chain is blocked. This could be because:

1. The game is waiting for some condition that's never satisfied
2. There's a missing thread or initialization sequence
3. A critical function earlier in the boot sequence is failing or looping
4. The game is stuck in a different code path that doesn't lead to graphics init

## Next Steps

### Option 1: Find What Should Call sub_825A16A0
Search for what calls `sub_825A16A0` and trace backwards to find where the execution diverges from Xenia.

### Option 2: Force Call to sub_825A85E0
Manually call `sub_825A85E0` from a boot shim or VBLANK handler to bypass the missing call chain.

### Option 3: Deeper Xenia Tracing
Implement detailed tracing in Xenia to capture:
- When `sub_825A16A0` is called
- What triggers the call to `sub_825A16A0`
- The full call stack leading to `VdInitializeEngines`
- Thread IDs and timing of these calls

## Xenia Tracing Instructions

To implement deeper tracing in Xenia Canary (at `f:\XBox\xenia-canary\`):

### 1. Add Function Entry Logging

Edit `src/xenia/cpu/ppc/ppc_emit_control.cc` to add logging for specific function addresses:

```cpp
// In EmitBranchTo or EmitCall function
if (target_address == 0x825A16A0 || 
    target_address == 0x825A8698 || 
    target_address == 0x825A85E0) {
  XELOGD("[MW05-TRACE] Calling function 0x{:08X} from lr=0x{:08X} tid={:X}", 
         target_address, lr_value, current_thread_id);
}
```

### 2. Add VdInitializeEngines Parameter Logging

Edit `src/xenia/kernel/xboxkrnl/xboxkrnl_video.cc`:

```cpp
dword_result_t VdInitializeEngines_entry(
    dword_t unk0, lpvoid_t callback, lpvoid_t arg,
    lpvoid_t pfp_ptr, lpvoid_t me_ptr) {
  
  auto lr = kernel_state()->processor()->GetLR();
  auto tid = XThread::GetCurrentThreadId();
  
  XELOGD("[MW05-VDINIT] unk0=0x{:08X} cb=0x{:08X} arg=0x{:08X} pfp=0x{:08X} me=0x{:08X} lr=0x{:08X} tid={:X}",
         unk0, callback.guest_address(), arg.guest_address(),
         pfp_ptr.guest_address(), me_ptr.guest_address(), lr, tid);
  
  // Dump call stack
  auto stack_walker = kernel_state()->processor()->GetStackWalker();
  XELOGD("[MW05-VDINIT] Call stack:");
  for (int i = 0; i < 10; i++) {
    uint32_t return_addr = stack_walker->GetReturnAddress(i);
    if (return_addr == 0) break;
    XELOGD("  [%d] 0x%08X", i, return_addr);
  }
  
  // ... rest of function
}
```

### 3. Add Thread Creation Logging

Edit `src/xenia/kernel/xthread.cc`:

```cpp
// In XThread::Create or XThread::Run
XELOGD("[MW05-THREAD] Thread created: tid={:X} entry=0x{:08X} name='{}'",
       thread_id, creation_params.entry_point, name);
```

### 4. Build and Run Xenia

```powershell
cd f:\XBox\xenia-canary
python xb build
xenia-canary.exe --log_level=2 "path\to\NfsMWEurope.xex" > mw05_detailed_trace.log 2>&1
```

### 5. Analyze the Trace

Look for:
- When `sub_825A16A0` is first called
- What thread calls it
- The call stack leading to it
- Any patterns or conditions that trigger the call

### 6. Compare with Our Implementation

Once you have the Xenia trace showing when/how `sub_825A16A0` is called, compare with our trace log to find where the execution diverges.

## NEW CRITICAL DISCOVERY (from updated Xenia log)

### Thread 7 Analysis

Xenia shows that `VdInitializeEngines` is called on **thread 7** with entry point `0x828508A8`:
```
i> F8000008 [MW05-THREAD] Thread created: tid=7 entry=0x828508A8 name='XThread6008 (F800000C)' suspended=true
i> F800000C [MW05-VDINIT] unk0=0x08570000 cb=0x825A85C8 arg=0x00000000 pfp_ptr=0x00000000 me_ptr=0x00000000 lr=0x825A8610 tid=7
```

### Our Implementation Has These Threads

We DO create threads with entry point `0x828508A8`:
- `hostTid=00001A64` (created by tid=6730)
- `hostTid=000038E8` (created by tid=6ee8)
- And more...

### The Problem: Threads Are Sleeping

Thread `1a64` (and presumably others) are stuck in a sleep loop:
- Last activity: `__imp__KeDelayExecutionThread tid=1a64 lr=0x8262F300`
- They NEVER call `sub_823AF590` (the function that leads to graphics init)
- They're waiting for something that never happens

### What Should Happen (from Xenia)

In Xenia, thread 7:
1. Wakes up from sleep
2. Calls `sub_823AF590`
3. Which calls `sub_82216088`
4. Which eventually leads to `sub_825A16A0` → `sub_825A8698` → `sub_825A85E0` → `VdInitializeEngines`

### What's Missing

The threads with entry `0x828508A8` are waiting for an event or condition that never occurs in our implementation. Possible causes:
1. Missing event signaling (KeSetEvent)
2. Missing VBLANK or interrupt handling
3. Missing synchronization primitive
4. Incorrect thread scheduling or priority

### Next Investigation Steps

1. **Find what wakes up thread 7 in Xenia**: Look for `KeSetEvent` or other synchronization calls before the `VdInitializeEngines` call
2. **Compare thread states**: Check if our threads are waiting on the same events as Xenia's thread 7
3. **Check VBLANK handling**: The Xenia log shows `VD notify` calls - these might be what triggers the thread to wake up
4. **Force thread wake-up**: Try manually signaling the event that thread `1a64` is waiting on

## FINAL ROOT CAUSE ANALYSIS

### The Complete Picture

1. **Xenia (Working)**:
   - Thread 7 (entry `0x828508A8`) calls `KeWaitForSingleObject` on event `0x400007E0`
   - Event is signaled repeatedly by `KeSetEvent` calls
   - Thread wakes up and calls `sub_823AF590` → `sub_82216088` → ... → `VdInitializeEngines`
   - `VdInitializeEngines` is called with callback `0x825A85C8` (correct!)

2. **Our Implementation (Broken)**:
   - Threads with entry `0x828508A8` (e.g., `tid=1a64`) are created successfully
   - But they get stuck in `sub_8262F2A0` calling `KeDelayExecutionThread` in a loop
   - They NEVER call `KeWaitForSingleObject` on event `0x400007E0`
   - They NEVER wake up and progress to `sub_823AF590`
   - Therefore, `VdInitializeEngines` is never called with the correct callback

3. **Why the Threads Are in the Wrong Code Path**:
   - The threads are stuck in a sleep loop at `loc_8262F2F0` (line 5117 in `ppc_recomp.80.cpp`)
   - The loop checks `r31` - if it's 0, it exits; otherwise it keeps sleeping
   - In Xenia, `r31` must be getting set to 0 somehow, allowing the thread to exit the loop
   - In our implementation, `r31` stays non-zero, so the thread sleeps forever

4. **What Sets r31 to 0?**:
   - This is the missing piece - we need to find what modifies `r31` in the sleeping thread's context
   - Possible causes:
     - Another thread writing to the sleeping thread's stack
     - A signal/interrupt handler modifying the register
     - A memory-mapped I/O operation
     - A kernel function that modifies thread state

### Attempted Workarounds (All Failed)

1. **Force call to `sub_823AF590` from VBLANK handler**: Blocks/crashes
2. **Force call from thread `828508A8` wrapper**: Thread never returns from `__imp__sub_828508A8`
3. **Manual `VdInitializeEngines` calls**: Wrong parameters (callbacks not initialized yet)

### Next Steps to Fix

**IMMEDIATE ACTION REQUIRED**: Use Xenia debugger to find what wakes up the sleeping threads

1. **Set breakpoint in Xenia at `0x8262F2F0`** (the sleep loop in `sub_8262F2A0`):
   ```
   bp 0x8262F2F0
   ```

2. **When breakpoint hits, check r31 value**:
   - If r31 != 0, the thread will keep sleeping
   - Continue execution and watch when r31 becomes 0

3. **Find what sets r31 to 0**:
   - Option A: Set memory watchpoint on the stack location where r31 is stored
   - Option B: Step through the code and watch r31 change
   - Option C: Add logging to `sub_8262F2A0` to print r31 value each iteration

4. **Once you find what sets r31 to 0**:
   - Check if it's another thread writing to memory
   - Check if it's a signal/interrupt handler
   - Check if it's a kernel function modifying thread state
   - Implement the same mechanism in our code

5. **Alternative: Force threads to skip sleep loop**:
   - Create PPC function override for `sub_8262F2A0`
   - Force r4 parameter to 0 (which becomes r31)
   - This will make threads exit sleep loop immediately
   - **NOTE**: Attempted this but hit linker issues with weak symbols on Windows
   - Need to investigate why `PPC_FUNC` overrides don't work for recompiled functions

6. **Alternative: Signal event `0x400007E0` from VBLANK**:
   - Call `KeSetEvent(0x400007E0, 0, false)` from VBLANK handler
   - This should wake up threads waiting on the event
   - **NOTE**: Attempted this but hit build issues
   - Need to fix `KeSetEvent` call syntax

