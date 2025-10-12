# Thread #2 Root Cause Analysis

## Executive Summary

**Problem**: Thread #2 (entry=0x82812ED0) completes immediately without doing any work, while in Xenia it waits on an Event in a loop (7,132 calls to NtWaitForSingleObjectEx).

**Root Cause**: The context structure passed to Thread #2 contains garbage data. Thread #1 is not properly initializing the structure before creating Thread #2.

**Impact**: Thread #2 cannot execute its worker function, blocking game initialization and preventing draw commands from being issued.

---

## Technical Analysis

### Function `sub_82812ED0` - The Trampoline

**Assembly Code**:
```assembly
.text:82812ED0 sub_82812ED0:
.text:82812ED0                 mflr      r12                    # Save link register
.text:82812ED4                 stw       r12, -8(r1)           # Store LR on stack
.text:82812ED8                 stwu      r1, -0x70(r1)         # Allocate stack frame (112 bytes)
.text:82812EDC                 mr        r11, r3               # r11 = r3 (context parameter)
.text:82812EE0                 li        r9, 1                 # r9 = 1
.text:82812EE4                 lwz       r8, 0(r11)            # r8 = *(r11 + 0)  - load state field
.text:82812EE8                 lwz       r10, 4(r11)           # r10 = *(r11 + 4) - load FUNCTION POINTER
.text:82812EEC                 lwz       r3, 8(r11)            # r3 = *(r11 + 8)  - load context for call
.text:82812EF0                 stw       r9, 0(r11)            # *(r11 + 0) = 1   - set state to 1
.text:82812EF4                 stw       r8, 0x50(r1)          # Save original state on stack
.text:82812EF8                 mtctr     r10                   # CTR = r10 (function pointer)
.text:82812EFC                 bctrl                           # Call function at CTR
.text:82812F00                 addi      r1, r1, 0x70          # Restore stack
.text:82812F04                 lwz       r12, -8(r1)           # Restore LR
.text:82812F08                 mtlr      r12
.text:82812F0C                 blr                             # Return
```

**Function Behavior**:
1. Takes a context structure pointer in r3
2. Loads a function pointer from offset +4 of the structure
3. Loads a context parameter from offset +8
4. Sets the state field at offset +0 to 1
5. Calls the function pointer with the context parameter
6. Returns

**Context Structure**:
```c
struct ThreadContext {
    uint32_t state;        // offset +0x00 - set to 1 before calling
    uint32_t function_ptr; // offset +0x04 - function to call
    uint32_t context;      // offset +0x08 - parameter to pass to function
};
```

---

## Memory Dump Analysis

### Our Implementation (BROKEN)

**Thread #2 created with**: `ctx=0x00120E10`

**Memory at 0x00120E10**:
```
+0x00 (state):    0x00000000  ✓ OK (will be set to 1 by function)
+0x04 (func_ptr): 0xE0348182  ✗ GARBAGE! Not a valid function pointer!
+0x08 (context):  0x00000000  ✓ OK (NULL is valid)
```

**Result**: Function tries to call 0xE0348182, which is invalid, causing crash or immediate return.

### Xenia (WORKING)

**Thread #2 created with**: `ctx=0x701EFAF0`

**Expected Memory at 0x701EFAF0** (not logged, but inferred):
```
+0x00 (state):    0x00000000  (or some initial value)
+0x04 (func_ptr): 0x82XXXXXX  (valid game function address)
+0x08 (context):  0xF8000014  (Event handle to wait on)
```

**Result**: Function calls the valid function pointer, which waits on Event F8000014 in a loop.

---

## Execution Flow Comparison

### Xenia (Working)

1. **Line 9343**: Thread #1 creates Event F8000014 (via KeInitializeEvent)
2. **Line 9535**: Thread #1 creates Thread #2 with ctx=0x701EFAF0
   - Context structure at 0x701EFAF0 is already initialized with:
     - function_ptr = address of worker function
     - context = 0xF8000014 (Event handle)
3. **Line 9968**: Thread #1 calls NtResumeThread to resume Thread #2
4. **Line 10071**: Thread #2 starts executing
5. **Line 16411**: Thread #2 calls guest entry (sub_82812ED0)
   - r3=0x00000000 (logged, but might be incorrect - see note below)
6. **Line 16874**: Thread #2 calls NtWaitForSingleObjectEx on F8000014
7. **Lines 16874-214993**: Thread #2 waits on Event in loop (7,132 calls)

**Note**: The Xenia log shows r3=0x00000000 at line 16411, but the function clearly dereferences r3 to load the function pointer. This suggests either:
- The logging is incorrect
- Xenia has special handling for NULL dereferences
- The context is passed differently than logged

### Our Implementation (Broken)

1. **No Event creation**: Thread #1 never creates Event F8000014
2. **Thread #2 created**: Thread #1 creates Thread #2 with ctx=0x00120E10
   - Context structure at 0x00120E10 contains GARBAGE:
     - function_ptr = 0xE0348182 (invalid!)
     - context = 0x00000000
3. **Thread #2 resumed**: NtResumeThread called
4. **Thread #2 executes**: Wrapper called with r3=0x00120E10
5. **Function loads garbage**: Loads 0xE0348182 from offset +4
6. **Function crashes or returns**: Tries to call invalid address
7. **Thread #2 completes**: Returns immediately without doing work

---

## Root Cause

**Thread #1 (entry=0x828508A8) is not initializing the context structure before creating Thread #2.**

In Xenia, Thread #1 must be executing code that:
1. Allocates memory for the context structure (0x701EFAF0)
2. Initializes the structure with:
   - function_ptr = address of worker function (probably waits on event)
   - context = Event handle (F8000014)
3. Creates Thread #2 with pointer to this initialized structure

In our implementation, Thread #1 is either:
- Not executing this initialization code
- Executing it but writing to the wrong address
- The recompiled code is buggy and not initializing properly

---

## Investigation Steps

### Step 1: Find Where Context is Allocated

Search Thread #1's execution for memory allocation around 0x00120E10:
- Check if MmAllocatePhysicalMemoryEx is called with size matching the structure
- Check if the allocation returns address 0x00120E10

### Step 2: Find Where Context is Initialized

Search for stores to addresses 0x00120E10, 0x00120E14, 0x00120E18:
- 0x00120E10 + 0 = state field
- 0x00120E10 + 4 = function_ptr field (should be set to valid address)
- 0x00120E10 + 8 = context field (should be set to Event handle)

### Step 3: Compare with Xenia

In Xenia, search for:
- Allocation of 0x701EFAF0
- Stores to 0x701EFAF0, 0x701EFAF4, 0x701EFAF8
- What function address is stored at +4
- What Event handle is stored at +8

### Step 4: Check Thread #1 Execution

Verify Thread #1 is executing the same code path as in Xenia:
- Add logging to Thread #1 wrapper (sub_828508A8)
- Log all function calls made by Thread #1
- Compare with Xenia's Thread #1 execution

---

## Potential Fixes

### Option 1: Find and Fix Missing Initialization

1. Identify where Thread #1 should initialize the context
2. Check if the recompiled code is correct
3. Fix any bugs in the recompilation or kernel functions

### Option 2: Manual Initialization (Workaround)

Add code to initialize the context structure before Thread #2 starts:
```cpp
// In Thread #1 wrapper or before ExCreateThread
uint32_t* ctx = (uint32_t*)(base + 0x00120E10);
ctx[0] = 0;                    // state
ctx[1] = 0x82XXXXXX;           // function_ptr (find correct address)
ctx[2] = event_handle;         // context (Event handle)
```

### Option 3: Implement Missing Kernel Function

If the initialization is done via a kernel function we haven't implemented:
1. Find which kernel function initializes worker thread contexts
2. Implement it properly
3. Ensure it's called by Thread #1

---

## Next Steps

1. **Add logging to Thread #1**: Log all memory stores to see if context is being initialized
2. **Check Xenia log**: Search for stores to 0x701EFAF0 to find initialization code
3. **Disassemble Thread #1**: Look at sub_828508A8 assembly to find context initialization
4. **Test with manual initialization**: Try workaround to verify hypothesis

---

## Files Modified

- `Mw05Recomp/cpu/mw05_trace_threads.cpp`: Added context structure dump logging
- `Mw05Recomp/kernel/imports.cpp`: Added NtCreateEvent and NtWaitForSingleObjectEx logging
- `AGENTS.md`: Updated status with root cause findings
- `XENIA_DEBUG_INSTRUCTIONS.md`: Instructions for deeper Xenia debugging
- `analyze_thread2_xenia.py`: Python script to analyze Xenia log

---

## Key Insights

1. **sub_82812ED0 is a trampoline**, not the actual worker function
2. **The real worker function is stored in the context structure** at offset +4
3. **The context structure is not being initialized** in our implementation
4. **Thread #1 is responsible for initialization**, but it's not doing it
5. **Event F8000014 is created via KeInitializeEvent**, not NtCreateEvent (no kernel call logged)

---

## Questions to Answer

1. Where does Thread #1 allocate the context structure?
2. Where does Thread #1 initialize the function pointer at offset +4?
3. What is the actual worker function address that should be stored?
4. How is Event F8000014 created if there's no NtCreateEvent call?
5. Why does Xenia log r3=0 but the function clearly dereferences it?

