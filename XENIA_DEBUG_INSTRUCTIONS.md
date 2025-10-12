# Xenia Debugging Instructions

## Objective
Trace Thread #2 (entry=0x82812ED0) execution in Xenia to understand what it does and why our implementation completes immediately without doing work.

## Key Questions to Answer
1. What does Thread #2 (0x82812ED0) actually execute?
2. What kernel calls does it make?
3. Does it wait on any events or synchronization objects?
4. What triggers it to do work vs. exit immediately?
5. What happens between Thread #2 creation (line 9951) and Thread #2 execution (line 10399)?

## Files to Modify in Xenia

### 1. Thread Execution Logging
**File**: `src/xenia/kernel/xthread.cc`

**Location**: `XThread::Execute()` method

**Add logging**:
```cpp
void XThread::Execute() {
  // Add at the start of Execute()
  XELOGI("XThread::Execute START tid={} entry=0x{:08X} name='{}' suspended={}",
         thread_id_, creation_params_.start_address, thread_name_, 
         creation_params_.creation_flags & 0x1);
  
  // ... existing code ...
  
  // Add before calling guest code
  if (creation_params_.start_address == 0x82812ED0) {
    XELOGI("THREAD_82812ED0: About to call guest entry, r3=0x{:08X}", 
           thread_state_->context()->r[3]);
  }
  
  // ... existing code ...
  
  // Add after guest code returns
  if (creation_params_.start_address == 0x82812ED0) {
    XELOGI("THREAD_82812ED0: Guest entry returned, r3=0x{:08X}", 
           thread_state_->context()->r[3]);
  }
  
  XELOGI("XThread::Execute END tid={} entry=0x{:08X}", 
         thread_id_, creation_params_.start_address);
}
```

### 2. Kernel Call Logging for Thread #2
**File**: `src/xenia/cpu/processor.cc` or `src/xenia/kernel/xboxkrnl/xboxkrnl_threading.cc`

**Add logging to all kernel calls**:
```cpp
// In the kernel call dispatcher or each kernel function
if (XThread::GetCurrentThread()->thread_id() == 8) {  // Thread #2 is tid=8 in Xenia log
  XELOGI("THREAD_82812ED0: Kernel call {} args=[...]", function_name);
}
```

### 3. Specific Functions to Log

**ExCreateThread**:
```cpp
dword_result_t ExCreateThread_entry(...) {
  XELOGI("ExCreateThread: entry=0x{:08X} ctx=0x{:08X} flags=0x{:08X} caller_tid={}",
         start_address, start_context, creation_flags, 
         XThread::GetCurrentThread()->thread_id());
  // ... existing code ...
}
```

**NtResumeThread**:
```cpp
dword_result_t NtResumeThread_entry(...) {
  auto thread = kernel_state()->object_table()->LookupObject<XThread>(thread_handle);
  XELOGI("NtResumeThread: tid={} entry=0x{:08X} caller_tid={}", 
         thread->thread_id(), thread->creation_params_.start_address,
         XThread::GetCurrentThread()->thread_id());
  // ... existing code ...
}
```

**KeDelayExecutionThread**:
```cpp
void KeDelayExecutionThread_entry(...) {
  auto current_thread = XThread::GetCurrentThread();
  if (current_thread->thread_id() == 8) {
    XELOGI("THREAD_82812ED0: KeDelayExecutionThread interval={} alertable={}", 
           interval, alertable);
  }
  // ... existing code ...
}
```

**NtSetEvent / NtWaitForSingleObject**:
```cpp
// Log all event operations for Thread #2
if (XThread::GetCurrentThread()->thread_id() == 8) {
  XELOGI("THREAD_82812ED0: {} event_handle=0x{:08X}", 
         function_name, event_handle);
}
```

## Build and Run Xenia

### Build Commands
```bash
cd f:\XBox\xenia-canary
python xb.py build
```

### Run with Logging
```bash
# Run with verbose logging
xenia-canary.exe --log_level=2 "path\to\NfsMWEurope.xex" > xenia_thread2_trace.log 2>&1
```

### Alternative: Use Xenia's Built-in Tracing
```bash
# Enable kernel tracing
xenia-canary.exe --trace_kernel_calls=true "path\to\NfsMWEurope.xex"
```

## What to Look For in the Logs

### 1. Thread #2 Lifecycle
```
Line XXXX: ExCreateThread: entry=0x82812ED0 ctx=0x00120E10 flags=0x00000001 caller_tid=7
Line XXXX: XThread::Execute START tid=8 entry=0x82812ED0 suspended=true
Line XXXX: NtResumeThread: tid=8 entry=0x82812ED0 caller_tid=7
Line XXXX: THREAD_82812ED0: About to call guest entry, r3=0x00120E10
Line XXXX: THREAD_82812ED0: Kernel call KeWaitForSingleObject ...
Line XXXX: THREAD_82812ED0: Guest entry returned, r3=0x00000000
Line XXXX: XThread::Execute END tid=8 entry=0x82812ED0
```

### 2. Key Patterns to Identify
- **Does Thread #2 wait on an event?** Look for `KeWaitForSingleObject` or `NtWaitForSingleObjectEx`
- **Does it process work items?** Look for loops or repeated kernel calls
- **What's in r3 (context parameter)?** This might point to a work queue structure
- **Does it call back into game code?** Look for function calls to other game addresses

### 3. Memory Inspection
If Thread #2 uses r3 as a context pointer (0x00120E10), inspect that memory:
```cpp
// In Xenia debugger or logging
auto ctx_ptr = memory->TranslateVirtual(0x00120E10);
XELOGI("THREAD_82812ED0: Context at 0x00120E10:");
for (int i = 0; i < 64; i += 4) {
  XELOGI("  +0x{:02X}: 0x{:08X}", i, *(uint32_t*)(ctx_ptr + i));
}
```

## Comparison with Our Implementation

### Our Thread #2 Behavior
```
[MW05_FIX] Thread #2 created: entry=82812ED0 ctx=00120E10 flags=00000001 SUSPENDED
[MW05_FIX] NtResumeThread called: handle=00000001C052DBF0 tid=00006DE4
[WRAPPER_82812ED0] ENTER - wrapper is being called!
[GUEST_THREAD] Thread tid=00006DE4 entry=82812ED0 COMPLETED
```

Thread #2 completes immediately without logging any kernel calls or work.

### Expected Xenia Behavior
Based on the Xenia log pattern, Thread #2 should:
1. Start executing at line 10399 (448 lines after creation)
2. Possibly wait on events or process work items
3. Continue running (not exit immediately)

## Specific Debugging Targets

### Target 1: Why 448-line delay?
Between line 9951 (creation) and line 10399 (execution), there are 448 lines of main thread sleeping. This suggests:
- Thread #2 is created suspended
- Something resumes it after ~448 VBlank ticks
- Need to find what calls NtResumeThread for Thread #2

### Target 2: Work Queue Pattern
The context parameter (0x00120E10) might be a work queue. Check if:
- It contains function pointers to execute
- It has a state field that controls execution
- Thread #2 loops checking this structure

### Target 3: Event Synchronization
Thread #2 might wait on an event that gets signaled by:
- VBlank interrupt
- Thread #1 completing some work
- Graphics initialization completing

## Output Format

Please provide:
1. **Full trace of Thread #2** from creation to first 100 kernel calls
2. **Memory dump** of context at 0x00120E10 (first 256 bytes)
3. **Call stack** when Thread #2 calls kernel functions
4. **Comparison** with Thread #1 behavior (does it follow same pattern?)

## Alternative: Minimal Trace

If full logging is too verbose, add this minimal trace:

```cpp
// In XThread::Execute() for entry=0x82812ED0 only
static int call_count = 0;
XELOGI("THREAD_82812ED0[{}]: r3=0x{:08X} lr=0x{:08X}", 
       call_count++, context->r[3], context->lr);

// Log every 10th instruction
if (call_count % 10 == 0) {
  XELOGI("THREAD_82812ED0[{}]: pc=0x{:08X}", call_count, context->pc);
}
```

This will show the execution flow without overwhelming the log.

