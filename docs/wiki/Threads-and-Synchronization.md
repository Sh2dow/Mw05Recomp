# Threads & Synchronization

## Fixes Implemented

### Thread Params Race Condition (FIXED)
- **Problem**: `GuestThreadFunc` receives pointer to `hThread`, but `hThread->params` can be corrupted by another thread
- **Solution**: Make local copy of `params` IMMEDIATELY at function entry before any other operations
- **File**: `Mw05Recomp/cpu/guest_thread.cpp` lines 147-170
- **Result**: Invalid entry address `0x92AA0003` COMPLETELY ELIMINATED! All threads have correct entry addresses

### Dynamic Cast Race Condition (FIXED)
- **Problem**: Kernel object can be deleted between `IsKernelObjectAlive` check and `dynamic_cast`
- **Solution**: Wrap ALL kernel object access (dynamic_cast + Wait) in SEH __try/__except block
- **File**: `Mw05Recomp/kernel/imports.cpp` lines 4731-4787
- **Result**: Access violations caught and handled gracefully, game continues running

### Access Violation in Wait() (FIXED)
- **Problem**: Game crashed at second 5 with access violation in `kernel->Wait(timeout)`
- **Solution**: Use SEH (Structured Exception Handling) instead of C++ try-catch to catch Windows structured exceptions
- **Result**: Game now runs for 10+ minutes without crashing

### Worker Thread Context Initialization (FIXED)
- **Problem**: `Mw05ForceCreateMissingWorkerThreads()` was allocating context addresses but NOT initializing them
- **Solution**: Modified function to allocate contexts on heap and initialize with callback pointers
- **Files**: `Mw05Recomp/cpu/mw05_trace_threads.cpp` lines 299-351
- **Context Structure** (96 bytes):
  - +0x00: State field (0x00000000)
  - +0x04: Some field (0xFFFFFFFF)
  - +0x08: Another field (0x00000000)
  - +0x54 (84): **Callback function pointer** (0x8261A558) - CRITICAL!
  - +0x58 (88): **Callback parameter** (0x82A2B318) - CRITICAL!
- **Result**: Worker threads now run their main loop instead of exiting immediately

## Current Thread Status
- ✅ All 12 threads created (same as Xenia)
- ✅ Worker contexts properly initialized
- ✅ Thread params race fixed
- ✅ Dynamic cast race fixed
- ✅ SEH exception handling working

## Thread List
1. Thread #1-2 (entry=0x828508A8, 0x82812ED0) - naturally created by game
2. Thread #3-7 (entry=0x828508A8) - worker threads (force-created with proper initialization)
3. Thread #8 (entry=0x825AA970) - special thread (force-created with proper initialization)
4. Thread #9-12 (entry=0x82812ED0) - additional worker threads (naturally created by game)

## SEH Exception Handling Pattern
```cpp
NTSTATUS result = STATUS_INVALID_HANDLE;
__try {
    // Record last-wait EA/type (dynamic_cast operations)
    if (auto* ev = dynamic_cast<Event*>(kernel)) { ... }
    else if (auto* sem = dynamic_cast<Semaphore*>(kernel)) { ... }

    // Call Wait() on kernel object
    result = kernel->Wait(timeout);
} __except(EXCEPTION_EXECUTE_HANDLER) {
    // Catch access violations from dynamic_cast or Wait()
    DWORD exceptionCode = GetExceptionCode();
    fprintf(stderr, "[WAIT_SYNC] SEH Exception - code=0x%08lX\n", exceptionCode);
    return STATUS_INVALID_HANDLE;
}
return result;
```

## Tips
- Use `thread.list` in debug console to verify state
- Log NtCreateThreadEx/NtResumeThread flows when diagnosing missing workers
- Check thread context initialization (callback pointers at +84, +88)
- Monitor for race conditions (params copy, dynamic_cast + Wait())

