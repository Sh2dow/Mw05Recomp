# Action Plan: Fix Thread Context Issues

## Priority 1: Verify Current Behavior

### Step 1: Add Logging to Track Context Address

Add logging in `Mw05Recomp/kernel/imports.cpp` in the `ExCreateThread` function to see what context address is actually being used:

```cpp
uint32_t ExCreateThread(be<uint32_t>* handle, uint32_t stackSize, be<uint32_t>* threadId, uint32_t xApiThreadStartup, uint32_t startAddress, uint32_t startContext, uint32_t creationFlags)
{
    // ... existing code ...
    
    fprintf(stderr, "[CONTEXT-DEBUG] ExCreateThread: entry=0x%08X ctx=0x%08X\n", startAddress, startContext);
    
    // For Thread #2 (entry=0x82812ED0), verify the context address
    if (startAddress == 0x82812ED0) {
        fprintf(stderr, "[CONTEXT-DEBUG] Thread #2 context address: 0x%08X\n", startContext);
        fprintf(stderr, "[CONTEXT-DEBUG] Expected address: 0x828F1F98\n");
        
        if (startContext == 0x828F1F98) {
            fprintf(stderr, "[CONTEXT-DEBUG] ✅ Context address is CORRECT (static global)\n");
        } else if (startContext == 0x00120E10) {
            fprintf(stderr, "[CONTEXT-DEBUG] ❌ Context address is WRONG (old bug address)\n");
        } else if ((startContext >= 0x70000000) && (startContext < 0x80000000)) {
            fprintf(stderr, "[CONTEXT-DEBUG] ⚠️ Context address is on HEAP (Xenia-style)\n");
        } else {
            fprintf(stderr, "[CONTEXT-DEBUG] ⚠️ Context address is UNKNOWN location\n");
        }
    }
    
    // ... rest of function ...
}
```

### Step 2: Verify Memory Accessibility

Add a check to ensure the memory at 0x828F1F98 is accessible:

```cpp
// In main.cpp or memory initialization
void VerifyContextMemory() {
    const uint32_t ctx_addr = 0x828F1F98;
    void* ctx_ptr = g_memory.Translate(ctx_addr);
    
    if (ctx_ptr == nullptr) {
        fprintf(stderr, "[MEMORY-ERROR] Context at 0x%08X is NOT MAPPED!\n", ctx_addr);
        fprintf(stderr, "[MEMORY-ERROR] This is a CRITICAL ERROR - .data section not loaded!\n");
    } else {
        fprintf(stderr, "[MEMORY-OK] Context at 0x%08X is mapped to host %p\n", ctx_addr, ctx_ptr);
        
        // Try to read/write to verify accessibility
        uint64_t* qword_ptr = (uint64_t*)ctx_ptr;
        uint64_t test_value = __builtin_bswap64(*qword_ptr);
        fprintf(stderr, "[MEMORY-OK] Current value at qword_828F1F98: 0x%016llX\n", test_value);
    }
}
```

## Priority 2: Fix Any Bugs

### If Context Address is Wrong (0x00120E10 or other)

This indicates a bug in how the recompiled code calculates the address. Possible causes:

1. **Incorrect register calculation**: Check if the `lis` and `addi` instructions are being recompiled correctly
2. **Memory mapping issue**: The .data section might not be loaded at the correct address
3. **Endianness issue**: The address calculation might have byte-swapping errors

### If Context Address is Correct (0x828F1F98)

Then the issue is NOT about heap vs static, but about:

1. **Initialization**: The context structure at 0x828F1F98 is not being initialized properly
2. **Corruption**: Something is overwriting the context after initialization
3. **Timing**: The context is being used before it's initialized

## Priority 3: Ensure Proper Initialization

### Check sub_82813598 Execution

This function initializes qword_828F1F98. Verify it's being called and working correctly:

```cpp
// In mw05_trace_threads.cpp, sub_82813598 wrapper
void sub_82813598(PPCContext& ctx, uint8_t* base) {
    const uint32_t qword_addr = 0x828F1F98;
    void* qword_host = g_memory.Translate(qword_addr);
    
    if (qword_host) {
        uint64_t* qword_ptr = (uint64_t*)qword_host;
        uint64_t value_before = __builtin_bswap64(*qword_ptr);
        fprintf(stderr, "[INIT-DEBUG] BEFORE sub_82813598: qword_828F1F98 = 0x%016llX\n", value_before);
    }
    
    SetPPCContext(ctx);
    __imp__sub_82813598(ctx, base);
    
    if (qword_host) {
        uint64_t* qword_ptr = (uint64_t*)qword_host;
        uint64_t value_after = __builtin_bswap64(*qword_ptr);
        fprintf(stderr, "[INIT-DEBUG] AFTER sub_82813598: qword_828F1F98 = 0x%016llX\n", value_after);
        
        if (value_after == 0) {
            fprintf(stderr, "[INIT-ERROR] qword_828F1F98 is still 0! Initialization FAILED!\n");
        } else {
            fprintf(stderr, "[INIT-OK] qword_828F1F98 initialized to 0x%016llX\n", value_after);
        }
    }
}
```

## Priority 4: Compare with Xenia

### Extract Xenia's Memory Layout

From the Xenia log, we know:
- Thread #2 context in Xenia: 0x701EFAF0
- This is in the heap/stack region (0x70000000 range)

But the PPC code says it should be at 0x828F1F98 (static global).

**Question**: Does Xenia TRANSLATE 0x828F1F98 to 0x701EFAF0?

To verify, check Xenia's memory translation:
1. Look at Xenia's memory mapping code
2. See if it redirects .data section accesses to heap
3. Understand why Xenia uses heap instead of static

### Hypothesis

Xenia might be:
1. **Allocating a shadow copy**: The .data section is copied to heap for thread safety
2. **Using virtual memory**: The address 0x828F1F98 is mapped to heap via page tables
3. **Intercepting accesses**: Memory reads/writes to 0x828F1F98 are redirected to heap

## Priority 5: Test and Verify

### Test Plan

1. **Build with logging**: Add all the debug logging above
2. **Run the game**: Execute and capture logs
3. **Verify context address**: Check if it's 0x828F1F98 or something else
4. **Check initialization**: Verify qword_828F1F98 is set correctly
5. **Monitor for corruption**: Watch for any overwrites

### Expected Results

If everything is working correctly:
- Context address should be 0x828F1F98
- qword_828F1F98 should be initialized to 0xFFFFFFFFFFFE7960 (or similar non-zero value)
- Thread #2 should run its worker loop instead of exiting immediately

### If Results Don't Match

If the context address is NOT 0x828F1F98:
1. Check the recompiled code for bugs in address calculation
2. Verify the .data section is loaded correctly
3. Check for memory mapping issues

If qword_828F1F98 is NOT initialized:
1. Verify sub_82813598 is being called
2. Check if the `divw` instruction is working correctly (we already fixed this)
3. Look for any code that overwrites the value

## Summary

The key insight is:

**We should NOT try to make our recompilation use heap allocation like Xenia. The recompilation is CORRECT to use static globals. The issue is ensuring the static global at 0x828F1F98 is properly initialized and accessible.**

Next steps:
1. Add logging to verify current behavior
2. Fix any bugs in address calculation or initialization
3. Test and verify the fix works

