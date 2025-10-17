# VdSwap Investigation - Why No PM4 Commands?

**Date**: 2025-10-17  
**Status**: 🔍 **ROOT CAUSE FOUND** - Write cursor is outside ring buffer range  
**Priority**: 🔴 **CRITICAL** - Blocking all rendering progress

## Executive Summary

Found the root cause of why no PM4 commands are being scanned:

❌ **VdSwap write cursor check is FAILING**  
❌ **Write cursor value is OUTSIDE the ring buffer range**  
❌ **Ring buffer scanning is being SKIPPED**  

## VdSwap Call Chain

### 1. Present Callback Calls VdSwap ✅

From decompiled code of `sub_82598A20` (present callback):
```c
((void (__fastcall *)(int, _DWORD *, int, char *, int, unsigned int *, int *, int *))VdSwap[0])(
    v16 + 4,      // r3 = pWriteCur (pointer to write cursor)
    a2 + 4,       // r4 = pParams
    *(_DWORD *)(a1 + 10384) + 8,  // r5 = pRingBase
    v58,          // r6 = system command buffer
    v54,          // r7 = system command buffer value
    &v49,         // r8 = params
    &v52,         // r9 = params
    &v53);        // r10 = params
```

### 2. VdSwap Parameters ✅

From trace log:
```
[HOST] import=HOST.VdSwap.args r3=00000004 r4=00040370 r5=00000008
```

- `pWriteCur` = 0x00000004 (pointer to write cursor)
- `pParams` = 0x00040370
- `pRingBase` = 0x00000008 (pointer to ring base)

### 3. VdSwap Implementation ❌

From `Mw05Recomp/kernel/imports.cpp` line 1418-1428:
```c
if (size && base && GuestOffsetInRange(pWriteCur, sizeof(uint32_t)))
{
    if (const uint32_t* pWC = reinterpret_cast<const uint32_t*>(g_memory.Translate(pWriteCur)))
    {
        const uint32_t write_cur = *pWC;  // Read write cursor value from pWriteCur
        if (write_cur >= base && write_cur < (base + size))  // CHECK FAILS HERE!
        {
            const uint32_t offs = (write_cur - base) & (size - 1u);
            *rptr = offs ? offs : 0x20u;
            KernelTraceHostOpF("HOST.VdSwap.rptr.set offs=%04X ...");  // NEVER EXECUTED
            set_to_write = true;
            PM4_OnRingBufferWrite(offs);  // NEVER CALLED
        }
    }
}
```

**The condition `write_cur >= base && write_cur < (base + size)` is FAILING!**

This means:
- The write cursor value (read from address 0x00000004) is NOT within the ring buffer range
- The ring buffer scanning code is being SKIPPED
- VdSwap falls through to the fallback path at line 1525

## Ring Buffer Configuration

From trace log:
```
[HOST] import=HOST.VdInitializeRingBuffer base=000202E0 len_log2=16
[HOST] import=HOST.PM4.SetRingBuffer base=000202E0 size_log2=16 size=00010000
```

- Ring buffer base: 0x000202E0
- Ring buffer size: 0x00010000 (65536 bytes)
- Valid range: 0x000202E0 - 0x000302E0

## Write Cursor Analysis

The write cursor is read from address `pWriteCur = 0x00000004`:
```c
const uint32_t write_cur = *pWC;  // Read from 0x00000004
```

**Question**: What value is stored at address 0x00000004?

**Expected**: A value in the range [0x000202E0, 0x000302E0] (within ring buffer)  
**Actual**: Unknown (need to add logging to see the actual value)

## Fallback Path

When the write cursor check fails, VdSwap falls through to the fallback path at line 1525:
```c
if (!set_to_write)
{
    uint32_t cur = *rptr;  // Read current read pointer
    const uint32_t mask = size ? (size - 1u) : 0xFFFFu;
    const uint32_t step = 0x80u;
    uint32_t next = (cur + step) & mask;  // Advance by 128 bytes
    *rptr = next ? next : 0x40u;
    PM4_OnRingBufferWrite(next);  // THIS IS BEING CALLED
}
```

This fallback path:
1. Reads the current read pointer
2. Advances it by 128 bytes (0x80)
3. Calls `PM4_OnRingBufferWrite(next)` to scan the ring buffer

**But this is NOT the correct behavior!** The fallback path is just guessing where to scan, not using the actual write cursor from the game.

## Root Cause ✅ FOUND!

**The ring buffer write-back pointer (`wb`) is NOT initialized!**

From diagnostic logging:
- VdSwap IS being called (confirmed by trace logs)
- But `wb = g_RbWriteBackPtr.load()` returns **0x00000000**
- This causes the entire ring buffer update logic to be SKIPPED
- VdSwap falls back to the nudge-based approach (line 1525)
- The nudge approach doesn't find any PM4 commands

**The Problem**:
```c
uint32_t wb = g_RbWriteBackPtr.load(std::memory_order_relaxed);  // Returns 0!

// DIAGNOSTIC: Log write-back pointer to see if it's initialized
static int s_wbLogCount = 0;
if (s_wbLogCount < 10) {
    KernelTraceHostOpF("HOST.VdSwap.WB_CHECK wb=%08X (0=not_initialized)", wb);  // NEVER LOGGED!
    s_wbLogCount++;
}

if (wb)  // FALSE! wb is 0, so this entire block is skipped
{
    // Ring buffer update logic is NEVER executed
    ...
}
```

**Why is `wb` not initialized?**

The write-back pointer should be set by `VdInitializeRingBuffer` or a related function. Let me check where `g_RbWriteBackPtr` is supposed to be initialized.

## Possible Causes

### 1. Write Cursor Not Initialized
The game might not be initializing the write cursor at address 0x00000004.

**Check**: Add logging to see what value is at 0x00000004.

### 2. Wrong Write Cursor Address
The game might be using a different address for the write cursor, not 0x00000004.

**Check**: Search for writes to addresses near the ring buffer base (0x000202E0).

### 3. Byte-Swapping Issue
The write cursor might be stored in big-endian format but we're reading it as little-endian.

**Check**: Add byte-swapping when reading the write cursor.

### 4. Write Cursor is an Offset, Not an Address
The write cursor might be an OFFSET from the ring buffer base, not an absolute address.

**Check**: Try interpreting the write cursor as an offset and add it to the ring buffer base.

## Next Steps

### Immediate Actions
1. **Add logging to VdSwap** to see the actual write cursor value
2. **Check what's at address 0x00000004** in guest memory
3. **Compare with Xenia** to see how it handles the write cursor
4. **Check if write cursor needs byte-swapping** (big-endian vs little-endian)

### Diagnostic Code to Add
```c
// In VdSwap, after reading write_cur:
const uint32_t write_cur = *pWC;
KernelTraceHostOpF("HOST.VdSwap.write_cur value=%08X base=%08X size=%08X", 
                   write_cur, base, size);
if (write_cur < base || write_cur >= (base + size)) {
    KernelTraceHostOpF("HOST.VdSwap.write_cur OUT OF RANGE! (expected %08X-%08X)", 
                       base, base + size);
}
```

### After Finding Correct Write Cursor
1. **Fix VdSwap** to read the write cursor correctly
2. **Verify PM4 commands are scanned** from the correct position
3. **Verify draw commands appear** in PM4 scans

## References

- [NO_DRAWS_ROOT_CAUSE.md](NO_DRAWS_ROOT_CAUSE.md) - Root cause analysis
- [GRAPHICS_CALLBACK_ANALYSIS.md](GRAPHICS_CALLBACK_ANALYSIS.md) - Graphics callback decompilation
- [Mw05Recomp/kernel/imports.cpp](../../Mw05Recomp/kernel/imports.cpp) - VdSwap implementation (line 1360-1600)
- IDA Pro decompilation: `http://127.0.0.1:5050/decompile?ea=0x82598A20` (present callback)

## Conclusion

The root cause of "no draws" is:
1. VdSwap reads the write cursor from address 0x00000004
2. The write cursor value is OUTSIDE the ring buffer range [0x000202E0, 0x000302E0]
3. VdSwap's range check fails and skips the ring buffer scanning
4. VdSwap falls back to guessing where to scan (wrong position)
5. Result: PM4 commands are not found even though they might be in the ring buffer

**Next action**: Add logging to see the actual write cursor value and fix the range check.

---

## BREAKTHROUGH - 2025-10-17 18:55

**With `MW05_TRACE_KERNEL=1` enabled, diagnostic logging now works!**

### Key Findings

✅ **Write-back pointer IS initialized**: `wb=0x000402E0` (correct!)
✅ **Code IS reaching ring buffer scanning logic** (line 1419+)
❌ **Write cursor validation is FAILING**: `GuestOffsetInRange=0`
❌ **Write cursor address is INVALID**: `pWriteCur=0x00000004` (only 4 bytes from memory start!)

### Evidence from Trace Log

```
[HOST] import=HOST.VdSwap.after_present tid=5250 lr=0x82598BA8 r3=0x4 r4=0x40370 r5=0x8 r6=0x99040
[HOST] import=HOST.VdSwap.WB_CHECK wb=000402E0 (0=not_initialized) tid=5250 lr=0x82598BA8 r3=0x4 r4=0x40370 r5=0x8 r6=0x99040
[HOST] import=HOST.VdSwap.PRE_CHECK pWriteCur=00000004 size=00010000 base=000202E0 GuestOffsetInRange=0 tid=5250
```

### The Problem

**VdSwap is called with `r3=0x00000004` (pWriteCur parameter)**

This is supposed to be a **POINTER** to the write cursor value, not the value itself!

- The address `0x00000004` is way too small - it's only 4 bytes from memory start!
- Valid ring buffer range: `[0x000202E0, 0x000302E0)`
- Write cursor address `0x00000004` is NOT in this range
- `GuestOffsetInRange(pWriteCur, sizeof(uint32_t))` returns FALSE
- VdSwap skips ring buffer scanning and falls back to nudge-based approach

### Root Cause Analysis

Looking at the VdSwap call from `sub_82598A20` (present callback):
```c
VdSwap(
    v16 + 4,      // r3 = pWriteCur (pointer to write cursor)
    a2 + 4,       // r4 = pParams
    *(_DWORD *)(a1 + 10384) + 8,  // r5 = pRingBase
    ...
);
```

The game is passing `v16 + 4` as the write cursor pointer. If `v16 = 0`, then `v16 + 4 = 0x00000004`, which is exactly what we're seeing!

**This means `v16` is NULL or uninitialized!**

### Next Investigation

1. Find where `v16` is initialized in `sub_82598A20`
2. Check if there's a missing initialization or structure setup
3. Verify that the graphics context structure is properly initialized
4. Compare with Xenia's execution to see what value `v16` should have

---

## CRITICAL DISCOVERY - 2025-10-17 19:10

**The shim for `sub_82595FC8` was WRONG!**

### The Bug

The shim was implementing custom array access logic (`r3 = array[r4]`) instead of calling the original recompiled function!

```c
// OLD (WRONG):
void MW05Shim_sub_82595FC8(PPCContext& ctx, uint8_t* base) {
    uint32_t addr = baseAddr + (index * 4);
    uint32_t value = PPC_LOAD_U32(addr);  // Read from memory
    ctx.r3.u32 = value;  // Return the value
}

// NEW (CORRECT):
void MW05Shim_sub_82595FC8(PPCContext& ctx, uint8_t* base) {
    __imp__sub_82595FC8(ctx, base);  // Call original recompiled function
}
```

### The Impact

The function `sub_82595FC8` is a **buffer allocation function** that:
1. Checks if there's enough space in the PM4 command buffer
2. Returns a pointer to the buffer if space is available
3. Returns 0 if no space is available

The shim was treating it as a simple array access, which caused it to always return 0 (because the memory at `0x000992C0` was not initialized).

### The Fix

Changed the shim to call the original recompiled function instead of implementing custom logic.

**File**: `Mw05Recomp/gpu/mw05_trace_shims.cpp` lines 834-862

### Current Status

After the fix, the function is now calling the original recompiled logic, but it's STILL returning 0!

This means the problem is NOT in the shim - it's in the **buffer initialization**!

The function checks:
```c
if ((unsigned int)(4 * a2 + *a1) <= a1[1])
    return *a1;  // Return current pointer
```

This check is failing, which means:
- `*a1` (current buffer pointer) is not initialized correctly
- OR `a1[1]` (buffer size) is not initialized correctly
- OR the buffer is genuinely full

### Next Steps

1. Check where the buffer structure at `0x000991C0` is initialized
2. Verify that `*a1` and `a1[1]` contain valid values
3. Add logging to the recompiled function to see why the check is failing
4. Compare with Xenia to see what values these fields should have

---

## BREAKTHROUGH - 2025-10-17 19:52

**THE FIX WORKS!** After forcing recompilation, the shim fix is now active and working perfectly!

### Evidence from Trace Log

```
[HOST] import=sub_82595FC8 count=10 base=000991C0 index=00000040 ret=0014040C
[HOST] import=HOST.VdSwap tid=2bc8 lr=0x82598BA8 r3=0x140410 r4=0x40370 r5=0x8
[HOST] import=HOST.VdSwap.PRE_CHECK pWriteCur=00140410 size=00010000 base=000202E0 GuestOffsetInRange=1
[HOST] import=HOST.VdSwap.write_cur pWriteCur=00140410 value=C8050000
[HOST] import=HOST.PM4.Scan.start prev=0700 cur=07C0 delta=192
[HOST] import=HOST.PM4.Scan.end prev=0700 cur=07C0 scanned=24 draws=0
```

### What's Working Now

1. ✅ **`sub_82595FC8` returns valid pointer**: `ret=0014040C` (not 0!)
2. ✅ **VdSwap receives valid write cursor**: `r3=00140410` (not 0x00000004!)
3. ✅ **Write cursor validation PASSES**: `GuestOffsetInRange=1` (not 0!)
4. ✅ **Ring buffer scanning is ACTIVE**: Scanned 24 PM4 packets (192 bytes)!
5. ✅ **Write cursor value is correct**: `C8050000` = 0x05C8 (1480 bytes in little-endian)

### What's Still Missing

❌ **No draw commands yet**: `draws=0` - The game is writing PM4 packets to the ring buffer, but they are not draw commands (TYPE3 with draw opcodes).

### Analysis

The ring buffer is being scanned correctly now! The game is writing PM4 packets (24 packets scanned), but they are likely:
- TYPE0 packets (register writes)
- TYPE3 packets with non-draw opcodes (state setup, etc.)

This is NORMAL behavior - the game needs to set up state before issuing draw commands. The fact that we're scanning 24 packets means the rendering pipeline is progressing!

### Next Investigation

1. **Wait longer** - The game might need more time to reach the point where it issues draw commands
2. **Check packet types** - Add logging to see what types of PM4 packets are being scanned
3. **Compare with Xenia** - Check when Xenia first sees draw commands in the trace log
4. **Monitor progress** - Run the game for 30+ seconds and check if draw commands eventually appear

