# CRITICAL BUG: VdInitializeEngines Hook Only Executes Once

## Status: BLACK SCREEN - Root Cause Identified

**Date**: 2025-10-09  
**Severity**: CRITICAL - Blocks all rendering

## Problem Summary

The game has a black screen with no draw commands because `VdInitializeEngines` is only being called ONCE, even though the game attempts to call it 34 times with different parameters. This prevents the game's graphics initialization callbacks from running, which means the rendering system never starts.

## Evidence

### 1. Trace Log Shows 34 Calls
From `mw05_host_trace.log`:
```
[HOST] import=HOST.VdInitializeEngines tid=a7c8 lr=0x0 r3=0x0 r4=0x0 r5=0x0 r6=0x0
[HOST] import=HOST.VdInitializeEngines tid=7958 lr=0x0 r3=0x7FEA17B0 r4=0x411800 r5=0x410200 r6=0x0
[HOST] import=HOST.VdInitializeEngines tid=b140 lr=0x0 r3=0x0 r4=0x0 r5=0x0 r6=0x0
... (31 more calls)
```

**Total**: 34 calls logged by `KernelTraceImport`  
**Calls with non-zero callback**: 22 calls (most to `0x7FEA17B0`)

### 2. Host Function Only Called Once
From `debug_stderr.txt`:
```
[VdInitEngines #1] ENTRY: cb=00000000 arg1=00000000 arg2=00000000 arg3=00000000 arg4=00000000 tid=1598
[VdInitEngines #1] No callback (cb=0), call_count=1
```

**Only 1 execution** of the actual `VdInitializeEngines` function, with `cb=0` (no callback).

### 3. No VdSwap Calls
The game never calls `VdSwap`, which is required to present frames and trigger draw commands.

From Xenia (working):
```
VdSwap
Draw opcode=PM4_DRAW_INDX_2 prim=1 indices=1 indexed=0
```

From our implementation:
```
(no VdSwap calls at all)
```

## Root Cause

The `GUEST_FUNCTION_HOOK` mechanism is broken for `VdInitializeEngines`:

1. **Hook wrapper IS being called**: `KernelTraceImport` logs 34 calls
2. **`HostToGuestFunction<VdInitializeEngines>` IS being invoked**: 34 times
3. **Actual `VdInitializeEngines` function is NOT being called**: Only 1 execution

This means the problem is in the `HostToGuestFunction` template or in how `std::apply(Func, args)` is being executed.

## Code Flow

```cpp
// Generated PPC code calls:
__imp__VdInitializeEngines(ctx, base);

// Which expands to (via GUEST_FUNCTION_HOOK macro):
void __imp__VdInitializeEngines(PPCContext& ctx, uint8_t* base) {
    KernelTraceImport("__imp__VdInitializeEngines", ctx);  // ✅ Called 34 times
    HostToGuestFunction<VdInitializeEngines>(ctx, base);   // ❓ Called 34 times but...
}

// HostToGuestFunction template:
template<auto Func>
PPC_FUNC(HostToGuestFunction) {
    // ...
    auto args = function_args(Func);
    _translate_args_to_host<Func>(ctx, base, args);
    KernelTraceHostBegin(ctx);
    std::apply(Func, args);  // ❌ Only executes ONCE!
    KernelTraceHostEnd();
}
```

## Impact

1. **Graphics context never initialized**: The callback at `0x7FEA17B0` never runs
2. **Rendering system never starts**: Game doesn't enter rendering mode
3. **No VdSwap calls**: Game never presents frames
4. **No draw commands**: PM4 buffers contain only register writes (24,576 type-0 packets), zero draws
5. **Black screen**: No visual output

## Comparison with Xenia

| Aspect | Xenia (Working) | Our Implementation (Broken) |
|--------|----------------|----------------------------|
| VdInitializeEngines calls | Multiple with callbacks | 1 call with cb=0 |
| Graphics callbacks executed | Yes | No |
| VdSwap called | Yes, regularly | Never |
| Draw commands issued | Yes (PM4_DRAW_INDX_2) | No (0 draws) |
| Screen output | Game renders | Black screen |

## Attempted Fixes

1. ❌ **Custom hook implementation**: Replaced `GUEST_FUNCTION_HOOK` with manual implementation - same result
2. ❌ **Manually calling callbacks**: Called `0x7FEA17B0` via `GuestToHostFunction` - callback returns NULL
3. ❌ **Calling VdInitializeEngines directly**: From VBLANK handler - doesn't help
4. ❌ **Adding logging to macro**: Logging doesn't appear (build issues)
5. ❌ **Adding logging to template**: Build fails with PCH errors

## Next Steps Required

### Option 1: Fix the HostToGuestFunction Template
- Debug why `std::apply(Func, args)` only executes once
- Check if there's caching or early-return logic somewhere
- Compare with working hooks (e.g., `VdSetGraphicsInterruptCallback` which IS called 5+ times)

### Option 2: Bypass the Hook Mechanism
- Create a custom PPC_FUNC for `__imp__VdInitializeEngines` that directly calls the host function
- Don't use `HostToGuestFunction` template at all
- Manually extract parameters from `ctx` and call `VdInitializeEngines`

### Option 3: Call All Callbacks Manually
- Extract all 22 callback addresses from trace log
- Call them manually from VBLANK handler or boot sequence
- Bypass the broken hook mechanism entirely

## Files Involved

- `Mw05Recomp/kernel/function.h`: `HostToGuestFunction` template, `GUEST_FUNCTION_HOOK` macro
- `Mw05Recomp/kernel/imports.cpp`: `VdInitializeEngines` implementation, hook registration
- `Mw05RecompLib/ppc/ppc_recomp_shared.h`: `PPC_EXTERN_FUNC(__imp__VdInitializeEngines)` declaration
- `Mw05RecompLib/ppc/ppc_func_mapping.cpp`: Maps `0x828AA15C` → `__imp__VdInitializeEngines`
- `Mw05RecompLib/ppc/ppc_recomp.72.cpp`: Generated code that calls `__imp__VdInitializeEngines`

## Diagnostic Commands

```powershell
# Extract VdInitializeEngines calls from trace
python tools/extract_vdinit_calls.py

# Check how many times host function was called
Get-Content debug_stderr.txt | Select-String 'VdInitEngines'

# Check for VdSwap calls
Get-Content debug_stderr.txt | Select-String 'VdSwap'

# Check for draw commands
Get-Content debug_stderr.txt | Select-String 'Draw|PM4.*draws'
```

## Conclusion

The `GUEST_FUNCTION_HOOK` / `HostToGuestFunction` mechanism has a critical bug that causes it to only execute the host function ONCE for `VdInitializeEngines`, even though the hook wrapper is called 34 times. This prevents the game's graphics initialization from completing, resulting in a black screen with no rendering.

**The game is very close to working** - we just need to fix this one critical bug in the function hooking mechanism.

