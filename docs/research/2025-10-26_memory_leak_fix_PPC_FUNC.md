# Memory Leak Fix - PPC Function Override Pattern

**Date**: 2025-10-26  
**Status**: ✅ FIXED  
**Impact**: 90% reduction in memory usage (15-20 GB → 1.76 GB)

## Problem

The game was experiencing catastrophic memory leaks:
- **Working Set**: 15-20 GB (should be ~1.7 GB)
- **Peak Working Set**: 18-20 GB
- **Commit Size**: 21-37 GB

This made the game unplayable on systems with less than 32 GB RAM, which is unacceptable for a 2005 Xbox 360 game that originally ran on 512 MB.

## Root Cause

The memory leak was caused by **improper PPC function override patterns** in the MW05 shim files. Several functions were defined as regular C++ functions instead of using the proper `PPC_FUNC_IMPL` + `PPC_FUNC` weak symbol override pattern.

### Why This Caused Memory Leaks

When you define a function as:
```cpp
void sub_XXXXXXXX(PPCContext& ctx, uint8_t* base) { ... }
```

Instead of:
```cpp
PPC_FUNC_IMPL(__imp__sub_XXXXXXXX);
PPC_FUNC(sub_XXXXXXXX) { ... }
```

The linker creates **duplicate symbols** - one from the recompiled code and one from your override. This causes:
1. Both versions of the function to exist in memory
2. Memory allocations to be duplicated
3. Cascading memory leaks as the game runs

## Files Fixed

### 1. `Mw05Recomp/cpu/mw05_scheduler_shims.cpp`

**Before** (lines 193-194):
```cpp
void sub_82621640(PPCContext& ctx, uint8_t* base) {
{  // <-- Extra opening brace!
    SetPPCContext(ctx);
    // ...
}
```

**After**:
```cpp
PPC_FUNC_IMPL(__imp__sub_82621640);
PPC_FUNC(sub_82621640)
{
    SetPPCContext(ctx);
    // ...
}
```

**Same fix applied to**: `sub_8284E658` (line 387)

### 2. `Mw05Recomp/cpu/mw05_boot_shims.cpp`

**Before** (line 585):
```cpp
void sub_8215BC78(PPCContext& ctx, uint8_t* base) {
    // ...
}
```

**After**:
```cpp
PPC_FUNC_IMPL(__imp__sub_8215BC78);
PPC_FUNC(sub_8215BC78)
{
    // ...
}
```

**Also fixed**: `sub_828134E0` (line 448) - added missing `PPC_FUNC_IMPL`

### 3. `Mw05Recomp/cpu/ppc_list_shims.cpp`

**Before** (lines 64, 130):
```cpp
void sub_8215FEF0(PPCContext& ctx, uint8_t* base) { ... }
void sub_820E25C0(PPCContext& ctx, uint8_t* base) { ... }
```

**After**:
```cpp
PPC_FUNC_IMPL(__imp__sub_8215FEF0);
PPC_FUNC(sub_8215FEF0) { ... }

PPC_FUNC_IMPL(__imp__sub_820E25C0);
PPC_FUNC(sub_820E25C0) { ... }
```

### 4. `Mw05Recomp/cpu/mw05_loader_shims.cpp`

**Before** (lines 177-193):
```cpp
#define LOADER_SHIM(NAME) \
  void NAME(PPCContext& ctx, uint8_t* base) { \
    // ...
  }
```

**After**:
```cpp
#define LOADER_SHIM(NAME) \
  PPC_FUNC_IMPL(__imp__##NAME); \
  PPC_FUNC(NAME) { \
    // ...
  }
```

## Results

### Memory Usage (Task Manager)

**Before Fix**:
- Working Set: 15-20 GB
- Peak Working Set: 18-20 GB
- Commit Size: 21-37 GB

**After Fix**:
- Working Set: **1.76 GB** ✅
- Peak Working Set: **1.76 GB** ✅
- Commit Size: 4.5 GB (virtual memory, acceptable)

**Improvement**: **90% reduction** in physical memory usage!

### Heap Allocations

**Before Fix**:
- Physical heap: 1.085 GB (40% of 2.5 GB capacity)
- User heap: 6.75 MB
- Unknown: ~13-18 GB (leaked memory)

**After Fix**:
- Physical heap: 361 MB (22% of 2.5 GB capacity)
- User heap: 5 MB
- No leaks detected

## The Correct Pattern

### ✅ ALWAYS Use This Pattern

```cpp
// Declare the weak symbol from recompiled code
PPC_FUNC_IMPL(__imp__sub_XXXXXXXX);

// Define your override
PPC_FUNC(sub_XXXXXXXX)
{
    // Your implementation
    // Can call original: __imp__sub_XXXXXXXX(ctx, base);
}
```

### ❌ NEVER Use These Patterns

```cpp
// WRONG #1: Regular function definition
void sub_XXXXXXXX(PPCContext& ctx, uint8_t* base) { ... }

// WRONG #2: Missing PPC_FUNC_IMPL
PPC_FUNC(sub_XXXXXXXX) { ... }

// WRONG #3: Forward declaration instead of PPC_FUNC_IMPL
extern "C" void __imp__sub_XXXXXXXX(PPCContext& ctx, uint8_t* base);
PPC_FUNC(sub_XXXXXXXX) { ... }
```

## How to Verify

### 1. Check Memory Usage
```powershell
# Run the game for 30 seconds
python scripts/auto_handle_messageboxes.py --duration 30

# Check Task Manager:
# - Working Set should be ~1.7 GB
# - Peak Working Set should be ~1.7 GB
```

### 2. Check Heap Stats
```powershell
Get-Content traces/auto_test_stderr.txt | Select-String -Pattern "Physical heap usage"

# Expected output:
# Physical heap usage: 361 MB / 2.5 GB (22.46%)
```

### 3. Verify No Leaks
```powershell
# Run for 60 seconds and check if memory grows
python scripts/auto_handle_messageboxes.py --duration 60

# Working Set should stay stable at ~1.7 GB
```

## Lessons Learned

1. **Always use the proper PPC_FUNC pattern** - it's not just a style choice, it prevents memory leaks
2. **Watch for extra braces** - the `{` on line 194/387 in scheduler shims was a red flag
3. **Check all shim files** - memory leaks can come from any file that overrides PPC functions
4. **Use Task Manager Peak Working Set** - this metric reveals memory spikes that might not be visible in current usage
5. **Git bisect is your friend** - the user found the issue by identifying the commit that introduced the leak

## Prevention

To prevent this issue in the future:

1. **Code Review**: Always check that PPC function overrides use `PPC_FUNC_IMPL` + `PPC_FUNC`
2. **Grep Check**: Before committing, search for `void sub_[0-9A-F]{8}` in shim files
3. **Memory Testing**: Run 30-60 second tests and check Peak Working Set after any shim changes
4. **Documentation**: Keep AGENTS.md updated with this critical rule

## Related Issues

- ✅ Heap corruption (fixed 2025-10-22) - moved heap start to 0x100000
- ❌ No rendering (draws=0) - still under investigation

## References

- `XenonUtils/ppc_context.h` - Defines `PPC_FUNC` and `PPC_FUNC_IMPL` macros
- `AGENTS.md` - Critical rules for AI agents (updated with this fix)
- Commit 72d10d3180506369980b556efca880d54b10622c - Last known good commit before leak

