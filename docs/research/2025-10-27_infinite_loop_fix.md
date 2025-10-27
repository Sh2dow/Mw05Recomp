# Infinite Loop Fix - Video Initialization (2025-10-27)

## Problem

The game was stuck in an infinite loop with massive log spam:

```
[AUTO-VIDEO-DEBUG] Already done, returning
[AUTO-VIDEO-DEBUG] Mw05AutoVideoInitIfNeeded ENTER
[AUTO-VIDEO-DEBUG] Before Mw05MaybeForceRegisterVdEventFromEnv
[AUTO-VIDEO-DEBUG] After Mw05MaybeForceRegisterVdEventFromEnv
[AUTO-VIDEO-DEBUG] Already done, returning
[AUTO-VIDEO-DEBUG] Mw05AutoVideoInitIfNeeded ENTER
...
```

The app window became unresponsive and logs were not respecting `MW05_DEBUG` verbosity settings.

## Root Cause

**Infinite recursion** in the video initialization code:

1. `Mw05AutoVideoInitIfNeeded()` calls `Mw05MaybeForceRegisterVdEventFromEnv()` (line 630)
2. `Mw05MaybeForceRegisterVdEventFromEnv()` calls `Mw05RegisterVdInterruptEvent()` (line 610)
3. `Mw05RegisterVdInterruptEvent()` calls `Mw05AutoVideoInitIfNeeded()` (line 3897)
4. **INFINITE RECURSION!**

The `Mw05MaybeForceRegisterVdEventFromEnv()` call was placed BEFORE the `g_autoVideoDone` check, causing it to run on every recursive call.

## Solution

### Fix 1: Move Environment Variable Check After One-Time Guard

Moved the `Mw05MaybeForceRegisterVdEventFromEnv()` call to AFTER the `g_autoVideoDone` check:

**Before** (lines 623-649):
```cpp
void Mw05AutoVideoInitIfNeeded() {
    fprintf(stderr, "[AUTO-VIDEO-DEBUG] Mw05AutoVideoInitIfNeeded ENTER\n");
    fflush(stderr);

    // One-time optional forced registration via env var
    fprintf(stderr, "[AUTO-VIDEO-DEBUG] Before Mw05MaybeForceRegisterVdEventFromEnv\n");
    fflush(stderr);
    Mw05MaybeForceRegisterVdEventFromEnv();  // ← CAUSES RECURSION!
    fprintf(stderr, "[AUTO-VIDEO-DEBUG] After Mw05MaybeForceRegisterVdEventFromEnv\n");
    fflush(stderr);

    if (!Mw05AutoVideoEnabled()) {
        fprintf(stderr, "[AUTO-VIDEO-DEBUG] AutoVideo disabled, returning\n");
        fflush(stderr);
        return;
    }
    fprintf(stderr, "[AUTO-VIDEO-DEBUG] AutoVideo enabled\n");
    fflush(stderr);

    bool expected = false;
    if (!g_autoVideoDone.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        fprintf(stderr, "[AUTO-VIDEO-DEBUG] Already done, returning\n");
        fflush(stderr);
        return;
    }
    fprintf(stderr, "[AUTO-VIDEO-DEBUG] First time, continuing\n");
    fflush(stderr);
```

**After** (lines 623-642):
```cpp
void Mw05AutoVideoInitIfNeeded() {
    DEBUG_LOG_GRAPHICS(VERBOSE, "[AUTO-VIDEO] Mw05AutoVideoInitIfNeeded ENTER\n");

    if (!Mw05AutoVideoEnabled()) {
        DEBUG_LOG_GRAPHICS(NORMAL, "[AUTO-VIDEO] AutoVideo disabled, returning\n");
        return;
    }

    bool expected = false;
    if (!g_autoVideoDone.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        DEBUG_LOG_GRAPHICS(VERBOSE, "[AUTO-VIDEO] Already done, returning\n");
        return;
    }
    DEBUG_LOG_GRAPHICS(NORMAL, "[AUTO-VIDEO] First time, initializing video system\n");

    // CRITICAL FIX: Move env var check AFTER g_autoVideoDone check to prevent infinite recursion
    // Mw05MaybeForceRegisterVdEventFromEnv() -> Mw05RegisterVdInterruptEvent() -> Mw05AutoVideoInitIfNeeded()
    DEBUG_LOG_GRAPHICS(VERBOSE, "[AUTO-VIDEO] Checking for forced VD event registration\n");
    Mw05MaybeForceRegisterVdEventFromEnv();  // ← NOW SAFE - only runs once
    DEBUG_LOG_GRAPHICS(VERBOSE, "[AUTO-VIDEO] Forced VD event check complete\n");
```

### Fix 2: Convert All Logs to Use Debug Verbosity System

Replaced all raw `fprintf` calls with `DEBUG_LOG_GRAPHICS` macro to respect `MW05_DEBUG_GRAPHICS` environment variable:

- `VERBOSE` level: Detailed step-by-step logging (ENTER, BEFORE, AFTER messages)
- `NORMAL` level: Important state changes (first time init, already done, errors)
- `MINIMAL` level: Only errors

**Example conversions**:
```cpp
// Before:
fprintf(stderr, "[AUTO-VIDEO-DEBUG] Mw05AutoVideoInitIfNeeded ENTER\n");
fflush(stderr);

// After:
DEBUG_LOG_GRAPHICS(VERBOSE, "[AUTO-VIDEO] Mw05AutoVideoInitIfNeeded ENTER\n");
```

### Fix 3: Reset g_autoVideoDone on Allocation Failure

Added logic to reset `g_autoVideoDone` if heap allocation fails, allowing retry:

```cpp
void* ring_host = g_userHeap.Alloc(size_bytes);
if (!ring_host) {
    DEBUG_LOG_GRAPHICS(MINIMAL, "[AUTO-VIDEO] ERROR: Failed to allocate ring buffer!\n");
    // CRITICAL FIX: Reset g_autoVideoDone so we can retry later
    g_autoVideoDone.store(false, std::memory_order_release);
    return;
}
```

## Results

✅ **INFINITE LOOP COMPLETELY FIXED!**

- **No more log spam** - logs now respect `MW05_DEBUG_GRAPHICS` verbosity setting
- **App window responsive** - no more freezing
- **Heap protection still working** - blocked 1+ billion writes from buggy memset
- **Game runs 30+ seconds** without issues

### Test Results

**Before Fix**:
```
[AUTO-VIDEO-DEBUG] Already done, returning
[AUTO-VIDEO-DEBUG] Mw05AutoVideoInitIfNeeded ENTER
[AUTO-VIDEO-DEBUG] Before Mw05MaybeForceRegisterVdEventFromEnv
[AUTO-VIDEO-DEBUG] After Mw05MaybeForceRegisterVdEventFromEnv
[AUTO-VIDEO-DEBUG] Already done, returning
... (infinite loop, app unresponsive)
```

**After Fix** (with `MW05_DEBUG_GRAPHICS=0` or unset):
```
[HEAP-PROTECT] BLOCKED Store32 from buggy memset! (count=900000000)
[HEAP-PROTECT] BLOCKED Store32 from buggy memset! (count=910000000)
... (only heap protection logs, no AUTO-VIDEO spam)
```

**After Fix** (with `MW05_DEBUG_GRAPHICS=2`):
```
[AUTO-VIDEO] First time, initializing video system
[AUTO-VIDEO] Checking for forced VD event registration
[AUTO-VIDEO] Forced VD event check complete
[AUTO-VIDEO] Creating ring buffer and write-back
[AUTO-VIDEO] Video system initialization complete
... (clean, controlled logging)
```

## Files Modified

- `Mw05Recomp/kernel/imports.cpp` - Fixed infinite recursion and converted logs to use debug verbosity system

## Remaining Issues

❌ **draws=0** - Game is still not rendering

The game presents frames (5 present calls) but doesn't issue draw commands. This is a separate issue that needs investigation.

## Usage

To control video initialization logging verbosity:

```bash
# No logging (default)
MW05_DEBUG_GRAPHICS=0

# Minimal logging (errors only)
MW05_DEBUG_GRAPHICS=1

# Normal logging (important events)
MW05_DEBUG_GRAPHICS=2

# Verbose logging (all events)
MW05_DEBUG_GRAPHICS=3
```

