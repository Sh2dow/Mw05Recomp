# Initialization Patterns for MW05Recomp

## Problem Statement

The game was crashing during C++ global object construction because static constructors were calling `g_memory.InsertFunction()` before `g_memory.base` was allocated in the `Memory()` constructor.

This is known as the **Static Initialization Order Fiasco** - a classic C++ problem where the order of global object construction is undefined across translation units.

## Solution 1: Lazy Initialization Pattern (Recommended)

### Overview
Add safety checks to `Memory::InsertFunction()` to detect and prevent calls before memory is initialized.

### Implementation

```cpp
// In memory.h
struct Memory
{
    // ... existing members ...

    // Lazy initialization - ensures memory is allocated before any operations
    bool EnsureInitialized() noexcept
    {
        if (base == nullptr) {
            fprintf(stderr, "[MEMORY] ERROR: Memory not initialized! Call from global constructor?\n");
            fflush(stderr);
            return false;
        }
        return true;
    }

    // Safe version of InsertFunction that checks if memory is initialized
    bool InsertFunction(uint32_t guest, PPCFunc* host)
    {
        // CRITICAL: Check if memory is initialized before accessing function table
        if (!EnsureInitialized()) {
            fprintf(stderr, "[INSERT-FUNC] ERROR: Cannot insert function 0x%08X - memory not initialized!\n", guest);
            fflush(stderr);
            return false;  // Gracefully fail instead of crashing
        }

        // ... rest of implementation ...
        return true;
    }
};
```

### Benefits
- ✅ Prevents crashes from premature access
- ✅ Clear error messages for debugging
- ✅ Minimal code changes
- ✅ No performance impact (single pointer check)
- ✅ Works with existing code

### Drawbacks
- ⚠️ Silently fails if called too early (but logs error)
- ⚠️ Doesn't solve the root cause (static initialization order)

## Solution 2: Centralized Initialization Manager (Best Practice)

### Overview
Create a centralized system that manages all initialization callbacks and runs them in a controlled order after memory is ready.

### Implementation

See `Mw05Recomp/kernel/init_manager.h` for the full implementation.

### Usage Example

```cpp
// In file_system.cpp
#include <kernel/init_manager.h>

// Register initialization callback (runs automatically at program start)
REGISTER_INIT_CALLBACK("FileSystemHooks", []() {
    // This code runs AFTER g_memory is initialized
    g_memory.InsertFunction(0x82BD4668, sub_82BD4668);  // XCreateFileA
    g_memory.InsertFunction(0x82BD4A88, sub_82BD4A88);  // XReadFile
    // ... more hooks ...
});
```

```cpp
// In main.cpp
#include <kernel/init_manager.h>

int main(int argc, char** argv)
{
    // ... early initialization ...

    // Initialize memory subsystem
    // g_memory constructor runs here (global object)

    // Initialize heap
    g_userHeap.Init();

    // NOW run all registered initialization callbacks
    InitManager::Instance().RunAll();

    // ... rest of main ...
}
```

### With Priority Control

```cpp
// Critical system initialization (runs first)
REGISTER_INIT_CALLBACK_PRIORITY("FileSystemHooks", 50, []() {
    RegisterFileSystemHooks();
});

// Game hooks (runs after core systems)
REGISTER_INIT_CALLBACK_PRIORITY("GameHooks", 100, []() {
    RegisterMw05FunctionHooks();
});

// Optional features (runs last)
REGISTER_INIT_CALLBACK_PRIORITY("DebugFeatures", 150, []() {
    RegisterDebugHooks();
});
```

### Benefits
- ✅ Solves static initialization order fiasco completely
- ✅ Clear dependency management (priority system)
- ✅ Easy to debug (logs all registrations)
- ✅ Thread-safe registration
- ✅ Graceful error handling (try-catch around each callback)
- ✅ Can register callbacks from any module
- ✅ Late registration support (runs immediately if already initialized)
- ✅ No manual tracking needed

### Drawbacks
- ⚠️ Requires refactoring existing code
- ⚠️ Adds small overhead (vector of callbacks, mutex)
- ⚠️ Requires discipline (must use REGISTER_INIT_CALLBACK macro)

## Solution 3: Hybrid Approach (Recommended for MW05)

Combine both patterns for maximum safety and flexibility:

1. **Add safety checks** to `Memory::InsertFunction()` (Solution 1)
2. **Use InitManager** for new code (Solution 2)
3. **Gradually migrate** existing static constructors to InitManager

### Migration Path

#### Step 1: Add Safety Checks (Done)
```cpp
// memory.h - Already implemented
bool InsertFunction(uint32_t guest, PPCFunc* host)
{
    if (!EnsureInitialized()) {
        return false;  // Fail gracefully
    }
    // ... rest of implementation ...
}
```

#### Step 2: Create InitManager (Done)
See `Mw05Recomp/kernel/init_manager.h`

#### Step 3: Migrate Static Constructors

**Before:**
```cpp
// file_system.cpp
static void RegisterFileSystemHooks() {
    g_memory.InsertFunction(0x82BD4668, sub_82BD4668);
    // ... more hooks ...
}

__attribute__((constructor)) 
static void file_system_hooks_ctor() { 
    RegisterFileSystemHooks(); 
}
```

**After:**
```cpp
// file_system.cpp
#include <kernel/init_manager.h>

static void RegisterFileSystemHooks() {
    g_memory.InsertFunction(0x82BD4668, sub_82BD4668);
    // ... more hooks ...
}

// Register with InitManager instead of static constructor
REGISTER_INIT_CALLBACK_PRIORITY("FileSystemHooks", 50, []() {
    RegisterFileSystemHooks();
});
```

#### Step 4: Update main.cpp

```cpp
// main.cpp
int main(int argc, char** argv)
{
    // ... early initialization ...

    // Memory is initialized here (g_memory global constructor)
    
    // Initialize heap
    g_userHeap.Init();
    g_userHeap.inGlobalConstruction = false;

    // Run all registered initialization callbacks
    InitManager::Instance().RunAll();

    // ... rest of main ...
}
```

## Comparison Table

| Feature | Lazy Init | InitManager | Hybrid |
|---------|-----------|-------------|--------|
| Prevents crashes | ✅ | ✅ | ✅ |
| Solves root cause | ❌ | ✅ | ✅ |
| Easy to implement | ✅ | ⚠️ | ⚠️ |
| Easy to debug | ⚠️ | ✅ | ✅ |
| Performance impact | None | Minimal | Minimal |
| Requires refactoring | No | Yes | Gradual |
| Thread-safe | N/A | ✅ | ✅ |
| Priority control | ❌ | ✅ | ✅ |
| Error handling | Basic | Advanced | Advanced |

## Recommendation

**Use the Hybrid Approach:**

1. ✅ **Already done**: Added safety checks to `Memory::InsertFunction()`
2. ✅ **Already done**: Created `InitManager` class
3. 🔄 **Next step**: Migrate existing static constructors to use `REGISTER_INIT_CALLBACK`
4. 🔄 **Next step**: Update `main.cpp` to call `InitManager::Instance().RunAll()`

This gives you:
- Immediate crash prevention (safety checks)
- Long-term maintainability (InitManager)
- Gradual migration path (no big-bang refactoring)
- Clear dependency management (priority system)

## Example: Complete Migration

### File: `Mw05Recomp/cpu/mw05_function_hooks.cpp`

**Before:**
```cpp
static void RegisterMw05FunctionHooks() {
    // ... hook registrations ...
}

// DISABLED: Static constructor causes crash
// __attribute__((constructor)) 
// static void mw05_function_hooks_ctor() { 
//     RegisterMw05FunctionHooks(); 
// }
```

**After:**
```cpp
#include <kernel/init_manager.h>

static void RegisterMw05FunctionHooks() {
    // ... hook registrations ...
}

// Register with InitManager (priority 100 = default, runs after core systems)
REGISTER_INIT_CALLBACK("MW05FunctionHooks", []() {
    RegisterMw05FunctionHooks();
});
```

### File: `Mw05Recomp/main.cpp`

```cpp
#include <kernel/init_manager.h>

int main(int argc, char** argv)
{
    // ... early initialization ...

    // Initialize heap
    g_userHeap.Init();
    g_userHeap.inGlobalConstruction = false;

    // Run all registered initialization callbacks in priority order
    fprintf(stderr, "[MAIN] Running initialization callbacks...\n");
    InitManager::Instance().RunAll();
    fprintf(stderr, "[MAIN] Initialization complete!\n");

    // ... rest of main ...
}
```

## Testing

After migration, you should see output like:

```
[INIT-MGR] Registered: 'FileSystemHooks' (priority: 50)
[INIT-MGR] Registered: 'MW05FunctionHooks' (priority: 100)
[INIT-MGR] Registered: 'VideoHooks' (priority: 100)
[INIT-MGR] ========================================
[INIT-MGR] Running 3 initialization callbacks...
[INIT-MGR] ========================================
[INIT-MGR] Running: 'FileSystemHooks' (priority: 50)...
[INIT-MGR] ✓ 'FileSystemHooks' completed successfully
[INIT-MGR] Running: 'MW05FunctionHooks' (priority: 100)...
[INIT-MGR] ✓ 'MW05FunctionHooks' completed successfully
[INIT-MGR] Running: 'VideoHooks' (priority: 100)...
[INIT-MGR] ✓ 'VideoHooks' completed successfully
[INIT-MGR] ========================================
[INIT-MGR] Initialization complete: 3 succeeded, 0 failed
[INIT-MGR] ========================================
```

