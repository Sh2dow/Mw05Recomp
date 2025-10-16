# File I/O Hooks Registration - SUCCESS!

## Date: 2025-10-16

## Summary
✅ **FILE I/O HOOKS REGISTERED!** The X* file API hooks are now being registered at startup.

## Changes Made

### 1. Added File System Hook Registration (`Mw05Recomp/kernel/io/file_system.cpp`)

Added a static constructor that registers all X* file API hooks at startup:

```cpp
// Register X* file API hooks (direct recompiled functions)
// Note: Nt* imports are automatically registered by ProcessImportTable()
static void RegisterFileSystemHooks() {
    KernelTraceHostOp("HOST.FileSystem.RegisterXFileHooks");
    
    // Register X* file API hooks at their known addresses
    if (&sub_82BD4668) g_memory.InsertFunction(0x82BD4668, sub_82BD4668); // XCreateFileA
    if (&sub_82BD4600) g_memory.InsertFunction(0x82BD4600, sub_82BD4600); // XGetFileSizeA
    if (&sub_82BD5608) g_memory.InsertFunction(0x82BD5608, sub_82BD5608); // XGetFileSizeExA
    if (&sub_82BD4478) g_memory.InsertFunction(0x82BD4478, sub_82BD4478); // XReadFile
    if (&sub_831CD3E8) g_memory.InsertFunction(0x831CD3E8, sub_831CD3E8); // XSetFilePointer
    if (&sub_831CE888) g_memory.InsertFunction(0x831CE888, sub_831CE888); // XSetFilePointerEx
    if (&sub_831CDC58) g_memory.InsertFunction(0x831CDC58, sub_831CDC58); // XFindFirstFileA
    if (&sub_831CDC00) g_memory.InsertFunction(0x831CDC00, sub_831CDC00); // XFindNextFileA
    if (&sub_831CDF40) g_memory.InsertFunction(0x831CDF40, sub_831CDF40); // XReadFileEx
    if (&sub_831CD6E8) g_memory.InsertFunction(0x831CD6E8, sub_831CD6E8); // XGetFileAttributesA
    if (&sub_831CE3F8) g_memory.InsertFunction(0x831CE3F8, sub_831CE3F8); // XCreateFileA (duplicate)
    if (&sub_82BD4860) g_memory.InsertFunction(0x82BD4860, sub_82BD4860); // XWriteFile
    
    KernelTraceHostOp("HOST.FileSystem.RegisterXFileHooks.done");
}

// Use static constructor to register hooks early
#if defined(_MSC_VER)
#  pragma section(".CRT$XCU",read)
    static void __cdecl file_system_hooks_ctor();
    __declspec(allocate(".CRT$XCU")) void (__cdecl*file_system_hooks_ctor_)(void) = file_system_hooks_ctor;
    static void __cdecl file_system_hooks_ctor() { RegisterFileSystemHooks(); }
#else
    __attribute__((constructor)) static void file_system_hooks_ctor() { RegisterFileSystemHooks(); }
#endif
```

## How It Works

### X* File Functions (Direct Calls)
- These are regular recompiled functions in the game code (e.g., `XCreateFileA` at 0x82BD4668)
- The `GUEST_FUNCTION_HOOK` macro creates a PPC_FUNC that replaces the original function
- But the hook must be registered using `g_memory.InsertFunction()` to take effect
- The static constructor ensures hooks are registered before the game starts

### Nt* File Functions (Import Table)
- These are import table entries (e.g., `__imp__NtCreateFile`)
- The `GUEST_FUNCTION_HOOK` macro creates a PPC_FUNC for each import
- `ProcessImportTable()` in `main.cpp` automatically registers these hooks
- The import lookup table (`import_lookup.cpp`) provides the function pointers

## Test Results

### Build
✅ Build succeeded without errors

### Runtime
✅ Hook registration confirmed in trace:
```
[HOST] import=HOST.FileSystem.RegisterXFileHooks
```

### Current Status
- ✅ Game runs without crashing
- ✅ Main loop is executing
- ✅ PM4 commands are being processed
- ✅ File I/O hooks are registered
- ⚠️ **NO FILE I/O CALLS YET** - Game hasn't tried to open/read files
- ⚠️ **NO DRAWS YET** - All PM4 scans show `draws=0`

## Why No File I/O?

The game is running but hasn't made any file I/O calls yet. Possible reasons:

1. **Still in initialization** - Game may be in early boot phase before file loading
2. **Missing resources** - Game may be waiting for something before loading files
3. **Different I/O method** - Game may use a different file I/O API we haven't hooked
4. **Blocked on missing imports** - 331 imports are still not implemented

## Next Steps

### Immediate
1. **Monitor for file I/O** - Watch for `NtCreateFile`, `NtOpenFile`, `NtReadFile` calls
2. **Check missing imports** - Implement critical missing imports that might be blocking file I/O
3. **Investigate game state** - Determine what the game is waiting for

### Long-term
1. **Implement missing imports** - Add the remaining 331 imports (NetDll, Xam, XMA)
2. **Create missing threads** - Xenia creates 9 threads, we only create 3
3. **Debug draw commands** - Figure out why no draw commands are being issued

## Files Modified
- `Mw05Recomp/kernel/io/file_system.cpp` - Added hook registration function

## Related Documentation
- `docs/research/RENDERING_STATUS.md` - Current rendering status
- `docs/research/IMPORT_TABLE_SUCCESS.md` - Import table patching details
- `Mw05Recomp/kernel/import_lookup.cpp` - Auto-generated import lookup table

