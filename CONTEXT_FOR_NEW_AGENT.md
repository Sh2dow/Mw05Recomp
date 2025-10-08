# MW05 Recomp - Graphics Rendering Investigation Context

## Project Overview
**Mw05Recomp** is an Xbox 360 NFS: Most Wanted recompilation project that translates PowerPC code to x64 with D3D12/Vulkan backend.

## Current Status: NO RENDERING

### What Works ✅
1. **Game runs stably** for 30+ seconds without crashing
2. **Vblank pump** running at 60 Hz
3. **Multiple threads** created successfully
4. **PM4 packets** being submitted (TYPE0 register writes)
5. **File I/O** operations succeeding
6. **Memory allocator fix** - Successfully intercepted game's broken allocator (`sub_8215CB08`) and replaced with host implementation
7. **Graphics callback registration** - `VdSetGraphicsInterruptCallback` can be called successfully

### Critical Issue ❌
**ZERO DRAW COMMANDS** - No TYPE3 packets, no DRAW_INDX opcodes (0x22, 0x36), only TYPE0 packets (register writes)

## Root Cause Analysis

### Expected Graphics Initialization Chain (from Xenia trace)
```
sub_823AF590 → sub_821BB4D0 → sub_82216088 → sub_825A16A0 → sub_825A8698 → sub_825A85E0 → VdSetGraphicsInterruptCallback
```

**Xenia execution sequence:**
1. `VdInitializeEngines` called with `unk0=0x08570000 cb=0x825A85C8 arg=0x00000000`
2. `VdSetGraphicsInterruptCallback` called with `cb=0x825979A8 ctx=0x40007180`
3. **VD notify** - Callback invoked with `source=0 data=0x40007180`
4. **Ring buffer initialization:**
   - `VdSetSystemCommandBufferGpuIdentifierAddress ea=0x00000000`
   - `VdInitializeRingBuffer base=0x0A0F8000 size_log2=12`
   - `VdEnableRingBufferRPtrWriteBack wb=0x1FCA603C lenlog2=6`
   - `VdSetSystemCommandBufferGpuIdentifierAddress ea=0xFFCA5008`

### Why Initialization Chain Doesn't Execute

#### Problem 1: `sub_821BB4D0` Memory Allocator Hang
- **Location**: `Mw05RecompLib/ppc/ppc_recomp.12.cpp` lines 28793-28958
- **Issue**: First call tries to allocate 12MB, which hung in game's custom allocator
- **Root cause**: `sub_8215CB08` (memory allocator) calls indirect function via callback that wasn't initialized
- **Solution implemented**: Intercepted `sub_8215CB08` and replaced with `MmAllocatePhysicalMemoryEx` (following Xenia's approach)
- **Result**: 12MB allocation now succeeds, but function takes very long time or still hangs

#### Problem 2: Game Doesn't Naturally Progress
- The initialization chain is **NOT** being executed by the game naturally
- Even with memory allocator fixed, game doesn't reach graphics initialization
- Likely waiting for some event, condition, or stuck in synchronization

## Attempted Solutions

### Attempt 1: Force Call Initialization Chain
**Code location**: `Mw05Recomp/kernel/imports.cpp` vblank ISR (around line 1869)
- Tried calling `sub_821BB4D0` directly at tick 300
- Result: Function hangs or takes extremely long time

### Attempt 2: Call Graphics Functions Directly
- Tried calling `sub_825A85E0` directly
- Tried calling `VdSetGraphicsInterruptCallback` directly
- Result: Functions execute but context not properly initialized

### Attempt 3: Use Environment Variable Force Registration
**Environment variables**:
- `MW05_FORCE_GFX_NOTIFY_CB=1` - Enable forced callback registration
- `MW05_FORCE_GFX_NOTIFY_CB_CTX=0x40007180` - Set context pointer

**Code location**: `Mw05Recomp/kernel/imports.cpp` lines 5884-5908 (`Mw05ForceRegisterGfxNotifyIfRequested`)

**Result**:
```
[*] [vd] SetGraphicsInterruptCallback cb=0x825979A8 ctx=0x40007180
```
✅ Callback registered successfully
❌ Crashes at tick 60 with exception `0xC0000005` (access violation)
❌ Memory at context `0x40007180` doesn't exist - not allocated by game

## Key Technical Details

### Memory Allocator Interception
**File**: `Mw05Recomp/kernel/imports.cpp` lines 7382-7411

```cpp
void sub_8215CB08_debug(PPCContext& ctx, uint8_t* base) {
    uint32_t size = ctx.r3.u32;
    uint32_t alignment = (size >= 64 * 1024) ? 0x10000 : 0x1000;
    uint32_t result = MmAllocatePhysicalMemoryEx(0, size, PAGE_READWRITE, 0, 0xFFFFFFFF, alignment);
    ctx.r3.u32 = result;
}
```

**Hooks**: Lines 7487-7493
```cpp
GUEST_FUNCTION_HOOK(sub_8215CB08, sub_8215CB08_debug);
GUEST_FUNCTION_HOOK(sub_8215C790, sub_8215C790_debug);
GUEST_FUNCTION_HOOK(sub_8215C838, sub_8215C838_debug);
```

### Graphics Callback Function
**Address**: `0x825979A8`
**Context**: `0x40007180`
**File**: `Mw05RecompLib/ppc/ppc_recomp.72.cpp` lines 5447-5660

The callback:
1. Checks flag at `0x7FE86544`
2. Loads function pointer from `ctx + 15596`
3. Calls it to perform rendering work

### Ring Buffer Functions (Already Implemented)
**File**: `Mw05Recomp/kernel/imports.cpp`
- `VdInitializeRingBuffer` (lines 5718-5727)
- `VdEnableRingBufferRPtrWriteBack` (lines 5698-5716)
- `VdSetSystemCommandBufferGpuIdentifierAddress` (lines 5947-5951)

## Available Tools

### IDA HTML Scanners
1. **`tools/scan_ida_html.py`** - Parse IDA HTML export for functions and text
   ```bash
   python tools/scan_ida_html.py NfsMWEurope.xex.html --dump-func 825A85E0 --context 1500
   python tools/scan_ida_html.py NfsMWEurope.xex.html --locate 0x825A85E0
   ```

2. **`tools/scan_ida_html_2.py`** - Alternative scanner with different features
   ```bash
   python tools/scan_ida_html_2.py NfsMWEurope.xex.html --near 825A85
   python tools/scan_ida_html_2.py NfsMWEurope.xex.html --grep "VdInitializeEngines"
   ```

### Xenia Sources (for reference)
**Location**: `F:/XBox/xenia-canary/`
- Already patched for tracing
- Can be modified to extend tracing capabilities
- Key file: `src/xenia/kernel/xboxkrnl/xboxkrnl_video.cc`

### Xenia Trace Log
**Location**: `out/xenia/Debug/xenia.log`
- Contains complete execution trace from working Xenia run
- Shows exact sequence of kernel calls
- Shows when `VdSetGraphicsInterruptCallback` is called and with what parameters

## Repository Structure
- `Mw05Recomp/`: Application and platform code (ui/, gpu/, apu/, kernel/, install/)
- `Mw05RecompLib/`: Recompiled game library and generated PPC sources (ppc/)
- `Mw05RecompResources/`: Art/assets (no proprietary game data)
- `tools/`: Helper tools including IDA scanners
- `thirdparty/`: Vendored deps (includes thirdparty/vcpkg)
- `out/`: CMake/Ninja build output

## Build Commands
```powershell
# Configure
cmake --preset x64-Clang-Debug

# Build app only
./build_cmd.ps1 -Stage app

# Clean and rebuild
./build_cmd.ps1 -Clean -Stage codegen
./build_cmd.ps1 -Stage all
```

## Key Files Modified
1. `Mw05Recomp/kernel/imports.cpp` - Memory allocator interception, vblank ISR, VD functions
2. Generated PPC files (DO NOT EDIT MANUALLY):
   - `Mw05RecompLib/ppc/ppc_recomp.8.cpp` - Contains `sub_8215CB08` (allocator)
   - `Mw05RecompLib/ppc/ppc_recomp.12.cpp` - Contains `sub_821BB4D0` (init function)
   - `Mw05RecompLib/ppc/ppc_recomp.72.cpp` - Contains graphics callback `sub_825979A8`

## Next Steps / Open Questions

### Critical Questions
1. **Why doesn't the game naturally progress to graphics initialization?**
   - Is it waiting for a specific event?
   - Thread synchronization issue?
   - Stuck in a loop somewhere?

2. **What needs to happen before `sub_821BB4D0` can be called?**
   - What preconditions must be met?
   - What state must be initialized?

3. **How to properly initialize the context structure at `0x40007180`?**
   - What should this structure contain?
   - When/how does the game normally allocate it?
   - Can we analyze the structure layout from IDA?

### Possible Approaches
1. **Analyze `sub_825A85E0` in IDA** to understand what it does and what it needs
   - Use `tools/scan_ida_html.py --dump-func 825A85E0 --context 2000`
   - Understand the full initialization sequence

2. **Trace game execution** to find where it's stuck
   - Add logging to track thread states
   - Monitor what functions are being called
   - Identify blocking waits or infinite loops

3. **Allocate and initialize context structure manually**
   - Analyze structure at `0x40007180` in IDA
   - Allocate memory and initialize fields
   - Then register callback

4. **Find alternative initialization path**
   - Maybe there's a simpler path that doesn't require `sub_821BB4D0`
   - Look for other functions that call `VdSetGraphicsInterruptCallback`

## User Preferences
- Prefers automated research/debug with minimal interruptions
- Status updates only when game is ready to play
- Open to deeper Xenia debug tracing if needed
- Can route instructions to AI agent in Xenia repo if necessary

## Environment
- Windows 10/11
- LLVM at `$env:LLVM_HOME\bin` (standalone, not VS BuildTools)
- Game assets at `./game`
- Xenia sources at `F:/XBox/xenia-canary/`
- IDA export at `NfsMWEurope.xex.html`

