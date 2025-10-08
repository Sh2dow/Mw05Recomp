# Code Snippets and Implementation Details

## Current Memory Allocator Interception

### Location: `Mw05Recomp/kernel/imports.cpp`

#### Debug Wrapper (lines 7382-7411)
```cpp
void sub_8215CB08_debug(PPCContext& ctx, uint8_t* base) {
    int depth = s_debug_call_depth.fetch_add(1);
    uint32_t size = ctx.r3.u32;
    uint32_t flags = ctx.r4.u32;
    fprintf(stderr, "[MW05_DEBUG] [depth=%d] ENTER sub_8215CB08 r3=%08X (size=%u bytes = %u KB) r4=%08X\n", 
            depth, size, size, size/1024, flags);
    fflush(stderr);
    
    // INTERCEPT: Handle memory allocation ourselves like Xenia does
    // Instead of calling the game's broken allocator, use our own memory allocation
    uint32_t alignment = 0x1000;  // 4KB default
    if (size >= 64 * 1024) {
        alignment = 0x10000;  // 64KB for large allocations
    }
    
    // Allocate from physical memory using MmAllocatePhysicalMemoryEx
    uint32_t result = MmAllocatePhysicalMemoryEx(0, size, PAGE_READWRITE, 0, 0xFFFFFFFF, alignment);
    
    if (result == 0) {
        fprintf(stderr, "[MW05_DEBUG] [depth=%d] FAILED sub_8215CB08 - MmAllocatePhysicalMemoryEx returned 0 for size=%u\n", 
                depth, size);
    } else {
        fprintf(stderr, "[MW05_DEBUG] [depth=%d] SUCCESS sub_8215CB08 - allocated %u bytes at %08X\n", 
                depth, size, result);
    }
    
    ctx.r3.u32 = result;
    fflush(stderr);
    s_debug_call_depth.fetch_sub(1);
}
```

#### Function Hooks (lines 7487-7493)
```cpp
GUEST_FUNCTION_HOOK(sub_8215CB08, sub_8215CB08_debug);
GUEST_FUNCTION_HOOK(sub_8215C790, sub_8215C790_debug);
GUEST_FUNCTION_HOOK(sub_8215C838, sub_8215C838_debug);
GUEST_FUNCTION_HOOK(sub_821B2C28, sub_821B2C28_debug);
GUEST_FUNCTION_HOOK(sub_821B71E0, sub_821B71E0_debug);
GUEST_FUNCTION_HOOK(sub_821B7C28, sub_821B7C28_debug);
GUEST_FUNCTION_HOOK(sub_821BB4D0, sub_821BB4D0_debug);
```

## Force Graphics Callback Registration

### Location: `Mw05Recomp/kernel/imports.cpp` lines 5884-5908

```cpp
static void Mw05ForceRegisterGfxNotifyIfRequested() {
    const char* en = std::getenv("MW05_FORCE_GFX_NOTIFY_CB");
    if (!en || (en[0]=='0' && en[1]=='\0')) return;
    
    // Default EA from known-good Xenia capture if not provided via MW05_FORCE_GFX_NOTIFY_CB_EA
    uint32_t cb_ea = 0x825979A8u;
    if (const char* s = std::getenv("MW05_FORCE_GFX_NOTIFY_CB_EA")) {
        cb_ea = (uint32_t)std::strtoul(s, nullptr, 0);
    }
    
    uint32_t ctx = 1u;
    if (const char* c = std::getenv("MW05_FORCE_GFX_NOTIFY_CB_CTX")) {
        ctx = (uint32_t)std::strtoul(c, nullptr, 0);
    }
    
    // Only install if caller hasn't already set a real ISR (avoid overriding guest)
    if (auto cur = VdGetGraphicsInterruptCallback(); cur == 0 || cur == kHostDefaultVdIsrMagic) {
        KernelTraceHostOpF("HOST.VdISR.force_register cb=%08X ctx=%08X", cb_ea, ctx);
        VdSetGraphicsInterruptCallback(cb_ea, ctx);
        // Also register into notification list so VdCallGraphicsNotificationRoutines hits it
        VdRegisterGraphicsNotificationRoutine(cb_ea, ctx);
        Mw05LogIsrIfRegisteredOnce();
        // Immediately drive one notify so the newly registered ISR runs right away
        VdCallGraphicsNotificationRoutines(0u);
    } else {
        KernelTraceHostOp("HOST.VdISR.force_register.skipped (already set)\n");
    }
}
```

### Usage
```batch
set MW05_FORCE_GFX_NOTIFY_CB=1
set MW05_FORCE_GFX_NOTIFY_CB_CTX=0x40007180
out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe
```

## VD Functions Implementation

### VdSetGraphicsInterruptCallback (lines 6018-6024)
```cpp
void VdSetGraphicsInterruptCallback(uint32_t callback, uint32_t context)
{
    g_VdGraphicsCallback = callback;
    g_VdGraphicsCallbackCtx = context;
    LOGFN("[vd] SetGraphicsInterruptCallback cb=0x{:08X} ctx=0x{:08X}", callback, context);
    KernelTraceHostOpF("HOST.VdSetGraphicsInterruptCallback cb=%08X ctx=%08X", callback, context);
}
```

### VdInitializeRingBuffer (lines 5718-5727)
```cpp
void VdInitializeRingBuffer(uint32_t base, uint32_t len)
{
    KernelTraceHostOpF("HOST.VdInitializeRingBuffer base=%08X len_log2=%u", base, len);
    if (auto* ctx = GetPPCContext()) {
        KernelTraceHostOpF("HOST.VdInitializeRingBuffer.caller lr=%08X", (uint32_t)ctx->lr);
    }
    // MW05 (and Xenia logs) pass the ring buffer size as log2(len).
    // Convert to bytes to ensure we zero the correct range so readers see a clean buffer.
    g_RbBase = base;
    g_RbLen = len;
    // ... (rest of implementation)
}
```

### VdEnableRingBufferRPtrWriteBack (lines 5698-5716)
```cpp
void VdEnableRingBufferRPtrWriteBack(uint32_t base)
{
    KernelTraceHostOpF("HOST.VdEnableRingBufferRPtrWriteBack base=%08X", base);
    // Record write-back pointer; zero it to indicate idle.
    g_RbWriteBackPtr = base;
    auto* p = reinterpret_cast<uint32_t*>(g_memory.Translate(base));
    if (p) *p = 0;
    g_vdInterruptPending.store(true, std::memory_order_release);
    
    // default it to the write-back area at base+8 so MW05_HOST_ISR_TICK_SYSID has a target.
    if (g_VdSystemCommandBufferGpuIdAddr.load(std::memory_order_acquire) == 0) {
        VdSetSystemCommandBufferGpuIdentifierAddress(base + 8);
        KernelTraceHostOpF("HOST.VdSetSystemCommandBufferGpuIdentifierAddress.addr.auto base=%08X ea=%08X", base, base + 8);
    }
    
    Mw05DispatchVdInterruptIfPending();
    Mw05StartVblankPumpOnce();
}
```

## Xenia Reference Implementation

### From `F:/XBox/xenia-canary/src/xenia/kernel/xboxkrnl/xboxkrnl_video.cc`

```cpp
dword_result_t VdInitializeEngines_entry(unknown_t unk0, function_t callback,
                                         lpvoid_t arg, lpdword_t pfp_ptr,
                                         lpdword_t me_ptr) {
    // r3 = 0x4F810000
    // r4 = function ptr (cleanup callback?)
    // r5 = function arg
    // r6 = PFP Microcode
    // r7 = ME Microcode
    auto tls = XThread::GetCurrentThread();
    auto ts = tls ? tls->thread_state() : nullptr;
    auto ctx = ts ? ts->context() : nullptr;
    uint32_t lr = ctx ? static_cast<uint32_t>(ctx->lr) : 0;
    XELOGI("VdInitializeEngines unk0=0x%08X cb=0x%08X arg=0x%08X pfp_ptr=0x%08X me_ptr=0x%08X lr=0x%08X",
           unk0, callback.guest_address(), arg.guest_address(),
           pfp_ptr.guest_address(), me_ptr.guest_address(), lr);
    // ... implementation
}
```

## Xenia Trace Log Excerpt

```
i> F800000C [MW05] VdInitializeEngines unk0=0x08570000 cb=0x825A85C8 arg=0x00000000 pfp_ptr=0x00000000 me_ptr=0x00000000 lr=0x825A8610
i> 01000014 [MW05] MarkVblank tick
i> F800000C [MW05] VdSetGraphicsInterruptCallback cb=0x825979A8 ctx=0x40007180
i> 01000014 [MW05] GPU counter increment: 70 -> 71
i> 01000014 [MW05] VD notify source=0 cb=0x825979A8 data=0x40007180
i> 0100001C [MW05] KeSetEvent ea=0x400007E0 incr=0 wait=0 signal_state=1
i> F800000C [MW05] VdSetSystemCommandBufferGpuIdentifierAddress ea=0x00000000 lr=0x825982E0
i> F800000C [MW05] VdInitializeRingBuffer base=0x0A0F8000 size_log2=12 lr=0x82598434
i> F800000C [MW05] VdEnableRingBufferRPtrWriteBack wb=0x1FCA603C lenlog2=6 lr=0x8259846C
i> F800000C [MW05] VdSetSystemCommandBufferGpuIdentifierAddress ea=0xFFCA5008 lr=0x82598524
```

## Function Call Chain Analysis

### From Xenia Trace
```
sub_823AF590 (unknown entry point)
  ↓
sub_821BB4D0 (memory/resource initialization)
  ↓ (hangs here - 12MB allocation issue)
sub_82216088 (graphics initialization entry)
  ↓
sub_825A16A0
  ↓
sub_825A8698
  ↓
sub_825A85E0 (calls VdInitializeEngines + VdSetGraphicsInterruptCallback)
  ↓
VdInitializeEngines(0x08570000, 0x825A85C8, 0, 0, 0)
VdSetGraphicsInterruptCallback(0x825979A8, 0x40007180)
```

### Graphics Callback Function
**Address**: `0x825979A8`
**File**: `Mw05RecompLib/ppc/ppc_recomp.72.cpp` lines 5447-5660

Pseudo-code:
```cpp
void sub_825979A8(PPCContext& ctx, uint8_t* base) {
    uint32_t source = ctx.r3.u32;      // 0 for vblank, 1 for other
    uint32_t context = ctx.r4.u32;     // 0x40007180
    
    // Check flag at 0x7FE86544
    uint32_t flag = PPC_LOAD_U32(base, 0x7FE86544);
    if (flag != 0) {
        // Load function pointer from context + 15596 (0x3CEC)
        uint32_t func_ptr = PPC_LOAD_U32(base, context + 15596);
        if (func_ptr != 0) {
            // Call the function to perform rendering work
            PPC_CALL_INDIRECT_FUNC(func_ptr);
        }
    }
}
```

## IDA HTML Scanner Usage Examples

### Dump Function Context
```bash
python tools/scan_ida_html.py NfsMWEurope.xex.html --dump-func 825A85E0 --context 2000
python tools/scan_ida_html.py NfsMWEurope.xex.html --dump-func 821BB4D0 --context 1500
```

### Locate Function by Address
```bash
python tools/scan_ida_html.py NfsMWEurope.xex.html --locate 0x825979A8
python tools/scan_ida_html.py NfsMWEurope.xex.html --locate 0x40007180
```

### Find Functions in Range
```bash
python tools/scan_ida_html.py NfsMWEurope.xex.html --find 825A85
python tools/scan_ida_html_2.py NfsMWEurope.xex.html --near 821BB4
```

### Search for Text
```bash
python tools/scan_ida_html.py NfsMWEurope.xex.html --grep "VdInitializeEngines" --context 400
python tools/scan_ida_html.py NfsMWEurope.xex.html --grep "VdSetGraphicsInterruptCallback" --context 400
```

## Debugging Commands

### Run with Environment Variables
```batch
set MW05_FORCE_GFX_NOTIFY_CB=1
set MW05_FORCE_GFX_NOTIFY_CB_CTX=0x40007180
out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe
```

### Filter Output for Key Events
```powershell
out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe 2>&1 | Select-String -Pattern "VdSetGraphicsInterruptCallback|VdInitializeRingBuffer|DRAW|TYPE3|VD notify"
```

### Check Xenia Log
```powershell
Get-Content 'out/xenia/Debug/xenia.log' | Select-String -Pattern 'VdInitializeEngines|VdSetGraphicsInterruptCallback|VdInitializeRingBuffer'
```

## Memory Map
```
0x00000000-0x3FFFFFFF: System memory
0x40000000-0x7FFFFFFF: User memory (context at 0x40007180 should be here)
0x80000000-0x9FFFFFFF: XEX image (code at 0x82000000)
0xA0000000-0xBFFFFFFF: Physical memory allocations
0xC0000000-0xDFFFFFFF: Additional allocations
0xE0000000-0xFFFFFFFF: System reserved
```

## Known Issues

1. **Context structure at `0x40007180` not allocated**
   - Causes crash when callback is invoked
   - Need to either allocate manually or wait for game to allocate

2. **`sub_821BB4D0` takes too long or hangs**
   - Even with memory allocator fix
   - Prevents natural progression to graphics init

3. **Game doesn't naturally call initialization chain**
   - Unknown why it's not progressing
   - May be waiting for event or stuck in loop

4. **Ring buffer not initialized**
   - Even when callback is registered
   - Need to call ring buffer init functions after callback registration

