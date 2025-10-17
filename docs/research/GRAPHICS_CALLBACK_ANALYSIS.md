# Graphics Callback Analysis - sub_825979A8

**Date**: 2025-10-17  
**Function**: `sub_825979A8` (VD Graphics Interrupt Callback)  
**Status**: 🔍 **ANALYZING** - Understanding what the callback does

## Function Signature

```c
void __fastcall sub_825979A8(
    int a1,        // r3 - Interrupt type (0 or 1)
    _DWORD *a2,    // r4 - Graphics context pointer
    int a3,        // r5
    int a4,        // r6
    int a5,        // r7
    int a6,        // r8
    __int64 a7     // r9-r10
)
```

## Decompiled Code Analysis

### Branch 1: CPU Interrupt (a1 == 1)

```c
if ( a1 == 1 )
{
    LODWORD(a7) = a2[2597];                    // Load structure pointer from context+0x2894
    v10 = *(_DWORD *)(a7 + 16);                // Load function pointer from structure+0x10
    
    if ( v10 == 195948557 )                    // Check for magic value 0x0BADF00D
    {
        sub_825A58C0("ERR[D3D]: Unanticipated CPU_INTERRUPT. Sign of a corrupt command buffer?\n", ...);
        __trap();                              // CRASH!
    }
    
    if ( v10 )                                 // If function pointer is not NULL
    {
        __asm { mtspr CTR, r30 }              // Load function pointer into CTR register
        v8(*(_DWORD **)(a2[2597] + 20));      // Call through CTR (indirect call)
    }
    
    // Spinlock operations
    v11 = a2 + 2598;                          // Spinlock at context+0x2898
    v12 = (int *)a2[2597];                    // Structure pointer
    v14 = 1 << *(_BYTE *)(v7 + 268);          // Calculate bit mask
    KeAcquireSpinLockAtRaisedIrql(v13);       // Acquire spinlock
    *v12 = (unsigned __int8)*v12 & (unsigned __int8)~(_BYTE)v14 & 0x3F;  // Clear bit
    KeReleaseSpinLockFromRaisedIrql(v11);     // Release spinlock
}
```

**Analysis**:
- This branch handles **CPU interrupts** (a1 == 1)
- Loads a function pointer from `*(context + 0x2894) + 0x10`
- **CRITICAL**: If the function pointer is `0x0BADF00D`, it crashes with "corrupt command buffer" error
- If the function pointer is valid (non-zero), it calls through CTR register
- Then acquires a spinlock and clears a bit in the structure

**This is the code path mentioned in AGENTS.md that crashes with NULL function pointers!**

### Branch 2: VBlank Interrupt (a1 == 0)

```c
else if ( !a1 && (MEMORY[0x7FC86544] & 1) != 0 )  // VBlank interrupt AND flag is set
{
    v15 = a2[3902];                               // Load counter from context+0x3CF8
    ++a2[3900];                                   // Increment frame counter at context+0x3CF0
    
    if ( v15 > 0 )                                // If counter > 0
    {
        v16 = v15 - 1;                            // Decrement counter
        a2[3902] = v16;                           // Store decremented value
        
        if ( !v16 )                               // If counter reached 0
        {
            *(_DWORD *)(a2[2597] + 4) = 0;        // Clear field at structure+0x04
            a2[3901] = a2[3900];                  // Copy frame counter to context+0x3CF4
        }
    }
    
    if ( a2[3899] )                               // If callback pointer is set (context+0x3CEC)
    {
        v23[1] = a2[3903];                        // Prepare callback arguments
        v23[2] = 0;
        v23[0] = a2[3900];                        // Frame counter
        __asm { mtspr CTR, r11 }                  // Load callback pointer into CTR
        v8(v23);                                  // Call callback with arguments
    }
}
```

**Analysis**:
- This branch handles **VBlank interrupts** (a1 == 0)
- Checks if flag at `MEMORY[0x7FC86544]` is set (this is the VD ISR flag we set in our code!)
- Increments a frame counter at `context+0x3CF0`
- Decrements a countdown timer at `context+0x3CF8`
- When the countdown reaches 0, it clears a field and copies the frame counter
- If a callback pointer is set at `context+0x3CEC`, it calls that callback with frame counter as argument

**This is the PRESENT callback path!**

## Structure Layout

Based on the decompiled code, the graphics context structure has these fields:

```c
struct GraphicsContext {
    // ... (first 0x2894 bytes unknown)
    
    // +0x2894 (offset 10388, a2[2597])
    void* inner_structure;           // Pointer to inner structure
    
    // +0x2898 (offset 10392, a2[2598])
    KSPIN_LOCK spinlock;             // Spinlock for synchronization
    
    // ... (more fields)
    
    // +0x3CEC (offset 15596, a2[3899])
    void* present_callback;          // Present callback function pointer
    
    // +0x3CF0 (offset 15600, a2[3900])
    uint32_t frame_counter;          // Frame counter (incremented every VBlank)
    
    // +0x3CF4 (offset 15604, a2[3901])
    uint32_t frame_snapshot;         // Snapshot of frame counter
    
    // +0x3CF8 (offset 15608, a2[3902])
    uint32_t countdown_timer;        // Countdown timer
    
    // +0x3CFC (offset 15612, a2[3903])
    uint32_t callback_arg;           // Argument to pass to present callback
};

struct InnerStructure {
    uint32_t field_00;               // +0x00
    uint32_t field_04;               // +0x04 - Cleared when countdown reaches 0
    uint32_t field_08;               // +0x08
    uint32_t field_0C;               // +0x0C
    uint32_t callback_ptr;           // +0x10 - Function pointer (can be NULL or 0xBADF00D)
    uint32_t callback_arg;           // +0x14 - Argument to pass to callback
    // ... more fields
};
```

## Key Findings

### 1. Present Callback is Being Called ✅

The VBlank interrupt path (a1 == 0) calls the present callback at `context+0x3CEC` with the frame counter as argument.

From our trace log:
```
[HOST] import=HOST.VblankPump.guest_isr.call ticks=2 cb=825979A8 ctx=00040360 count=0
[HOST] import=sub_82598A20.PRESENT enter lr=82597AB4 r3=000991C0 r4=00040360
```

This confirms that:
- The graphics callback (0x825979A8) is being called
- The present callback (0x82598A20) is being called from the graphics callback
- The frame counter is being incremented

### 2. CPU Interrupt Path is NOT Being Called ❌

The CPU interrupt path (a1 == 1) is the one that calls the function pointer at `*(context + 0x2894) + 0x10`.

This is the path that was crashing with NULL function pointers in the AGENTS.md analysis!

**Question**: Why is the CPU interrupt path not being called? Is it supposed to be called?

### 3. The Present Callback Does NOT Create Render Threads ❌

Looking at the decompiled code, the present callback (sub_82598A20) is called from the VBlank interrupt path, but it doesn't create any threads. It just:
1. Increments the frame counter
2. Calls the present callback with the frame counter

**This means the render threads must be created somewhere else!**

## Comparison with Xenia

From AGENTS.md:
```
Line 35788+: VD notify callback invoked, NEW THREAD created
Line 317731: First draw command issued!
```

Xenia shows that the VD notify callback triggers **NEW THREAD CREATION**. But our decompiled code doesn't show any thread creation in the graphics callback!

**Hypothesis**: The thread creation happens in the **PRESENT CALLBACK** (sub_82598A20), not in the graphics callback (sub_825979A8).

## Next Steps

### 1. Analyze Present Callback (sub_82598A20)
Decompile and analyze the present callback to see if it creates render threads.

**Action**: Fetch decompiled code for sub_82598A20 from IDA.

### 2. Check Thread Creation Functions
Search for calls to `ExCreateThread` or `PsCreateSystemThread` in the game code.

**Action**: Use IDA to find all thread creation calls.

### 3. Compare with Xenia Thread Creation
Check the Xenia log to see exactly when and where threads are created.

**Action**: Search Xenia log for thread creation messages.

### 4. Check for Missing Kernel Functions
The game might be calling kernel functions that are not implemented, causing thread creation to fail silently.

**Action**: Enable full kernel function tracing and look for STUB messages.

## Critical Questions

1. **Why is the CPU interrupt path (a1 == 1) not being called?**
   - Is it supposed to be called?
   - What triggers a CPU interrupt?
   - Is there a missing initialization step?

2. **Where are the render threads created?**
   - In the present callback (sub_82598A20)?
   - In some other initialization function?
   - Are they created at all?

3. **Why is the ring buffer cleared but empty?**
   - Is the game waiting for something before writing PM4 commands?
   - Is there a missing synchronization primitive?
   - Is there a missing kernel function?

## References

- [NO_DRAWS_ROOT_CAUSE.md](NO_DRAWS_ROOT_CAUSE.md) - Root cause analysis
- [AGENTS.md](../../AGENTS.md) - Current status and debugging information
- IDA Pro decompilation: `http://127.0.0.1:5050/decompile?ea=0x825979A8`
- [Mw05Recomp/kernel/imports.cpp](../../Mw05Recomp/kernel/imports.cpp) - VdSetGraphicsInterruptCallback implementation

## Conclusion

The graphics callback (sub_825979A8) has two paths:
1. **CPU interrupt path** (a1 == 1) - Calls function pointer at `*(context + 0x2894) + 0x10` (NOT being called)
2. **VBlank interrupt path** (a1 == 0) - Calls present callback at `context+0x3CEC` (BEING called)

The present callback is being called every frame, but it's not creating render threads or writing PM4 commands.

**Next action**: Analyze the present callback (sub_82598A20) to see what it's doing and why it's not creating render threads.

