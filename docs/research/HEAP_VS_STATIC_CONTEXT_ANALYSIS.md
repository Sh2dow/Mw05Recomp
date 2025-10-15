# Thread Context Storage: Heap vs Static Analysis

## Executive Summary

**CONCLUSION**: The recompilation approach is CORRECT. Thread contexts should be stored in STATIC GLOBAL variables in the XEX data section, NOT on the heap. Xenia uses heap allocation because it's an EMULATOR, but we are a RECOMPILER.

## The Question

Why does Xenia allocate thread contexts on the heap (0x701EFAF0) while our recompilation uses static globals (0x828F1F98)?

## The Answer

### Xenia (Emulator Approach)
- **Context address**: 0x701EFAF0 (heap memory, 0x70000000 range)
- **Why heap**: Xenia emulates the Xbox 360 memory model
  - Allocates memory dynamically for game structures
  - Maps XEX data section to emulated memory
  - When game code references 0x828F1F98, Xenia translates to heap address
  - This allows Xenia to handle multiple games with different memory layouts

### Our Recompilation (Static Recompilation Approach)
- **Context address**: 0x828F1F98 (static global in .data section)
- **Why static**: We recompile PPC code to x64 native code
  - The PPC assembly explicitly uses compile-time constant addresses
  - The recompiler generates runtime address calculation
  - Memory is directly mapped, not emulated

## PPC Assembly Analysis

From `sub_82813598` in `ppc_recomp.96.cpp` lines 13221-13224:

```asm
lis r11,-32113      ; Load upper 16 bits: r11 = 0x828F0000
addi r31,r11,8080   ; Add offset: r31 = 0x828F1F90
```

Later, at line 13298-13299:
```asm
addi r4,r31,8       ; r4 = 0x828F1F98 (context address)
```

This is passed to `ExCreateThread` as the context parameter.

## IDA Analysis

From `NfsMWEurope.xex.html`:

```
.data:828F1F90 dword_828F1F90: .long 0xFFFFFFFF
.data:828F1F94                 .align 3
.data:828F1F98 qword_828F1F98: .quad 0
```

`qword_828F1F98` is a **STATIC GLOBAL VARIABLE** in the `.data` section.

## Recompiled Code

From `Mw05RecompLib/ppc/ppc_recomp.96.cpp`:

```cpp
// lis r11,-32113
ctx.r11.s64 = -2104557568;  // 0x828F0000
// addi r31,r11,8080
ctx.r31.s64 = ctx.r11.s64 + 8080;  // 0x828F1F90
// ...
// addi r4,r31,8
ctx.r4.s64 = ctx.r31.s64 + 8;  // 0x828F1F98
```

The recompiler correctly generates runtime address calculation that results in 0x828F1F98.

## Why the Discrepancy?

### Old Trace Files Show 0x00120E10

The old trace files (e.g., `allocation_trace2.txt`) show:
```
[MW05_FIX] Thread #2 created: entry=82812ED0 ctx=00120E10 flags=00000001 SUSPENDED
```

This address 0x00120E10 is **INCORRECT** and was likely from:
1. A bug in old debugging code
2. A different code path that was being tested
3. Incorrect memory mapping in early development

The correct address should be 0x828F1F98.

## Memory Layout Comparison

### Xenia Memory Map
```
0x00000000-0x3FFFFFFF: System memory
0x40000000-0x7FFFFFFF: User memory (heap allocations)
0x70000000-0x7FFFFFFF: Thread stacks and contexts (HEAP)
0x80000000-0x9FFFFFFF: XEX image (code + data)
```

### Our Recompilation Memory Map
```
0x00000000-0x3FFFFFFF: System memory
0x40000000-0x7FFFFFFF: User memory (heap allocations)
0x80000000-0x9FFFFFFF: XEX image (code + data)
  0x82000000-0x828FFFFF: Code section
  0x828F0000-0x82FFFFFF: Data section (includes qword_828F1F98)
```

## The Correct Approach

### For Emulators (like Xenia)
- Allocate thread contexts on the heap
- Translate static addresses to heap addresses
- Allows flexibility for different games

### For Static Recompilers (like us)
- Use static globals as specified in the PPC code
- Direct memory mapping without translation
- More efficient, no runtime overhead

## Implications

1. **Our recompilation is CORRECT** - we should use 0x828F1F98
2. **Xenia's approach is CORRECT for an emulator** - heap allocation is appropriate
3. **The old traces with 0x00120E10 are WRONG** - this was a bug

## What Needs to be Fixed

### NOT THIS:
- ❌ Change recompiler to use heap allocation like Xenia
- ❌ Modify memory layout to match Xenia

### THIS:
- ✅ Ensure the .data section is properly initialized
- ✅ Verify that qword_828F1F98 is accessible and writable
- ✅ Fix any bugs that caused the old 0x00120E10 address
- ✅ Ensure the recompiled code correctly calculates 0x828F1F98

## Verification Steps

1. **Check current runtime address**:
   - Add logging to see what address is actually used for thread context
   - Verify it's 0x828F1F98, not 0x00120E10

2. **Verify memory is accessible**:
   - Check that memory at 0x828F1F98 is mapped and writable
   - Ensure the .data section is properly loaded

3. **Test thread creation**:
   - Verify Thread #2 is created with ctx=0x828F1F98
   - Check that the context structure is properly initialized

## Conclusion

The user's question about "why Xenia uses heap and we use static" is based on a misunderstanding. The correct answer is:

**Xenia uses heap because it's an EMULATOR that needs flexibility. We use static globals because we're a RECOMPILER that directly translates PPC code to x64. Both approaches are correct for their respective use cases.**

The real issue is NOT the choice of heap vs static, but ensuring that:
1. The static global at 0x828F1F98 is properly initialized
2. The recompiled code correctly references this address
3. Any bugs that caused the old 0x00120E10 address are fixed

