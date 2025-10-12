# PPC Recompiler Bug Investigation & Fix Instructions

## Executive Summary

The PPC-to-x64 recompiler (XenonRecomp) has a bug in function `sub_82813598` where the following instruction sequence produces incorrect results:

```assembly
.text:8281361C                 divw      r9, r10, r30      # r9 = 0xFF676980 / r3
.text:82813624                 extsw     r11, r9           # r11 = sign-extend(r9)
.text:8281363C                 std       r11, (qword_828F1F98 - 0x828F1F90)(r31)  # Store r11
```

**Expected behavior**: Store `0xFFFFFFFFFFFE7960` into `qword_828F1F98`  
**Actual behavior**: Stores `0x0000000000000000` instead

## Problem Context

### Function Details
- **Function**: `sub_82813598` (worker thread initialization)
- **Location**: `Mw05RecompLib/ppc/ppc_recomp.54.cpp` (generated file)
- **Address**: `0x82813598`
- **Purpose**: Initialize worker thread, set continuation flag, create Thread #2

### Input Parameters
- **r3** (parameter 1): `0x00000064` (100 decimal) - verified correct at runtime

### Expected Calculation
```
r10 = 0xFF676980 (constant loaded at line 0x82813608-0x82813614)
r30 = r3 = 0x00000064 (parameter, copied at line 0x828135A8: mr r30, r3)
r9 = divw(0xFF676980, 0x00000064) = 0xFFFE7960
r11 = extsw(0xFFFE7960) = 0xFFFFFFFFFFFE7960 (sign-extended to 64-bit)
Store r11 to qword_828F1F98
```

### Actual Result
- `qword_828F1F98` remains `0x0000000000000000` after function executes
- Workaround: Manually setting the value works, but recompiled code overwrites it back to 0

## Investigation Steps

### Step 1: Locate the Recompiler Source Code

1. **Find XenonRecomp repository/directory**:
   ```bash
   # Search for recompiler in the project
   find . -name "*recomp*" -type d
   # Look for tools that generate ppc_recomp.*.cpp files
   ls tools/
   ```

2. **Expected locations**:
   - `tools/XenonRecomp/` - Recompiler tool
   - `tools/recompiler/` - Alternative location
   - Check `CMakeLists.txt` for custom commands that generate PPC code

3. **Key files to find**:
   - Instruction emitters for `divw`, `extsw`, `std`
   - Register allocation/tracking code
   - Code generation for arithmetic operations

### Step 2: Understand the Recompiler Architecture

1. **Read the recompiler documentation**:
   - Look for `README.md` or `DESIGN.md` in the recompiler directory
   - Check for comments in the main recompiler source files

2. **Identify key components**:
   - **Instruction decoder**: Parses PPC assembly
   - **IR (Intermediate Representation)**: Internal representation of instructions
   - **Code generator**: Emits x64 code from IR
   - **Register allocator**: Maps PPC registers to x64 registers or memory

3. **Find the instruction handlers**:
   ```cpp
   // Search for these patterns in the recompiler source
   grep -r "divw" tools/
   grep -r "extsw" tools/
   grep -r "std" tools/
   ```

### Step 3: Analyze the Generated Code

1. **Locate the generated function**:
   ```bash
   # Find sub_82813598 in generated files
   grep -n "sub_82813598" Mw05RecompLib/ppc/ppc_recomp.*.cpp
   ```

2. **Examine the generated C++ code**:
   - Look for the division operation
   - Check how r9, r11, r30 are represented
   - Verify the store operation to `qword_828F1F98`

3. **Compare with expected behavior**:
   - Trace the data flow from r3 → r30 → division → r9 → r11 → memory
   - Identify where the value becomes 0

### Step 4: Debug the Specific Instructions

#### A. Debug `divw` (Divide Word)

**PPC Instruction**: `divw rD, rA, rB`
- Divides rA by rB (signed 32-bit division)
- Stores result in rD
- Result is 32-bit signed integer

**Expected implementation**:
```cpp
// Pseudo-code for divw r9, r10, r30
int32_t r10_val = (int32_t)ctx.r10.u32;
int32_t r30_val = (int32_t)ctx.r30.u32;
int32_t result = r10_val / r30_val;
ctx.r9.u32 = (uint32_t)result;
```

**Things to check**:
1. Is r30 being read correctly? (Should be 0x64)
2. Is r10 being read correctly? (Should be 0xFF676980)
3. Is the division using signed or unsigned arithmetic?
4. Is the result being truncated or sign-extended incorrectly?
5. Is there a divide-by-zero check that's incorrectly triggering?

**Debug approach**:
```cpp
// Add logging to the divw implementation
fprintf(stderr, "[DIVW-DEBUG] divw r%d, r%d, r%d\n", rD, rA, rB);
fprintf(stderr, "[DIVW-DEBUG] rA (r%d) = 0x%08X (%d)\n", rA, rA_val, (int32_t)rA_val);
fprintf(stderr, "[DIVW-DEBUG] rB (r%d) = 0x%08X (%d)\n", rB, rB_val, (int32_t)rB_val);
fprintf(stderr, "[DIVW-DEBUG] result = 0x%08X (%d)\n", result, (int32_t)result);
```

#### B. Debug `extsw` (Extend Sign Word)

**PPC Instruction**: `extsw rD, rS`
- Sign-extends a 32-bit value to 64-bit
- Copies bit 31 (sign bit) to bits 32-63

**Expected implementation**:
```cpp
// Pseudo-code for extsw r11, r9
int32_t r9_val = (int32_t)ctx.r9.u32;
int64_t result = (int64_t)r9_val;  // Sign-extend
ctx.r11.u64 = (uint64_t)result;
```

**Things to check**:
1. Is r9 being read as a 32-bit value?
2. Is the sign extension happening correctly?
3. Is the result being stored as a 64-bit value?
4. For 0xFFFE7960 (negative in 32-bit), should become 0xFFFFFFFFFFFE7960

**Debug approach**:
```cpp
// Add logging to the extsw implementation
fprintf(stderr, "[EXTSW-DEBUG] extsw r%d, r%d\n", rD, rS);
fprintf(stderr, "[EXTSW-DEBUG] rS (r%d) = 0x%08X (32-bit)\n", rS, rS_val_32);
fprintf(stderr, "[EXTSW-DEBUG] sign bit = %d\n", (rS_val_32 >> 31) & 1);
fprintf(stderr, "[EXTSW-DEBUG] result = 0x%016llX (64-bit)\n", result);
```

#### C. Debug `std` (Store Doubleword)

**PPC Instruction**: `std rS, offset(rA)`
- Stores 64-bit value from rS to memory at address (rA + offset)
- Big-endian byte order

**Expected implementation**:
```cpp
// Pseudo-code for std r11, offset(r31)
uint32_t addr = ctx.r31.u32 + offset;
uint64_t value = ctx.r11.u64;
uint64_t* ptr = (uint64_t*)TranslateAddress(addr);
*ptr = __builtin_bswap64(value);  // Convert to big-endian
```

**Things to check**:
1. Is the address calculation correct? (r31 + offset)
2. Is r11 being read as a 64-bit value?
3. Is the byte-swapping happening correctly?
4. Is the memory write actually executing?
5. Is the address valid and mapped?

**Debug approach**:
```cpp
// Add logging to the std implementation
fprintf(stderr, "[STD-DEBUG] std r%d, %d(r%d)\n", rS, offset, rA);
fprintf(stderr, "[STD-DEBUG] rA (r%d) = 0x%08X\n", rA, rA_val);
fprintf(stderr, "[STD-DEBUG] address = 0x%08X\n", addr);
fprintf(stderr, "[STD-DEBUG] value (r%d) = 0x%016llX\n", rS, value);
fprintf(stderr, "[STD-DEBUG] host ptr = %p\n", ptr);
fprintf(stderr, "[STD-DEBUG] writing big-endian value = 0x%016llX\n", __builtin_bswap64(value));
```

### Step 5: Check Register Preservation

**Potential issue**: r30 might not be preserved correctly across function calls

1. **Check the function prologue** (lines 0x82813598-0x828135A8):
   ```assembly
   .text:82813598                 mflr      r12
   .text:8281359C                 bl        __savegprlr_28    # Saves r28-r31
   .text:828135A0                 stwu      r1, -0x80(r1)
   .text:828135A8                 mr        r30, r3           # r30 = r3 (parameter)
   ```

2. **Verify r30 is saved/restored**:
   - `__savegprlr_28` should save r28-r31 to stack
   - Check if the recompiler correctly implements this

3. **Check if r30 is modified before the division**:
   - Trace all uses of r30 between line 0x828135A8 and 0x8281361C
   - Ensure no function calls or operations overwrite r30

### Step 6: Add Comprehensive Logging

Create a debug build of the recompiler with extensive logging:

```cpp
// In the code generator for sub_82813598
void GenerateFunction_82813598() {
    // At line 0x828135A8: mr r30, r3
    EmitLog("r30 = r3 = 0x%08X", ctx.r3.u32);
    
    // At line 0x8281361C: divw r9, r10, r30
    EmitLog("BEFORE divw: r10=0x%08X r30=0x%08X", ctx.r10.u32, ctx.r30.u32);
    EmitDivw(9, 10, 30);
    EmitLog("AFTER divw: r9=0x%08X", ctx.r9.u32);
    
    // At line 0x82813624: extsw r11, r9
    EmitLog("BEFORE extsw: r9=0x%08X", ctx.r9.u32);
    EmitExtsw(11, 9);
    EmitLog("AFTER extsw: r11=0x%016llX", ctx.r11.u64);
    
    // At line 0x8281363C: std r11, offset(r31)
    EmitLog("BEFORE std: r11=0x%016llX r31=0x%08X", ctx.r11.u64, ctx.r31.u32);
    EmitStd(11, offset, 31);
    EmitLog("AFTER std: memory[0x828F1F98]=0x%016llX", ReadMemory64(0x828F1F98));
}
```

### Step 7: Test the Fix

1. **Regenerate the PPC code**:
   ```bash
   # Clean old generated files
   ./build_cmd.ps1 -Clean -Stage codegen
   
   # Regenerate with fixed recompiler
   ./build_cmd.ps1 -Stage codegen
   ```

2. **Rebuild the application**:
   ```bash
   ./build_cmd.ps1 -Stage app
   ```

3. **Run the test**:
   ```bash
   out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe 2> test_output.txt
   ```

4. **Verify the fix**:
   ```bash
   # Check if qword_828F1F98 is set correctly
   grep "qword_828F1F98" test_output.txt
   
   # Check if Thread #2 is running (not completing immediately)
   grep "Thread.*COMPLETED" test_output.txt
   ```

## Expected Outcomes

### Success Criteria

1. **qword_828F1F98 is set to 0xFFFFFFFFFFFE7960** after sub_82813598 executes
2. **Thread #2 does NOT complete immediately** - it should run in a loop
3. **No workaround needed** - the recompiled code works correctly

### Verification

```bash
# Should see this in the log:
[WORKER-INIT] AFTER: qword_828F1F98 = 0xFFFFFFFFFFFE7960
[WORKER-INIT] SUCCESS: qword_828F1F98 is set to non-zero value!

# Should NOT see this:
[WORKER-INIT] WARNING: qword_828F1F98 is still 0!
[GUEST_THREAD] Thread tid=XXXXX entry=82812ED0 COMPLETED
```

## Common Pitfalls

1. **Endianness issues**: PPC is big-endian, x64 is little-endian
   - All memory reads/writes need byte-swapping
   - Register values are stored in host byte order

2. **32-bit vs 64-bit operations**:
   - PPC has both 32-bit and 64-bit registers
   - Ensure operations use the correct size

3. **Signed vs unsigned arithmetic**:
   - `divw` is SIGNED division
   - `divwu` is UNSIGNED division
   - Don't confuse them!

4. **Register aliasing**:
   - Some PPC registers might be aliased in the recompiler
   - Ensure r9, r11, r30 are independent

5. **Optimization issues**:
   - Compiler optimizations might reorder operations
   - Use `volatile` or memory barriers if needed

## Additional Resources

### Assembly Reference
- **Line 0x828135A8**: `mr r30, r3` - Copy r3 to r30
- **Line 0x82813608-0x82813614**: Load constant 0xFF676980 into r10
- **Line 0x8281361C**: `divw r9, r10, r30` - r9 = r10 / r30
- **Line 0x82813624**: `extsw r11, r9` - Sign-extend r9 to 64-bit
- **Line 0x82813638**: `twllei r30, 0` - Trap if r30 <= 0 (should not fire)
- **Line 0x8281363C**: `std r11, (qword_828F1F98)` - Store r11 to memory

### Memory Addresses
- **qword_828F1F98**: Worker thread continuation flag
- **dword_828F1F90**: Base address for offset calculation
- **Offset**: `qword_828F1F98 - dword_828F1F90 = 0x8`

### Current Workaround Location
- **File**: `Mw05Recomp/cpu/mw05_trace_threads.cpp`
- **Function**: `sub_82813598` (wrapper)
- **Lines**: ~534-560
- **Workaround**: Manually calculates and sets qword_828F1F98 before/after function call

## Contact & Questions

If you need more information:
1. Check `AGENTS.md` for current debugging status
2. Review `tools/xenia.log` for reference behavior from working emulator
3. Check `Mw05Recomp/cpu/mw05_trace_threads.cpp` for current workaround implementation
4. Run `./run_with_debug.ps1` for automated testing with logs

Good luck fixing the recompiler! 🚀

