# Crash Analysis - Divide by Zero Exception

**Date**: 2025-10-21  
**Exception**: 0xC0000094 (STATUS_INTEGER_DIVIDE_BY_ZERO)  
**Status**: Investigating

## Crash Details

```
[EXCEPTION] code=0xC0000094 addr=00007FF7F6ADCD84 tid=00007F2C
[*] [crash] unhandled exception code=0xC0000094 addr=0x7ff7f6adcd84 tid=00007F2C
[*] [crash]   frame[0] = 0x7ff7f54897fe module=Mw05Recomp.exe base=0x7ff7f5480000 +0x97FE
[*] [crash]   frame[1] = 0x7ff7f5488c1f module=Mw05Recomp.exe base=0x7ff7f5480000 +0x8C1F
[*] [crash]   frame[2] = 0x7ff7f5488bc7 module=Mw05Recomp.exe base=0x7ff7f5480000 +0x8BC7
```

**Exception Code**: 0xC0000094 = STATUS_INTEGER_DIVIDE_BY_ZERO  
**Crash Address**: 0x7ff7f6adcd84 (offset +0x165CD84 from base)  
**Thread ID**: 0x7F2C

## NULL-CALL Messages Before Crash

```
[NULL-CALL] lr=8218B23C target=00000000 r3=00000004 r31=829065FC r4=00000000
[NULL-CALL] lr=821AFD48 target=00000000 r3=00000000 r31=829065FC r4=0000C800
[NULL-CALL] lr=821AFD60 target=00000000 r3=00000001 r31=829065FC r4=00000000
[NULL-CALL] lr=821956E0 target=00000000 r3=00000005 r31=82062C24 r4=8206CC18
[NULL-CALL] lr=82195538 target=00000000 r3=00000000 r31=82A30AE8 r4=8206CBF4
```

**Analysis**:
- NULL-CALL messages are EXPECTED behavior (game calls NULL function pointers, we catch and return 0)
- These are NOT the cause of the crash
- The crash is a divide-by-zero exception in HOST code (not PPC code)

## Hypothesis

The divide-by-zero crash is likely in:
1. **PM4 processing code** - Dividing by packet count or buffer size
2. **Frame timing code** - Dividing by frame time or FPS
3. **Heap statistics code** - Dividing by allocation count
4. **Thread scheduling code** - Dividing by thread count

## Investigation Steps

### Step 1: Use CDB to Break on Exception

```batch
scripts\debug_crash.cmd
```

This will launch CDB and break on first-chance divide-by-zero exception.

**When CDB breaks**:
```
# Show call stack
k

# Show registers
r

# Disassemble at crash location
u

# Show local variables
dv

# Continue to see if it's recoverable
g
```

### Step 2: Identify Crash Location

From call stack frame[0] = +0x97FE, we need to find which function this is.

**Using addr2line** (if available):
```batch
addr2line -e out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe 0x97FE
```

**Using CDB**:
```
# In CDB, when broken at crash:
ln 0x7ff7f54897fe
```

This will show the function name and offset.

### Step 3: Check for Common Divide-by-Zero Patterns

**Pattern 1: FPS Calculation**
```cpp
// WRONG
float fps = 1000.0f / frame_time;  // Crash if frame_time == 0

// RIGHT
float fps = (frame_time > 0) ? (1000.0f / frame_time) : 0.0f;
```

**Pattern 2: PM4 Buffer Size**
```cpp
// WRONG
int packets_per_frame = total_packets / frame_count;  // Crash if frame_count == 0

// RIGHT
int packets_per_frame = (frame_count > 0) ? (total_packets / frame_count) : 0;
```

**Pattern 3: Heap Statistics**
```cpp
// WRONG
size_t avg_alloc_size = total_allocated / alloc_count;  // Crash if alloc_count == 0

// RIGHT
size_t avg_alloc_size = (alloc_count > 0) ? (total_allocated / alloc_count) : 0;
```

### Step 4: Fix Root Cause

Once we identify the crash location:
1. Add NULL/zero check before division
2. Add assertion to catch this in debug builds
3. Add logging to understand why the value is zero
4. Test fix

## Debugging Commands

### Launch with CDB (Break on Exception)

```batch
scripts\debug_crash.cmd
```

### Manual CDB Commands

```batch
cdb -g -c "sxe dz; g" out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe
```

**Explanation**:
- `sxe dz` - Break on first-chance divide-by-zero exception
- `g` - Continue execution until exception

### When CDB Breaks

```
# Show call stack with symbols
k

# Show call stack with frame numbers and addresses
kv

# Show registers
r

# Disassemble at current location
u

# Show local variables
dv

# Show function name at address
ln <address>

# Continue execution
g

# Quit debugger
q
```

## Expected Results

### If Crash is in PM4 Code

**Likely Location**: `Mw05Recomp/gpu/pm4_parser.cpp` or `video.cpp`

**Likely Cause**: Dividing by zero when calculating PM4 statistics

**Fix**: Add zero check before division

### If Crash is in Frame Timing Code

**Likely Location**: `Mw05Recomp/gpu/video.cpp` (FPS counter)

**Likely Cause**: Dividing by zero frame time

**Fix**: Add zero check before FPS calculation

### If Crash is in Heap Code

**Likely Location**: `Mw05Recomp/kernel/heap.cpp`

**Likely Cause**: Dividing by zero allocation count

**Fix**: Add zero check before calculating average

## Next Steps

1. **Run `scripts\debug_crash.cmd`** to break on exception
2. **Get call stack** with `k` command
3. **Identify crash location** with `ln` command
4. **Examine code** at crash location
5. **Add zero check** before division
6. **Test fix** and verify crash is gone

## Success Criteria

- ✅ CDB breaks on divide-by-zero exception
- ✅ Call stack shows exact crash location
- ✅ Code examination reveals division by zero
- ✅ Fix applied (zero check added)
- ✅ Game runs without crash

## Notes

- NULL-CALL messages are NORMAL (game calls NULL function pointers, we catch them)
- The crash is in HOST code (x64), not PPC code
- This is likely a simple divide-by-zero that needs a zero check
- Should be a quick fix once we identify the location

