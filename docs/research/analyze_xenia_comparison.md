# Xenia vs MW05Recomp Comparison

## Graphics Callback Analysis

### Callback Function at 0x825979A8

**What the callback does:**

1. **Check interrupt type** (`r3 == 1`)
   - If not 1, skip to `loc_82597A38`

2. **Load structure pointer** from `context+0x2894`
   ```asm
   lwz r10, 0x2894(r31)  # r31 = context pointer
   ```

3. **Check for error condition** (`0xBADF00D` magic value)
   ```asm
   lis r11, 0xBAD
   ori r11, r11, 0xF00D   # r11 = 0xBADF00D
   lwz r30, 0x10(r10)     # Load value from structure+0x10
   cmplw cr6, r30, r11    # Compare with 0xBADF00D
   bne cr6, loc_825979E8  # If NOT equal, continue
   # If equal, print error and crash
   ```

4. **Call function pointer** (if structure+0x10 is not zero)
   ```asm
   lwz r11, 0x2894(r31)   # Reload structure pointer
   lwz r3, 0x14(r11)      # Load parameter from structure+0x14
   mtctr r30              # r30 = function pointer from structure+0x10
   bctrl                  # Call the function
   ```

5. **Acquire spinlock** at `context+0x2898`
   ```asm
   addi r30, r31, 0x2898  # r30 = &context->spinlock
   lwz r31, 0x2894(r31)   # r31 = structure pointer
   bl KeAcquireSpinLockAtRaisedIrql
   ```

6. **Continue processing** (more code follows)

### Structure at context+0x2894

**Size:** 32 bytes (0x20)

**Known offsets:**
- `+0x00`: Unknown (accessed by `lwz r11, 0(r31)` after spinlock)
- `+0x10`: Function pointer OR error flag
  - If `0xBADF00D`: Error condition, crash
  - If `0`: Skip function call
  - Otherwise: Function pointer to call
- `+0x14`: Parameter to pass to function at `+0x10`

**Current initialization:**
- ✅ Allocated (32 bytes)
- ✅ Zero-initialized
- ✅ Pointer stored at `context+0x2894`

**Problem:**
- The structure is zero-initialized, so `+0x10` is 0
- This means the callback skips the function call (which is correct)
- But something else is wrong that causes the crash later

### Spinlock at context+0x2898

**Current status:** NOT initialized

**Required initialization:**
- Should be initialized to 0 (unlocked state)
- Size: 4 bytes (KSPIN_LOCK is a DWORD)

## What We're Missing

### 1. Spinlock Initialization ❌

The callback tries to acquire a spinlock at `context+0x2898`, but we haven't initialized it.

**Fix needed:**
```cpp
// Initialize spinlock at context+0x2898
uint32_t* spinlock_ptr = reinterpret_cast<uint32_t*>(
    static_cast<uint8_t*>(ctx_ptr) + 0x2898);
*spinlock_ptr = 0;  // Unlocked state
```

### 2. Other Context Members ❌

The context is 16KB but we only initialize:
- The whole context to zero
- Pointer at `+0x2894`
- (Missing) Spinlock at `+0x2898`

**Potential missing members:**
- Other pointers
- Other spinlocks
- State flags
- Counters

### 3. Thread Initialization Order

**Current threads:**
1. Thread #1: entry=0x828508A8, ctx=0x7FEA17B0 (tick 0)
2. Thread #2: entry=0x82812ED0, ctx=0x00100E10 (tick 0)
3. Thread #3: entry=0x82849D40, ctx=0x00000080 (tick 300, video thread)

**Questions:**
- Are there other threads that should be created?
- What is the correct order?
- What do these threads do?

## Xenia Comparison Checklist

To properly compare with Xenia, we need to check:

### Initialization Sequence
- [ ] What VD functions does Xenia call and in what order?
- [ ] What structures does Xenia allocate during graphics init?
- [ ] What threads does Xenia create and when?
- [ ] What is the timing of graphics callback registration?

### Memory Layout
- [ ] What is at `context+0x2894` in Xenia?
- [ ] What is at `context+0x2898` in Xenia?
- [ ] What other context members does Xenia initialize?
- [ ] What is the size of the context structure in Xenia?

### Callback Behavior
- [ ] How many times does Xenia invoke the callback before the game is stable?
- [ ] What does the callback do in Xenia?
- [ ] Does the callback call the function pointer at structure+0x10?
- [ ] What happens after the callback returns?

### Thread Behavior
- [ ] What threads does Xenia create?
- [ ] What is the thread creation order?
- [ ] What do the threads do?
- [ ] Are there graphics worker threads?

## Immediate Action Items

### 1. Initialize Spinlock ✅ HIGH PRIORITY
The callback acquires a spinlock at `context+0x2898`. We need to initialize it.

### 2. Monitor Callback Behavior
Add logging to track:
- What the callback accesses
- What it writes
- What functions it calls
- What happens after it returns

### 3. Check for Other Missing Structures
Search the IDA export for:
- Other allocations near graphics init
- Other context members accessed
- Other spinlocks or synchronization primitives

### 4. Compare with Xenia (if logs available)
If we have Xenia trace logs:
- Compare initialization sequence
- Compare memory layout
- Compare thread creation
- Compare callback timing

## Hypothesis

The crash might be caused by:

1. **Uninitialized spinlock** at `context+0x2898`
   - The callback tries to acquire it
   - If not initialized, it might corrupt memory

2. **Missing structures** that the callback expects
   - The callback might access other memory
   - If not initialized, it might crash

3. **Wrong thread state** after callback
   - The callback might change thread state
   - If not handled correctly, it might crash

4. **Missing synchronization** between callback and game code
   - The callback runs asynchronously
   - Game code might not be ready for it

## Next Steps

1. **Initialize the spinlock** at `context+0x2898`
2. **Test again** to see if it helps
3. **Add detailed logging** to monitor callback behavior
4. **Search for other missing structures** in the IDA export
5. **Compare with Xenia** if logs are available

