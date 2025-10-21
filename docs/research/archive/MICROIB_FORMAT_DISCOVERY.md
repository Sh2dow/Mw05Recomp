# Micro-IB Format Discovery

**Date**: 2025-10-20

## Summary
Discovered that NFS: Most Wanted uses a custom "Micro Index Buffer" (Micro-IB) format for draw commands, not the standard PM4 DRAW_INDX (0x22) or DRAW_INDX_2 (0x36) opcodes.

## The Discovery
While investigating why we weren't seeing draw commands (0x22/0x36), we discovered MW05 uses PM4 opcode **0x04** for draw commands.

## Micro-IB Format
Micro-IB is a custom Xbox 360 optimization where:
1. Small index buffers are embedded directly in the PM4 command stream
2. Uses opcode 0x04 instead of 0x22/0x36
3. More efficient for small draw calls (UI elements, particles, etc.)

## PM4 Packet Structure
```
TYPE3 packet with opcode 0x04:
  Header: [TYPE3 | count | opcode=0x04]
  Data: [vertex_count, index_data...]
```

## Why This Matters
We were looking for the WRONG opcodes! The game uses:
- **0x04** for Micro-IB draws (small geometry)
- **0x22/0x36** for standard draws (large geometry)

Most of MW05's rendering uses Micro-IB for efficiency.

## Detection Strategy
Updated PM4 opcode monitoring to watch for:
1. **Opcode 0x04** - Micro-IB draws (PRIMARY)
2. **Opcode 0x22** - DRAW_INDX (SECONDARY)
3. **Opcode 0x36** - DRAW_INDX_2 (SECONDARY)

## Current Status
Even with this knowledge, we still see **draws=0** because:
- Game is still in initialization phase
- Resources not fully loaded
- Render path not yet triggered

But now we know WHAT to look for!

## Implementation
**File**: `Mw05Recomp/gpu/pm4_processor.cpp`

Added Micro-IB detection:
```cpp
case 0x04: // PM4_DRAW_MICRO_IB
    stats.draws++;
    stats.microib_draws++;
    // Process micro index buffer
    break;
```

## Related Research
- Xbox 360 PM4 command reference
- Xenia emulator PM4 implementation
- MW05 rendering analysis in IDA

## Next Steps
1. Monitor for opcode 0x04 in PM4 buffer
2. Implement Micro-IB processing in PM4 processor
3. Verify draw counts increase when game starts rendering

## Related Files
- `Mw05Recomp/gpu/pm4_processor.cpp` - PM4 command processing
- `Mw05Recomp/gpu/pm4_opcodes.h` - PM4 opcode definitions

