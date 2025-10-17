# MicroIB Format Discovery

**Date**: 2025-10-17 21:15  
**Status**: 🔍 CRITICAL DISCOVERY - Descriptor contains embedded PM4 commands!

## Summary

After investigating why no draw commands are appearing, I discovered that the MicroIB descriptor format is **COMPLETELY DIFFERENT** from what we expected. The descriptor doesn't contain offset/size pairs - it contains **embedded PM4 commands**!

## The Discovery

### Expected Format (Mode C - Parameter List)

We expected the descriptor to have this format:
```
d[0] = magic marker (0xFFFAFF3D or 0xFFFAFEFD)
d[1] = base address
d[2] = offset in dwords (pair 0)
d[3] = size in bytes (pair 0)
d[4] = offset in dwords (pair 1)
d[5] = size in bytes (pair 1)
...
```

### Actual Format (Embedded PM4 Commands!)

But the actual data shows:
```
d[0] = FFFAFEFD  - Magic marker
d[1] = 00140410  - Base address
d[2] = C0015100  - TYPE3 PM4 packet header! (opcode 0x51, count 1)
d[3] = FFFFFFFF  - PM4 parameter (not a size!)
d[4] = FFFFFFFF  - PM4 parameter (not a size!)
d[5] = 00000000  - PM4 parameter
d[6] = 81000007  - Another PM4 header?
d[7] = 00140410  - Base address again
```

### Analysis of d[2] = C0015100

Breaking down the PM4 header:
```
C0015100 = 11000000 00000001 01010001 00000000
           ││      │        │        └─ Predicate (0)
           ││      │        └────────── Opcode 0x51 (81 decimal)
           ││      └─────────────────── Count (1 dword)
           │└────────────────────────── Reserved (0)
           └─────────────────────────── Type (11 = TYPE3)
```

This is a **TYPE3 packet with opcode 0x51 and 1 parameter**!

## The Problem

The Mode C (parameter list) code is trying to interpret these PM4 commands as offset/size pairs:
- It reads `d[2]=C0015100` as an offset (signed int32 = -1073094400)
- It reads `d[3]=FFFFFFFF` as a size (uint32 = 4294967295 = 0xFFFFFFFF)
- The size check fails: `if (size_bytes == 0 || size_bytes > 0x10000u) continue;`
- The pair is skipped
- No PM4 commands are scanned

## The Solution

The MicroIB descriptor is NOT a list of offset/size pairs - it's a **list of PM4 commands**!

The interpreter should:
1. Read the magic marker and base address
2. **Scan the remaining dwords as PM4 commands** (not as offset/size pairs)
3. Execute/process these embedded PM4 commands

This is a **completely different format** from what the current code expects!

## Evidence

### Trace Log

```
[HOST] import=HOST.PM4.MW05.MicroIB.params d0=FFFAFEFD d1=00140410 d2=C0015100 d3=FFFFFFFF d4=FFFFFFFF d5=00000000 d6=81000007 d7=00140410
```

### PM4 Header Breakdown

- `d[2]=C0015100` - TYPE3, opcode 0x51, count 1
- `d[6]=81000007` - Possible PM4 header (0x81 = TYPE2 or malformed TYPE3?)

### Magic Markers

Two different magic markers are being used:
1. `0xFFFAFF3D` - Seen in earlier traces (incomplete descriptor)
2. `0xFFFAFEFD` - Seen in current traces (embedded PM4 commands)

These might indicate different descriptor formats!

## Next Steps

1. **Rewrite Mode C parser** - Scan the descriptor as PM4 commands instead of offset/size pairs
2. **Check opcode 0x51** - Find out what this PM4 command does
3. **Investigate magic markers** - Determine if different markers indicate different formats
4. **Compare with Xenia** - See how Xenia handles these descriptors
5. **Test the fix** - Verify that scanning the descriptor as PM4 commands finds draw commands

## Impact

This is a **MAJOR DISCOVERY** that explains why no draw commands are appearing:
- The current code is looking for offset/size pairs
- But the descriptor contains embedded PM4 commands
- These commands are being skipped because they don't match the expected format
- The actual draw commands might be in these embedded PM4 packets!

## Confidence

**HIGH** - The evidence is clear:
- `d[2]=C0015100` is definitely a TYPE3 PM4 header
- The size check is failing because `d[3]=FFFFFFFF` is too large
- The descriptor format is completely different from what we expected

This is a **critical bug** in the MicroIB interpreter that needs to be fixed!

