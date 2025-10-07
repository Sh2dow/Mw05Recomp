#!/usr/bin/env python3
"""Analyze the MW05 crash and determine the root cause."""

# Crash information
crash_offset = 0xF02538  # Host offset from executable base
crash_addr_faulting = 0x7ff614612538  # Faulting address (example from one run)

# PPC information
PPC_IMAGE_BASE = 0x82000000
PPC_IMAGE_SIZE = 0xCD0000  # From build output
PPC_IMAGE_END = PPC_IMAGE_BASE + PPC_IMAGE_SIZE

# Function information
sub_828134E0_addr = 0x828134E0
r29_value = 0x82813090  # Calculated by: -32113 << 16 + 8080

print("=" * 80)
print("MW05 Crash Analysis")
print("=" * 80)

print(f"\n1. Crash Location:")
print(f"   Host offset: +0x{crash_offset:X}")
print(f"   This is NOT a guest address - it's a host executable offset")

print(f"\n2. Function Being Executed:")
print(f"   sub_828134E0 at guest address 0x{sub_828134E0_addr:08X}")

print(f"\n3. Memory Access:")
print(f"   r29 = 0x{r29_value:08X}")
print(f"   Trying to load from: *(r29 + 0) = 0x{r29_value:08X}")

print(f"\n4. PPC Image Range:")
print(f"   Base:  0x{PPC_IMAGE_BASE:08X}")
print(f"   End:   0x{PPC_IMAGE_END:08X}")
print(f"   Size:  0x{PPC_IMAGE_SIZE:X} ({PPC_IMAGE_SIZE // 1024 // 1024} MB)")

print(f"\n5. Address Validation:")
if PPC_IMAGE_BASE <= r29_value < PPC_IMAGE_END:
    print(f"   ✓ Address 0x{r29_value:08X} is WITHIN the PPC image range")
    offset_from_base = r29_value - PPC_IMAGE_BASE
    print(f"   Offset from base: +0x{offset_from_base:X}")
else:
    print(f"   ✗ Address 0x{r29_value:08X} is OUTSIDE the PPC image range")
    if r29_value < PPC_IMAGE_BASE:
        print(f"   Too low by: 0x{PPC_IMAGE_BASE - r29_value:X}")
    else:
        print(f"   Too high by: 0x{r29_value - PPC_IMAGE_END:X}")

print(f"\n6. Hypothesis:")
print(f"   The address 0x{r29_value:08X} is in the DATA section of the XEX.")
print(f"   The crash suggests that either:")
print(f"   a) The XEX data section is not being loaded correctly")
print(f"   b) The address translation in PPC_LOAD_U32 is failing")
print(f"   c) The memory at this address is not initialized")

print(f"\n7. Next Steps:")
print(f"   1. Enable debug logging to see the actual loadAddress and imageSize")
print(f"   2. Check if 0x{r29_value:08X} is within [loadAddress, loadAddress+imageSize)")
print(f"   3. Examine the memory at this address to see what's there")
print(f"   4. Add logging to PPC_LOAD_U32 to see what address it's trying to access")

print("\n" + "=" * 80)

