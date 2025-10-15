#!/usr/bin/env python3

PPC_IMAGE_BASE = 0x82000000
PPC_IMAGE_SIZE = 0xCD0000
PPC_CODE_BASE = 0x820E0000
PPC_CODE_SIZE = 0x7E8DA0

print("Current configuration:")
print(f"  PPC_IMAGE_BASE: 0x{PPC_IMAGE_BASE:08X}")
print(f"  PPC_IMAGE_SIZE: 0x{PPC_IMAGE_SIZE:08X}")
print(f"  PPC_CODE_BASE:  0x{PPC_CODE_BASE:08X}")
print(f"  PPC_CODE_SIZE:  0x{PPC_CODE_SIZE:08X}")
print()

IMAGE_END = PPC_IMAGE_BASE + PPC_IMAGE_SIZE
CODE_END = PPC_CODE_BASE + PPC_CODE_SIZE

print("Address ranges:")
print(f"  Full XEX image: [0x{PPC_IMAGE_BASE:08X}, 0x{IMAGE_END:08X})")
print(f"  Code section:   [0x{PPC_CODE_BASE:08X}, 0x{CODE_END:08X})")
print()

print("Gap analysis:")
print(f"  Gap before code: 0x{PPC_CODE_BASE - PPC_IMAGE_BASE:08X} bytes")
print(f"  Gap after code:  0x{IMAGE_END - CODE_END:08X} bytes")
print()

# Calculate what PPC_CODE_SIZE should be to cover the full image
FULL_CODE_SIZE = IMAGE_END - PPC_CODE_BASE
print("To cover full XEX image:")
print(f"  PPC_CODE_SIZE should be: 0x{FULL_CODE_SIZE:08X}")
print(f"  This would cover: [0x{PPC_CODE_BASE:08X}, 0x{PPC_CODE_BASE + FULL_CODE_SIZE:08X})")
print()

# Calculate function table size
FUNC_TABLE_SIZE_CURRENT = PPC_CODE_SIZE // 8
FUNC_TABLE_SIZE_FULL = FULL_CODE_SIZE // 8

print("Function table size:")
print(f"  Current: {FUNC_TABLE_SIZE_CURRENT:,} entries = {PPC_CODE_SIZE:,} bytes")
print(f"  Full:    {FUNC_TABLE_SIZE_FULL:,} entries = {FULL_CODE_SIZE:,} bytes")
print(f"  Increase: {FUNC_TABLE_SIZE_FULL - FUNC_TABLE_SIZE_CURRENT:,} entries = {FULL_CODE_SIZE - PPC_CODE_SIZE:,} bytes")

