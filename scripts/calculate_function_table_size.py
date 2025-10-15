#!/usr/bin/env python3

PPC_IMAGE_BASE = 0x82000000
PPC_IMAGE_SIZE = 0xCD0000
PPC_CODE_BASE = 0x820E0000

# Addresses we want to support
HOST_CALLBACK_ADDR = 0x82FF1000
VTABLE_STUB_1 = 0x82FF2000
VTABLE_STUB_2 = 0x82FF2010

# Find the maximum address we need to support
MAX_ADDR = max(HOST_CALLBACK_ADDR, VTABLE_STUB_1, VTABLE_STUB_2)

# Calculate the required PPC_CODE_SIZE
REQUIRED_CODE_SIZE = MAX_ADDR - PPC_CODE_BASE + 0x1000  # Add 4KB padding

print(f"PPC_IMAGE_BASE: 0x{PPC_IMAGE_BASE:08X}")
print(f"PPC_IMAGE_SIZE: 0x{PPC_IMAGE_SIZE:08X}")
print(f"PPC_CODE_BASE:  0x{PPC_CODE_BASE:08X}")
print()

print(f"Addresses to support:")
print(f"  Host callback: 0x{HOST_CALLBACK_ADDR:08X}")
print(f"  Vtable stub 1: 0x{VTABLE_STUB_1:08X}")
print(f"  Vtable stub 2: 0x{VTABLE_STUB_2:08X}")
print(f"  Maximum:       0x{MAX_ADDR:08X}")
print()

print(f"Required PPC_CODE_SIZE: 0x{REQUIRED_CODE_SIZE:08X}")
print(f"This would cover: [0x{PPC_CODE_BASE:08X}, 0x{PPC_CODE_BASE + REQUIRED_CODE_SIZE:08X})")
print()

# Calculate function table size
FUNC_TABLE_SIZE = REQUIRED_CODE_SIZE // 8
FUNC_TABLE_BYTES = REQUIRED_CODE_SIZE

print(f"Function table size:")
print(f"  Entries: {FUNC_TABLE_SIZE:,}")
print(f"  Bytes:   {FUNC_TABLE_BYTES:,} ({FUNC_TABLE_BYTES / 1024 / 1024:.2f} MB)")

