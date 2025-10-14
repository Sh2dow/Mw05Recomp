#!/usr/bin/env python3

PPC_CODE_BASE = 0x820E0000
PPC_CODE_SIZE = 0x1000000  # Extended to 16 MB to cover host callbacks
PPC_CODE_END = PPC_CODE_BASE + PPC_CODE_SIZE

print(f"PPC_CODE_BASE: 0x{PPC_CODE_BASE:08X}")
print(f"PPC_CODE_SIZE: 0x{PPC_CODE_SIZE:08X}")
print(f"Valid range: [0x{PPC_CODE_BASE:08X}, 0x{PPC_CODE_END:08X})")
print()

addresses = [
    ("0x828C8000 (NEW host callback)", 0x828C8000),
    ("0x82FF1000 (OLD host callback)", 0x82FF1000),
    ("0x82FF2000 (vtable stub 1)", 0x82FF2000),
    ("0x82FF2010 (vtable stub 2)", 0x82FF2010),
]

print("Address validation:")
for name, addr in addresses:
    valid = PPC_CODE_BASE <= addr < PPC_CODE_END
    status = "VALID" if valid else "INVALID"
    print(f"  {name:40s} = 0x{addr:08X} - {status}")
    if not valid:
        if addr < PPC_CODE_BASE:
            print(f"    ERROR: Address is 0x{PPC_CODE_BASE - addr:08X} bytes BEFORE valid range")
        else:
            print(f"    ERROR: Address is 0x{addr - PPC_CODE_END:08X} bytes AFTER valid range")

