#!/usr/bin/env python3
"""
Analyze the address being accessed in the infinite loop.
"""

# Line 1945: lis r29,-32256
# This loads the high 16 bits of r29 with -32256
# lis (Load Immediate Shifted) shifts the value left by 16 bits

# In PPC, lis r29, -32256 means:
# r29 = -32256 << 16 = -2113929216 (as shown in the code)

r29_value = -2113929216
offset = 2556

# Convert to unsigned 32-bit for address calculation
r29_u32 = r29_value & 0xFFFFFFFF
address = (r29_u32 + offset) & 0xFFFFFFFF

print(f"r29 (signed): {r29_value}")
print(f"r29 (as u32): 0x{r29_u32:08X}")
print(f"Offset: {offset} (0x{offset:X})")
print(f"Address being read: 0x{address:08X}")

# The loop reads from this address, dereferences it, and if non-null,
# calls a function pointer at offset 24 from the dereferenced object.
# This looks like a callback table or vtable iteration.

print("\nThis appears to be iterating through a callback/vtable array.")
print("The game is waiting for this table to be initialized.")
print("\nPossible solutions:")
print("1. Initialize the pointer at 0x{:08X} to point to a valid structure".format(address))
print("2. Set the pointer to NULL so the loop skips the callback")
print("3. Break the loop by forcing r30 (loop counter) to 0")

