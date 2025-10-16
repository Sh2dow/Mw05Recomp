#!/usr/bin/env python3
"""Find which PPC function corresponds to a crash offset."""

import sys

# Crash offset from the log
crash_offset = 0x4C10421

# Constants from the build
PPC_IMAGE_SIZE = 0xCD0000
PPC_CODE_BASE = 0x820E0000

# Calculate guest address
offset_from_image_end = crash_offset - PPC_IMAGE_SIZE
guest_addr = PPC_CODE_BASE + offset_from_image_end

print(f"Crash offset: 0x{crash_offset:08X}")
print(f"PPC image size: 0x{PPC_IMAGE_SIZE:08X}")
print(f"Offset from image end: 0x{offset_from_image_end:08X}")
print(f"Estimated guest address: 0x{guest_addr:08X}")
print()
print("This address is in the recompiled PPC code section.")
print("Search for this address in the generated ppc_recomp.*.cpp files.")

