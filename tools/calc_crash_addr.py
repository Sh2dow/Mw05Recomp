#!/usr/bin/env python3
"""Calculate PPC guest address from crash offset."""

offset = 0x4C27CD0
ppc_code_base = 0x820E0000
ppc_image_size = 0xCD0000

print(f"Crash offset: 0x{offset:X}")
print(f"PPC_IMAGE_SIZE: 0x{ppc_image_size:X}")
print(f"Offset from PPC_IMAGE_SIZE: 0x{offset - ppc_image_size:X}")

# The function table is stored after the image data
# Each entry is 8 bytes (sizeof(PPCFunc*))
# So the guest address is: PPC_CODE_BASE + (offset - PPC_IMAGE_SIZE) / 8
guest_addr = ppc_code_base + ((offset - ppc_image_size) // 8)
print(f"Estimated guest address: 0x{guest_addr:X}")

