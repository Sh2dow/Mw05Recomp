#!/usr/bin/env python3
"""Fetch function sizes from IDA Pro HTTP server"""

import requests
import sys

IDA_SERVER = "http://127.0.0.1:5050"

functions = [
    (0x8211E470, "sub_8211E470"),
    (0x8211E3E0, "sub_8211E3E0"),
    (0x8211E3E8, "sub_8211E3E8"),
    (0x8211E538, "sub_8211E538"),
    (0x8211F4A0, "sub_8211F4A0"),
]

print("Fetching function sizes from IDA Pro...")
print()

toml_entries = []

for addr, name in functions:
    print(f"Fetching {name} at 0x{addr:08X}...")
    
    try:
        uri = f"{IDA_SERVER}/disasm?ea=0x{addr:08X}&count=500"
        response = requests.get(uri, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if data.get("disasm") and len(data["disasm"]) > 0:
            first_addr = int(data["disasm"][0]["ea"], 16)
            last_addr = int(data["disasm"][-1]["ea"], 16)
            size = last_addr - first_addr + 4
            
            print(f"  Start: 0x{first_addr:08X}")
            print(f"  End:   0x{last_addr:08X}")
            print(f"  Size:  0x{size:X} ({size} bytes)")
            print(f"  TOML:  {{ address = 0x{addr:08X}, size = 0x{size:X} }}")
            print()
            
            toml_entries.append((addr, size, name))
        else:
            print(f"  ERROR: No disassembly data returned")
            print()
    except Exception as e:
        print(f"  ERROR: {e}")
        print()

print("=" * 80)
print("TOML entries to add to Mw05RecompLib/config/MW05.toml:")
print("=" * 80)
for addr, size, name in toml_entries:
    print(f"{{ address = 0x{addr:08X}, size = 0x{size:X} }}  # {name}")

