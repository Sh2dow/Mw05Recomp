#!/usr/bin/env python3
"""
Find what function 0x82813358 is by searching PPC recompiled files.
"""

import os
import re

def main():
    ppc_dir = 'Mw05RecompLib/ppc'
    
    # Search for the address in function implementations
    target_addr = 0x82813358
    
    print(f"Searching for function at address 0x{target_addr:08X}...")
    
    # Search all ppc_recomp.*.cpp files
    for filename in sorted(os.listdir(ppc_dir)):
        if not filename.startswith('ppc_recomp.') or not filename.endswith('.cpp'):
            continue
        
        filepath = os.path.join(ppc_dir, filename)
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Look for PPC_FUNC_IMPL with this address
        pattern = r'PPC_FUNC_IMPL\((sub_[0-9A-Fa-f]+)\)'
        matches = re.finditer(pattern, content)
        
        for match in matches:
            func_name = match.group(1)
            # Extract address from function name
            addr_str = func_name.replace('sub_', '')
            try:
                addr = int(addr_str, 16)
                if addr == target_addr:
                    print(f"\nFound function {func_name} in {filename}")
                    # Get some context
                    start = max(0, match.start() - 200)
                    end = min(len(content), match.end() + 500)
                    print(f"\nContext:")
                    print(content[start:end])
                    return
            except ValueError:
                continue
    
    print(f"\nFunction at 0x{target_addr:08X} not found in PPC files.")
    print("\nThis might be:")
    print("1. The XEX entry point")
    print("2. A kernel-created thread")
    print("3. A function in a different address range")
    
    # Let's check what functions are near this address
    print(f"\nSearching for functions near 0x{target_addr:08X}...")
    nearby = []
    
    for filename in sorted(os.listdir(ppc_dir)):
        if not filename.startswith('ppc_recomp.') or not filename.endswith('.cpp'):
            continue
        
        filepath = os.path.join(ppc_dir, filename)
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        pattern = r'PPC_FUNC_IMPL\((sub_[0-9A-Fa-f]+)\)'
        matches = re.finditer(pattern, content)
        
        for match in matches:
            func_name = match.group(1)
            addr_str = func_name.replace('sub_', '')
            try:
                addr = int(addr_str, 16)
                # Check if within 0x1000 bytes
                if abs(addr - target_addr) < 0x1000:
                    nearby.append((addr, func_name, filename))
            except ValueError:
                continue
    
    if nearby:
        print(f"\nFunctions within 0x1000 bytes of 0x{target_addr:08X}:")
        for addr, func_name, filename in sorted(nearby):
            offset = addr - target_addr
            print(f"  0x{addr:08X} ({offset:+6d}): {func_name} in {filename}")

if __name__ == '__main__':
    main()

