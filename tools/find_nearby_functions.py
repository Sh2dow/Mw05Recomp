#!/usr/bin/env python3
"""
Find functions near address 0x8262E9A8.
"""

import os
import re

def main():
    ppc_dir = 'Mw05RecompLib/ppc'
    
    target_addr = 0x8262E9A8
    
    print(f"Searching for functions near 0x{target_addr:08X}...")
    
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
                # Check if within 0x10000 bytes
                if abs(addr - target_addr) < 0x10000:
                    nearby.append((addr, func_name, filename))
            except ValueError:
                continue
    
    if nearby:
        print(f"\nFunctions within 0x10000 bytes of 0x{target_addr:08X}:")
        for addr, func_name, filename in sorted(nearby):
            offset = addr - target_addr
            print(f"  0x{addr:08X} ({offset:+8d}): {func_name} in {filename}")
    else:
        print(f"\nNo functions found near 0x{target_addr:08X}")
    
    # Find the address range of all functions
    all_addrs = [addr for addr, _, _ in nearby]
    if all_addrs:
        print(f"\nAddress range: 0x{min(all_addrs):08X} - 0x{max(all_addrs):08X}")

if __name__ == '__main__':
    main()

