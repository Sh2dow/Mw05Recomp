#!/usr/bin/env python3
"""Find what triggers initialization - search for functions that might call the missing ones"""

import os
import sys
import re

def main():
    log_path = r'out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log'
    
    if not os.path.exists(log_path):
        print(f"ERROR: Log file not found: {log_path}")
        return 1
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    print(f"Total log lines: {len(lines)}")
    
    # Extract all unique function addresses from lr= fields
    print("\n" + "="*80)
    print("EXTRACTING UNIQUE FUNCTION ADDRESSES FROM lr= FIELDS")
    print("="*80)
    
    lr_pattern = re.compile(r'lr=0x([0-9A-Fa-f]{8})')
    unique_lrs = set()
    
    for line in lines:
        matches = lr_pattern.findall(line)
        for match in matches:
            addr = match.upper()
            if addr != '00000000' and addr.startswith('82'):  # Filter out NULL and non-game addresses
                unique_lrs.add(addr)
    
    print(f"Found {len(unique_lrs)} unique non-zero lr addresses")
    
    # Sort and display
    sorted_lrs = sorted(unique_lrs)
    print("\nFirst 50 unique lr addresses:")
    for i, addr in enumerate(sorted_lrs[:50]):
        print(f"  0x{addr}", end='')
        if (i + 1) % 5 == 0:
            print()
        else:
            print(', ', end='')
    print()
    
    # Check if any of the missing functions appear in lr
    print("\n" + "="*80)
    print("CHECKING IF MISSING FUNCTIONS APPEAR IN lr= FIELDS")
    print("="*80)
    
    missing_funcs = ['82849DE8', '82881020', '82880FA0', '824411E0', '8284F548']
    for func in missing_funcs:
        if func in unique_lrs:
            print(f"✓ FOUND {func} in lr= fields (function IS being called)")
        else:
            print(f"✗ NOT FOUND: {func} in lr= fields")
    
    # Search for functions that call ExCreateThread
    print("\n" + "="*80)
    print("FUNCTIONS THAT CALL ExCreateThread")
    print("="*80)
    
    for i, line in enumerate(lines):
        if 'ExCreateThread' in line and 'lr=' in line:
            # Extract lr value
            match = lr_pattern.search(line)
            if match:
                lr = match.group(1).upper()
                print(f"Line {i+1}: lr=0x{lr}")
                print(f"  {line.rstrip()}")
    
    # Search for the caller of sub_825960B8 (which calls sub_825968B0)
    print("\n" + "="*80)
    print("SEARCHING FOR CALLERS OF sub_825960B8")
    print("="*80)
    
    # sub_825960B8 calls sub_825968B0 at 0x82596110
    # So we should see lr=82596110 in sub_825968B0 calls
    for i, line in enumerate(lines):
        if '825968B0' in line and 'lr=82596110' in line:
            print(f"Line {i+1}: sub_825968B0 called from sub_825960B8")
            # Now find what called sub_825960B8
            # Look backwards for context
            for j in range(max(0, i-10), i):
                if 'lr=' in lines[j] and '825960B8' in lines[j]:
                    print(f"  Line {j+1}: {lines[j].rstrip()}")
    
    # Search for initialization-related functions
    print("\n" + "="*80)
    print("SEARCHING FOR INITIALIZATION PATTERNS")
    print("="*80)
    
    init_patterns = ['Init', 'init', 'Start', 'start', 'Create', 'create', 'Setup', 'setup']
    init_lines = []
    
    for i, line in enumerate(lines[:1000]):  # Only check first 1000 lines
        for pattern in init_patterns:
            if pattern in line and 'import=' in line:
                init_lines.append((i+1, line.rstrip()))
                break
    
    print(f"Found {len(init_lines)} initialization-related lines in first 1000 lines:")
    for line_num, line in init_lines[:20]:
        print(f"Line {line_num}: {line}")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())

