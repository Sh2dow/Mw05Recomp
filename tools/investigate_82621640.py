#!/usr/bin/env python3
"""Investigate sub_82621640 and search for references to missing functions"""

import os
import sys
import re

def main():
    ida_path = 'NfsMWEurope.xex.html'
    
    if not os.path.exists(ida_path):
        print(f"ERROR: IDA export not found: {ida_path}")
        return 1
    
    with open(ida_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    print("="*80)
    print("INVESTIGATING sub_82621640")
    print("="*80)
    
    # Search for sub_82621640
    target = '82621640'
    found_func = False
    
    for i, line in enumerate(lines):
        if f'.text:{target}' in line and 'sub_' in line:
            found_func = True
            print(f"\nFound function at line {i+1}:")
            print(line.rstrip())
            
            # Show next 60 lines
            print("\n--- Function body (next 60 lines) ---")
            for j in range(i+1, min(len(lines), i+61)):
                print(f"{j+1}: {lines[j].rstrip()}")
            break
    
    if not found_func:
        print(f"Function sub_{target} not found")
    
    # Search for references to the missing functions
    print("\n" + "="*80)
    print("SEARCHING FOR REFERENCES TO MISSING FUNCTIONS")
    print("="*80)
    
    missing_funcs = {
        '82849DE8': 'Video thread creation trigger',
        '82881020': 'Video thread creation chain',
        '82880FA0': 'Video thread creation chain',
        '824411E0': 'Main thread unblock trigger',
        '8284F548': 'Thread creation function'
    }
    
    for func_addr, desc in missing_funcs.items():
        print(f"\n--- Searching for references to {func_addr} ({desc}) ---")
        
        # Search for direct calls (bl sub_XXXXXXXX)
        pattern1 = f'bl.*sub_{func_addr}'
        # Search for address loads (lis/addi patterns)
        pattern2 = func_addr
        
        found_refs = []
        for i, line in enumerate(lines):
            if re.search(pattern1, line, re.IGNORECASE) or (pattern2 in line and '.text:' in line):
                found_refs.append((i+1, line.rstrip()))
        
        if found_refs:
            print(f"Found {len(found_refs)} references:")
            for line_num, line_text in found_refs[:10]:  # Show first 10
                print(f"  Line {line_num}: {line_text}")
        else:
            print(f"No references found")
    
    # Search for function pointer tables that might contain these addresses
    print("\n" + "="*80)
    print("SEARCHING FOR FUNCTION POINTER TABLES")
    print("="*80)
    
    # Look for .data or .rdata sections with these addresses
    for func_addr in missing_funcs.keys():
        # Convert to different formats
        addr_formats = [
            func_addr,
            f'0x{func_addr}',
            f'.long.*{func_addr}',
        ]
        
        for i, line in enumerate(lines):
            for fmt in addr_formats:
                if re.search(fmt, line, re.IGNORECASE) and ('.data:' in line or '.rdata:' in line):
                    print(f"\nLine {i+1}: {line.rstrip()}")
                    # Show context
                    for j in range(max(0, i-3), min(len(lines), i+4)):
                        if j != i:
                            print(f"  {j+1}: {lines[j].rstrip()}")
                    break
    
    return 0

if __name__ == '__main__':
    sys.exit(main())

