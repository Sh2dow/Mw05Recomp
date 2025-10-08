#!/usr/bin/env python3
"""Find what should call sub_82548F18"""

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
    print("SEARCHING FOR sub_82548F18")
    print("="*80)
    
    # Find the function definition
    target = '82548F18'
    for i, line in enumerate(lines):
        if f'.text:{target}' in line and 'sub_' in line:
            print(f"\nFound function at line {i+1}:")
            print(line.rstrip())
            
            # Show next 40 lines
            print("\n--- Function body (next 40 lines) ---")
            for j in range(i+1, min(len(lines), i+41)):
                print(f"{j+1}: {lines[j].rstrip()}")
            break
    
    # Search for references to sub_82548F18
    print("\n" + "="*80)
    print("SEARCHING FOR REFERENCES TO sub_82548F18")
    print("="*80)
    
    pattern = f'bl.*sub_{target}|{target}'
    found_refs = []
    
    for i, line in enumerate(lines):
        if re.search(pattern, line, re.IGNORECASE):
            # Skip the function definition itself
            if f'.text:{target}' in line and 'sub_' in line:
                continue
            found_refs.append((i+1, line.rstrip()))
    
    if found_refs:
        print(f"Found {len(found_refs)} references:")
        for line_num, line_text in found_refs[:20]:  # Show first 20
            print(f"  Line {line_num}: {line_text}")
    else:
        print(f"No references found")
    
    # Also search for the 4 functions that call sub_824411E0
    print("\n" + "="*80)
    print("SEARCHING FOR FUNCTIONS THAT CALL sub_824411E0")
    print("="*80)
    
    callers = ['823AFE50', '823AFF7C', '823B4B80', '823B5798']
    for caller in callers:
        print(f"\n--- Searching for sub_{caller} ---")
        
        for i, line in enumerate(lines):
            if f'.text:{caller}' in line and ('sub_' in line or 'loc_' in line):
                print(f"Found at line {i+1}:")
                
                # Show previous 20 lines to find function start
                start = max(0, i - 20)
                print("\n--- Context (previous 20 lines) ---")
                for j in range(start, i):
                    print(f"{j+1}: {lines[j].rstrip()}")
                
                print(f"\n{i+1}: {line.rstrip()}")
                
                # Show next 10 lines
                print("\n--- Context (next 10 lines) ---")
                for j in range(i+1, min(len(lines), i+11)):
                    print(f"{j+1}: {lines[j].rstrip()}")
                
                break
    
    return 0

if __name__ == '__main__':
    sys.exit(main())

