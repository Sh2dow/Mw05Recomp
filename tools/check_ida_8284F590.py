#!/usr/bin/env python3
"""Check what function 0x8284F590 is in the IDA export"""

import os
import sys

def main():
    ida_path = 'NfsMWEurope.xex.html'
    
    if not os.path.exists(ida_path):
        print(f"ERROR: IDA export not found: {ida_path}")
        return 1
    
    with open(ida_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    print("Searching for 0x8284F590 in IDA export...")
    
    # Search for the address
    target = '8284F590'
    found = False
    
    for i, line in enumerate(lines):
        if target in line:
            found = True
            print(f"\nLine {i+1}: {line.rstrip()}")
            
            # Show context (previous 20 lines to find function name)
            start = max(0, i - 20)
            print("\n--- Context (previous 20 lines) ---")
            for j in range(start, i):
                print(f"Line {j+1}: {lines[j].rstrip()}")
            
            # Show next 10 lines
            print("\n--- Context (next 10 lines) ---")
            for j in range(i+1, min(len(lines), i+11)):
                print(f"Line {j+1}: {lines[j].rstrip()}")
            
            break
    
    if not found:
        print(f"Address {target} not found in IDA export")
        
        # Try to find the function that contains this address
        # 0x8284F590 is likely inside a function that starts before it
        # Let's search for functions around this address
        print("\nSearching for functions around 0x8284F590...")
        
        # Search for function starts between 0x8284F000 and 0x8284F600
        for addr_offset in range(0, 0x600, 8):
            addr = f'8284F{addr_offset:03X}'
            for i, line in enumerate(lines):
                if f'.text:{addr.upper()}' in line and 'sub_' in line:
                    print(f"Found function at 0x{addr.upper()}: {line.rstrip()}")
                    break
    
    # Also search for sub_8284F548 to compare
    print("\n" + "="*80)
    print("Searching for sub_8284F548 (the missing video thread creation function)...")
    print("="*80)
    
    target2 = '8284F548'
    for i, line in enumerate(lines):
        if target2 in line and ('.text:' in line or 'sub_' in line):
            print(f"\nLine {i+1}: {line.rstrip()}")
            
            # Show next 40 lines to see the function
            print("\n--- Function body (next 40 lines) ---")
            for j in range(i+1, min(len(lines), i+41)):
                print(f"Line {j+1}: {lines[j].rstrip()}")
            
            break
    
    return 0

if __name__ == '__main__':
    sys.exit(main())

