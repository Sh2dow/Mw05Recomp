#!/usr/bin/env python3
"""Analyze sub_825968B0 calls in the log"""

import os
import sys

def main():
    log_path = r'out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log'
    
    if not os.path.exists(log_path):
        print(f"ERROR: Log file not found: {log_path}")
        return 1
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    print(f"Total log lines: {len(lines)}")
    print("\n" + "="*80)
    print("SEARCHING FOR sub_825968B0 CALLS")
    print("="*80)
    
    found_count = 0
    for i, line in enumerate(lines):
        if '825968B0' in line:
            found_count += 1
            print(f"\nLine {i+1}: {line.rstrip()}")
            
            # Show context (next 5 lines)
            if i + 1 < len(lines):
                for j in range(1, min(6, len(lines) - i)):
                    print(f"  +{j}: {lines[i+j].rstrip()}")
            
            if found_count >= 5:
                print("\n... (showing first 5 occurrences)")
                break
    
    print(f"\n\nTotal occurrences of '825968B0': {found_count}")
    
    # Count all occurrences
    total_count = sum(1 for line in lines if '825968B0' in line)
    print(f"Total occurrences in entire log: {total_count}")
    
    # Check if it's the shim or the import
    print("\n" + "="*80)
    print("CHECKING CALL TYPE")
    print("="*80)
    
    for i, line in enumerate(lines):
        if '825968B0' in line:
            if 'SHIM-ENTRY' in line:
                print(f"Line {i+1}: SHIM ENTRY (new code)")
            elif 'import=' in line:
                print(f"Line {i+1}: IMPORT LOG (old code)")
            else:
                print(f"Line {i+1}: UNKNOWN TYPE")
            print(f"  {line.rstrip()}")
            
            if i >= 10:  # Only check first few
                break
    
    return 0

if __name__ == '__main__':
    sys.exit(main())

