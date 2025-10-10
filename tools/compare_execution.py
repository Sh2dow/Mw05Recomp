#!/usr/bin/env python3
"""Compare our trace with Xenia to find divergence point."""

import re
import sys

def extract_function_calls(log_path, is_xenia=False):
    """Extract function call sequence."""
    calls = []
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if is_xenia:
                # Xenia format: look for function addresses
                match = re.search(r'0x([0-9A-Fa-f]{8})', line)
                if match:
                    addr = match.group(1).upper()
                    calls.append(addr)
            else:
                # Our format: HOST.import=
                match = re.search(r'import=HOST\.([^ ]+)', line)
                if match:
                    func = match.group(1)
                    calls.append(func)
    return calls

def main():
    our_log = 'out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log'
    xenia_log = 'tools/xenia.log'
    
    print("Extracting our calls...")
    our_calls = extract_function_calls(our_log, False)
    print(f"  Found {len(our_calls)} calls")
    
    print("\nOur first 50 calls:")
    for i, call in enumerate(our_calls[:50], 1):
        print(f"{i:3d}. {call}")
    
    print("\nOur last 50 calls:")
    for i, call in enumerate(our_calls[-50:], 1):
        print(f"{i:3d}. {call}")

if __name__ == '__main__':
    main()

