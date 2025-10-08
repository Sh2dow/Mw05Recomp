#!/usr/bin/env python3
"""
Compare Xenia execution trace with Mw05Recomp trace to find missing calls.
"""

import re
import sys

def parse_xenia_log(path):
    """Extract key Vd* function calls from Xenia log."""
    calls = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            # Look for MW05 tagged lines with Vd* calls
            if '[MW05]' in line and ('Vd' in line or 'Draw' in line):
                # Extract function name
                match = re.search(r'\[MW05\]\s+(\w+)', line)
                if match:
                    func = match.group(1)
                    calls.append((line_num, func, line.strip()))
    return calls

def parse_recomp_log(path):
    """Extract key Vd* function calls from recomp log."""
    calls = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            # Look for HOST.Vd* calls
            if 'HOST.Vd' in line or 'HOST.Draw' in line:
                # Extract function name
                match = re.search(r'HOST\.(\w+)', line)
                if match:
                    func = match.group(1)
                    calls.append((line_num, func, line.strip()))
    return calls

def main():
    xenia_log = 'tools/xenia.log'
    recomp_log = 'out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log'
    
    print("Parsing Xenia log...")
    xenia_calls = parse_xenia_log(xenia_log)
    
    print("Parsing Recomp log...")
    recomp_calls = parse_recomp_log(recomp_log)
    
    # Get unique function names
    xenia_funcs = set(call[1] for call in xenia_calls)
    recomp_funcs = set(call[1] for call in recomp_calls)
    
    print(f"\n=== Xenia Vd* calls: {len(xenia_funcs)} unique functions ===")
    for func in sorted(xenia_funcs):
        count = sum(1 for c in xenia_calls if c[1] == func)
        print(f"  {func}: {count} calls")
    
    print(f"\n=== Recomp Vd* calls: {len(recomp_funcs)} unique functions ===")
    for func in sorted(recomp_funcs):
        count = sum(1 for c in recomp_calls if c[1] == func)
        print(f"  {func}: {count} calls")
    
    print(f"\n=== Missing in Recomp (present in Xenia) ===")
    missing = xenia_funcs - recomp_funcs
    for func in sorted(missing):
        count = sum(1 for c in xenia_calls if c[1] == func)
        print(f"  {func}: {count} calls in Xenia")
        # Show first occurrence
        for line_num, f, line in xenia_calls:
            if f == func:
                print(f"    Line {line_num}: {line[:100]}")
                break
    
    print(f"\n=== Extra in Recomp (not in Xenia) ===")
    extra = recomp_funcs - xenia_funcs
    for func in sorted(extra):
        count = sum(1 for c in recomp_calls if c[1] == func)
        print(f"  {func}: {count} calls")
    
    # Check for Draw commands specifically
    print(f"\n=== Draw Commands ===")
    xenia_draws = [c for c in xenia_calls if 'Draw' in c[1] or 'IssueDraw' in c[1]]
    recomp_draws = [c for c in recomp_calls if 'Draw' in c[1]]
    print(f"Xenia: {len(xenia_draws)} draw-related calls")
    print(f"Recomp: {len(recomp_draws)} draw-related calls")
    
    if xenia_draws and not recomp_draws:
        print("\n⚠️  CRITICAL: Xenia has draw commands but Recomp has NONE!")
        print("First draw in Xenia:")
        print(f"  Line {xenia_draws[0][0]}: {xenia_draws[0][2]}")

if __name__ == '__main__':
    main()

