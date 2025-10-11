#!/usr/bin/env python3
"""Analyze trace log to see what functions are being called most frequently."""

import re
from collections import Counter
from pathlib import Path

def main():
    trace_file = Path("out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log")
    
    if not trace_file.exists():
        print(f"Trace file not found: {trace_file}")
        return
    
    print(f"Analyzing {trace_file}...")
    
    # Count function calls
    function_calls = Counter()
    
    with open(trace_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Look for import= pattern
            match = re.search(r'import=([^ ]+)', line)
            if match:
                func_name = match.group(1)
                function_calls[func_name] += 1
    
    print(f"\nTotal unique functions called: {len(function_calls)}")
    print(f"Total function calls: {sum(function_calls.values())}")
    
    print("\nTop 50 most frequently called functions:")
    print("=" * 80)
    for func, count in function_calls.most_common(50):
        print(f"{func:60s} {count:10d}")
    
    # Look for specific patterns
    print("\n" + "=" * 80)
    print("File I/O functions:")
    file_io = {k: v for k, v in function_calls.items() if 'File' in k or 'Read' in k or 'Write' in k}
    for func, count in sorted(file_io.items(), key=lambda x: x[1], reverse=True):
        print(f"  {func}: {count}")
    
    print("\nXam* functions:")
    xam = {k: v for k, v in function_calls.items() if k.startswith('HOST.Xam') or 'Xam' in k}
    for func, count in sorted(xam.items(), key=lambda x: x[1], reverse=True)[:20]:
        print(f"  {func}: {count}")
    
    print("\nVd* (graphics) functions:")
    vd = {k: v for k, v in function_calls.items() if 'Vd' in k or 'GFX' in k or 'RENDER' in k}
    for func, count in sorted(vd.items(), key=lambda x: x[1], reverse=True):
        print(f"  {func}: {count}")

if __name__ == "__main__":
    main()

