#!/usr/bin/env python3
"""Analyze kernel function calls from trace log."""

import re
from collections import Counter

def main():
    trace_file = "out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log"
    
    # Count kernel function calls
    func_calls = Counter()
    
    with open(trace_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Match: import=__imp__FunctionName
            match = re.search(r'import=__imp__([a-zA-Z0-9_]+)', line)
            if match:
                func_name = match.group(1)
                func_calls[func_name] += 1
    
    print("Top 20 most frequently called kernel functions:")
    print("=" * 60)
    for func, count in func_calls.most_common(20):
        print(f"{func:40s} {count:10d}")
    
    print("\n" + "=" * 60)
    print(f"Total unique functions called: {len(func_calls)}")
    print(f"Total function calls: {sum(func_calls.values())}")

if __name__ == "__main__":
    main()

