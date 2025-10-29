#!/usr/bin/env python3
"""Analyze which PPC functions are being called most frequently."""

import re
from collections import Counter

def main():
    ppc_calls = []
    
    with open('traces/auto_test_stderr.txt', 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Look for function call patterns like "sub_XXXXXXXX" in logs
            matches = re.findall(r'sub_([0-9A-F]{8})', line)
            ppc_calls.extend(matches)
    
    # Count occurrences
    counter = Counter(ppc_calls)
    
    print("Top 50 most frequently called PPC functions:")
    print("=" * 60)
    for func, count in counter.most_common(50):
        print(f"sub_{func:8s} : {count:8d} calls")
    
    print("\n" + "=" * 60)
    print(f"Total unique functions: {len(counter)}")
    print(f"Total calls: {sum(counter.values())}")

if __name__ == '__main__':
    main()

