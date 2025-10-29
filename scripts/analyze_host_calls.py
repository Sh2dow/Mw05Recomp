#!/usr/bin/env python3
"""Analyze which HOST functions are being called."""

import re
from collections import Counter

def main():
    host_calls = []
    
    with open('traces/auto_test_stderr.txt', 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if '[HOST.' in line and 'PM4' not in line and 'VdSwap' not in line:
                # Extract function name
                match = re.search(r'\[HOST\.([^\]]+)\]', line)
                if match:
                    func_name = match.group(1)
                    host_calls.append(func_name)
    
    # Count occurrences
    counter = Counter(host_calls)
    
    print("HOST functions called (excluding PM4 and VdSwap):")
    print("=" * 60)
    for func, count in counter.most_common():
        print(f"{func:50s} : {count:6d} calls")
    
    print("\n" + "=" * 60)
    print(f"Total unique functions: {len(counter)}")
    print(f"Total calls: {sum(counter.values())}")

if __name__ == '__main__':
    main()

