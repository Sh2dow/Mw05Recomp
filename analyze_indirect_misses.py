#!/usr/bin/env python3
"""Analyze indirect call misses from MW05 trace output."""

import re
import sys

def main():
    # Read from stdin or file
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    else:
        content = sys.stdin.read()
    
    # Extract all indirect-miss targets
    pattern = r'\[ppc\]\[indirect-miss\] target=0x([0-9A-Fa-f]{8})'
    matches = re.findall(pattern, content)
    
    # Count occurrences
    from collections import Counter
    counter = Counter(matches)
    
    # Sort by frequency (descending)
    sorted_misses = sorted(counter.items(), key=lambda x: x[1], reverse=True)
    
    print(f"Total indirect call misses: {len(matches)}")
    print(f"Unique missing functions: {len(counter)}")
    print()
    print("Top 50 most frequently called missing functions:")
    print("=" * 60)
    for addr, count in sorted_misses[:50]:
        print(f"0x{addr.upper()}: {count:5d} calls")
    
    # Output all unique addresses for adding to MW05.toml
    print()
    print("=" * 60)
    print("All unique missing function addresses (for MW05.toml):")
    print("=" * 60)
    for addr, _ in sorted(counter.items(), key=lambda x: int(x[0], 16)):
        print(f"0x{addr.upper()}")

if __name__ == '__main__':
    main()

