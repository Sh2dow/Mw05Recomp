#!/usr/bin/env python3
"""Show context around first draw in Xenia log."""

with open('tools/xenia.log', 'r', encoding='utf-8', errors='ignore') as f:
    lines = f.readlines()

# Find first draw
for i, line in enumerate(lines):
    if 'Draw' in line and 'NDX' in line:
        print(f"First draw at line {i}:")
        print()
        
        # Show 50 lines before
        start = max(0, i - 50)
        for j in range(start, i):
            print(f"{j:6d}: {lines[j]}", end='')
        
        # Show the draw line
        print(f"{i:6d}: >>> {lines[i]}", end='')
        
        # Show 10 lines after
        end = min(len(lines), i + 10)
        for j in range(i + 1, end):
            print(f"{j:6d}: {lines[j]}", end='')
        
        break

