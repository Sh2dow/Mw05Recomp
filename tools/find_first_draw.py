#!/usr/bin/env python3
"""Find the first draw command in Xenia log and show context."""

import re

def find_first_draw(filename):
    """Find the first draw command and show context."""
    
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    for i, line in enumerate(lines):
        if re.search(r'Draw.*NDX', line):
            print(f"Found first draw command at line {i}:")
            print()
            
            # Show 50 lines before
            start = max(0, i - 50)
            for j in range(start, i):
                print(f"{j:6d}: {lines[j]}", end='')
            
            # Show the draw command line
            print(f"{i:6d}: >>> {lines[i]}", end='')
            
            # Show 10 lines after
            end = min(len(lines), i + 10)
            for j in range(i + 1, end):
                print(f"{j:6d}: {lines[j]}", end='')
            
            return i
    
    print("No draw command found in log!")
    return None

if __name__ == '__main__':
    find_first_draw('tools/xenia.log')

