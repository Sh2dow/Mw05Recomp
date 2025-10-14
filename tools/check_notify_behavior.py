#!/usr/bin/env python3
"""Check XNotifyGetNext behavior in Xenia vs our implementation."""

import re

def analyze_xenia():
    """Analyze Xenia log for XNotifyGetNext calls."""
    with open('tools/xenia.log', 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    for i, line in enumerate(lines):
        if 'XNotifyGetNext' in line:
            print(f"=== XENIA: XNotifyGetNext at line {i+1} ===")
            # Print context
            start = max(0, i-10)
            end = min(len(lines), i+50)
            for j in range(start, end):
                marker = ">>>" if j == i else "   "
                print(f"{marker} {j+1:6d}: {lines[j].rstrip()}")
            break

def analyze_ours():
    """Analyze our trace log for XNotifyGetNext calls."""
    with open('out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log', 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    count = 0
    for i, line in enumerate(lines):
        if 'XNotifyGetNext' in line:
            count += 1
            if count <= 5:
                print(f"Call {count}: {line.rstrip()}")
    
    print(f"\nTotal XNotifyGetNext calls: {count}")

if __name__ == '__main__':
    print("=== XENIA ANALYSIS ===")
    analyze_xenia()
    print("\n=== OUR IMPLEMENTATION ANALYSIS ===")
    analyze_ours()

