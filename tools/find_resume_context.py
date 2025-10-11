#!/usr/bin/env python3
"""Find NtResumeThread calls and show context."""

import re

def find_resume_calls(filename):
    """Find NtResumeThread calls and show context."""
    
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    for i, line in enumerate(lines):
        if 'NtResumeThread' in line:
            print(f"Found NtResumeThread at line {i}:")
            print()
            
            # Show 10 lines before
            start = max(0, i - 10)
            for j in range(start, i):
                print(f"{j:6d}: {lines[j]}", end='')
            
            # Show the resume line
            print(f"{i:6d}: >>> {lines[i]}", end='')
            
            # Show 5 lines after
            end = min(len(lines), i + 5)
            for j in range(i + 1, end):
                print(f"{j:6d}: {lines[j]}", end='')
            
            print()

if __name__ == '__main__':
    find_resume_calls('out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log')

