#!/usr/bin/env python3
"""Analyze thread creation in Xenia log to understand what triggers Thread #2 to create more threads."""

import re

def main():
    with open('tools/xenia.log', 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    print(f"Total lines in xenia.log: {len(lines)}")
    
    # Find all thread creation events
    thread_creations = []
    for i, line in enumerate(lines):
        if 'ExCreateThread' in line and 'entry=' in line:
            thread_creations.append((i + 1, line.strip()))
    
    print(f"\nFound {len(thread_creations)} thread creation events:")
    for line_num, line in thread_creations[:15]:
        print(f"  Line {line_num}: {line}")
    
    # Find the specific thread creation at line 19106
    print(f"\n\nContext around line 19106 (Thread F800000C creates first worker thread):")
    for i in range(19090, 19121):
        if i < len(lines):
            line = lines[i].strip()
            if line and 'KeDelayExecutionThread' not in line:
                print(f"  Line {i+1}: {line}")
    
    # Find what Thread F800000C was doing before creating the thread
    print(f"\n\nThread F800000C activity before line 19106 (excluding sleep):")
    count = 0
    for i in range(19105, 0, -1):
        if i >= len(lines):
            continue
        line = lines[i].strip()
        if 'F800000C' in line and 'KeDelayExecutionThread' not in line:
            print(f"  Line {i+1}: {line}")
            count += 1
            if count >= 20:
                break
    
    # Check for XObject creation around line 19093
    print(f"\n\nXObject creation around line 19093:")
    for i in range(19080, 19100):
        if i < len(lines):
            line = lines[i].strip()
            if 'XObject' in line or 'ObCreateObject' in line or 'ObInsertObject' in line:
                print(f"  Line {i+1}: {line}")

    # Check what Thread F8000018 (tid=8, entry=0x82812ED0) does
    print(f"\n\nThread F8000018 (tid=8, entry=0x82812ED0) activity:")
    count = 0
    for i, line in enumerate(lines):
        if 'F8000018' in line and 'KeDelayExecutionThread' not in line:
            print(f"  Line {i+1}: {line.strip()}")
            count += 1
            if count >= 30:
                break

if __name__ == '__main__':
    main()

