#!/usr/bin/env python3
"""
Analyze Xenia log to find what triggers thread creation around vblank tick 227.
"""

import re

def main():
    log_file = 'tools/xenia.log'
    
    print("Reading Xenia log...")
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    print(f"Total lines: {len(lines)}")
    
    # Find the first line with thread F800000C
    thread_first_line = None
    for i, line in enumerate(lines):
        if 'F800000C' in line:
            thread_first_line = i
            print(f"\nFound first mention of thread F800000C at line {i}:")
            print(f"  {line.strip()}")
            break

    if thread_first_line is None:
        print("Thread F800000C not found!")
        return

    # Find ExCreateThread calls around that time
    print(f"\n=== ExCreateThread calls around line {thread_first_line} ===")
    start = max(0, thread_first_line - 50)
    end = min(len(lines), thread_first_line + 10)
    for i in range(start, end):
        if 'ExCreateThread' in lines[i]:
            print(f"{i:6d}: {lines[i].strip()}")

    thread_creation_line = thread_first_line
    
    # Show context before thread creation (50 lines before)
    print(f"\n=== Context BEFORE thread creation (50 lines) ===")
    start = max(0, thread_creation_line - 50)
    for i in range(start, thread_creation_line):
        print(f"{i:6d}: {lines[i].rstrip()}")
    
    print(f"\n=== Thread creation line ===")
    print(f"{thread_creation_line:6d}: {lines[thread_creation_line].rstrip()}")
    
    # Show context after thread creation (10 lines after)
    print(f"\n=== Context AFTER thread creation (10 lines) ===")
    end = min(len(lines), thread_creation_line + 11)
    for i in range(thread_creation_line + 1, end):
        print(f"{i:6d}: {lines[i].rstrip()}")
    
    # Look for patterns in the 100 lines before thread creation
    print(f"\n=== Analysis of 100 lines before thread creation ===")
    start = max(0, thread_creation_line - 100)
    context = lines[start:thread_creation_line]

    # Count different types of operations
    file_ops = sum(1 for line in context if any(op in line for op in ['NtReadFile', 'NtOpenFile', 'NtCreateFile', 'NtClose']))
    events = sum(1 for line in context if any(op in line for op in ['KeSetEvent', 'KeWaitFor', 'NtSetEvent']))
    memory_ops = sum(1 for line in context if any(op in line for op in ['NtAllocate', 'NtFree', 'MmAllocate']))
    thread_ops = sum(1 for line in context if 'Thread' in line and 'ExCreateThread' not in line)

    print(f"  File operations: {file_ops}")
    print(f"  Event operations: {events}")
    print(f"  Memory operations: {memory_ops}")
    print(f"  Thread operations: {thread_ops}")

    # Look for what thread F8000008 was doing before creating the new thread
    print(f"\n=== Thread F8000008 activity in 200 lines before thread creation ===")
    start = max(0, thread_creation_line - 200)
    for i in range(start, thread_creation_line):
        if 'F8000008' in lines[i] and 'MarkVblank' not in lines[i] and 'GPU counter' not in lines[i] and 'VD notify' not in lines[i]:
            print(f"{i:6d}: {lines[i].strip()}")
    
    # Find the last significant operation before thread creation
    print(f"\n=== Last 10 significant operations before thread creation ===")
    significant_ops = []
    for i in range(thread_creation_line - 1, max(0, thread_creation_line - 200), -1):
        line = lines[i]
        if any(op in line for op in ['Nt', 'Ke', 'Mm', 'Ex', 'Vd', 'Xam']):
            significant_ops.append((i, line.strip()))
            if len(significant_ops) >= 10:
                break
    
    for i, line in reversed(significant_ops):
        print(f"{i:6d}: {line}")

if __name__ == '__main__':
    main()

