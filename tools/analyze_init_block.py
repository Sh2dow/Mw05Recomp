#!/usr/bin/env python3
"""
Analyze MW05 initialization to find what's blocking CreateDevice from being called.
"""

import sys
import re
from collections import defaultdict, Counter

def analyze_log(log_path):
    """Analyze the log to understand initialization flow."""
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    print(f"Total log lines: {len(lines)}")
    print()
    
    # Find all unique function calls
    func_calls = []
    for line in lines[:500]:  # First 500 lines
        if 'import=' in line:
            match = re.search(r'import=([^ ]+)', line)
            if match:
                func_calls.append(match.group(1))
    
    print("=== First 500 lines - Function call frequency ===")
    counter = Counter(func_calls)
    for func, count in counter.most_common(30):
        print(f"{count:5d}  {func}")
    print()
    
    # Check for CreateDevice
    create_device_calls = [line for line in lines if 'CreateDevice' in line or 'sub_82598230' in line]
    print(f"=== CreateDevice mentions: {len(create_device_calls)} ===")
    for line in create_device_calls[:10]:
        print(line.rstrip())
    print()
    
    # Check for thread creation
    thread_lines = [line for line in lines if 'ThreadEntry' in line]
    print(f"=== Thread entries: {len(thread_lines)} ===")
    for line in thread_lines[:10]:
        print(line.rstrip())
    print()
    
    # Check for waits/blocks
    wait_lines = [line for line in lines if 'Wait' in line or 'wait' in line or 'block' in line]
    print(f"=== Wait/block events: {len(wait_lines)} ===")
    for line in wait_lines[:20]:
        print(line.rstrip())
    print()
    
    # Check what's happening in the vblank loop
    vblank_lines = [line for line in lines if 'VblankPump' in line or 'VdCallGraphicsNotificationRoutines' in line]
    print(f"=== Vblank activity: {len(vblank_lines)} ===")
    print(f"First 5:")
    for line in vblank_lines[:5]:
        print(line.rstrip())
    print(f"Last 5:")
    for line in vblank_lines[-5:]:
        print(line.rstrip())
    print()
    
    # Check for file I/O
    io_lines = [line for line in lines if 'NtReadFile' in line or 'NtCreateFile' in line or 'NtOpenFile' in line]
    print(f"=== File I/O: {len(io_lines)} ===")
    for line in io_lines[:20]:
        print(line.rstrip())
    print()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python analyze_init_block.py <log_path>")
        sys.exit(1)
    
    analyze_log(sys.argv[1])

