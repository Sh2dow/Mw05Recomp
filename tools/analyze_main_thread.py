#!/usr/bin/env python3
"""
Analyze the main thread (tid=a9c4) to see what it's doing.
"""

import re
import sys

def analyze_main_thread(log_path):
    """Analyze the main thread's execution."""
    
    main_tid = 'a9c4'
    
    # Track function calls (non-Store operations)
    function_calls = []
    last_100_lines = []
    
    print(f"Analyzing main thread {main_tid}...")
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if f'tid={main_tid}' in line:
                last_100_lines.append(line.strip())
                if len(last_100_lines) > 100:
                    last_100_lines.pop(0)
                
                # Skip Store operations
                if 'Store64BE_W' not in line and 'Store8BE_W' not in line:
                    function_calls.append(line.strip())
    
    print("\n" + "="*80)
    print(f"MAIN THREAD ({main_tid}) - NON-STORE FUNCTION CALLS")
    print("="*80)
    print(f"Total non-store calls: {len(function_calls)}")
    print("\nFirst 20:")
    for i, call in enumerate(function_calls[:20], 1):
        # Extract just the important part
        match = re.search(r'\[HOST\] import=([^ ]+)', call)
        if match:
            print(f"{i:3d}. {match.group(1)}")
    
    print("\nLast 20:")
    for i, call in enumerate(function_calls[-20:], 1):
        match = re.search(r'\[HOST\] import=([^ ]+)', call)
        if match:
            print(f"{i:3d}. {match.group(1)}")
    
    print("\n" + "="*80)
    print("LAST 100 LINES (including stores)")
    print("="*80)
    for i, line in enumerate(last_100_lines[-20:], 1):
        # Extract key info
        match = re.search(r'import=([^ ]+).*lr=(0x[0-9A-Fa-f]+)', line)
        if match:
            func = match.group(1)
            lr = match.group(2)
            print(f"{i:3d}. {func:50s} lr={lr}")

if __name__ == '__main__':
    log_path = sys.argv[1] if len(sys.argv) > 1 else 'out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log'
    analyze_main_thread(log_path)

