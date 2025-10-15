#!/usr/bin/env python3
"""
Analyze initialization sequence to find missing function calls.
"""

import re
import sys

def analyze_trace(trace_file):
    """Analyze trace file to find initialization sequence."""
    
    print("=== ANALYZING INITIALIZATION SEQUENCE ===\n")
    
    # Read trace file
    with open(trace_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    # Find all function calls in order
    func_calls = []
    for line in lines:
        # Match HOST import lines
        match = re.search(r'\[HOST\] import=([^ ]+)', line)
        if match:
            func_name = match.group(1)
            func_calls.append(func_name)
    
    # Count unique functions
    unique_funcs = set(func_calls)
    print(f"Total function calls: {len(func_calls)}")
    print(f"Unique functions: {len(unique_funcs)}\n")
    
    # Find functions that are called only once (likely initialization)
    func_counts = {}
    for func in func_calls:
        func_counts[func] = func_counts.get(func, 0) + 1
    
    init_funcs = [f for f, count in func_counts.items() if count == 1]
    print(f"Functions called only once (likely init): {len(init_funcs)}")
    for func in sorted(init_funcs):
        print(f"  {func}")
    
    print("\n=== FIRST 50 FUNCTION CALLS (INITIALIZATION) ===\n")
    for i, func in enumerate(func_calls[:50]):
        print(f"{i+1:3d}. {func}")
    
    # Check for specific initialization functions
    print("\n=== CHECKING FOR KEY INITIALIZATION FUNCTIONS ===\n")
    key_funcs = [
        'sub_82548A08',  # Caller 1
        'sub_8284D218',  # Caller 2
        'sub_8284D168',  # Singleton manager
        'sub_82849DE8',  # Worker thread creator
        'sub_82547178',  # Function that calls sub_82548A08
    ]
    
    for func in key_funcs:
        count = func_counts.get(func, 0)
        if count > 0:
            print(f"✓ {func}: called {count} times")
        else:
            print(f"✗ {func}: NOT CALLED")
    
    # Find where VdSwap is first called
    print("\n=== FINDING FIRST VdSwap CALL ===\n")
    for i, func in enumerate(func_calls):
        if 'VdSwap' in func:
            print(f"First VdSwap at call #{i+1}")
            print(f"Previous 10 calls:")
            for j in range(max(0, i-10), i):
                print(f"  {j+1:3d}. {func_calls[j]}")
            break

if __name__ == '__main__':
    trace_file = 'Traces/test_trace.log'
    if len(sys.argv) > 1:
        trace_file = sys.argv[1]
    
    analyze_trace(trace_file)

