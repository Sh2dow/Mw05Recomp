#!/usr/bin/env python3
"""Compare kernel call sequences between Xenia and our implementation."""

import re
import sys

def extract_xenia_calls(filename, max_lines=2000):
    """Extract kernel calls from Xenia log."""
    calls = []
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            if i >= max_lines:
                break
            # Match lines like: "  i> F8000008 [MW05] KeDelayExecutionThread ..."
            match = re.search(r'i>\s+([0-9A-F]+)\s+\[MW05\]\s+(\S+)', line)
            if match:
                addr = match.group(1)
                func = match.group(2)
                calls.append((addr, func))
    return calls

def extract_our_calls(filename, max_lines=10000):
    """Extract kernel calls from our trace log."""
    calls = []
    # Skip debug/trace functions
    skip_prefixes = ('HOST.', 'watch.', 'Store', 'Load', 'TitleEntry', 'main.',
                     'Init.', 'UnblockThread', 'GuestThread', 'GameWindow',
                     'VideoDevice', 'KernelVar', 'KiSystemStartup', 'sub_')

    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            if i >= max_lines:
                break
            # Match lines like: "[HOST] import=__imp__ExCreateThread tid=..."
            match = re.search(r'import=([^ ]+)', line)
            if match:
                func = match.group(1)
                # Clean up function names
                if func.startswith('__imp__'):
                    func = func[7:]  # Remove __imp__ prefix
                elif func.startswith('HOST.'):
                    func = func[5:]  # Remove HOST. prefix

                # Skip debug/trace functions
                if any(func.startswith(prefix) for prefix in skip_prefixes):
                    continue

                calls.append(func)
    return calls

def compare_sequences(xenia_calls, our_calls, context=5):
    """Compare the two sequences and find differences."""
    print("=" * 80)
    print("XENIA KERNEL CALL SEQUENCE (first 100 calls):")
    print("=" * 80)
    for i, (addr, func) in enumerate(xenia_calls[:100]):
        print(f"{i:3d}. {addr} {func}")
    
    print("\n" + "=" * 80)
    print("OUR KERNEL CALL SEQUENCE (first 100 calls):")
    print("=" * 80)
    for i, func in enumerate(our_calls[:100]):
        print(f"{i:3d}. {func}")
    
    print("\n" + "=" * 80)
    print("ANALYSIS:")
    print("=" * 80)
    
    # Extract just function names from Xenia for comparison
    xenia_funcs = [func for addr, func in xenia_calls]
    
    # Find first divergence
    min_len = min(len(xenia_funcs), len(our_calls))
    first_diff = None
    for i in range(min_len):
        if xenia_funcs[i] != our_calls[i]:
            first_diff = i
            break
    
    if first_diff is not None:
        print(f"\nFirst divergence at position {first_diff}:")
        print(f"  Xenia: {xenia_funcs[first_diff]}")
        print(f"  Ours:  {our_calls[first_diff]}")
        
        print(f"\nContext around divergence:")
        start = max(0, first_diff - context)
        end = min(min_len, first_diff + context + 1)
        
        print("\n  Xenia sequence:")
        for i in range(start, end):
            marker = " >>> " if i == first_diff else "     "
            print(f"  {marker}{i:3d}. {xenia_funcs[i]}")
        
        print("\n  Our sequence:")
        for i in range(start, end):
            marker = " >>> " if i == first_diff else "     "
            print(f"  {marker}{i:3d}. {our_calls[i]}")
    else:
        print(f"\nSequences match for the first {min_len} calls!")
    
    # Count unique functions
    xenia_unique = set(xenia_funcs[:100])
    our_unique = set(our_calls[:100])
    
    print(f"\n\nUnique functions in Xenia (first 100): {len(xenia_unique)}")
    print(f"Unique functions in ours (first 100): {len(our_unique)}")
    
    in_xenia_not_ours = xenia_unique - our_unique
    in_ours_not_xenia = our_unique - xenia_unique
    
    if in_xenia_not_ours:
        print(f"\nFunctions in Xenia but not in ours:")
        for func in sorted(in_xenia_not_ours):
            print(f"  - {func}")
    
    if in_ours_not_xenia:
        print(f"\nFunctions in ours but not in Xenia:")
        for func in sorted(in_ours_not_xenia):
            print(f"  - {func}")

if __name__ == '__main__':
    xenia_log = 'tools/xenia.log'
    our_log = 'out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log'
    
    print("Extracting Xenia kernel calls...")
    xenia_calls = extract_xenia_calls(xenia_log)
    print(f"Found {len(xenia_calls)} calls in Xenia log")
    
    print("Extracting our kernel calls...")
    our_calls = extract_our_calls(our_log)
    print(f"Found {len(our_calls)} calls in our log")
    
    print("\n")
    compare_sequences(xenia_calls, our_calls)

