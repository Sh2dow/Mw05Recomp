#!/usr/bin/env python3
"""Analyze what the main thread is doing between frame updates."""

import re
from collections import Counter

def analyze_main_thread_pattern(filename, main_tid='688c'):
    """Analyze the pattern of calls in the main thread."""
    
    calls = []
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Match lines for the main thread
            match = re.search(r'import=([^ ]+).*tid=' + main_tid, line)
            if match:
                func = match.group(1)
                
                # Clean up function names
                if func.startswith('__imp__'):
                    func = func[7:]
                elif func.startswith('HOST.'):
                    func = func[5:]
                
                # Skip debug/trace functions
                skip_prefixes = ('Store', 'Load', 'watch.', 'TitleEntry', 'main.', 
                               'Init.', 'UnblockThread', 'GuestThread', 'GameWindow', 
                               'VideoDevice', 'KernelVar', 'KiSystemStartup')
                if any(func.startswith(prefix) for prefix in skip_prefixes):
                    continue
                
                calls.append(func)
    
    return calls

def find_repeating_patterns(calls, min_length=3, max_length=20):
    """Find repeating patterns in the call sequence."""
    patterns = Counter()
    
    for length in range(min_length, max_length + 1):
        for i in range(len(calls) - length):
            pattern = tuple(calls[i:i+length])
            patterns[pattern] += 1
    
    # Filter to patterns that repeat at least 3 times
    repeating = {p: count for p, count in patterns.items() if count >= 3}
    return repeating

if __name__ == '__main__':
    log_file = 'out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log'
    
    print("Analyzing main thread call pattern...")
    calls = analyze_main_thread_pattern(log_file)
    
    print(f"\nTotal calls by main thread: {len(calls)}")
    
    # Show first 100 calls
    print("\nFirst 100 calls:")
    for i, func in enumerate(calls[:100]):
        print(f"  {i:3d}. {func}")
    
    # Find repeating patterns
    print("\n" + "="*80)
    print("REPEATING PATTERNS (3+ occurrences):")
    print("="*80)
    patterns = find_repeating_patterns(calls)
    
    # Sort by frequency
    sorted_patterns = sorted(patterns.items(), key=lambda x: -x[1])
    
    for pattern, count in sorted_patterns[:20]:
        print(f"\nPattern (repeated {count} times):")
        for func in pattern:
            print(f"  - {func}")

