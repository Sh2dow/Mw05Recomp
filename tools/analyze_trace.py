#!/usr/bin/env python3
"""
Analyze MW05 trace log to identify what the game is waiting for.
"""

import re
import sys
from collections import Counter, defaultdict

def analyze_trace(log_path):
    """Analyze the trace log to find blocking patterns."""
    
    # Counters
    function_calls = Counter()
    thread_activity = defaultdict(Counter)
    delay_calls_by_thread = Counter()
    
    # Track what happens between delays
    between_delays = []
    last_was_delay = False
    current_sequence = []
    
    print(f"Analyzing {log_path}...")
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            # Extract function name
            match = re.search(r'import=([^ ]+)', line)
            if match:
                func = match.group(1)
                function_calls[func] += 1
                
                # Extract thread ID
                tid_match = re.search(r'tid=([0-9a-f]+)', line)
                if tid_match:
                    tid = tid_match.group(1)
                    thread_activity[tid][func] += 1
                    
                    # Track delay patterns
                    if 'KeDelayExecutionThread' in func:
                        delay_calls_by_thread[tid] += 1
                        
                        if current_sequence:
                            between_delays.append(current_sequence[:])
                        current_sequence = []
                        last_was_delay = True
                    else:
                        if last_was_delay:
                            current_sequence = [func]
                            last_was_delay = False
                        else:
                            current_sequence.append(func)
    
    print("\n" + "="*80)
    print("TOP 20 MOST CALLED FUNCTIONS")
    print("="*80)
    for func, count in function_calls.most_common(20):
        print(f"{count:8d}  {func}")
    
    print("\n" + "="*80)
    print("THREAD ACTIVITY")
    print("="*80)
    for tid in sorted(thread_activity.keys()):
        total = sum(thread_activity[tid].values())
        delays = delay_calls_by_thread.get(tid, 0)
        delay_pct = (delays / total * 100) if total > 0 else 0
        print(f"\nThread {tid}: {total} calls, {delays} delays ({delay_pct:.1f}%)")
        print(f"  Top functions:")
        for func, count in thread_activity[tid].most_common(5):
            pct = (count / total * 100) if total > 0 else 0
            print(f"    {count:6d} ({pct:5.1f}%)  {func}")
    
    print("\n" + "="*80)
    print("PATTERNS BETWEEN DELAYS (first 20)")
    print("="*80)
    for i, seq in enumerate(between_delays[:20], 1):
        if seq:
            print(f"{i:3d}. {' -> '.join(seq[:10])}")
    
    print("\n" + "="*80)
    print("MISSING CRITICAL FUNCTIONS")
    print("="*80)
    critical_funcs = [
        'XamInputGetState',
        'XamInputGetCapabilities',
        'KeSetEvent',
        'KeWaitForSingleObject',
        'NtCreateFile',
        'NtReadFile',
        'PM4_DRAW_INDX',
        'PM4_DRAW_INDX_2',
    ]
    for func in critical_funcs:
        count = function_calls.get(func, 0)
        status = "✓" if count > 0 else "✗"
        print(f"  {status} {func}: {count}")
    
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    total_calls = sum(function_calls.values())
    delay_calls = function_calls.get('HOST.FastDelay.KeDelayExecutionThread', 0) + \
                  function_calls.get('HOST.Wait.observe.KeDelayExecutionThread', 0)
    delay_pct = (delay_calls / total_calls * 100) if total_calls > 0 else 0
    print(f"Total function calls: {total_calls}")
    print(f"Delay calls: {delay_calls} ({delay_pct:.1f}%)")
    print(f"Unique functions: {len(function_calls)}")
    print(f"Active threads: {len(thread_activity)}")

if __name__ == '__main__':
    log_path = sys.argv[1] if len(sys.argv) > 1 else 'out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log'
    analyze_trace(log_path)

