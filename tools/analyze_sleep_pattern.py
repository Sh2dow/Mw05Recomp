#!/usr/bin/env python3
"""Analyze sleep pattern to understand what the game is waiting for."""

import re
from pathlib import Path
from collections import defaultdict

def main():
    trace_file = Path("out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log")
    
    if not trace_file.exists():
        print(f"Trace file not found: {trace_file}")
        return
    
    print(f"Analyzing {trace_file}...")
    
    # Track sleep calls and what happens around them
    sleep_contexts = []
    lines = []
    
    with open(trace_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    print(f"Total lines: {len(lines)}")
    
    # Find all KeDelayExecutionThread calls
    for i, line in enumerate(lines):
        if 'KeDelayExecutionThread' in line:
            # Get context: 5 lines before and 5 lines after
            context_before = lines[max(0, i-5):i]
            context_after = lines[i+1:min(len(lines), i+6)]
            
            sleep_contexts.append({
                'line_num': i,
                'line': line,
                'before': context_before,
                'after': context_after
            })
    
    print(f"\nTotal sleep calls: {len(sleep_contexts)}")
    
    # Analyze first few sleep calls
    print("\n" + "=" * 80)
    print("First 5 sleep calls with context:")
    print("=" * 80)
    for ctx in sleep_contexts[:5]:
        print(f"\nLine {ctx['line_num']}:")
        print("  Before:")
        for line in ctx['before'][-3:]:
            print(f"    {line.rstrip()}")
        print(f"  >>> {ctx['line'].rstrip()}")
        print("  After:")
        for line in ctx['after'][:3]:
            print(f"    {line.rstrip()}")
    
    # Analyze what functions are called between sleeps
    print("\n" + "=" * 80)
    print("Functions called between sleeps:")
    print("=" * 80)
    
    if len(sleep_contexts) >= 2:
        # Look at what happens between first two sleeps
        start = sleep_contexts[0]['line_num']
        end = sleep_contexts[1]['line_num']
        between_lines = lines[start+1:end]
        
        print(f"\nBetween sleep 1 and sleep 2 ({end - start - 1} lines):")
        functions = defaultdict(int)
        for line in between_lines:
            match = re.search(r'import=([^ ]+)', line)
            if match:
                functions[match.group(1)] += 1
        
        for func, count in sorted(functions.items(), key=lambda x: x[1], reverse=True)[:20]:
            print(f"  {func}: {count}")
    
    # Check if sleep duration changes
    print("\n" + "=" * 80)
    print("Sleep durations:")
    print("=" * 80)
    
    durations = []
    for ctx in sleep_contexts[:100]:  # First 100 sleeps
        match = re.search(r'timeout=([0-9]+)', ctx['line'])
        if match:
            durations.append(int(match.group(1)))
    
    if durations:
        print(f"  Min: {min(durations)}")
        print(f"  Max: {max(durations)}")
        print(f"  Avg: {sum(durations) / len(durations):.2f}")
        print(f"  Unique values: {sorted(set(durations))}")
    
    # Look for patterns in what the game is doing
    print("\n" + "=" * 80)
    print("Looking for patterns:")
    print("=" * 80)
    
    # Check if there are any waits on specific objects
    waits = [line for line in lines if 'WaitForSingleObject' in line or 'NtWaitForSingleObject' in line]
    print(f"  Wait calls: {len(waits)}")
    if waits:
        print("  Sample waits:")
        for wait in waits[:5]:
            print(f"    {wait.rstrip()}")
    
    # Check for thread creation
    threads = [line for line in lines if 'CreateThread' in line or 'ExCreateThread' in line]
    print(f"\n  Thread creations: {len(threads)}")
    if threads:
        print("  Threads created:")
        for thread in threads:
            print(f"    {thread.rstrip()}")
    
    # Check for event/semaphore operations
    events = [line for line in lines if 'SetEvent' in line or 'PulseEvent' in line or 'ReleaseSemaphore' in line]
    print(f"\n  Event/Semaphore operations: {len(events)}")
    if events:
        print("  Sample operations:")
        for event in events[:10]:
            print(f"    {event.rstrip()}")

if __name__ == "__main__":
    main()

