#!/usr/bin/env python3
"""Analyze thread activity in MW05 trace logs to understand what the game is doing."""

import re
import sys
from collections import defaultdict, Counter
from pathlib import Path

def analyze_thread_activity(log_path):
    """Analyze what threads are doing in the trace log."""
    
    print("=" * 80)
    print("MW05 THREAD ACTIVITY ANALYSIS")
    print("=" * 80)
    print()
    
    # Track thread activity
    thread_calls = defaultdict(Counter)
    thread_last_lr = {}
    thread_delays = defaultdict(list)
    
    # Read last 50000 lines for recent activity
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
        total_lines = len(lines)
        recent_lines = lines[-50000:] if len(lines) > 50000 else lines
    
    print(f"Analyzing last {len(recent_lines):,} lines of {total_lines:,} total")
    print()
    
    # Parse thread activity
    for line in recent_lines:
        # Extract thread ID and import call
        tid_match = re.search(r'tid=([0-9a-f]+)', line, re.IGNORECASE)
        import_match = re.search(r'import=HOST\.(\w+)', line)
        lr_match = re.search(r'lr=0x([0-9A-F]+)', line, re.IGNORECASE)
        
        if tid_match and import_match:
            tid = tid_match.group(1)
            import_name = import_match.group(1)
            thread_calls[tid][import_name] += 1
            
            if lr_match:
                lr = lr_match.group(1)
                thread_last_lr[tid] = lr
            
            # Track delay durations
            if 'KeDelayExecutionThread' in line:
                r6_match = re.search(r'r6=0x([0-9A-F]+)', line, re.IGNORECASE)
                if r6_match:
                    delay_ticks = int(r6_match.group(1), 16)
                    thread_delays[tid].append(delay_ticks)
    
    # Report thread activity
    print("THREAD ACTIVITY SUMMARY")
    print("=" * 80)
    print()
    
    for tid in sorted(thread_calls.keys()):
        calls = thread_calls[tid]
        total_calls = sum(calls.values())
        last_lr = thread_last_lr.get(tid, "unknown")
        
        print(f"Thread {tid}:")
        print(f"  Total calls: {total_calls:,}")
        print(f"  Last LR: 0x{last_lr}")
        print(f"  Top calls:")
        for call, count in calls.most_common(5):
            pct = (count / total_calls) * 100
            print(f"    {call:30s}: {count:6,} ({pct:5.1f}%)")
        
        # Show delay stats if thread is sleeping
        if tid in thread_delays and thread_delays[tid]:
            delays = thread_delays[tid]
            avg_delay = sum(delays) / len(delays)
            min_delay = min(delays)
            max_delay = max(delays)
            print(f"  Delay stats: avg={avg_delay:.0f} min={min_delay} max={max_delay} count={len(delays)}")
        
        print()
    
    # Check for specific patterns
    print("=" * 80)
    print("DIAGNOSTIC CHECKS")
    print("=" * 80)
    print()
    
    # Check if any thread is busy-waiting
    for tid, calls in thread_calls.items():
        if calls.get('KeDelayExecutionThread', 0) > 100:
            print(f"⚠️  Thread {tid} is sleeping frequently ({calls['KeDelayExecutionThread']} times)")
            print(f"   This suggests it's waiting for something")
            print()
    
    # Check for GPU-related calls
    gpu_calls = 0
    for tid, calls in thread_calls.items():
        for call in calls:
            if any(x in call.lower() for x in ['vd', 'gpu', 'video', 'present', 'swap']):
                gpu_calls += calls[call]
    
    if gpu_calls > 0:
        print(f"✓ Found {gpu_calls:,} GPU-related calls")
    else:
        print(f"❌ No GPU-related calls found - game may not be initializing graphics")
    print()
    
    # Check for file I/O
    io_calls = 0
    for tid, calls in thread_calls.items():
        for call in calls:
            if any(x in call.lower() for x in ['file', 'read', 'write', 'io']):
                io_calls += calls[call]
    
    if io_calls > 0:
        print(f"✓ Found {io_calls:,} I/O calls - game is loading assets")
    else:
        print(f"⚠️  No I/O calls found")
    print()

if __name__ == '__main__':
    log_path = Path('../out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log')
    if not log_path.exists():
        print(f"Error: Log file not found at {log_path}")
        sys.exit(1)

    analyze_thread_activity(log_path)

