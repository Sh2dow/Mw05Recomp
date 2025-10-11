#!/usr/bin/env python3
"""
Deep debugging script to analyze where the game is stuck.
Analyzes the trace log to find execution patterns and blocking points.
"""

import re
import sys
from collections import defaultdict, Counter
from pathlib import Path

def parse_trace_log(log_path):
    """Parse the trace log and extract key information."""
    
    print(f"Analyzing trace log: {log_path}")
    
    # Track function calls per thread
    thread_calls = defaultdict(list)
    function_counts = Counter()
    lr_addresses = Counter()
    
    # Track specific patterns
    sleep_calls = []
    frame_update_calls = []
    file_io_calls = []
    
    # Track main thread activity
    main_thread_id = None
    main_thread_functions = []
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            # Extract thread ID
            tid_match = re.search(r'tid=([0-9a-fA-F]+)', line)
            if tid_match:
                tid = tid_match.group(1)
                
                # Extract function name
                func_match = re.search(r'import=([a-zA-Z0-9_]+)', line)
                if func_match:
                    func_name = func_match.group(1)
                    thread_calls[tid].append(func_name)
                    function_counts[func_name] += 1
                    
                    # Track main thread (first thread that calls frame update)
                    if 'sub_8262DE60' in func_name and main_thread_id is None:
                        main_thread_id = tid
                        print(f"Main thread identified: tid={tid}")
                    
                    # Track specific function calls
                    if 'KeDelayExecutionThread' in func_name or 'sub_8262D9D0' in func_name:
                        sleep_calls.append((line_num, tid, line.strip()))
                    
                    if 'sub_8262DE60' in func_name:
                        frame_update_calls.append((line_num, tid, line.strip()))
                    
                    if any(x in func_name for x in ['NtCreateFile', 'NtOpenFile', 'NtReadFile']):
                        file_io_calls.append((line_num, tid, line.strip()))
                
                # Extract link register (lr) to see where calls are coming from
                lr_match = re.search(r'lr=0x([0-9a-fA-F]+)', line)
                if lr_match:
                    lr = lr_match.group(1)
                    lr_addresses[lr] += 1
    
    return {
        'thread_calls': thread_calls,
        'function_counts': function_counts,
        'lr_addresses': lr_addresses,
        'sleep_calls': sleep_calls,
        'frame_update_calls': frame_update_calls,
        'file_io_calls': file_io_calls,
        'main_thread_id': main_thread_id,
    }

def analyze_main_thread_pattern(data):
    """Analyze the main thread's execution pattern."""
    
    main_tid = data['main_thread_id']
    if not main_tid:
        print("WARNING: Main thread not identified!")
        return
    
    print(f"\n=== MAIN THREAD ANALYSIS (tid={main_tid}) ===")
    
    # Get main thread calls
    main_calls = data['thread_calls'][main_tid]
    
    if not main_calls:
        print("No calls found for main thread!")
        return
    
    print(f"Total calls: {len(main_calls)}")
    
    # Find repeating patterns
    print("\nMost common functions called by main thread:")
    main_counter = Counter(main_calls)
    for func, count in main_counter.most_common(20):
        print(f"  {func}: {count} calls")
    
    # Look for loops (repeating sequences)
    print("\nLooking for repeating patterns...")
    
    # Check last 100 calls for patterns
    recent_calls = main_calls[-100:] if len(main_calls) > 100 else main_calls
    
    # Find most common 3-call sequence
    sequences = []
    for i in range(len(recent_calls) - 2):
        seq = tuple(recent_calls[i:i+3])
        sequences.append(seq)
    
    seq_counter = Counter(sequences)
    if seq_counter:
        print("\nMost common 3-call sequences in recent activity:")
        for seq, count in seq_counter.most_common(5):
            if count > 1:
                print(f"  {' -> '.join(seq)}: {count} times")

def analyze_sleep_pattern(data):
    """Analyze sleep call patterns."""
    
    print("\n=== SLEEP PATTERN ANALYSIS ===")
    print(f"Total sleep calls: {len(data['sleep_calls'])}")
    
    if data['sleep_calls']:
        print("\nFirst 5 sleep calls:")
        for line_num, tid, line in data['sleep_calls'][:5]:
            print(f"  Line {line_num} (tid={tid}): {line[:100]}")
        
        print("\nLast 5 sleep calls:")
        for line_num, tid, line in data['sleep_calls'][-5:]:
            print(f"  Line {line_num} (tid={tid}): {line[:100]}")

def analyze_frame_updates(data):
    """Analyze frame update call patterns."""
    
    print("\n=== FRAME UPDATE ANALYSIS ===")
    print(f"Total frame update calls: {len(data['frame_update_calls'])}")
    
    if data['frame_update_calls']:
        print("\nFirst 5 frame updates:")
        for line_num, tid, line in data['frame_update_calls'][:5]:
            print(f"  Line {line_num} (tid={tid}): {line[:100]}")
        
        print("\nLast 5 frame updates:")
        for line_num, tid, line in data['frame_update_calls'][-5:]:
            print(f"  Line {line_num} (tid={tid}): {line[:100]}")

def analyze_hotspots(data):
    """Find execution hotspots (most called functions)."""
    
    print("\n=== EXECUTION HOTSPOTS ===")
    print("Top 30 most called functions:")
    
    for func, count in data['function_counts'].most_common(30):
        print(f"  {func}: {count:,} calls")

def analyze_call_sites(data):
    """Analyze where calls are coming from (link register addresses)."""
    
    print("\n=== CALL SITE ANALYSIS ===")
    print("Top 20 link register addresses (where calls originate):")
    
    for lr, count in data['lr_addresses'].most_common(20):
        print(f"  lr=0x{lr}: {count:,} calls")

def check_for_file_io(data):
    """Check if any file I/O has occurred."""
    
    print("\n=== FILE I/O CHECK ===")
    
    if data['file_io_calls']:
        print(f"File I/O calls found: {len(data['file_io_calls'])}")
        for line_num, tid, line in data['file_io_calls'][:10]:
            print(f"  Line {line_num} (tid={tid}): {line[:100]}")
    else:
        print("NO FILE I/O CALLS FOUND!")
        print("This indicates the game hasn't progressed to asset loading.")

def find_blocking_point(data):
    """Try to identify where the game is blocked."""
    
    print("\n=== BLOCKING POINT ANALYSIS ===")
    
    # If there's no file I/O, the game is stuck before asset loading
    if not data['file_io_calls']:
        print("Game is stuck BEFORE file I/O stage.")
        print("Likely causes:")
        print("  1. Waiting for audio initialization")
        print("  2. Waiting for some event that never occurs")
        print("  3. Stuck in an initialization loop")
        print("  4. Missing kernel function implementation")
    
    # Check if main thread is doing anything
    main_tid = data['main_thread_id']
    if main_tid and main_tid in data['thread_calls']:
        main_calls = data['thread_calls'][main_tid]
        
        # If main thread is mostly sleeping, it's waiting for something
        sleep_count = sum(1 for call in main_calls if 'sleep' in call.lower() or 'delay' in call.lower())
        sleep_ratio = sleep_count / len(main_calls) if main_calls else 0
        
        print(f"\nMain thread sleep ratio: {sleep_ratio:.2%}")
        if sleep_ratio > 0.5:
            print("Main thread is spending >50% of time sleeping!")
            print("This suggests it's waiting for an event or condition.")

def main():
    log_path = Path("out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log")
    
    if not log_path.exists():
        print(f"ERROR: Trace log not found at {log_path}")
        sys.exit(1)
    
    print("=" * 80)
    print("MW05 DEEP DEBUGGING TRACE ANALYSIS")
    print("=" * 80)
    
    data = parse_trace_log(log_path)
    
    analyze_hotspots(data)
    analyze_call_sites(data)
    analyze_main_thread_pattern(data)
    analyze_sleep_pattern(data)
    analyze_frame_updates(data)
    check_for_file_io(data)
    find_blocking_point(data)
    
    print("\n" + "=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    main()

