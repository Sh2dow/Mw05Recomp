#!/usr/bin/env python3
"""Analyze what the main game loop is doing."""

import re
from collections import Counter, defaultdict

def analyze_thread_activity(filename, target_tid=None):
    """Analyze what each thread is doing."""
    
    # Track function calls per thread
    thread_calls = defaultdict(Counter)
    thread_addresses = defaultdict(Counter)
    
    # Track last N calls per thread
    thread_recent = defaultdict(list)
    recent_limit = 50
    
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Match lines like: "[HOST] import=sub_82441CF0 tid=688c lr=0x82441E54"
            match = re.search(r'import=([^ ]+).*tid=([0-9a-f]+).*lr=(0x[0-9A-F]+)', line)
            if match:
                func = match.group(1)
                tid = match.group(2)
                lr = match.group(3)
                
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
                
                thread_calls[tid][func] += 1
                thread_addresses[tid][lr] += 1
                
                # Track recent calls
                thread_recent[tid].append((func, lr))
                if len(thread_recent[tid]) > recent_limit:
                    thread_recent[tid].pop(0)
    
    return thread_calls, thread_addresses, thread_recent

def find_main_thread(thread_calls):
    """Find the main game thread (likely the one calling sub_82441CF0)."""
    for tid, calls in thread_calls.items():
        if 'sub_82441CF0' in calls:
            return tid
    # If not found, return the thread with most activity
    return max(thread_calls.items(), key=lambda x: sum(x[1].values()))[0]

def analyze_spin_loops(thread_addresses):
    """Find potential spin loops (same address called many times)."""
    spin_loops = {}
    for tid, addresses in thread_addresses.items():
        # Find addresses called more than 100 times
        hot_addresses = {addr: count for addr, count in addresses.items() if count > 100}
        if hot_addresses:
            spin_loops[tid] = hot_addresses
    return spin_loops

if __name__ == '__main__':
    log_file = 'out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log'
    
    print("Analyzing thread activity...")
    thread_calls, thread_addresses, thread_recent = analyze_thread_activity(log_file)
    
    print(f"\nFound {len(thread_calls)} active threads")
    
    # Find main thread
    main_tid = find_main_thread(thread_calls)
    print(f"\nMain game thread: tid={main_tid}")
    
    # Show top functions for main thread
    print(f"\nTop 20 functions called by main thread (tid={main_tid}):")
    for func, count in thread_calls[main_tid].most_common(20):
        print(f"  {count:6d}  {func}")
    
    # Show recent calls for main thread
    print(f"\nLast {len(thread_recent[main_tid])} calls by main thread:")
    for i, (func, lr) in enumerate(thread_recent[main_tid][-20:]):
        print(f"  {i:3d}. {func:40s} lr={lr}")
    
    # Find spin loops
    print("\n" + "="*80)
    print("POTENTIAL SPIN LOOPS (addresses called >100 times):")
    print("="*80)
    spin_loops = analyze_spin_loops(thread_addresses)
    for tid, addresses in sorted(spin_loops.items()):
        print(f"\nThread tid={tid}:")
        for addr, count in sorted(addresses.items(), key=lambda x: -x[1])[:10]:
            print(f"  {count:6d} calls from lr={addr}")
    
    # Show all threads and their activity
    print("\n" + "="*80)
    print("ALL THREADS SUMMARY:")
    print("="*80)
    for tid in sorted(thread_calls.keys()):
        total_calls = sum(thread_calls[tid].values())
        top_func = thread_calls[tid].most_common(1)[0] if thread_calls[tid] else ("N/A", 0)
        print(f"tid={tid}: {total_calls:6d} calls, top: {top_func[0]} ({top_func[1]})")

