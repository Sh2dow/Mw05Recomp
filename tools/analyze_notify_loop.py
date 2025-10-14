#!/usr/bin/env python3
"""Analyze the XNotifyGetNext loop to find the root cause."""

from pathlib import Path
import re

def main():
    log_path = Path("out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log")
    
    if not log_path.exists():
        print(f"ERROR: {log_path} not found!")
        return
    
    # Find all XNotifyGetNext calls
    notify_calls = []
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if 'XNotifyGetNext' in line and 'tid=' in line:
                # Extract tid
                tid_match = re.search(r'tid=([0-9a-f]+)', line)
                if tid_match:
                    tid = tid_match.group(1)
                    notify_calls.append((tid, line.strip()))
    
    print(f"\n=== XNotifyGetNext CALL ANALYSIS ===")
    print(f"Total calls: {len(notify_calls)}")
    
    # Group by thread
    by_thread = {}
    for tid, line in notify_calls:
        if tid not in by_thread:
            by_thread[tid] = []
        by_thread[tid].append(line)
    
    print(f"Threads calling XNotifyGetNext: {len(by_thread)}")
    
    for tid, calls in by_thread.items():
        print(f"\nThread {tid}: {len(calls)} calls")
        print("First 5 calls:")
        for call in calls[:5]:
            print(f"  {call}")
        if len(calls) > 5:
            print(f"  ... ({len(calls) - 5} more calls)")
    
    # Check what happens after the first FOUND
    print(f"\n\n=== CHECKING WHAT HAPPENS AFTER FIRST FOUND ===\n")
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    # Find the line with "FOUND"
    found_idx = -1
    for i, line in enumerate(lines):
        if 'XNotifyGetNext FOUND' in line:
            found_idx = i
            break
    
    if found_idx >= 0:
        print(f"Found FOUND at line {found_idx + 1}")
        print("\nContext (10 lines before and 30 lines after):\n")
        
        start = max(0, found_idx - 10)
        end = min(len(lines), found_idx + 31)
        
        for i in range(start, end):
            marker = ">>> " if i == found_idx else "    "
            print(f"{marker}{i+1:6d}: {lines[i].rstrip()}")

if __name__ == "__main__":
    main()

