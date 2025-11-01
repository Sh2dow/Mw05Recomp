#!/usr/bin/env python3
"""
Analyze worker thread state to identify why loader jobs aren't being processed.
"""

import re
import sys
from collections import defaultdict

def analyze_worker_threads(stderr_file):
    """Analyze worker thread activity and identify blocking issues."""
    
    with open(stderr_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    print("=" * 80)
    print("WORKER THREAD ANALYSIS")
    print("=" * 80)
    
    # Find worker thread creation
    worker_threads = []
    for line in lines:
        if 'FORCE_WORKERS' in line and 'created' in line:
            match = re.search(r'handle=(0x[0-9A-F]+)\s+tid=(0x[0-9A-F]+)', line)
            if match:
                worker_threads.append({
                    'handle': match.group(1),
                    'tid': match.group(2)
                })
    
    print(f"\n{len(worker_threads)} worker threads created:")
    for i, worker in enumerate(worker_threads, 1):
        print(f"  Worker #{i}: handle={worker['handle']} tid={worker['tid']}")
    
    # Check if worker threads are running
    print("\nWorker thread activity:")
    worker_activity = defaultdict(int)
    for line in lines:
        for worker in worker_threads:
            if worker['tid'] in line:
                worker_activity[worker['tid']] += 1
    
    for worker in worker_threads:
        tid = worker['tid']
        count = worker_activity.get(tid, 0)
        print(f"  {tid}: {count} log entries")
        if count == 0:
            print(f"    ⚠️  WARNING: No activity detected!")
    
    # Check loader state
    print("\nLoader state:")
    loader_states = []
    for line in lines:
        if 'LOADER-STATE' in line:
            loader_states.append(line.strip())
    
    if loader_states:
        print(f"  Found {len(loader_states)} loader state checks")
        print(f"  First: {loader_states[0]}")
        print(f"  Last:  {loader_states[-1]}")
    else:
        print("  ⚠️  No loader state checks found!")
    
    # Check job queue
    print("\nJob queue state:")
    job_queue_states = []
    for line in lines:
        if 'JOB-QUEUE' in line:
            job_queue_states.append(line.strip())
    
    if job_queue_states:
        print(f"  Found {len(job_queue_states)} job queue checks")
        print(f"  First: {job_queue_states[0]}")
        print(f"  Last:  {job_queue_states[-1]}")
    else:
        print("  ⚠️  No job queue checks found!")
    
    # Check for wait/sleep calls
    print("\nWait/Sleep activity:")
    wait_patterns = [
        ('NtWaitForSingleObject', r'NtWaitForSingleObject'),
        ('NtWaitForMultipleObjects', r'NtWaitForMultipleObjects'),
        ('Sleep', r'Sleep|sleep'),
        ('KeWaitForSingleObject', r'KeWaitForSingleObject'),
    ]
    
    for name, pattern in wait_patterns:
        count = sum(1 for line in lines if re.search(pattern, line, re.IGNORECASE))
        if count > 0:
            print(f"  {name}: {count} calls")
    
    # Check for thread completion
    print("\nThread completion:")
    completed_threads = []
    for line in lines:
        if 'GUEST_THREAD' in line and 'COMPLETED' in line:
            completed_threads.append(line.strip())
    
    if completed_threads:
        print(f"  {len(completed_threads)} threads completed:")
        for line in completed_threads[:10]:  # Show first 10
            print(f"    {line}")
    else:
        print("  No threads completed (workers may be stuck in infinite loop)")
    
    # Check for errors
    print("\nErrors:")
    error_count = sum(1 for line in lines if 'ERROR' in line or 'FAILED' in line)
    if error_count > 0:
        print(f"  Found {error_count} error messages")
        for line in lines:
            if 'ERROR' in line or 'FAILED' in line:
                print(f"    {line.strip()}")
                if error_count > 10:
                    break
    else:
        print("  No errors found")
    
    print("\n" + "=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)

if __name__ == '__main__':
    stderr_file = 'traces/auto_test_stderr.txt'
    if len(sys.argv) > 1:
        stderr_file = sys.argv[1]
    
    analyze_worker_threads(stderr_file)

