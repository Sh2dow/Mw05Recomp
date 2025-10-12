#!/usr/bin/env python3
"""
Analyze Thread #2 (F8000018, entry=0x82812ED0) behavior in Xenia log.
This script extracts all activity related to Thread #2 to understand what it does.
"""

import re
import sys

def analyze_xenia_log(log_file):
    """Analyze Xenia log for Thread #2 (F8000018) activity."""
    
    print("=" * 80)
    print("Thread #2 (F8000018, entry=0x82812ED0) Analysis")
    print("=" * 80)
    
    thread_created_line = None
    thread_execute_line = None
    thread_lines = []
    kernel_calls = []
    
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            # Find thread creation
            if 'F8000018' in line and 'Thread created' in line and 'entry=0x82812ED0' in line:
                thread_created_line = line_num
                print(f"\n[Line {line_num}] THREAD CREATED:")
                print(f"  {line.strip()}")
            
            # Find thread execution start
            if 'F8000018' in line and 'Execute' in line:
                thread_execute_line = line_num
                print(f"\n[Line {line_num}] THREAD EXECUTION START:")
                print(f"  {line.strip()}")
                if thread_created_line:
                    delay = line_num - thread_created_line
                    print(f"  Delay from creation: {delay} lines")
            
            # Collect all lines mentioning F8000018
            if 'F8000018' in line or (line.startswith('i> F800000C') and 'F8000018' in line):
                thread_lines.append((line_num, line.strip()))
                
                # Extract kernel calls
                if '[MW05]' in line:
                    # Extract kernel function name
                    match = re.search(r'\[MW05\]\s+(\w+)', line)
                    if match:
                        kernel_calls.append((line_num, match.group(1), line.strip()))
    
    # Print summary
    print(f"\n{'=' * 80}")
    print("SUMMARY")
    print(f"{'=' * 80}")
    print(f"Thread created at line: {thread_created_line}")
    print(f"Thread execution started at line: {thread_execute_line}")
    if thread_created_line and thread_execute_line:
        print(f"Delay: {thread_execute_line - thread_created_line} lines")
    print(f"Total lines mentioning F8000018: {len(thread_lines)}")
    print(f"Kernel calls made by thread: {len(kernel_calls)}")
    
    # Print all thread activity
    print(f"\n{'=' * 80}")
    print("ALL THREAD #2 ACTIVITY (first 50 lines)")
    print(f"{'=' * 80}")
    for i, (line_num, line) in enumerate(thread_lines[:50]):
        print(f"[{line_num:6d}] {line}")
    
    if len(thread_lines) > 50:
        print(f"\n... ({len(thread_lines) - 50} more lines)")
    
    # Print kernel calls
    if kernel_calls:
        print(f"\n{'=' * 80}")
        print("KERNEL CALLS BY THREAD #2")
        print(f"{'=' * 80}")
        for line_num, func_name, line in kernel_calls[:30]:
            print(f"[{line_num:6d}] {func_name}")
            print(f"           {line}")
        
        if len(kernel_calls) > 30:
            print(f"\n... ({len(kernel_calls) - 30} more kernel calls)")
    
    # Analyze patterns
    print(f"\n{'=' * 80}")
    print("PATTERN ANALYSIS")
    print(f"{'=' * 80}")
    
    # Count kernel call types
    call_counts = {}
    for _, func_name, _ in kernel_calls:
        call_counts[func_name] = call_counts.get(func_name, 0) + 1
    
    if call_counts:
        print("\nKernel call frequency:")
        for func_name, count in sorted(call_counts.items(), key=lambda x: -x[1]):
            print(f"  {func_name}: {count} calls")
    
    # Check for specific patterns
    print("\nPattern checks:")
    
    # Does thread wait on events?
    wait_calls = [c for c in kernel_calls if 'Wait' in c[1]]
    print(f"  Wait calls: {len(wait_calls)}")
    if wait_calls:
        print(f"    First wait: Line {wait_calls[0][0]} - {wait_calls[0][1]}")
    
    # Does thread sleep?
    sleep_calls = [c for c in kernel_calls if 'Delay' in c[1] or 'Sleep' in c[1]]
    print(f"  Sleep calls: {len(sleep_calls)}")
    if sleep_calls:
        print(f"    First sleep: Line {sleep_calls[0][0]} - {sleep_calls[0][1]}")
    
    # Does thread create other threads?
    create_calls = [c for c in kernel_calls if 'CreateThread' in c[1]]
    print(f"  Thread creation calls: {len(create_calls)}")
    
    # Does thread do I/O?
    io_calls = [c for c in kernel_calls if any(x in c[1] for x in ['Read', 'Write', 'Open', 'Create', 'File'])]
    print(f"  I/O calls: {len(io_calls)}")
    
    return {
        'created_line': thread_created_line,
        'execute_line': thread_execute_line,
        'total_lines': len(thread_lines),
        'kernel_calls': len(kernel_calls),
        'call_counts': call_counts,
        'thread_lines': thread_lines,
        'kernel_calls_list': kernel_calls
    }

def find_resume_call(log_file):
    """Find who calls NtResumeThread for Thread #2."""
    print(f"\n{'=' * 80}")
    print("SEARCHING FOR NtResumeThread CALLS FOR THREAD #2")
    print(f"{'=' * 80}")
    
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            if 'NtResumeThread' in line or 'ResumeThread' in line:
                # Check if it's around the thread creation time (lines 9951-10399)
                if 9900 < line_num < 10500:
                    print(f"[{line_num:6d}] {line.strip()}")

if __name__ == '__main__':
    log_file = 'tools/xenia.log'
    
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    
    print(f"Analyzing: {log_file}\n")
    
    result = analyze_xenia_log(log_file)
    find_resume_call(log_file)
    
    print(f"\n{'=' * 80}")
    print("ANALYSIS COMPLETE")
    print(f"{'=' * 80}")
    print("\nKey findings:")
    print(f"  - Thread #2 created at line {result['created_line']}")
    print(f"  - Thread #2 execution started at line {result['execute_line']}")
    if result['created_line'] and result['execute_line']:
        delay = result['execute_line'] - result['created_line']
        print(f"  - Delay: {delay} lines (~{delay/60:.1f} seconds at 60Hz)")
    print(f"  - Total activity: {result['total_lines']} log lines")
    print(f"  - Kernel calls: {result['kernel_calls']}")
    
    if result['call_counts']:
        top_call = max(result['call_counts'].items(), key=lambda x: x[1])
        print(f"  - Most frequent call: {top_call[0]} ({top_call[1]} times)")

