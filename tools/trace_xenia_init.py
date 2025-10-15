#!/usr/bin/env python3
"""
Trace Xenia execution to find initialization sequence for work queue at 0x829091C8.
This script analyzes Xenia log to find:
1. When loc_828A89F0 is called (jump table entry)
2. When sub_823CA1D8 is called (queue processor)
3. What calls these functions
4. The initialization sequence
"""

import re
import sys

def analyze_xenia_log(log_path):
    """Analyze Xenia log for initialization sequence."""
    
    print(f"[*] Analyzing Xenia log: {log_path}")
    
    # Addresses of interest
    targets = {
        '0x828A89F0': 'loc_828A89F0 (jump table entry)',
        '0x828A89F4': 'loc_828A89F4 (loads queue address)',
        '0x823CA1D8': 'sub_823CA1D8 (queue processor)',
        '0x823B9E00': 'sub_823B9E00 (work queue processor)',
        '0x823BC638': 'sub_823BC638 (work queue wait)',
        '0x829091C8': 'work queue address',
        '0x829091CC': 'work queue tail',
    }
    
    # Track function calls
    calls = []
    writes = []
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            # Look for function calls
            for addr, desc in targets.items():
                if addr.lower() in line.lower():
                    calls.append({
                        'line': line_num,
                        'addr': addr,
                        'desc': desc,
                        'text': line.strip()
                    })
            
            # Look for memory writes to work queue
            if '829091c8' in line.lower() or '829091cc' in line.lower():
                writes.append({
                    'line': line_num,
                    'text': line.strip()
                })
    
    print(f"\n[*] Found {len(calls)} references to target addresses")
    print(f"[*] Found {len(writes)} references to work queue memory")
    
    # Print first 20 calls
    print("\n[*] First 20 function calls/references:")
    for i, call in enumerate(calls[:20]):
        print(f"  Line {call['line']:6d}: {call['addr']} - {call['desc']}")
        print(f"              {call['text'][:120]}")
    
    # Print memory writes
    print("\n[*] Memory writes to work queue:")
    for write in writes[:20]:
        print(f"  Line {write['line']:6d}: {write['text'][:120]}")
    
    return calls, writes

def find_call_chain(log_path, target_addr):
    """Find the call chain that leads to target_addr."""
    
    print(f"\n[*] Finding call chain to {target_addr}")
    
    # Look for ExCreateThread calls that might create threads
    # Look for function calls around the target
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    # Find lines with target address
    target_lines = []
    for i, line in enumerate(lines):
        if target_addr.lower() in line.lower():
            target_lines.append(i)
    
    print(f"[*] Found {len(target_lines)} lines with {target_addr}")
    
    # Print context around first occurrence
    if target_lines:
        first = target_lines[0]
        print(f"\n[*] Context around first occurrence (line {first+1}):")
        start = max(0, first - 10)
        end = min(len(lines), first + 10)
        for i in range(start, end):
            marker = ">>>" if i == first else "   "
            print(f"{marker} {i+1:6d}: {lines[i].rstrip()[:120]}")

if __name__ == '__main__':
    log_path = 'tools/xenia.log'
    
    if len(sys.argv) > 1:
        log_path = sys.argv[1]
    
    print("="*80)
    print("Xenia Initialization Trace Analyzer")
    print("="*80)
    
    calls, writes = analyze_xenia_log(log_path)
    
    # Find call chains for key functions
    find_call_chain(log_path, '0x823CA1D8')
    find_call_chain(log_path, '0x828A89F0')
    
    print("\n" + "="*80)
    print("Analysis complete")
    print("="*80)

