#!/usr/bin/env python3
"""
Analyze thread initialization call chain from IDA export.
Traces back from sub_8284F548 (video thread creation) to find what should trigger it.
"""

import re
import subprocess

def search_callers(func_name):
    """Use PowerShell to search for callers of a function."""
    cmd = f"powershell -Command \"Select-String -Path 'NfsMWEurope.xex.html' -Pattern 'bl.*{func_name}' | Select-Object -First 10\""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)

    callers = []
    for line in result.stdout.split('\n'):
        # Extract address from line like: .text:82548F44                 bl        sub_82849DE8
        match = re.search(r'\.text:([0-9A-F]{8})', line)
        if match:
            addr = match.group(1)
            callers.append(addr)

    return callers

def get_function_at_address(addr):
    """Find which function contains the given address."""
    cmd = f"powershell -Command \"Select-String -Path 'NfsMWEurope.xex.html' -Pattern '\.text:{addr}' -Context 20,0 | Select-Object -First 1\""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)

    # Look backwards in context for function definition
    lines = result.stdout.split('\n')
    for line in reversed(lines):
        # Match function definition: sub_82548F18:
        match = re.search(r'(sub_[0-9A-F]{8}):', line)
        if match:
            return match.group(1)

    return None

def trace_chain(func_name, depth=0, max_depth=10, visited=None):
    """Recursively trace call chain."""
    if visited is None:
        visited = set()

    if depth > max_depth or func_name in visited:
        return

    visited.add(func_name)
    indent = "  " * depth

    print(f"{indent}{func_name}")

    # Find callers
    caller_addrs = search_callers(func_name)
    if not caller_addrs:
        print(f"{indent}  [NO CALLERS FOUND]")
        return

    for addr in caller_addrs:
        caller_func = get_function_at_address(addr)
        if caller_func:
            print(f"{indent}  <- {caller_func} (at 0x{addr})")
            trace_chain(caller_func, depth + 1, max_depth, visited)

def main():
    print("="*80)
    print("VIDEO THREAD CREATION CHAIN")
    print("="*80)
    trace_chain('sub_8284F548', max_depth=8)

    print("\n" + "="*80)
    print("MAIN THREAD UNBLOCK CHAIN")
    print("="*80)
    trace_chain('sub_824411E0', max_depth=8)

if __name__ == '__main__':
    main()

