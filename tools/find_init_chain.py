#!/usr/bin/env python3
"""
Find the initialization chain that leads to VdSetGraphicsInterruptCallback.
Trace backwards from sub_825A85E0 to find the entry point.
"""

import re
import sys
from pathlib import Path

# The call chain we know so far:
# sub_825A85E0 -> VdSetGraphicsInterruptCallback
# sub_825A8698 -> sub_825A85E0
# sub_825A16A0 -> sub_825A8698
# sub_82440448 -> sub_825A16A0
# sub_82440530 -> sub_82440448
# sub_82216088 -> sub_82440530
# sub_823AF590 -> sub_82216088

def find_callers(func_addr, ppc_dir):
    """Find all functions that call the given function."""
    callers = []
    pattern = re.compile(rf'sub_{func_addr}\(ctx, base\)')
    
    for cpp_file in ppc_dir.glob('ppc_recomp.*.cpp'):
        with open(cpp_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Find all calls to this function
        for match in pattern.finditer(content):
            # Find the function that contains this call
            # Search backwards for the function definition
            before = content[:match.start()]
            func_def_pattern = re.compile(r'PPC_FUNC_IMPL\(__imp__sub_([0-9A-F]+)\)')
            func_defs = list(func_def_pattern.finditer(before))
            if func_defs:
                caller_addr = func_defs[-1].group(1)
                callers.append(caller_addr)
                print(f"  Found: sub_{caller_addr} -> sub_{func_addr} in {cpp_file.name}")
    
    return callers

def main():
    repo_root = Path(__file__).parent.parent
    ppc_dir = repo_root / 'Mw05RecompLib' / 'ppc'
    
    # Start from sub_823AF590 and trace backwards
    current = '823AF590'
    chain = [current]
    
    print(f"Tracing call chain backwards from sub_{current}...")
    print()
    
    for depth in range(10):  # Max depth 10
        print(f"Depth {depth}: Finding callers of sub_{current}...")
        callers = find_callers(current, ppc_dir)
        
        if not callers:
            print(f"  No callers found! sub_{current} might be the entry point.")
            break
        
        # Pick the first caller and continue
        current = callers[0]
        chain.append(current)
        print()
    
    print()
    print("=" * 60)
    print("CALL CHAIN (from entry point to VdSetGraphicsInterruptCallback):")
    print("=" * 60)
    for i, addr in enumerate(reversed(chain)):
        indent = "  " * i
        print(f"{indent}sub_{addr}")
    print(f"{'  ' * len(chain)}sub_825A85E0")
    print(f"{'  ' * (len(chain) + 1)}VdSetGraphicsInterruptCallback")
    
    # Now check which of these functions are being called in the trace log
    print()
    print("=" * 60)
    print("Checking which functions are called in mw05_host_trace.log...")
    print("=" * 60)
    
    trace_log = repo_root / 'out' / 'build' / 'x64-Clang-Debug' / 'Mw05Recomp' / 'mw05_host_trace.log'
    if trace_log.exists():
        with open(trace_log, 'r', encoding='utf-8') as f:
            log_content = f.read()
        
        for addr in reversed(chain):
            if addr in log_content:
                print(f"  ✓ sub_{addr} IS called")
            else:
                print(f"  ✗ sub_{addr} NOT called <-- FIRST MISSING")
                break
    else:
        print(f"  Trace log not found: {trace_log}")

if __name__ == '__main__':
    main()

